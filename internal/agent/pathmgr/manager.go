// Package pathmgr coordinates direct / punch / relay path selection per peer.
package pathmgr

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/betuah/svc-peer/internal/agent/punch"
	"github.com/betuah/svc-peer/internal/agent/relayclient"
	"github.com/betuah/svc-peer/internal/agent/wgdev"
	"github.com/betuah/svc-peer/internal/protocol"
)

// Control is the subset of hub client methods path manager needs.
type Control interface {
	Send(env protocol.Envelope) error
}

// Manager applies netmap peers, handles punch signals, and falls back to relay.
type Manager struct {
	log    *slog.Logger
	device wgdev.Device
	relay  *relayclient.Client
	ctrl   Control

	directWait time.Duration

	mu       sync.Mutex
	peers    map[string]protocol.PeerConfig // agentID → peer
	path     map[string]string              // agentID → direct|relay
	watching map[string]struct{}
}

// SetDirectWait configures how long to wait for a direct handshake before relay.
func (m *Manager) SetDirectWait(d time.Duration) {
	if d > 0 {
		m.directWait = d
	}
}

// New constructs a path manager.
func New(device wgdev.Device, relay *relayclient.Client, ctrl Control, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{
		log:        log,
		device:     device,
		relay:      relay,
		ctrl:       ctrl,
		directWait: 8 * time.Second,
		peers:      make(map[string]protocol.PeerConfig),
		path:       make(map[string]string),
		watching:   make(map[string]struct{}),
	}
}

// ApplyNetmap installs the peer set on the WG device and starts connectivity watches.
func (m *Manager) ApplyNetmap(ctx context.Context, revision uint64, peers []protocol.PeerConfig) error {
	if err := m.device.ConfigurePeers(revision, peers); err != nil {
		return err
	}
	var toWatch []protocol.PeerConfig
	m.mu.Lock()
	m.peers = make(map[string]protocol.PeerConfig, len(peers))
	for _, p := range peers {
		id := peerKey(p)
		m.peers[id] = p
		if _, ok := m.path[id]; !ok {
			m.path[id] = protocol.PathDirect
		}
		if _, watched := m.watching[id]; !watched {
			m.watching[id] = struct{}{}
			toWatch = append(toWatch, p)
		}
	}
	// Re-apply active relay shim endpoints after ReplacePeers.
	type relayFix struct {
		id  string
		pub string
	}
	var fixes []relayFix
	for id, path := range m.path {
		if path != protocol.PathRelay {
			continue
		}
		if p, ok := m.peers[id]; ok {
			fixes = append(fixes, relayFix{id: id, pub: p.PublicKey})
		}
	}
	m.mu.Unlock()

	for _, f := range fixes {
		local, err := m.relay.EnsurePeer(ctx, f.id)
		if err != nil {
			m.log.Debug("re-ensure relay after netmap", "peer", f.id, "err", err)
			continue
		}
		_ = m.device.UpdatePeerEndpoint(f.pub, local)
	}

	for _, p := range toWatch {
		p := p
		go m.watchPeer(ctx, p)
	}
	return nil
}

// HandlePunch runs UDP probes and sets WG endpoint to the first candidate.
func (m *Manager) HandlePunch(ctx context.Context, peerID string, candidates []protocol.Endpoint) {
	m.mu.Lock()
	peer, ok := m.peers[peerID]
	m.mu.Unlock()
	if !ok || peer.PublicKey == "" {
		return
	}
	punch.Probe(ctx, candidates)
	for _, c := range candidates {
		if c.IP == "" || c.Port == 0 {
			continue
		}
		ep := endpointString(c)
		if err := m.device.UpdatePeerEndpoint(peer.PublicKey, ep); err != nil {
			m.log.Debug("set punch endpoint failed", "peer", peerID, "err", err)
			continue
		}
		m.log.Info("punch endpoint applied", "peer", peerID, "endpoint", ep, "src", c.Src)
		m.setPath(peerID, protocol.PathDirect)
		_ = m.ctrl.Send(protocol.Envelope{
			Type:   protocol.TypePathStatus,
			PeerID: peerID,
			Path:   protocol.PathDirect,
		})
		return
	}
}

// HandleRelayTicket configures the relay client and switches peer to relay shim.
func (m *Manager) HandleRelayTicket(ctx context.Context, peerID, ticket string, urls []string) {
	m.relay.ConfigureTicket(ticket, urls)
	local, err := m.relay.EnsurePeer(ctx, peerID)
	if err != nil {
		m.log.Error("relay ensure peer failed", "peer", peerID, "err", err)
		return
	}
	m.mu.Lock()
	peer, ok := m.peers[peerID]
	m.mu.Unlock()
	if !ok {
		return
	}
	if err := m.device.UpdatePeerEndpoint(peer.PublicKey, local); err != nil {
		m.log.Error("set relay endpoint failed", "err", err)
		return
	}
	m.setPath(peerID, protocol.PathRelay)
	_ = m.ctrl.Send(protocol.Envelope{
		Type:   protocol.TypePathStatus,
		PeerID: peerID,
		Path:   protocol.PathRelay,
	})
	m.log.Info("relay path active", "peer", peerID, "shim", local)
}

func peerKey(p protocol.PeerConfig) string {
	if p.PeerID != "" {
		return p.PeerID
	}
	return p.AgentID
}

func (m *Manager) watchPeer(ctx context.Context, peer protocol.PeerConfig) {
	id := peerKey(peer)
	// Hub path uses keepalive/direct only — no A2A relay ticket.
	if id == "hub" {
		return
	}
	// Give direct / punch a chance, then request relay if no handshake.
	timer := time.NewTimer(m.directWait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	hs, ok, err := m.device.PeerLastHandshake(peer.PublicKey)
	if err == nil && ok && time.Since(hs) < 2*m.directWait {
		m.setPath(id, protocol.PathDirect)
		return
	}
	m.mu.Lock()
	cur := m.path[id]
	m.mu.Unlock()
	if cur == protocol.PathRelay {
		return
	}
	m.log.Info("direct path not established; requesting relay", "peer", id)
	_ = m.ctrl.Send(protocol.Envelope{
		Type:   protocol.TypeRelayRequest,
		PeerID: id,
	})
}

func (m *Manager) setPath(peerID, path string) {
	m.mu.Lock()
	m.path[peerID] = path
	m.mu.Unlock()
}

func endpointString(c protocol.Endpoint) string {
	return c.IP + ":" + strconv.Itoa(c.Port)
}
