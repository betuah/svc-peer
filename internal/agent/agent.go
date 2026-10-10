package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/betuah/svc-peer/internal/agent/allowlist"
	"github.com/betuah/svc-peer/internal/agent/dns"
	"github.com/betuah/svc-peer/internal/agent/endpoint"
	"github.com/betuah/svc-peer/internal/agent/grants"
	"github.com/betuah/svc-peer/internal/agent/identity"
	"github.com/betuah/svc-peer/internal/agent/localapi"
	"github.com/betuah/svc-peer/internal/agent/pathmgr"
	"github.com/betuah/svc-peer/internal/agent/relayclient"
	"github.com/betuah/svc-peer/internal/agent/wgdev"
	"github.com/betuah/svc-peer/internal/metrics"
	"github.com/betuah/svc-peer/internal/protocol"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Agent is the local peer process: register with hub, apply netmap, maintain WG device.
type Agent struct {
	cfg            Config
	log            *slog.Logger
	client         *HubClient
	device         wgdev.Device
	dns            *dns.Resolver
	relay          *relayclient.Client
	paths          *pathmgr.Manager
	allowlist      *allowlist.Store // center only
	grants         *grants.Store    // center only
	met            *metrics.Registry
	registerTotal  *metrics.Counter
	reconnectTotal *metrics.Counter
	agentID        string
	pubKey         string
	privKey        string
	stun           []string
	relays         []string

	mu            sync.RWMutex
	hubID         string
	role          string
	overlayIP     string
	centerAgentID string
}

// New constructs an agent from config.
func New(cfg Config, log *slog.Logger) (*Agent, error) {
	if log == nil {
		log = slog.Default()
	}
	dev, err := wgdev.Open(cfg.WGBackend)
	if err != nil {
		return nil, err
	}
	priv, pub, err := loadOrGenerateKeys(cfg.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	agentID, err := identity.LoadOrCreate(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	var al *allowlist.Store
	var gs *grants.Store
	if cfg.Role == protocol.RoleCenter {
		al, err = allowlist.Open(cfg.StateDir)
		if err != nil {
			return nil, err
		}
		seeds := make([]allowlist.Seed, 0, len(cfg.EdgeTokens))
		for _, t := range cfg.EdgeTokens {
			seeds = append(seeds, allowlist.Seed{ID: t.ID, Token: t.Token, Label: t.Label, Tags: t.Tags})
		}
		if err := al.SeedFromConfig(seeds); err != nil {
			return nil, fmt.Errorf("seed allowlist: %w", err)
		}
		gs, err = grants.Open(cfg.StateDir)
		if err != nil {
			return nil, err
		}
	}
	log = log.With("component", "agent", "role", cfg.Role, "agent_id", agentID)
	met := metrics.NewRegistry()
	registerTotal := met.Counter("svc_peer_agent_register_total", "Hub register attempts by result")
	reconnectTotal := met.Counter("svc_peer_agent_reconnect_total", "Control WebSocket connect attempts by result")
	a := &Agent{
		cfg:            cfg,
		log:            log,
		client:         NewHubClient(cfg.HubURL, cfg.AuthCredential(), cfg.HubTLSInsecureSkipVerify, log),
		device:         dev,
		dns:            dns.NewResolver(),
		allowlist:      al,
		grants:         gs,
		met:            met,
		registerTotal:  registerTotal,
		reconnectTotal: reconnectTotal,
		agentID:        agentID,
		role:           cfg.Role,
		privKey:        priv,
		pubKey:         pub,
	}
	a.registerPeerCollectors()
	return a, nil
}

// Metrics returns the agent Prometheus registry (served on the local API).
func (a *Agent) Metrics() *metrics.Registry { return a.met }

// Run registers, brings up WG, reports endpoints, and maintains control + path selection.
func (a *Agent) Run(ctx context.Context) error {
	reg, err := a.client.Register(ctx, protocol.RegisterRequest{
		AgentID:      a.agentID,
		Name:         a.cfg.Name,
		PublicKey:    a.pubKey,
		Role:         a.cfg.Role,
		Tags:         a.cfg.Tags,
		Capabilities: a.cfg.Capabilities,
		Platform:     runtime.GOOS + "/" + runtime.GOARCH,
		WGBackend:    a.device.Backend(),
	})
	if err != nil {
		a.registerTotal.Inc("result", "error")
		return fmt.Errorf("register: %w", err)
	}
	a.registerTotal.Inc("result", "ok")
	if reg.AgentID != a.agentID {
		return fmt.Errorf("hub returned different agent_id: local=%s hub=%s", a.agentID, reg.AgentID)
	}
	hubID := reg.HubID
	if hubID == "" {
		hubID = a.cfg.HubID
	}
	a.mu.Lock()
	a.hubID = hubID
	a.role = reg.Role
	a.overlayIP = reg.OverlayIP
	a.centerAgentID = reg.CenterAgentID
	a.mu.Unlock()
	a.stun = reg.STUNURLs
	a.relays = reg.RelayURLs
	a.dns.Update(reg.DNSMap)
	a.relay = relayclient.New(a.agentID, a.log)
	a.paths = pathmgr.New(a.device, a.relay, a.client, a.log)
	if a.cfg.DirectWaitSec > 0 {
		a.paths.SetDirectWait(time.Duration(a.cfg.DirectWaitSec) * time.Second)
	}

	a.log.Info("registered",
		"agent_id", reg.AgentID,
		"hub_id", reg.HubID,
		"role", reg.Role,
		"center_agent_id", reg.CenterAgentID,
		"overlay_ip", reg.OverlayIP,
		"dns_name", reg.DNSName,
		"peers", len(reg.Peers),
		"wg_backend", a.device.Backend(),
	)

	if a.cfg.LocalAPIListen != "" {
		lv := localView{a: a}
		localSrv := localapi.New(lv, lv, lv, a.log, a.met)
		go func() {
			if err := localSrv.Start(ctx, a.cfg.LocalAPIListen); err != nil && err != context.Canceled {
				a.log.Error("local api stopped", "err", err)
			}
		}()
	}

	// Center syncs edge join-token allowlist to thin hub (primary edge onboarding path).
	if a.cfg.Role == protocol.RoleCenter && a.allowlist != nil {
		syncResp, err := a.SyncAllowlistToHub(ctx)
		if err != nil {
			return fmt.Errorf("sync allowlist: %w", err)
		}
		a.log.Info("synced edge allowlist to hub", "upserted", syncResp.Upserted, "revoked", syncResp.Revoked, "ids", syncResp.IDs)
	}
	// Center re-pushes durable A2A grants so hub netmap/punch/relay match after restart.
	if a.cfg.Role == protocol.RoleCenter && a.grants != nil {
		grantSync, err := a.SyncGrantsToHub(ctx)
		if err != nil {
			return fmt.Errorf("sync grants: %w", err)
		}
		a.log.Info("synced A2A grants to hub", "upserted", grantSync.Upserted, "revoked", grantSync.Revoked, "ids", grantSync.IDs)
	}

	if err := a.device.Up(wgdev.InterfaceConfig{
		Name:       a.cfg.WGInterface,
		PrivateKey: a.privKey,
		Addresses:  []string{reg.OverlayIP},
		ListenPort: a.cfg.WGListenPort,
		MTU:        1420,
	}); err != nil {
		return fmt.Errorf("wg up: %w", err)
	}
	defer a.device.Close()
	defer a.relay.CloseAll()

	if err := a.paths.ApplyNetmap(ctx, reg.NetmapRevision, reg.Peers); err != nil {
		return err
	}

	hb := time.Duration(a.cfg.HeartbeatSec) * time.Second
	wsErr := make(chan error, 1)
	go func() {
		connected := false
		err := a.client.RunControlWS(ctx, a.agentID, hubID, hb, Handlers{
			OnNetmap: func(env protocol.Envelope) {
				a.dns.Update(env.DNSMap)
				if err := a.paths.ApplyNetmap(ctx, env.Revision, env.Peers); err != nil {
					a.log.Error("apply netmap failed", "err", err)
					return
				}
				a.log.Info("netmap applied", "revision", env.Revision, "peers", len(env.Peers))
			},
			OnPunch: func(env protocol.Envelope) {
				pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
				defer cancel()
				a.paths.HandlePunch(pctx, env.PeerID, env.Candidates)
			},
			OnRelayTicket: func(env protocol.Envelope) {
				urls := env.URLs
				if len(urls) == 0 {
					urls = a.relays
				}
				a.paths.HandleRelayTicket(ctx, env.PeerID, env.Ticket, urls)
			},
			OnConnected: func() {
				connected = true
				a.reconnectTotal.Inc("result", "ok")
				a.log.Info("control websocket connected", "hub_id", hubID)
			},
		})
		if err != nil && ctx.Err() == nil && !connected {
			a.reconnectTotal.Inc("result", "error")
		}
		wsErr <- err
	}()

	endpointTicker := time.NewTicker(60 * time.Second)
	defer endpointTicker.Stop()
	report := func() {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := a.ReportEndpoints(rctx); err != nil {
			a.log.Debug("endpoint report", "err", err)
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-wsErr:
		return err
	case <-time.After(300 * time.Millisecond):
		report()
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-wsErr:
			return err
		case <-endpointTicker.C:
			report()
		}
	}
}

// ReportEndpoints discovers host-local (private underlay + other) and STUN
// candidates, ranked for underlay-first path selection, and sends endpoint_report.
func (a *Agent) ReportEndpoints(ctx context.Context) error {
	eps, err := endpoint.Collect(ctx, a.cfg.WGListenPort, a.stun)
	if err != nil {
		return err
	}
	if len(eps) == 0 {
		return fmt.Errorf("no endpoints discovered")
	}
	private := 0
	for _, ep := range eps {
		if ep.Src == protocol.EndpointSrcHost && protocol.IsUnderlayPrivate(ep.IP) {
			private++
		}
	}
	a.log.Info("reporting endpoints", "count", len(eps), "private_host", private)
	return a.client.Send(protocol.Envelope{
		Type:      protocol.TypeEndpointReport,
		Endpoints: eps,
	})
}

// Resolver exposes MagicDNS for tests / local tooling.
func (a *Agent) Resolver() *dns.Resolver { return a.dns }

// AgentID returns the locally persisted agent id.
func (a *Agent) AgentID() string { return a.agentID }

func loadOrGenerateKeys(path string) (priv, pub string, err error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			priv = strings.TrimSpace(string(data))
			key, err := wgtypes.ParseKey(priv)
			if err != nil {
				return "", "", fmt.Errorf("parse private key file: %w", err)
			}
			return key.String(), key.PublicKey().String(), nil
		}
		if !os.IsNotExist(err) {
			return "", "", err
		}
	}
	priv, pub, err = wgdev.GenerateKeyPair()
	if err != nil {
		return "", "", err
	}
	if path != "" {
		if err := os.WriteFile(path, []byte(priv+"\n"), 0o600); err != nil {
			return "", "", fmt.Errorf("write private key: %w", err)
		}
	}
	return priv, pub, nil
}
