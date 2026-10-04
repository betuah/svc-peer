package hub

import (
	"strconv"

	"github.com/betuah/svc-peer/internal/protocol"
)

// PeerIDHub is the stable peer_id for the hub WireGuard peer in agent netmaps.
const PeerIDHub = "hub"

// HubPeer is the hub's WireGuard identity advertised to agents (hub-spoke default).
type HubPeer struct {
	PeerID    string
	PublicKey string
	Endpoint  string
	OverlayIP string // e.g. 10.10.0.1/32
	DNSName   string
}

// NetmapBuilder builds ACL-derived peer maps and MagicDNS name→IP maps.
type NetmapBuilder struct {
	reg    *Registry
	grants *GrantStore
	hub    HubPeer
}

// NewNetmapBuilder wraps registry + grants + hub peer identity.
func NewNetmapBuilder(reg *Registry, grants *GrantStore, hub HubPeer) *NetmapBuilder {
	if hub.PeerID == "" {
		hub.PeerID = PeerIDHub
	}
	return &NetmapBuilder{reg: reg, grants: grants, hub: hub}
}

// ForAgent returns peers visible to viewerAgentID under hub-spoke ACL:
// default peers = [hub] only; granted A2A agents are added as direct WG peers.
// Denied pairs get no peer and no hairpin (hub AllowedIPs is hub /32 only).
func (b *NetmapBuilder) ForAgent(viewerAgentID string) protocol.NetmapResponse {
	agents := b.reg.SnapshotAgents()
	dnsMap := make(map[string]string, len(agents)+1)
	dnsMap[b.hub.DNSName] = stripPrefix(b.hub.OverlayIP)
	dnsMap["hub"] = stripPrefix(b.hub.OverlayIP)

	for _, a := range agents {
		dnsMap[a.DNSName] = a.OverlayIP.Addr().String()
		dnsMap[a.Name] = a.OverlayIP.Addr().String()
	}

	peers := make([]protocol.PeerConfig, 0, 1+len(b.grants.PeersOf(viewerAgentID)))
	peers = append(peers, protocol.PeerConfig{
		PeerID:              b.hub.PeerID,
		AgentID:             b.hub.PeerID, // pathmgr keys off AgentID
		PublicKey:           b.hub.PublicKey,
		Endpoint:            b.hub.Endpoint,
		AllowedIPs:          []string{b.hub.OverlayIP},
		DNSName:             b.hub.DNSName,
		PersistentKeepalive: 25,
	})

	for _, peerID := range b.grants.PeersOf(viewerAgentID) {
		a, err := b.reg.Get(peerID)
		if err != nil {
			continue
		}
		endpoint := ""
		if len(a.Endpoints) > 0 {
			endpoint = formatEndpoint(a.Endpoints[0])
		}
		peers = append(peers, protocol.PeerConfig{
			PeerID:              a.ID,
			AgentID:             a.ID,
			PublicKey:           a.PublicKey,
			Endpoint:            endpoint,
			AllowedIPs:          []string{a.OverlayIP.String()},
			DNSName:             a.DNSName,
			PersistentKeepalive: 25,
		})
	}

	return protocol.NetmapResponse{
		Revision: b.reg.Revision(),
		Peers:    peers,
		DNSMap:   dnsMap,
	}
}

// ForHub returns the hub's peer list: all agents on this hub (hub→agents allow).
func (b *NetmapBuilder) ForHub() protocol.NetmapResponse {
	agents := b.reg.SnapshotAgents()
	peers := make([]protocol.PeerConfig, 0, len(agents))
	dnsMap := make(map[string]string, len(agents))
	for _, a := range agents {
		dnsMap[a.DNSName] = a.OverlayIP.Addr().String()
		dnsMap[a.Name] = a.OverlayIP.Addr().String()
		endpoint := ""
		if len(a.Endpoints) > 0 {
			endpoint = formatEndpoint(a.Endpoints[0])
		}
		peers = append(peers, protocol.PeerConfig{
			PeerID:              a.ID,
			AgentID:             a.ID,
			PublicKey:           a.PublicKey,
			Endpoint:            endpoint,
			AllowedIPs:          []string{a.OverlayIP.String()},
			DNSName:             a.DNSName,
			PersistentKeepalive: 25,
		})
	}
	return protocol.NetmapResponse{
		Revision: b.reg.Revision(),
		Peers:    peers,
		DNSMap:   dnsMap,
	}
}

func formatEndpoint(ep protocol.Endpoint) string {
	if ep.IP == "" || ep.Port == 0 {
		return ""
	}
	return ep.IP + ":" + strconv.Itoa(ep.Port)
}

func stripPrefix(cidr string) string {
	for i := 0; i < len(cidr); i++ {
		if cidr[i] == '/' {
			return cidr[:i]
		}
	}
	return cidr
}
