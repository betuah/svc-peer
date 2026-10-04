package hub

import (
	"github.com/betuah/svc-peer/internal/protocol"
)

// NetmapBuilder builds ACL-derived peer maps (edge↔center) and MagicDNS maps.
// Hub is NOT included as an application dataplane next-hop.
type NetmapBuilder struct {
	reg    *Registry
	grants *GrantStore
}

// NewNetmapBuilder wraps registry + grants.
func NewNetmapBuilder(reg *Registry, grants *GrantStore) *NetmapBuilder {
	return &NetmapBuilder{reg: reg, grants: grants}
}

// ForAgent returns peers for viewerAgentID under center-role ACL:
// - edge: peers = [center] (+ optional grants)
// - center: peers = all edges (+ optional grants)
// Hub never appears in the peer list for app traffic.
func (b *NetmapBuilder) ForAgent(viewerAgentID string) protocol.NetmapResponse {
	viewer, err := b.reg.Get(viewerAgentID)
	if err != nil {
		return protocol.NetmapResponse{Revision: b.reg.Revision()}
	}
	agents := b.reg.SnapshotAgents()
	dnsMap := make(map[string]string, len(agents))
	for _, a := range agents {
		dnsMap[a.DNSName] = a.OverlayIP.Addr().String()
		dnsMap[a.Name] = a.OverlayIP.Addr().String()
		if a.Role == protocol.RoleCenter {
			dnsMap["center"] = a.OverlayIP.Addr().String()
		}
	}

	centerID := b.reg.CenterAgentID()
	peers := make([]protocol.PeerConfig, 0)

	switch viewer.Role {
	case protocol.RoleEdge:
		if centerID != "" {
			if c, err := b.reg.Get(centerID); err == nil {
				peers = append(peers, peerFromAgent(c))
			}
		}
	case protocol.RoleCenter:
		for _, a := range agents {
			if a.ID == viewerAgentID || a.Role != protocol.RoleEdge {
				continue
			}
			peers = append(peers, peerFromAgent(a))
		}
	}

	// Extra center-authored A2A grants (beyond edge↔center).
	for _, peerID := range b.grants.PeersOf(viewerAgentID) {
		if peerID == centerID && viewer.Role == protocol.RoleEdge {
			continue // already included
		}
		if viewer.Role == protocol.RoleCenter {
			// center already has all edges; skip duplicates
			dup := false
			for _, p := range peers {
				if p.PeerID == peerID {
					dup = true
					break
				}
			}
			if dup {
				continue
			}
		}
		a, err := b.reg.Get(peerID)
		if err != nil {
			continue
		}
		peers = append(peers, peerFromAgent(a))
	}

	return protocol.NetmapResponse{
		Revision:      b.reg.Revision(),
		CenterAgentID: centerID,
		Peers:         peers,
		DNSMap:        dnsMap,
	}
}

// AllowedPeer reports whether A may have a direct WG / punch / relay path to B.
func (b *NetmapBuilder) AllowedPeer(agentA, agentB string) bool {
	if agentA == "" || agentB == "" || agentA == agentB {
		return false
	}
	a, errA := b.reg.Get(agentA)
	bAgent, errB := b.reg.Get(agentB)
	if errA != nil || errB != nil {
		return false
	}
	// Default allow: edge ↔ center
	if (a.Role == protocol.RoleEdge && bAgent.Role == protocol.RoleCenter) ||
		(a.Role == protocol.RoleCenter && bAgent.Role == protocol.RoleEdge) {
		return true
	}
	return b.grants.Allowed(agentA, agentB)
}

func peerFromAgent(a *Agent) protocol.PeerConfig {
	// Prefer underlay/private host endpoints over STUN reflexive so same-site
	// peers use direct L3 paths instead of hairpinning via public/NAT addresses.
	endpoint := protocol.PreferredEndpoint(a.Endpoints)
	return protocol.PeerConfig{
		PeerID:              a.ID,
		AgentID:             a.ID,
		Role:                a.Role,
		PublicKey:           a.PublicKey,
		Endpoint:            endpoint,
		AllowedIPs:          []string{a.OverlayIP.String()},
		DNSName:             a.DNSName,
		PersistentKeepalive: 25,
	}
}
