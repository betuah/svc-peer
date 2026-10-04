package hub

import (
	"strconv"

	"github.com/betuah/svc-peer/internal/protocol"
)

// NetmapBuilder builds agent↔agent peer maps and MagicDNS name→IP maps.
type NetmapBuilder struct {
	reg *Registry
}

// NewNetmapBuilder wraps a registry.
func NewNetmapBuilder(reg *Registry) *NetmapBuilder {
	return &NetmapBuilder{reg: reg}
}

// ForAgent returns peers visible to viewerAgentID (MVP: all other registered agents).
// ACL filtering is a future tightening; agents enforce via AllowedIPs only.
func (b *NetmapBuilder) ForAgent(viewerAgentID string) protocol.NetmapResponse {
	agents := b.reg.SnapshotAgents()
	peers := make([]protocol.PeerConfig, 0, len(agents))
	dnsMap := make(map[string]string, len(agents))

	for _, a := range agents {
		dnsMap[a.DNSName] = a.OverlayIP.Addr().String()
		dnsMap[a.Name] = a.OverlayIP.Addr().String()
		if a.ID == viewerAgentID {
			continue
		}
		endpoint := ""
		if len(a.Endpoints) > 0 {
			ep := a.Endpoints[0]
			endpoint = formatEndpoint(ep)
		}
		peers = append(peers, protocol.PeerConfig{
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
