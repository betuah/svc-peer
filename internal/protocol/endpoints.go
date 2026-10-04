package protocol

import (
	"net"
	"net/netip"
	"sort"
	"strconv"
)

// Endpoint source tags used in candidate exchange.
const (
	EndpointSrcHost  = "host"  // host-local interface address (private or public)
	EndpointSrcSrflx = "srflx" // STUN server-reflexive
)

// IsUnderlayPrivate reports whether ip is suitable for same-site / routed underlay
// direct paths (RFC1918, link-local, ULA, CGNAT).
func IsUnderlayPrivate(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return false
		}
		addr, err = netip.ParseAddr(parsed.String())
		if err != nil {
			return false
		}
	}
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() {
		return false
	}
	if addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return true
	}
	// CGNAT (RFC 6598) — common on site underlays / carrier NAT segments.
	if addr.Is4() {
		a := addr.As4()
		if a[0] == 100 && a[1] >= 64 && a[1] <= 127 {
			return true
		}
	}
	return false
}

// endpointRank lower is preferred for WireGuard peer selection.
// Order: underlay/private host → other host → STUN reflexive → unknown.
func endpointRank(ep Endpoint) int {
	switch ep.Src {
	case EndpointSrcHost, "":
		if IsUnderlayPrivate(ep.IP) {
			return 0
		}
		return 1
	case EndpointSrcSrflx:
		return 2
	default:
		return 3
	}
}

// RankEndpoints returns a copy sorted for path selection:
// private/underlay host, then other host, then STUN reflexive.
func RankEndpoints(eps []Endpoint) []Endpoint {
	out := append([]Endpoint(nil), eps...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := endpointRank(out[i]), endpointRank(out[j])
		if ri != rj {
			return ri < rj
		}
		if out[i].IP != out[j].IP {
			return out[i].IP < out[j].IP
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// PreferredEndpoint returns host:port for the highest-priority candidate, or "".
func PreferredEndpoint(eps []Endpoint) string {
	ranked := RankEndpoints(eps)
	for _, ep := range ranked {
		if ep.IP == "" || ep.Port == 0 {
			continue
		}
		return net.JoinHostPort(ep.IP, strconv.Itoa(ep.Port))
	}
	return ""
}
