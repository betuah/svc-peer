// Package endpoint discovers host-local (incl. private underlay) and STUN reflexive UDP candidates.
package endpoint

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/pion/stun/v2"
)

// Collect returns local host UDP endpoints for listenPort plus STUN srflx when possible.
// Results are ranked: private/underlay host → other host → STUN reflexive.
func Collect(ctx context.Context, listenPort int, stunURLs []string) ([]protocol.Endpoint, error) {
	var out []protocol.Endpoint
	hosts, err := hostIPs()
	if err != nil {
		return nil, err
	}
	for _, ip := range hosts {
		out = append(out, protocol.Endpoint{
			IP:    ip,
			Port:  listenPort,
			Proto: "udp",
			Src:   protocol.EndpointSrcHost,
		})
	}
	for _, raw := range stunURLs {
		srflx, err := stunReflexive(ctx, raw, listenPort)
		if err != nil {
			continue
		}
		out = append(out, srflx)
		break // one working STUN server is enough
	}
	return protocol.RankEndpoints(out), nil
}

func hostIPs() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var ips []string
	seen := make(map[string]struct{})
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			// IPv4 only for WG UDP candidates in MVP (matches prior behavior).
			v4 := ip.To4()
			if v4 == nil {
				continue
			}
			s := v4.String()
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			ips = append(ips, s)
		}
	}
	return ips, nil
}

func stunReflexive(ctx context.Context, stunURL string, localPort int) (protocol.Endpoint, error) {
	hostPort := strings.TrimPrefix(stunURL, "stun:")
	hostPort = strings.TrimPrefix(hostPort, "stuns:")
	if hostPort == stunURL && strings.Contains(stunURL, "://") {
		return protocol.Endpoint{}, fmt.Errorf("unsupported stun url %q", stunURL)
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	// Prefer ephemeral local port for STUN so we don't conflict with WG bind;
	// srflx still useful as candidate; WG listen port used for host candidates.
	conn, err := d.DialContext(ctx, "udp", hostPort)
	if err != nil {
		return protocol.Endpoint{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	uconn, ok := conn.(*net.UDPConn)
	if !ok {
		return protocol.Endpoint{}, fmt.Errorf("not udp")
	}
	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if _, err := uconn.Write(msg.Raw); err != nil {
		return protocol.Endpoint{}, err
	}
	buf := make([]byte, 1500)
	n, err := uconn.Read(buf)
	if err != nil {
		return protocol.Endpoint{}, err
	}
	var res stun.Message
	res.Raw = buf[:n]
	if err := res.Decode(); err != nil {
		return protocol.Endpoint{}, err
	}
	var xor stun.XORMappedAddress
	if err := xor.GetFrom(&res); err != nil {
		return protocol.Endpoint{}, err
	}
	port := xor.Port
	if localPort > 0 {
		// Prefer advertising WG listen port; NAT may still map differently — punch retries help.
		port = localPort
	}
	return protocol.Endpoint{
		IP:    xor.IP.String(),
		Port:  port,
		Proto: "udp",
		Src:   protocol.EndpointSrcSrflx,
	}, nil
}

// Format returns host:port.
func Format(ep protocol.Endpoint) string {
	return net.JoinHostPort(ep.IP, strconv.Itoa(ep.Port))
}
