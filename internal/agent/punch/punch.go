// Package punch sends coordinated UDP probes toward peer candidates.
package punch

import (
	"context"
	"net"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
)

// Probe sends a few UDP datagrams to each candidate to open NAT bindings.
// Uses an ephemeral local socket (kernel WG owns the listen port).
func Probe(ctx context.Context, candidates []protocol.Endpoint) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return
	}
	defer conn.Close()

	payload := []byte("svc-peer-punch")
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(2 * time.Second)
	}
	_ = conn.SetDeadline(deadline)

	for i := 0; i < 3; i++ {
		for _, c := range candidates {
			if c.IP == "" || c.Port == 0 {
				continue
			}
			addr := &net.UDPAddr{IP: net.ParseIP(c.IP), Port: c.Port}
			if addr.IP == nil {
				continue
			}
			_, _ = conn.WriteToUDP(payload, addr)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}
