package relay

import (
	"io"
	"sync/atomic"

	"github.com/betuah/svc-peer/internal/metrics"
)

// relayStats holds process-level relay counters shared by UDP and WS paths.
type relayStats struct {
	forwards *metrics.Counter
	bytes    *metrics.Counter
	udpPeers atomic.Int64
	wsPeers  atomic.Int64
}

func newRelayStats(reg *metrics.Registry) *relayStats {
	return &relayStats{
		forwards: reg.Counter("svc_peer_relay_forwards_total", "Opaque WireGuard frames forwarded"),
		bytes:    reg.Counter("svc_peer_relay_bytes_total", "Payload bytes forwarded"),
	}
}

func (s *relayStats) collect(w io.Writer) error {
	if err := metrics.WriteGaugeFamily(w, "svc_peer_relay_sessions",
		"Peers currently announced or connected to the relay",
		float64(s.udpPeers.Load()+s.wsPeers.Load()),
		"transport", "all"); err != nil {
		return err
	}
	if err := metrics.WriteGaugeSample(w, "svc_peer_relay_sessions",
		float64(s.udpPeers.Load()), "transport", "udp"); err != nil {
		return err
	}
	if err := metrics.WriteGaugeSample(w, "svc_peer_relay_sessions",
		float64(s.wsPeers.Load()), "transport", "ws"); err != nil {
		return err
	}
	return nil
}
