package agent

import (
	"io"
	"time"

	"github.com/betuah/svc-peer/internal/metrics"
	"github.com/betuah/svc-peer/internal/protocol"
)

func (a *Agent) registerPeerCollectors() {
	a.met.AddCollector(func(w io.Writer) error {
		peers, _ := a.currentPeers()
		agentID := a.agentID
		hubID := a.cfg.HubID
		a.mu.RLock()
		if a.hubID != "" {
			hubID = a.hubID
		}
		a.mu.RUnlock()

		if err := metrics.WriteGaugeFamily(w, "svc_peer_agent_peers",
			"Peers currently applied from the ACL netmap",
			float64(len(peers)),
			"hub_id", hubID, "agent_id", agentID, "role", a.cfg.Role); err != nil {
			return err
		}

		wroteHS := false
		wroteTX := false
		wroteRX := false
		now := time.Now()
		for _, p := range peers {
			peerID := p.PeerID
			if peerID == "" {
				peerID = p.AgentID
			}
			if p.PublicKey == "" || a.device == nil {
				continue
			}
			st, ok, err := a.device.PeerStats(p.PublicKey)
			if err != nil || !ok {
				continue
			}
			labels := []string{"hub_id", hubID, "agent_id", agentID, "peer_id", peerID}
			age := float64(-1)
			if !st.LastHandshake.IsZero() {
				age = now.Sub(st.LastHandshake).Seconds()
				if age < 0 {
					age = 0
				}
			}
			if !wroteHS {
				if err := metrics.WriteGaugeFamily(w, "svc_peer_agent_wg_handshake_age_seconds",
					"Seconds since last WireGuard handshake (-1 if none)",
					age, labels...); err != nil {
					return err
				}
				wroteHS = true
			} else {
				if err := metrics.WriteGaugeSample(w, "svc_peer_agent_wg_handshake_age_seconds", age, labels...); err != nil {
					return err
				}
			}
			if !wroteTX {
				if err := metrics.WriteGaugeFamily(w, "svc_peer_agent_wg_tx_bytes",
					"WireGuard transmit bytes to peer (device counters)",
					float64(st.TransmitBytes), labels...); err != nil {
					return err
				}
				wroteTX = true
			} else {
				if err := metrics.WriteGaugeSample(w, "svc_peer_agent_wg_tx_bytes", float64(st.TransmitBytes), labels...); err != nil {
					return err
				}
			}
			if !wroteRX {
				if err := metrics.WriteGaugeFamily(w, "svc_peer_agent_wg_rx_bytes",
					"WireGuard receive bytes from peer (device counters)",
					float64(st.ReceiveBytes), labels...); err != nil {
					return err
				}
				wroteRX = true
			} else {
				if err := metrics.WriteGaugeSample(w, "svc_peer_agent_wg_rx_bytes", float64(st.ReceiveBytes), labels...); err != nil {
					return err
				}
			}
		}
		return nil
	})
	_ = metrics.NewHTTPMetrics(a.met, "svc_peer_agent_local_api")
}

func (a *Agent) currentPeers() ([]protocol.PeerConfig, map[string]string) {
	if a.paths == nil {
		return nil, nil
	}
	return a.paths.SnapshotPeers()
}
