package hub

import (
	"io"

	"github.com/betuah/svc-peer/internal/metrics"
)

func (h *Hub) registerMetrics() {
	h.metrics.AddCollector(func(w io.Writer) error {
		hubID := h.cfg.HubID
		if err := metrics.WriteGaugeFamily(w, "svc_peer_hub_agents_registered",
			"Registered agents for this hub_id (online and offline)",
			float64(h.reg.RegisteredCount()), "hub_id", hubID); err != nil {
			return err
		}
		if err := metrics.WriteGaugeFamily(w, "svc_peer_hub_agents_online",
			"Agents currently marked online",
			float64(h.reg.OnlineCount()), "hub_id", hubID); err != nil {
			return err
		}
		if err := metrics.WriteGaugeFamily(w, "svc_peer_hub_allowlist_size",
			"Active edge join tokens in the hub allowlist cache",
			float64(h.tokens.EdgeAllowlistCount()), "hub_id", hubID); err != nil {
			return err
		}
		if err := metrics.WriteGaugeFamily(w, "svc_peer_hub_grants",
			"Active A2A grants in the hub cache",
			float64(h.grants.Count()), "hub_id", hubID); err != nil {
			return err
		}
		if err := metrics.WriteGaugeFamily(w, "svc_peer_hub_ws_connections",
			"Active agent control WebSocket connections",
			float64(h.WSConnCount()), "hub_id", hubID); err != nil {
			return err
		}
		return nil
	})
	// Ensure HTTP counter/histogram families exist even before the first request.
	_ = metrics.NewHTTPMetrics(h.metrics, "svc_peer_hub_http")
}
