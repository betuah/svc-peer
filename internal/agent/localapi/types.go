package localapi

import "time"

// AllowlistEntryView is one center-managed edge join token (secret redacted unless create).
type AllowlistEntryView struct {
	ID        string     `json:"id"`
	Token     string     `json:"token,omitempty"` // secret: only on create response
	Label     string     `json:"label,omitempty"`
	Tags      []string   `json:"tags,omitempty"`
	Status    string     `json:"status"` // active | revoked
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// AllowlistResponse is GET /local/allowlist.
type AllowlistResponse struct {
	Entries []AllowlistEntryView `json:"entries"`
}

// CreateAllowlistRequest is POST /local/allowlist.
type CreateAllowlistRequest struct {
	ID    string   `json:"id,omitempty"`
	Token string   `json:"token,omitempty"` // empty → generate
	Label string   `json:"label,omitempty"`
	Tags  []string `json:"tags,omitempty"`
}

// AllowlistSyncResult is POST /local/allowlist/sync (and internal center→hub sync).
type AllowlistSyncResult struct {
	HubID    string   `json:"hub_id,omitempty"`
	Upserted int      `json:"upserted"`
	IDs      []string `json:"ids,omitempty"`
	Revoked  int      `json:"revoked"`
}

// HealthResponse is GET /local/health.
type HealthResponse struct {
	Status  string `json:"status"`
	Role    string `json:"role"`
	AgentID string `json:"agent_id"`
	HubID   string `json:"hub_id,omitempty"`
}

// StatusResponse is GET /local/status (edge-oriented; also works on center).
type StatusResponse struct {
	Role              string `json:"role"`
	AgentID           string `json:"agent_id"`
	HubID             string `json:"hub_id,omitempty"`
	Name              string `json:"name,omitempty"`
	OverlayIP         string `json:"overlay_ip,omitempty"`
	CenterAgentID     string `json:"center_agent_id,omitempty"`
	HubConnected      bool   `json:"hub_connected"`
	CenterConnected   bool   `json:"center_connected"`
	CenterConnectivity string `json:"center_connectivity"` // online|offline|n/a
	WGBackend         string `json:"wg_backend,omitempty"`
}

// PeerView is one peer in GET /local/peers (and detail).
type PeerView struct {
	ID              string     `json:"id"`
	Name            string     `json:"name,omitempty"`
	Role            string     `json:"role,omitempty"`
	OverlayIP       string     `json:"overlay_ip,omitempty"`
	DNSName         string     `json:"dns_name,omitempty"`
	Online          *bool      `json:"online,omitempty"`
	LastSeen        *time.Time `json:"last_seen,omitempty"`
	Endpoint        string     `json:"endpoint,omitempty"`
	EndpointSummary string     `json:"endpoint_summary,omitempty"`
	Path            string     `json:"path,omitempty"` // direct|relay
	PublicKey       string     `json:"public_key,omitempty"`
	LastHandshake   *time.Time `json:"last_handshake,omitempty"`
	TXBytes         uint64     `json:"tx_bytes"`
	RXBytes         uint64     `json:"rx_bytes"`
	TXRXSource      string     `json:"tx_rx_source"` // wireguard_device
}

// PeersResponse is GET /local/peers.
type PeersResponse struct {
	Role  string     `json:"role"`
	HubID string     `json:"hub_id,omitempty"`
	Peers []PeerView `json:"peers"`
}
