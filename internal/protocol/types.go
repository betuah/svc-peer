// Package protocol defines shared control-plane message types used by hub, agent, and relay.
package protocol

import "time"

// Agent roles within a hub_id.
const (
	RoleCenter = "center"
	RoleEdge   = "edge"
)

// PeerConfig is a WireGuard peer entry in a netmap revision.
type PeerConfig struct {
	PeerID              string   `json:"peer_id"`
	AgentID             string   `json:"agent_id,omitempty"`
	Role                string   `json:"role,omitempty"` // center | edge
	PublicKey           string   `json:"public_key"`
	Endpoint            string   `json:"endpoint,omitempty"`
	AllowedIPs          []string `json:"allowed_ips"`
	DNSName             string   `json:"dns_name,omitempty"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`
}

// Endpoint describes a reported UDP candidate (host or STUN reflexive).
type Endpoint struct {
	IP    string `json:"ip"`
	Port  int    `json:"port"`
	Proto string `json:"proto"` // "udp"
	Src   string `json:"src"`   // "host" | "srflx"
}

// AgentSummary is returned by GET /agents.
type AgentSummary struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Role         string    `json:"role"`
	OverlayIP    string    `json:"overlay_ip"`
	DNSName      string    `json:"dns_name"`
	Tags         []string  `json:"tags,omitempty"`
	Capabilities []string  `json:"capabilities,omitempty"`
	Online       bool      `json:"online"`
	LastSeen     time.Time `json:"last_seen"`
}

// RegisterRequest is the body of POST /agents/register.
// AgentID is generated locally by the agent and persisted on disk — not assigned by the hub.
type RegisterRequest struct {
	AgentID      string   `json:"agent_id"`
	Name         string   `json:"name"`
	PublicKey    string   `json:"public_key"`
	Role         string   `json:"role,omitempty"` // center | edge
	Tags         []string `json:"tags,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Platform     string   `json:"platform,omitempty"`
	WGBackend    string   `json:"wg_backend,omitempty"`
}

// RegisterResponse is returned after a successful register (first or reconnect).
type RegisterResponse struct {
	AgentID        string            `json:"agent_id"`
	HubID          string            `json:"hub_id"`
	Role           string            `json:"role"`
	CenterAgentID  string            `json:"center_agent_id,omitempty"`
	OverlayIP      string            `json:"overlay_ip"`
	DNSName        string            `json:"dns_name"`
	NetmapRevision uint64            `json:"netmap_revision"`
	Peers          []PeerConfig      `json:"peers"`
	DNSMap         map[string]string `json:"dns_map,omitempty"`
	STUNURLs       []string          `json:"stun_urls,omitempty"`
	RelayURLs      []string          `json:"relay_urls,omitempty"`
}

// AgentsListResponse is the body of GET /agents.
type AgentsListResponse struct {
	HubID         string         `json:"hub_id"`
	CenterAgentID string         `json:"center_agent_id,omitempty"`
	Agents        []AgentSummary `json:"agents"`
}

// NetmapResponse is GET /netmap (or WS netmap push payload without type wrapper).
type NetmapResponse struct {
	Revision      uint64            `json:"revision"`
	CenterAgentID string            `json:"center_agent_id,omitempty"`
	Peers         []PeerConfig      `json:"peers"`
	DNSMap        map[string]string `json:"dns_map,omitempty"`
}

// HealthResponse is GET /health.
type HealthResponse struct {
	Status          string `json:"status"`
	HubID           string `json:"hub_id"`
	CenterAgentID   string `json:"center_agent_id,omitempty"`
	AgentsConnected int    `json:"agents_connected"`
	NetmapRevision  uint64 `json:"netmap_revision"`
}

// AllowlistToken is one edge join token pushed from center → hub.
type AllowlistToken struct {
	ID    string   `json:"id,omitempty"`
	Token string   `json:"token"`
	Label string   `json:"label,omitempty"`
	Tags  []string `json:"tags,omitempty"`
}

// AllowlistSyncRequest is PUT /hub/allowlist (center-authored).
type AllowlistSyncRequest struct {
	Tokens []AllowlistToken `json:"tokens"`
}

// AllowlistSyncResponse acknowledges a center allowlist sync.
type AllowlistSyncResponse struct {
	HubID  string   `json:"hub_id"`
	Upsert int      `json:"upserted"`
	IDs    []string `json:"ids,omitempty"`
}

// CreateTokenRequest is break-glass POST /hub/tokens (management only).
type CreateTokenRequest struct {
	Label string   `json:"label,omitempty"`
	Tags  []string `json:"tags,omitempty"`
}

// TokenInfo is returned when minting or listing tokens (secret only on create/sync ack optional).
type TokenInfo struct {
	ID        string    `json:"id"`
	HubID     string    `json:"hub_id,omitempty"`
	Role      string    `json:"role,omitempty"`
	Label     string    `json:"label,omitempty"`
	Token     string    `json:"token,omitempty"`
	AgentID   string    `json:"agent_id,omitempty"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
}

// RotateTokenResponse is POST /hub/tokens/{id}/rotate (break-glass).
type RotateTokenResponse struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	AgentID string `json:"agent_id,omitempty"`
}

// CreateGrantRequest is POST /hub/grants (center-authored; management break-glass also accepted).
type CreateGrantRequest struct {
	AgentAID string `json:"agent_a_id"`
	AgentBID string `json:"agent_b_id"`
}

// GrantInfo is returned for create/list grant operations.
type GrantInfo struct {
	ID        string    `json:"id"`
	HubID     string    `json:"hub_id"`
	AgentAID  string    `json:"agent_a_id"`
	AgentBID  string    `json:"agent_b_id"`
	CreatedAt time.Time `json:"created_at"`
}

// GrantsListResponse is GET /hub/grants.
type GrantsListResponse struct {
	HubID  string      `json:"hub_id"`
	Grants []GrantInfo `json:"grants"`
}
