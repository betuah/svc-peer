// Package protocol defines shared control-plane message types used by hub, agent, and relay.
package protocol

import "time"

// PeerConfig is a WireGuard peer entry in a netmap revision.
type PeerConfig struct {
	AgentID             string   `json:"agent_id"`
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
	OverlayIP    string    `json:"overlay_ip"`
	DNSName      string    `json:"dns_name"`
	Tags         []string  `json:"tags,omitempty"`
	Capabilities []string  `json:"capabilities,omitempty"`
	Online       bool      `json:"online"`
	LastSeen     time.Time `json:"last_seen"`
}

// RegisterRequest is the body of POST /agents/register.
type RegisterRequest struct {
	Name         string   `json:"name"`
	PublicKey    string   `json:"public_key"`
	Tags         []string `json:"tags,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Platform     string   `json:"platform,omitempty"`
	WGBackend    string   `json:"wg_backend,omitempty"`
}

// RegisterResponse is returned after a successful register (first or reconnect).
type RegisterResponse struct {
	AgentID        string       `json:"agent_id"`
	OverlayIP      string       `json:"overlay_ip"`
	DNSName        string       `json:"dns_name"`
	NetmapRevision uint64       `json:"netmap_revision"`
	Peers          []PeerConfig `json:"peers"`
	DNSMap         map[string]string `json:"dns_map,omitempty"` // name → overlay IP for MagicDNS
	STUNURLs       []string     `json:"stun_urls,omitempty"`
	RelayURLs      []string     `json:"relay_urls,omitempty"`
}

// AgentsListResponse is the body of GET /agents.
type AgentsListResponse struct {
	Agents []AgentSummary `json:"agents"`
}

// NetmapResponse is GET /netmap (or WS netmap push payload without type wrapper).
type NetmapResponse struct {
	Revision uint64            `json:"revision"`
	Peers    []PeerConfig      `json:"peers"`
	DNSMap   map[string]string `json:"dns_map,omitempty"`
}

// HealthResponse is GET /health.
type HealthResponse struct {
	Status          string `json:"status"`
	AgentsConnected int    `json:"agents_connected"`
	NetmapRevision  uint64 `json:"netmap_revision"`
}

// CreateTokenRequest is POST /hub/tokens.
type CreateTokenRequest struct {
	Label string   `json:"label,omitempty"`
	Tags  []string `json:"tags,omitempty"`
}

// TokenInfo is returned when minting or listing tokens (secret only on create).
type TokenInfo struct {
	ID        string    `json:"id"`
	Label     string    `json:"label,omitempty"`
	Token     string    `json:"token,omitempty"` // only on create
	AgentID   string    `json:"agent_id,omitempty"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
}

// RotateTokenResponse is POST /hub/tokens/{id}/rotate.
type RotateTokenResponse struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	AgentID string `json:"agent_id,omitempty"`
}
