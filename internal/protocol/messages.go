package protocol

// Control-plane WebSocket message type constants.
const (
	TypeHello          = "hello"
	TypeHeartbeat      = "heartbeat"
	TypeEndpointReport = "endpoint_report"
	TypePathStatus     = "path_status"
	TypeNetmap         = "netmap"
	TypePunch          = "punch"
	TypeRelayTicket    = "relay_ticket"
	TypeError          = "error"
	TypeAck            = "ack"
)

// Envelope is a typed control WebSocket message.
type Envelope struct {
	Type string `json:"type"`

	// Agent → hub
	AgentID   string     `json:"agent_id,omitempty"`
	Token     string     `json:"token,omitempty"`
	Endpoints []Endpoint `json:"endpoints,omitempty"`
	PeerID    string     `json:"peer_id,omitempty"`
	Path      string     `json:"path,omitempty"` // "direct" | "relay"
	RTTMs     int        `json:"rtt_ms,omitempty"`

	// Hub → agent
	Revision   uint64            `json:"revision,omitempty"`
	Peers      []PeerConfig      `json:"peers,omitempty"`
	DNSMap     map[string]string `json:"dns_map,omitempty"`
	Candidates []Endpoint        `json:"candidates,omitempty"`
	URLs       []string          `json:"urls,omitempty"`
	Ticket     string            `json:"ticket,omitempty"`
	ExpiresAt  string            `json:"expires_at,omitempty"`
	Code       string            `json:"code,omitempty"`
	Message    string            `json:"message,omitempty"`
}
