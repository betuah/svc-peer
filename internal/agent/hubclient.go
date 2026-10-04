package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/gorilla/websocket"
)

// HubClient talks to the hub REST + control WebSocket.
type HubClient struct {
	baseURL string
	token   string
	http    *http.Client
	log     *slog.Logger

	mu   sync.Mutex
	conn *websocket.Conn
}

// NewHubClient creates a control-plane client.
func NewHubClient(baseURL, token string, log *slog.Logger) *HubClient {
	if log == nil {
		log = slog.Default()
	}
	return &HubClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 15 * time.Second},
		log:     log,
	}
}

func (c *HubClient) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, string(data))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

// Register calls POST /api/v1/agents/register.
func (c *HubClient) Register(ctx context.Context, req protocol.RegisterRequest) (*protocol.RegisterResponse, error) {
	var out protocol.RegisterResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/agents/register", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SyncAllowlist pushes center-held edge join tokens to the thin hub (PUT /hub/allowlist).
func (c *HubClient) SyncAllowlist(ctx context.Context, tokens []protocol.AllowlistToken) (*protocol.AllowlistSyncResponse, error) {
	var out protocol.AllowlistSyncResponse
	if err := c.doJSON(ctx, http.MethodPut, "/hub/allowlist", protocol.AllowlistSyncRequest{Tokens: tokens}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListAgents calls GET /api/v1/agents (hub registry view: joined agents + online).
func (c *HubClient) ListAgents(ctx context.Context) (*protocol.AgentsListResponse, error) {
	var out protocol.AgentsListResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/agents", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Connected reports whether the control WebSocket is currently open.
func (c *HubClient) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

// Send writes a control message on the active WebSocket.
func (c *HubClient) Send(env protocol.Envelope) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return fmt.Errorf("control ws not connected")
	}
	return c.conn.WriteJSON(env)
}

// Handlers are callbacks for control-plane pushes.
type Handlers struct {
	OnNetmap      func(protocol.Envelope)
	OnPunch       func(protocol.Envelope)
	OnRelayTicket func(protocol.Envelope)
}

// RunControlWS connects to the control channel, sends heartbeats, and dispatches messages.
func (c *HubClient) RunControlWS(ctx context.Context, agentID, hubID string, heartbeat time.Duration, h Handlers) error {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	default:
		u.Scheme = "ws"
	}
	u.Path = "/ws/v1/agent"

	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, _, err := dialer.DialContext(ctx, u.String(), nil)
	if err != nil {
		return fmt.Errorf("control ws dial: %w", err)
	}
	defer conn.Close()

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.conn = nil
		c.mu.Unlock()
	}()

	if err := conn.WriteJSON(protocol.Envelope{
		Type:    protocol.TypeHello,
		AgentID: agentID,
		HubID:   hubID,
		Token:   c.token,
	}); err != nil {
		return err
	}

	errCh := make(chan error, 1)
	go func() {
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}
			var env protocol.Envelope
			if err := json.Unmarshal(data, &env); err != nil {
				continue
			}
			switch env.Type {
			case protocol.TypeNetmap:
				if h.OnNetmap != nil {
					h.OnNetmap(env)
				}
			case protocol.TypePunch:
				if h.OnPunch != nil {
					h.OnPunch(env)
				}
			case protocol.TypeRelayTicket:
				if h.OnRelayTicket != nil {
					h.OnRelayTicket(env)
				}
			case protocol.TypeError:
				c.log.Error("hub error", "code", env.Code, "message", env.Message)
			}
		}
	}()

	ticker := time.NewTicker(heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			return err
		case <-ticker.C:
			if err := c.Send(protocol.Envelope{Type: protocol.TypeHeartbeat}); err != nil {
				return err
			}
		}
	}
}
