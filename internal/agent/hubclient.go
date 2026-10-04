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

// GetNetmap calls GET /api/v1/netmap.
func (c *HubClient) GetNetmap(ctx context.Context) (*protocol.NetmapResponse, error) {
	var out protocol.NetmapResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/netmap", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListAgents calls GET /api/v1/agents.
func (c *HubClient) ListAgents(ctx context.Context) (*protocol.AgentsListResponse, error) {
	var out protocol.AgentsListResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/agents", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RunControlWS connects to WSS/WS control channel, sends heartbeats, and invokes onNetmap.
func (c *HubClient) RunControlWS(ctx context.Context, agentID string, heartbeat time.Duration, onNetmap func(protocol.Envelope)) error {
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

	if err := conn.WriteJSON(protocol.Envelope{
		Type:    protocol.TypeHello,
		AgentID: agentID,
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
				if onNetmap != nil {
					onNetmap(env)
				}
			case protocol.TypePunch, protocol.TypeRelayTicket:
				// TODO: hole punch / relay ticket handling
				c.log.Info("control message (stub)", "type", env.Type)
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
			if err := conn.WriteJSON(protocol.Envelope{Type: protocol.TypeHeartbeat}); err != nil {
				return err
			}
		}
	}
}
