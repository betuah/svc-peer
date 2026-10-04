package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/betuah/svc-peer/internal/agent/dns"
	"github.com/betuah/svc-peer/internal/agent/endpoint"
	"github.com/betuah/svc-peer/internal/agent/pathmgr"
	"github.com/betuah/svc-peer/internal/agent/relayclient"
	"github.com/betuah/svc-peer/internal/agent/wgdev"
	"github.com/betuah/svc-peer/internal/protocol"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Agent is the local peer process: register with hub, apply netmap, maintain WG device.
type Agent struct {
	cfg     Config
	log     *slog.Logger
	client  *HubClient
	device  wgdev.Device
	dns     *dns.Resolver
	relay   *relayclient.Client
	paths   *pathmgr.Manager
	agentID string
	pubKey  string
	privKey string
	stun    []string
	relays  []string
}

// New constructs an agent from config.
func New(cfg Config, log *slog.Logger) (*Agent, error) {
	if log == nil {
		log = slog.Default()
	}
	dev, err := wgdev.Open(cfg.WGBackend)
	if err != nil {
		return nil, err
	}
	priv, pub, err := loadOrGenerateKeys(cfg.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	return &Agent{
		cfg:     cfg,
		log:     log,
		client:  NewHubClient(cfg.HubURL, cfg.Token, log),
		device:  dev,
		dns:     dns.NewResolver(),
		privKey: priv,
		pubKey:  pub,
	}, nil
}

// Run registers, brings up WG, reports endpoints, and maintains control + path selection.
func (a *Agent) Run(ctx context.Context) error {
	reg, err := a.client.Register(ctx, protocol.RegisterRequest{
		Name:         a.cfg.Name,
		PublicKey:    a.pubKey,
		Tags:         a.cfg.Tags,
		Capabilities: a.cfg.Capabilities,
		Platform:     runtime.GOOS + "/" + runtime.GOARCH,
		WGBackend:    a.device.Backend(),
	})
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	a.agentID = reg.AgentID
	a.stun = reg.STUNURLs
	a.relays = reg.RelayURLs
	a.dns.Update(reg.DNSMap)
	a.relay = relayclient.New(a.agentID, a.log)
	a.paths = pathmgr.New(a.device, a.relay, a.client, a.log)
	if a.cfg.DirectWaitSec > 0 {
		a.paths.SetDirectWait(time.Duration(a.cfg.DirectWaitSec) * time.Second)
	}

	a.log.Info("registered",
		"agent_id", reg.AgentID,
		"overlay_ip", reg.OverlayIP,
		"dns_name", reg.DNSName,
		"peers", len(reg.Peers),
		"wg_backend", a.device.Backend(),
	)

	if err := a.device.Up(wgdev.InterfaceConfig{
		Name:       a.cfg.WGInterface,
		PrivateKey: a.privKey,
		Addresses:  []string{reg.OverlayIP},
		ListenPort: a.cfg.WGListenPort,
		MTU:        1420,
	}); err != nil {
		return fmt.Errorf("wg up: %w", err)
	}
	defer a.device.Close()
	defer a.relay.CloseAll()

	if err := a.paths.ApplyNetmap(ctx, reg.NetmapRevision, reg.Peers); err != nil {
		return err
	}

	hb := time.Duration(a.cfg.HeartbeatSec) * time.Second
	wsErr := make(chan error, 1)
	go func() {
		wsErr <- a.client.RunControlWS(ctx, a.agentID, hb, Handlers{
			OnNetmap: func(env protocol.Envelope) {
				a.dns.Update(env.DNSMap)
				if err := a.paths.ApplyNetmap(ctx, env.Revision, env.Peers); err != nil {
					a.log.Error("apply netmap failed", "err", err)
					return
				}
				a.log.Info("netmap applied", "revision", env.Revision, "peers", len(env.Peers))
			},
			OnPunch: func(env protocol.Envelope) {
				pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
				defer cancel()
				a.paths.HandlePunch(pctx, env.PeerID, env.Candidates)
			},
			OnRelayTicket: func(env protocol.Envelope) {
				urls := env.URLs
				if len(urls) == 0 {
					urls = a.relays
				}
				a.paths.HandleRelayTicket(ctx, env.PeerID, env.Ticket, urls)
			},
		})
	}()

	// Wait briefly for WS hello, then report endpoints (and refresh periodically).
	endpointTicker := time.NewTicker(60 * time.Second)
	defer endpointTicker.Stop()
	report := func() {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := a.ReportEndpoints(rctx); err != nil {
			a.log.Debug("endpoint report", "err", err)
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-wsErr:
		return err
	case <-time.After(300 * time.Millisecond):
		report()
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-wsErr:
			return err
		case <-endpointTicker.C:
			report()
		}
	}
}

// ReportEndpoints discovers host/STUN candidates and sends endpoint_report.
func (a *Agent) ReportEndpoints(ctx context.Context) error {
	eps, err := endpoint.Collect(ctx, a.cfg.WGListenPort, a.stun)
	if err != nil {
		return err
	}
	if len(eps) == 0 {
		return fmt.Errorf("no endpoints discovered")
	}
	a.log.Info("reporting endpoints", "count", len(eps))
	return a.client.Send(protocol.Envelope{
		Type:      protocol.TypeEndpointReport,
		Endpoints: eps,
	})
}

// Resolver exposes MagicDNS for tests / local tooling.
func (a *Agent) Resolver() *dns.Resolver { return a.dns }

func loadOrGenerateKeys(path string) (priv, pub string, err error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			priv = strings.TrimSpace(string(data))
			key, err := wgtypes.ParseKey(priv)
			if err != nil {
				return "", "", fmt.Errorf("parse private key file: %w", err)
			}
			return key.String(), key.PublicKey().String(), nil
		}
		if !os.IsNotExist(err) {
			return "", "", err
		}
	}
	priv, pub, err = wgdev.GenerateKeyPair()
	if err != nil {
		return "", "", err
	}
	if path != "" {
		if err := os.WriteFile(path, []byte(priv+"\n"), 0o600); err != nil {
			return "", "", fmt.Errorf("write private key: %w", err)
		}
	}
	return priv, pub, nil
}
