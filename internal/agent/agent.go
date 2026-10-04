package agent

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"github.com/betuah/svc-peer/internal/agent/dns"
	"github.com/betuah/svc-peer/internal/agent/wgdev"
	"github.com/betuah/svc-peer/internal/protocol"
)

// Agent is the local peer process: register with hub, apply netmap, maintain WG device.
type Agent struct {
	cfg      Config
	log      *slog.Logger
	client   *HubClient
	device   wgdev.Device
	dns      *dns.Resolver
	agentID  string
	pubKey   string
	privKey  string
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
	priv, pub, err := generateKeyPairStub()
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

// Run registers, brings up WG (stub), and maintains the control channel until ctx cancel.
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
	a.dns.Update(reg.DNSMap)
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
		return err
	}
	defer a.device.Close()

	if err := a.device.ConfigurePeers(reg.NetmapRevision, reg.Peers); err != nil {
		return err
	}

	hb := time.Duration(a.cfg.HeartbeatSec) * time.Second
	return a.client.RunControlWS(ctx, a.agentID, hb, func(env protocol.Envelope) {
		a.dns.Update(env.DNSMap)
		if err := a.device.ConfigurePeers(env.Revision, env.Peers); err != nil {
			a.log.Error("apply netmap failed", "err", err)
			return
		}
		a.log.Info("netmap applied", "revision", env.Revision, "peers", len(env.Peers))
	})
}

// Resolver exposes MagicDNS for tests / local tooling.
func (a *Agent) Resolver() *dns.Resolver { return a.dns }

// generateKeyPairStub returns random placeholder key material for scaffold register.
// TODO: real Curve25519 WG keypair (e.g. golang.zx2c4.com/wireguard/wgctrl/wgtypes).
func generateKeyPairStub() (priv, pub string, err error) {
	var b [64]byte
	if _, err = rand.Read(b[:]); err != nil {
		return "", "", err
	}
	priv = base64.StdEncoding.EncodeToString(b[:32])
	pub = base64.StdEncoding.EncodeToString(b[32:])
	return priv, pub, nil
}
