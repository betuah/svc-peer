//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/betuah/svc-peer/internal/agent"
	"github.com/betuah/svc-peer/internal/hub"
	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/google/uuid"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func writeIntegrationTLS(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "svc-peer-integration-tls"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func TestHubTLSRegisterAndControlWS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeIntegrationTLS(t, dir)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	h, err := hub.New(hub.Config{
		ListenAddr:          addr,
		HubID:               "hub-it-tls",
		CenterBootstrap:     "integration-boot-tls",
		ManagementTokenSeed: "integration-mgmt-tls",
		RelaySecret:         "integration-relay-tls",
		OverlayCIDR:         "10.55.0.0/16",
		DNSSuffix:           "peer.local",
		HeartbeatTimeoutSec: 45,
		TLSCertFile:         certFile,
		TLSKeyFile:          keyFile,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.ListenAndServe(ctx) }()

	baseURL := "https://" + addr
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	var healthOK bool
	for i := 0; i < 40; i++ {
		resp, err := httpClient.Get(baseURL + "/health")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				healthOK = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !healthOK {
		t.Fatal("hub TLS health not ready")
	}

	client := agent.NewHubClient(baseURL, "integration-boot-tls", true, nil)
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	agentID := uuid.NewString()
	regCtx, regCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer regCancel()
	reg, err := client.Register(regCtx, protocol.RegisterRequest{
		AgentID:   agentID,
		Name:      "center-it-tls",
		PublicKey: priv.PublicKey().String(),
		Role:      protocol.RoleCenter,
	})
	if err != nil {
		t.Fatal(err)
	}
	if reg.HubID != "hub-it-tls" {
		t.Fatalf("hub_id=%q", reg.HubID)
	}

	wsCtx, wsCancel := context.WithCancel(context.Background())
	defer wsCancel()
	done := make(chan error, 1)
	go func() {
		done <- client.RunControlWS(wsCtx, agentID, "hub-it-tls", time.Hour, agent.Handlers{})
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if client.Connected() {
			wsCancel()
			<-done
			// Confirm health JSON still well-formed over TLS.
			resp, err := httpClient.Get(baseURL + "/health")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var body map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["hub_id"] != "hub-it-tls" {
				t.Fatalf("health hub_id=%v", body["hub_id"])
			}
			cancel()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	wsCancel()
	t.Fatal("control WSS did not connect")
}
