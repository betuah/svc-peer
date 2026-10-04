package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/betuah/svc-peer/internal/hub"
	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/google/uuid"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func writeAgentTestCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "svc-peer-agent-tls"},
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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func TestHubClientHTTPSRegisterAndWSS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeAgentTestCert(t, dir)
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	h, err := hub.New(hub.Config{
		ListenAddr:          ":0",
		HubID:               "hub-client-tls",
		CenterBootstrap:     "boot-client-tls",
		ManagementTokenSeed: "mgmt-client-tls",
		RelaySecret:         "relay-client-tls",
		OverlayCIDR:         "10.66.0.0/16",
		DNSSuffix:           "peer.local",
		HeartbeatTimeoutSec: 45,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewUnstartedServer(h.Router())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}} //nolint:gosec
	srv.StartTLS()
	defer srv.Close()

	client := NewHubClient(srv.URL, "boot-client-tls", true, nil)
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	agentID := uuid.NewString()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reg, err := client.Register(ctx, protocol.RegisterRequest{
		AgentID:   agentID,
		Name:      "center-tls",
		PublicKey: priv.PublicKey().String(),
		Role:      protocol.RoleCenter,
	})
	if err != nil {
		t.Fatal(err)
	}
	if reg.AgentID != agentID || reg.Role != protocol.RoleCenter {
		t.Fatalf("register: %+v", reg)
	}

	wsCtx, wsCancel := context.WithCancel(context.Background())
	defer wsCancel()
	done := make(chan error, 1)
	go func() {
		done <- client.RunControlWS(wsCtx, agentID, "hub-client-tls", time.Hour, Handlers{})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if client.Connected() {
			wsCancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("control ws did not exit")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	wsCancel()
	t.Fatal("control WSS did not connect")
}

func TestHubClientRejectsBadScheme(t *testing.T) {
	c := NewHubClient("ftp://127.0.0.1:8080", "t", false, nil)
	err := c.RunControlWS(context.Background(), "a", "h", time.Second, Handlers{})
	if err == nil {
		t.Fatal("expected scheme error")
	}
}
