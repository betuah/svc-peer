package wgdev

import (
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Backend names.
const (
	BackendKernel    = "kernel"
	BackendUserspace = "userspace"
	BackendAuto      = "auto"
)

// InterfaceConfig configures the local WG interface / TUN.
type InterfaceConfig struct {
	Name       string
	PrivateKey string // base64 WG private key
	Addresses  []string
	ListenPort int
	MTU        int
}

// PeerStats is WireGuard device traffic/handshake state for one peer.
// TX/RX come from kernel wgctrl or userspace wireguard-go IPC stats — not the hub.
type PeerStats struct {
	PublicKey     string
	Endpoint      string
	LastHandshake time.Time
	ReceiveBytes  uint64
	TransmitBytes uint64
}

// Device is the agent WireGuard data-plane interface.
type Device interface {
	Backend() string
	Up(cfg InterfaceConfig) error
	ConfigurePeers(revision uint64, peers []protocol.PeerConfig) error
	UpdatePeerEndpoint(publicKey, endpoint string) error
	PeerLastHandshake(publicKey string) (time.Time, bool, error)
	// PeerStats returns device-level stats for a peer public key.
	// ok is false when the peer is not present on the device.
	PeerStats(publicKey string) (stats PeerStats, ok bool, err error)
	Close() error
}

// GenerateKeyPair creates a WireGuard Curve25519 keypair (base64).
func GenerateKeyPair() (priv, pub string, err error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", err
	}
	return key.String(), key.PublicKey().String(), nil
}

// ParseKey parses a base64 WireGuard key.
func ParseKey(s string) (wgtypes.Key, error) {
	return wgtypes.ParseKey(s)
}

// KeyToHex converts a base64 WG key to hex (wireguard-go IPC).
func KeyToHex(base64Key string) (string, error) {
	k, err := wgtypes.ParseKey(base64Key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(k[:]), nil
}

func peerLabel(p protocol.PeerConfig) string {
	if p.PeerID != "" {
		return p.PeerID
	}
	return p.AgentID
}

func peersToWG(peers []protocol.PeerConfig) ([]wgtypes.PeerConfig, error) {
	out := make([]wgtypes.PeerConfig, 0, len(peers))
	for _, p := range peers {
		if p.PublicKey == "" {
			continue
		}
		label := peerLabel(p)
		pk, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("peer %s public key: %w", label, err)
		}
		pc := wgtypes.PeerConfig{
			PublicKey:         pk,
			ReplaceAllowedIPs: true,
		}
		for _, ip := range p.AllowedIPs {
			_, cidr, err := net.ParseCIDR(ip)
			if err != nil {
				// allow bare IP → /32 or /128
				addr := net.ParseIP(ip)
				if addr == nil {
					return nil, fmt.Errorf("peer %s allowed_ip %q: %w", label, ip, err)
				}
				bits := 32
				if addr.To4() == nil {
					bits = 128
				}
				cidr = &net.IPNet{IP: addr, Mask: net.CIDRMask(bits, bits)}
			}
			pc.AllowedIPs = append(pc.AllowedIPs, *cidr)
		}
		if p.Endpoint != "" {
			udp, err := net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("peer %s endpoint: %w", label, err)
			}
			pc.Endpoint = udp
		}
		if p.PersistentKeepalive > 0 {
			ka := time.Duration(p.PersistentKeepalive) * time.Second
			pc.PersistentKeepaliveInterval = &ka
		}
		out = append(out, pc)
	}
	return out, nil
}
