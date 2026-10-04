package wgdev

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// UserspaceDevice uses wireguard-go + platform TUN.
type UserspaceDevice struct {
	log    *slog.Logger
	mu     sync.Mutex
	dev    *device.Device
	tun    tun.Device
	name   string
	cfg    InterfaceConfig
	up     bool
	peers  map[string]protocol.PeerConfig // pubkey → config
}

// NewUserspaceDevice constructs a userspace backend (not yet Up).
func NewUserspaceDevice() (*UserspaceDevice, error) {
	return &UserspaceDevice{
		log:   slog.Default(),
		peers: make(map[string]protocol.PeerConfig),
	}, nil
}

func (d *UserspaceDevice) Backend() string { return BackendUserspace }

func (d *UserspaceDevice) Up(cfg InterfaceConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if cfg.Name == "" {
		return fmt.Errorf("interface name required")
	}
	privHex, err := KeyToHex(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1420
	}

	tdev, err := tun.CreateTUN(cfg.Name, mtu)
	if err != nil {
		return fmt.Errorf("create TUN %s: %w (need CAP_NET_ADMIN / admin privileges)", cfg.Name, err)
	}
	realName, err := tdev.Name()
	if err != nil {
		_ = tdev.Close()
		return err
	}

	logger := device.NewLogger(device.LogLevelError, "wg-userspace")
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)

	ipc := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", privHex, cfg.ListenPort)
	if err := dev.IpcSet(ipc); err != nil {
		dev.Close()
		return fmt.Errorf("ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("device up: %w", err)
	}

	if err := assignAddresses(realName, cfg.Addresses); err != nil {
		dev.Close()
		return fmt.Errorf("assign addresses: %w", err)
	}

	d.tun = tdev
	d.dev = dev
	d.name = realName
	d.cfg = cfg
	d.up = true
	d.log.Info("wg userspace device up", "name", realName, "addrs", cfg.Addresses, "listen_port", cfg.ListenPort)
	return nil
}

func (d *UserspaceDevice) ConfigurePeers(revision uint64, peers []protocol.PeerConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.up {
		return fmt.Errorf("userspace device not up")
	}
	var b strings.Builder
	b.WriteString("replace_peers=true\n")
	d.peers = make(map[string]protocol.PeerConfig, len(peers))
	for _, p := range peers {
		if p.PublicKey == "" {
			continue
		}
		pkHex, err := KeyToHex(p.PublicKey)
		if err != nil {
			return fmt.Errorf("peer %s: %w", p.AgentID, err)
		}
		fmt.Fprintf(&b, "public_key=%s\n", pkHex)
		for _, ip := range p.AllowedIPs {
			cidr := ip
			if _, _, err := net.ParseCIDR(ip); err != nil {
				addr := net.ParseIP(ip)
				if addr == nil {
					return fmt.Errorf("peer %s allowed_ip %q", p.AgentID, ip)
				}
				if addr.To4() != nil {
					cidr = addr.String() + "/32"
				} else {
					cidr = addr.String() + "/128"
				}
			}
			fmt.Fprintf(&b, "allowed_ip=%s\n", cidr)
		}
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint)
		}
		ka := p.PersistentKeepalive
		if ka <= 0 {
			ka = 25
		}
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", ka)
		d.peers[p.PublicKey] = p
	}
	if err := d.dev.IpcSet(b.String()); err != nil {
		return err
	}
	d.log.Info("wg userspace peers configured", "revision", revision, "peers", len(peers))
	return nil
}

func (d *UserspaceDevice) UpdatePeerEndpoint(publicKey, endpoint string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.up {
		return fmt.Errorf("userspace device not up")
	}
	pkHex, err := KeyToHex(publicKey)
	if err != nil {
		return err
	}
	ipc := fmt.Sprintf("public_key=%s\nendpoint=%s\nupdate_only=true\n", pkHex, endpoint)
	return d.dev.IpcSet(ipc)
}

func (d *UserspaceDevice) PeerLastHandshake(publicKey string) (time.Time, bool, error) {
	st, ok, err := d.PeerStats(publicKey)
	if err != nil || !ok {
		return time.Time{}, false, err
	}
	if st.LastHandshake.IsZero() {
		return time.Time{}, false, nil
	}
	return st.LastHandshake, true, nil
}

func (d *UserspaceDevice) PeerStats(publicKey string) (PeerStats, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.up {
		return PeerStats{}, false, fmt.Errorf("userspace device not up")
	}
	pk, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return PeerStats{}, false, err
	}
	pkHex := hex.EncodeToString(pk[:])
	out, err := d.dev.IpcGet()
	if err != nil {
		return PeerStats{}, false, err
	}
	st, found := parseUserspacePeerStats(out, pkHex, publicKey)
	if !found {
		return PeerStats{}, false, nil
	}
	return st, true, nil
}

// parseUserspacePeerStats extracts stats for one peer from a wireguard-go IpcGet dump.
func parseUserspacePeerStats(ipc, pkHex, publicKeyB64 string) (PeerStats, bool) {
	lines := strings.Split(ipc, "\n")
	inPeer := false
	found := false
	st := PeerStats{PublicKey: publicKeyB64}
	for _, line := range lines {
		if strings.HasPrefix(line, "public_key=") {
			inPeer = strings.TrimPrefix(line, "public_key=") == pkHex
			if inPeer {
				found = true
			}
			continue
		}
		if !inPeer {
			continue
		}
		switch {
		case strings.HasPrefix(line, "endpoint="):
			st.Endpoint = strings.TrimPrefix(line, "endpoint=")
		case strings.HasPrefix(line, "last_handshake_time_sec="):
			var sec int64
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, "last_handshake_time_sec="), "%d", &sec); err == nil && sec > 0 {
				st.LastHandshake = time.Unix(sec, 0)
			}
		case strings.HasPrefix(line, "rx_bytes="):
			var n uint64
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, "rx_bytes="), "%d", &n); err == nil {
				st.ReceiveBytes = n
			}
		case strings.HasPrefix(line, "tx_bytes="):
			var n uint64
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, "tx_bytes="), "%d", &n); err == nil {
				st.TransmitBytes = n
			}
		}
	}
	return st, found
}

func (d *UserspaceDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.up {
		return nil
	}
	d.up = false
	if d.dev != nil {
		d.dev.Close()
		d.dev = nil
	}
	d.log.Info("wg userspace device closed", "name", d.name)
	return nil
}
