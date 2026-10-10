//go:build linux

package wgdev

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type wgLink struct {
	attrs netlink.LinkAttrs
}

func (l *wgLink) Attrs() *netlink.LinkAttrs { return &l.attrs }
func (l *wgLink) Type() string              { return "wireguard" }

// KernelDevice drives kernel WireGuard via wgctrl + netlink.
type KernelDevice struct {
	log    *slog.Logger
	client *wgctrl.Client
	name   string
	cfg    InterfaceConfig
	up     bool
}

// NewKernelDevice opens a wgctrl client.
func NewKernelDevice() (*KernelDevice, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %w (is the wireguard kernel module loaded?)", err)
	}
	return &KernelDevice{log: slog.Default(), client: client}, nil
}

func (d *KernelDevice) Backend() string { return BackendKernel }

func (d *KernelDevice) Up(cfg InterfaceConfig) error {
	if cfg.Name == "" {
		return fmt.Errorf("interface name required")
	}
	priv, err := wgtypes.ParseKey(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1420
	}

	// Remove stale interface if present.
	if link, err := netlink.LinkByName(cfg.Name); err == nil {
		_ = netlink.LinkDel(link)
	}

	link := &wgLink{attrs: netlink.LinkAttrs{Name: cfg.Name, MTU: mtu}}
	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("create wireguard link %s: %w (need CAP_NET_ADMIN)", cfg.Name, err)
	}
	created, err := netlink.LinkByName(cfg.Name)
	if err != nil {
		return err
	}

	for _, addr := range cfg.Addresses {
		a, err := netlink.ParseAddr(addr)
		if err != nil {
			_ = netlink.LinkDel(created)
			return fmt.Errorf("parse addr %s: %w", addr, err)
		}
		if err := netlink.AddrAdd(created, a); err != nil && !errors.Is(err, os.ErrExist) {
			// netlink may return EEXIST differently
			if !isExistErr(err) {
				_ = netlink.LinkDel(created)
				return fmt.Errorf("addr add %s: %w", addr, err)
			}
		}
	}

	port := cfg.ListenPort
	wcfg := wgtypes.Config{
		PrivateKey:   &priv,
		ListenPort:   &port,
		ReplacePeers: true,
		Peers:        nil,
	}
	if err := d.client.ConfigureDevice(cfg.Name, wcfg); err != nil {
		_ = netlink.LinkDel(created)
		return fmt.Errorf("configure device: %w", err)
	}
	if err := netlink.LinkSetUp(created); err != nil {
		_ = netlink.LinkDel(created)
		return fmt.Errorf("link up: %w", err)
	}

	d.name = cfg.Name
	d.cfg = cfg
	d.up = true
	d.log.Info("wg kernel device up", "name", cfg.Name, "addrs", cfg.Addresses, "listen_port", cfg.ListenPort)
	return nil
}

func (d *KernelDevice) ConfigurePeers(revision uint64, peers []protocol.PeerConfig) error {
	if !d.up {
		return fmt.Errorf("kernel device not up")
	}
	wgPeers, err := peersToWG(peers)
	if err != nil {
		return err
	}
	cfg := wgtypes.Config{ReplacePeers: true, Peers: wgPeers}
	if err := d.client.ConfigureDevice(d.name, cfg); err != nil {
		return err
	}
	d.log.Info("wg kernel peers configured", "revision", revision, "peers", len(wgPeers))
	return nil
}

func (d *KernelDevice) UpdatePeerEndpoint(publicKey, endpoint string) error {
	if !d.up {
		return fmt.Errorf("kernel device not up")
	}
	pk, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return err
	}
	udp, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return err
	}
	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:  pk,
			Endpoint:   udp,
			UpdateOnly: true,
		}},
	}
	return d.client.ConfigureDevice(d.name, cfg)
}

func (d *KernelDevice) PeerLastHandshake(publicKey string) (time.Time, bool, error) {
	st, ok, err := d.PeerStats(publicKey)
	if err != nil || !ok {
		return time.Time{}, false, err
	}
	if st.LastHandshake.IsZero() {
		return time.Time{}, false, nil
	}
	return st.LastHandshake, true, nil
}

func (d *KernelDevice) PeerStats(publicKey string) (PeerStats, bool, error) {
	if !d.up {
		return PeerStats{}, false, fmt.Errorf("kernel device not up")
	}
	pk, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return PeerStats{}, false, err
	}
	dev, err := d.client.Device(d.name)
	if err != nil {
		return PeerStats{}, false, err
	}
	for _, p := range dev.Peers {
		if p.PublicKey != pk {
			continue
		}
		st := PeerStats{
			PublicKey:     publicKey,
			LastHandshake: p.LastHandshakeTime,
			ReceiveBytes:  uint64(p.ReceiveBytes),
			TransmitBytes: uint64(p.TransmitBytes),
		}
		if p.Endpoint != nil {
			st.Endpoint = p.Endpoint.String()
		}
		return st, true, nil
	}
	return PeerStats{}, false, nil
}

func (d *KernelDevice) Close() error {
	if !d.up {
		if d.client != nil {
			_ = d.client.Close()
		}
		return nil
	}
	d.up = false
	if link, err := netlink.LinkByName(d.name); err == nil {
		_ = netlink.LinkDel(link)
	}
	if d.client != nil {
		_ = d.client.Close()
	}
	d.log.Info("wg kernel device closed", "name", d.name)
	return nil
}

func isExistErr(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, os.ErrExist) || os.IsExist(err)
}
