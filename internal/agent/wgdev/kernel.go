package wgdev

import (
	"fmt"
	"log/slog"

	"github.com/betuah/svc-peer/internal/protocol"
)

// KernelDevice is the preferred WireGuard backend (wgctrl / netlink).
// Scaffold stub: records config without creating a real interface.
type KernelDevice struct {
	log      *slog.Logger
	cfg      InterfaceConfig
	revision uint64
	peers    []protocol.PeerConfig
	up       bool
}

// NewKernelDevice returns a kernel WG stub device.
func NewKernelDevice() *KernelDevice {
	return &KernelDevice{log: slog.Default()}
}

func (d *KernelDevice) Backend() string { return BackendKernel }

func (d *KernelDevice) Up(cfg InterfaceConfig) error {
	// TODO: create/configure kernel WireGuard device via wgctrl + netlink addresses.
	d.cfg = cfg
	d.up = true
	d.log.Info("wg kernel device up (stub)", "name", cfg.Name, "addrs", cfg.Addresses, "listen_port", cfg.ListenPort)
	return nil
}

func (d *KernelDevice) ConfigurePeers(revision uint64, peers []protocol.PeerConfig) error {
	if !d.up {
		return fmt.Errorf("kernel device not up")
	}
	// TODO: ReplacePeers via wgctrl — AllowedIPs, endpoints, keepalive from netmap.
	d.revision = revision
	d.peers = append([]protocol.PeerConfig(nil), peers...)
	d.log.Info("wg kernel peers configured (stub)", "revision", revision, "peers", len(peers))
	return nil
}

func (d *KernelDevice) Close() error {
	d.up = false
	d.log.Info("wg kernel device closed (stub)")
	return nil
}
