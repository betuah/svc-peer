package wgdev

import (
	"fmt"
	"log/slog"

	"github.com/betuah/svc-peer/internal/protocol"
)

// UserspaceDevice is the wireguard-go fallback when kernel WG is unavailable.
// Scaffold stub: records config; real TUN + wireguard-go device is TODO.
type UserspaceDevice struct {
	log      *slog.Logger
	cfg      InterfaceConfig
	revision uint64
	peers    []protocol.PeerConfig
	up       bool
}

// NewUserspaceDevice returns a userspace WG stub device.
func NewUserspaceDevice() *UserspaceDevice {
	return &UserspaceDevice{log: slog.Default()}
}

func (d *UserspaceDevice) Backend() string { return BackendUserspace }

func (d *UserspaceDevice) Up(cfg InterfaceConfig) error {
	// TODO: open platform TUN and start golang.zx2c4.com/wireguard device.
	d.cfg = cfg
	d.up = true
	d.log.Info("wg userspace device up (stub)", "name", cfg.Name, "addrs", cfg.Addresses)
	return nil
}

func (d *UserspaceDevice) ConfigurePeers(revision uint64, peers []protocol.PeerConfig) error {
	if !d.up {
		return fmt.Errorf("userspace device not up")
	}
	// TODO: apply peer set to wireguard-go IPC / device.
	d.revision = revision
	d.peers = append([]protocol.PeerConfig(nil), peers...)
	d.log.Info("wg userspace peers configured (stub)", "revision", revision, "peers", len(peers))
	return nil
}

func (d *UserspaceDevice) Close() error {
	d.up = false
	d.log.Info("wg userspace device closed (stub)")
	return nil
}
