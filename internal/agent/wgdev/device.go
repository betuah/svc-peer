// Package wgdev abstracts WireGuard device backends (kernel preferred, userspace fallback).
package wgdev

import (
	"fmt"

	"github.com/betuah/svc-peer/internal/protocol"
)

// Backend names.
const (
	BackendKernel    = "kernel"
	BackendUserspace = "userspace"
	BackendAuto      = "auto"
)

// InterfaceConfig configures the local WG interface / TUN.
type InterfaceConfig struct {
	Name       string   // e.g. "sp0"
	PrivateKey string   // base64 WG private key (agent-local; never sent to hub)
	Addresses  []string // overlay addrs, e.g. ["10.10.0.15/32"]
	ListenPort int
	MTU        int
}

// Device is the agent WireGuard data-plane interface.
// Implementations: KernelDevice (preferred), UserspaceDevice (wireguard-go fallback).
type Device interface {
	Backend() string
	Up(cfg InterfaceConfig) error
	// ConfigurePeers applies a full peer set for a netmap revision (ReplacePeers semantics).
	ConfigurePeers(revision uint64, peers []protocol.PeerConfig) error
	Close() error
}

// Open selects a backend. Prefer kernel; fall back to userspace when unavailable or forced.
// Phase 1 scaffold: both backends are stubs that log intent; real wgctrl / wireguard-go wiring is TODO.
func Open(preference string) (Device, error) {
	switch preference {
	case BackendKernel:
		return NewKernelDevice(), nil
	case BackendUserspace:
		return NewUserspaceDevice(), nil
	case BackendAuto, "":
		if kernelAvailable() {
			return NewKernelDevice(), nil
		}
		return NewUserspaceDevice(), nil
	default:
		return nil, fmt.Errorf("unknown wg backend %q", preference)
	}
}

// kernelAvailable is a stub probe. Real implementation will try wgctrl / netlink.
func kernelAvailable() bool {
	// TODO: probe via wgctrl.New() and list devices, or check WireGuard module.
	// Scaffold assumes Linux may have kernel WG; Open(auto) still returns kernel stub first.
	return true
}
