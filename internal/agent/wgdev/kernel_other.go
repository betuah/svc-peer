//go:build !linux

package wgdev

import (
	"fmt"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
)

// KernelAvailable is always false off Linux.
func KernelAvailable() bool { return false }

// KernelDevice is unavailable off Linux.
type KernelDevice struct{}

// NewKernelDevice always errors off Linux.
func NewKernelDevice() (*KernelDevice, error) {
	return nil, fmt.Errorf("kernel WireGuard not available on this platform")
}

func (d *KernelDevice) Backend() string { return BackendKernel }
func (d *KernelDevice) Up(InterfaceConfig) error {
	return fmt.Errorf("kernel WireGuard not available on this platform")
}
func (d *KernelDevice) ConfigurePeers(uint64, []protocol.PeerConfig) error {
	return fmt.Errorf("kernel WireGuard not available on this platform")
}
func (d *KernelDevice) UpdatePeerEndpoint(string, string) error {
	return fmt.Errorf("kernel WireGuard not available on this platform")
}
func (d *KernelDevice) PeerLastHandshake(string) (time.Time, bool, error) {
	return time.Time{}, false, fmt.Errorf("kernel WireGuard not available on this platform")
}
func (d *KernelDevice) Close() error { return nil }
