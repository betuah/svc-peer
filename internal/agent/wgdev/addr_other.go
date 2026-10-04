//go:build !linux

package wgdev

import "fmt"

func assignAddresses(ifName string, addrs []string) error {
	// Platform-specific address plumbing for non-Linux is TODO (Windows netsh / utun routes).
	// Interface creation via wireguard-go TUN still runs; overlay IPs may need manual config.
	if len(addrs) == 0 {
		return nil
	}
	return fmt.Errorf("automatic address assignment for %s not implemented on this OS (addrs=%v)", ifName, addrs)
}
