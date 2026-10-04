//go:build linux

package wgdev

import "golang.zx2c4.com/wireguard/wgctrl"

// KernelAvailable reports whether the WireGuard kernel netlink API is usable
// via wgctrl (module loaded and genetlink family present).
func KernelAvailable() bool {
	client, err := wgctrl.New()
	if err != nil {
		return false
	}
	defer client.Close()
	_, err = client.Devices()
	return err == nil
}
