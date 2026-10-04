//go:build linux

package wgdev

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

func assignAddresses(ifName string, addrs []string) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		addr, err := netlink.ParseAddr(a)
		if err != nil {
			return fmt.Errorf("parse %s: %w", a, err)
		}
		if err := netlink.AddrReplace(link, addr); err != nil {
			return fmt.Errorf("addr %s: %w", a, err)
		}
	}
	return netlink.LinkSetUp(link)
}
