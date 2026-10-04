package hub

import (
	"fmt"
	"net/netip"
	"sync"
)

// IPAM allocates /32 overlay addresses from a configured CIDR.
type IPAM struct {
	mu       sync.Mutex
	network  netip.Prefix
	next     netip.Addr
	last     netip.Addr
	used     map[netip.Addr]struct{}
}

// NewIPAM parses overlayCIDR and prepares sequential allocation.
// The network address and broadcast (for IPv4) are skipped; first usable host is reserved for optional hub peer later.
func NewIPAM(overlayCIDR string) (*IPAM, error) {
	prefix, err := netip.ParsePrefix(overlayCIDR)
	if err != nil {
		return nil, fmt.Errorf("overlay_cidr: %w", err)
	}
	prefix = prefix.Masked()
	network := prefix.Addr()
	// Skip network addr + first host (reserved).
	start := network.Next()
	if !start.IsValid() {
		return nil, fmt.Errorf("overlay_cidr too small")
	}
	start = start.Next() // agent allocations begin at network+2
	if !start.IsValid() || !prefix.Contains(start) {
		return nil, fmt.Errorf("overlay_cidr too small for agent allocation")
	}

	// Compute last usable: for simplicity walk until outside prefix — store last as high addr of prefix.
	// IPv4: last = broadcast-1 conceptually; we just stop when !Contains.
	last := prefix.Addr()
	for a := prefix.Addr(); prefix.Contains(a); a = a.Next() {
		if !a.IsValid() {
			break
		}
		last = a
	}

	return &IPAM{
		network: prefix,
		next:    start,
		last:    last,
		used:    make(map[netip.Addr]struct{}),
	}, nil
}

// Allocate returns the next free overlay address.
func (i *IPAM) Allocate() (netip.Addr, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for a := i.next; i.network.Contains(a); a = a.Next() {
		if !a.IsValid() {
			break
		}
		if a == i.network.Addr() {
			continue
		}
		if _, taken := i.used[a]; taken {
			continue
		}
		i.used[a] = struct{}{}
		i.next = a.Next()
		return a, nil
	}
	return netip.Addr{}, fmt.Errorf("overlay CIDR exhausted")
}

// Reserve marks an address used (e.g. restore from durable store later).
func (i *IPAM) Reserve(addr netip.Addr) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.network.Contains(addr) {
		return fmt.Errorf("address %s outside overlay", addr)
	}
	if _, taken := i.used[addr]; taken {
		return fmt.Errorf("address %s already allocated", addr)
	}
	i.used[addr] = struct{}{}
	return nil
}
