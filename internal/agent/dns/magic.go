// Package dns provides agent-local MagicDNS resolution from hub-pushed netmap.
package dns

import (
	"strings"
	"sync"
)

// Resolver maps MagicDNS names to overlay IPs using the latest netmap DNS map.
// Platform OS resolver plumbing is deferred; this is the in-process lookup used by the agent.
type Resolver struct {
	mu     sync.RWMutex
	byName map[string]string // lowercased name → overlay IP
}

// NewResolver creates an empty MagicDNS resolver.
func NewResolver() *Resolver {
	return &Resolver{byName: make(map[string]string)}
}

// Update replaces the name→IP map from a netmap push.
func (r *Resolver) Update(dnsMap map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byName = make(map[string]string, len(dnsMap))
	for name, ip := range dnsMap {
		r.byName[strings.ToLower(name)] = ip
	}
}

// Lookup returns the overlay IP for a MagicDNS name, or false if unknown.
func (r *Resolver) Lookup(name string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ip, ok := r.byName[strings.ToLower(strings.TrimSpace(name))]
	return ip, ok
}
