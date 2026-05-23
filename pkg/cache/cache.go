// Package cache wraps an api.APIClient with a short-TTL response cache so that
// frequent scrapes reuse a recent API response instead of re-querying Wazuh.
// It carries no Prometheus dependency: hits/misses are reported via injected
// callbacks. Only successful responses are cached; errors are never cached.
package cache

import (
	"context"
	"sync"
	"time"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/wazuh/api"
)

type entry struct {
	data []byte
	at   time.Time
}

// Option configures a Cache.
type Option func(*Cache)

// WithClock injects a clock (tests).
func WithClock(clock func() time.Time) Option {
	return func(c *Cache) {
		if clock != nil {
			c.clock = clock
		}
	}
}

// WithHooks sets the cache-hit / cache-miss callbacks (e.g. metric incrementers).
func WithHooks(onHit, onMiss func()) Option {
	return func(c *Cache) {
		if onHit != nil {
			c.onHit = onHit
		}
		if onMiss != nil {
			c.onMiss = onMiss
		}
	}
}

// Cache wraps an api.APIClient and implements api.APIClient.
type Cache struct {
	next   api.APIClient
	ttl    time.Duration
	clock  func() time.Time
	onHit  func()
	onMiss func()

	mu      sync.Mutex
	entries map[string]entry
}

// New builds a Cache wrapping next with the given TTL.
func New(next api.APIClient, ttl time.Duration, opts ...Option) *Cache {
	c := &Cache{
		next:    next,
		ttl:     ttl,
		clock:   time.Now,
		onHit:   func() {},
		onMiss:  func() {},
		entries: make(map[string]entry),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Get returns a fresh cached response for path, or fetches and caches it. A
// backend error is returned without being cached, so a transient failure
// self-heals on the next call.
//
// The returned slice is owned by the cache and shared across hits within the
// TTL window; callers must treat it as read-only (do not mutate in place).
func (c *Cache) Get(ctx context.Context, path string) ([]byte, error) {
	now := c.clock()
	c.mu.Lock()
	// age >= 0 guards against a backward clock step (NTP): a future-stamped
	// entry must not read as eternally fresh.
	if e, ok := c.entries[path]; ok {
		if age := now.Sub(e.at); age >= 0 && age < c.ttl {
			data := e.data
			c.mu.Unlock()
			c.onHit()
			return data, nil
		}
	}
	c.mu.Unlock()

	c.onMiss()
	body, err := c.next.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	// Opportunistically drop entries that have fully aged out, so paths that stop
	// being queried (e.g. a removed/renamed cluster node) don't linger forever.
	// Only sweep entries at least ttl old relative to this call's start, so a
	// concurrently-written fresh entry for another path is never evicted.
	for k, e := range c.entries {
		if now.Sub(e.at) >= c.ttl {
			delete(c.entries, k)
		}
	}
	// Stamp at the pre-fetch time so a slow call cannot extend freshness past ttl.
	c.entries[path] = entry{data: body, at: now}
	c.mu.Unlock()
	return body, nil
}
