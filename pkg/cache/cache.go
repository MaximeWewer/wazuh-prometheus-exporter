// Package cache wraps an api.APIClient with a short-TTL response cache so that
// frequent scrapes reuse a recent API response instead of re-querying Wazuh.
// It carries no Prometheus dependency: hits/misses are reported via injected
// callbacks.
//
// Freshness has three zones, keyed on an entry's age:
//
//   - age < ttl                : fresh — served immediately (a hit).
//   - ttl <= age < ttl+maxStale: stale — served immediately (a hit) AND a
//     background refresh is kicked off so the next scrape sees fresh data
//     (stale-while-revalidate). The scrape never blocks on a slow backend.
//   - age >= ttl+maxStale      : cold — no usable entry; the caller blocks on the
//     background refresh, bounded by its own context, and gets a miss error if
//     that context fires first (the refresh keeps running and warms the cache).
//
// The background refresh runs on a detached context with its own fetchTimeout,
// NOT the caller's scrape context. This is what lets an endpoint slower than the
// scrape timeout (e.g. /cluster/configuration/validation, which can take longer
// than WAZUH_SCRAPE_TIMEOUT) ever complete and populate the cache: a scrape-bound
// fetch would be cancelled every time and never cache, so every scrape would
// re-fire it and block. Refreshes are single-flighted per path, so two concurrent
// scrapes of the same target (e.g. a ServiceMonitor selecting two Services) collapse
// to one backend call.
//
// Only successful responses are cached; a failed refresh leaves any existing
// (stale) entry in place until it ages past ttl+maxStale, after which the path
// goes cold — so a dead backend self-heals and never serves ancient data forever.
package cache

import (
	"context"
	"sync"
	"time"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/wazuh/api"
)

const defaultFetchTimeout = 30 * time.Second

type entry struct {
	data []byte
	at   time.Time
}

// refresh tracks a single in-flight background fetch for one path, so concurrent
// callers single-flight onto it and cold callers can wait for its result.
type refresh struct {
	done chan struct{}
	data []byte
	err  error
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
// A hit is any response served from the cache without blocking on the backend
// (fresh or stale); a miss is a cold path that had to wait on a backend fetch.
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

// WithMaxStale sets how long past the TTL a stale entry may still be served while
// a background refresh runs (stale-while-revalidate). 0 disables stale serving:
// an expired entry then behaves as cold. Negative is treated as 0.
func WithMaxStale(d time.Duration) Option {
	return func(c *Cache) {
		if d < 0 {
			d = 0
		}
		c.maxStale = d
	}
}

// WithFetchTimeout sets the budget for a background refresh (on the detached
// context). It must exceed the slowest endpoint's latency for that endpoint to
// ever cache. Non-positive values are ignored (the default is kept).
func WithFetchTimeout(d time.Duration) Option {
	return func(c *Cache) {
		if d > 0 {
			c.fetchTimeout = d
		}
	}
}

// WithBaseContext sets the lifetime context for background refreshes, so they
// stop when the process is shutting down rather than outliving it. Defaults to
// context.Background().
func WithBaseContext(ctx context.Context) Option {
	return func(c *Cache) {
		if ctx != nil {
			c.baseCtx = ctx
		}
	}
}

// Cache wraps an api.APIClient and implements api.APIClient.
type Cache struct {
	next         api.APIClient
	ttl          time.Duration
	maxStale     time.Duration
	fetchTimeout time.Duration
	baseCtx      context.Context
	clock        func() time.Time
	onHit        func()
	onMiss       func()

	// onRefresh, if set, is called after each background refresh completes. It is
	// a test seam for deterministically awaiting an async refresh; unused in prod.
	onRefresh func()

	mu       sync.Mutex
	entries  map[string]entry
	inflight map[string]*refresh
}

// New builds a Cache wrapping next with the given TTL.
func New(next api.APIClient, ttl time.Duration, opts ...Option) *Cache {
	c := &Cache{
		next:         next,
		ttl:          ttl,
		fetchTimeout: defaultFetchTimeout,
		baseCtx:      context.Background(),
		clock:        time.Now,
		onHit:        func() {},
		onMiss:       func() {},
		entries:      make(map[string]entry),
		inflight:     make(map[string]*refresh),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Get returns a cached response for path when one is fresh or servably stale, and
// otherwise blocks on a background fetch bounded by ctx. See the package doc for
// the freshness zones and the stale-while-revalidate contract.
//
// The returned slice is owned by the cache and shared across hits within the
// freshness window; callers must treat it as read-only (do not mutate in place).
func (c *Cache) Get(ctx context.Context, path string) ([]byte, error) {
	now := c.clock()
	c.mu.Lock()

	e, ok := c.entries[path]
	// age >= 0 guards against a backward clock step (NTP): a future-stamped entry
	// must not read as eternally fresh.
	if ok {
		if age := now.Sub(e.at); age >= 0 && age < c.ttl {
			data := e.data
			c.mu.Unlock()
			c.onHit()
			return data, nil
		}
	}

	// Not fresh: ensure a single background refresh is running for this path.
	r := c.startRefreshLocked(path)

	// Serve a still-recent stale entry immediately while the refresh runs behind it.
	if ok {
		if age := now.Sub(e.at); age >= 0 && age < c.ttl+c.maxStale {
			data := e.data
			c.mu.Unlock()
			c.onHit()
			return data, nil
		}
	}
	c.mu.Unlock()

	// Cold (no entry, aged past maxStale, or backward clock): wait on the refresh,
	// bounded by the caller's context. If ctx fires first the refresh keeps running
	// detached and will have warmed the cache for the next scrape.
	c.onMiss()
	select {
	case <-r.done:
		return r.data, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// startRefreshLocked returns the in-flight refresh for path, starting one if none
// is running. The caller must hold c.mu.
func (c *Cache) startRefreshLocked(path string) *refresh {
	if r, ok := c.inflight[path]; ok {
		return r
	}
	r := &refresh{done: make(chan struct{})}
	c.inflight[path] = r
	go c.runRefresh(path, r)
	return r
}

// runRefresh fetches path on the detached base context (with the fetch-timeout
// budget), stores a successful result, and signals waiters. A failed fetch leaves
// any existing entry untouched so it can still be served stale until it ages out.
func (c *Cache) runRefresh(path string, r *refresh) {
	ctx, cancel := context.WithTimeout(c.baseCtx, c.fetchTimeout)
	defer cancel()
	body, err := c.next.Get(ctx, path)

	now := c.clock()
	c.mu.Lock()
	if err == nil {
		c.entries[path] = entry{data: body, at: now}
	}
	// Opportunistically drop entries that have aged past the servable window, so
	// paths that stop being queried (e.g. a removed/renamed cluster node) don't
	// linger forever. Only sweep entries older than ttl+maxStale relative to this
	// refresh, so a concurrently-written fresh entry is never evicted.
	for k, ent := range c.entries {
		if now.Sub(ent.at) >= c.ttl+c.maxStale {
			delete(c.entries, k)
		}
	}
	delete(c.inflight, path)
	c.mu.Unlock()

	r.data, r.err = body, err
	close(r.done)
	if c.onRefresh != nil {
		c.onRefresh()
	}
}
