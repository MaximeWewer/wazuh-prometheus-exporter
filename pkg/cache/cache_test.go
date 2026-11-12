package cache

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClient struct {
	calls int64
	err   error
	body  []byte
}

func (f *fakeClient) Get(_ context.Context, _ string) ([]byte, error) {
	atomic.AddInt64(&f.calls, 1)
	return f.body, f.err
}

// ctrlClient is a backend whose body is mutable and whose Get can be gated on a
// channel, so tests can control refresh timing and observe stale-while-revalidate.
type ctrlClient struct {
	mu    sync.Mutex
	calls int64
	body  []byte
	err   error
	gate  chan struct{} // nil: return immediately; else block until closed/sent or ctx done
}

func (c *ctrlClient) Get(ctx context.Context, _ string) ([]byte, error) {
	atomic.AddInt64(&c.calls, 1)
	if c.gate != nil {
		select {
		case <-c.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.body, c.err
}

func (c *ctrlClient) set(b []byte) {
	c.mu.Lock()
	c.body = b
	c.mu.Unlock()
}

// TestCache_StaleServedWhileRevalidate: once an entry expires but is still within
// maxStale, the scrape gets the old value immediately while a background refresh
// pulls the new one, so a later scrape sees fresh data — the scrape never blocks.
func TestCache_StaleServedWhileRevalidate(t *testing.T) {
	now := time.Unix(1000, 0)
	fake := &ctrlClient{body: []byte("v1")}
	refreshed := make(chan struct{}, 8)
	c := New(fake, 30*time.Second,
		WithClock(func() time.Time { return now }),
		WithMaxStale(2*time.Minute),
	)
	c.onRefresh = func() { refreshed <- struct{}{} }

	// Cold warm: stores v1 at t=1000.
	if b, err := c.Get(context.Background(), "/p"); err != nil || string(b) != "v1" {
		t.Fatalf("cold get: %v %q", err, b)
	}
	<-refreshed

	// Expire the entry (age 31s: past ttl, within maxStale) and change the backend.
	now = now.Add(31 * time.Second)
	fake.set([]byte("v2"))

	// Stale read: returns the OLD value immediately, triggers a background refresh.
	if b, err := c.Get(context.Background(), "/p"); err != nil || string(b) != "v1" {
		t.Fatalf("stale get should serve old value without blocking: %v %q", err, b)
	}
	<-refreshed // background refresh stored v2 (stamped at now)

	// Next read is fresh and reflects the refreshed value.
	if b, err := c.Get(context.Background(), "/p"); err != nil || string(b) != "v2" {
		t.Fatalf("post-refresh get: %v %q", err, b)
	}
	if got := atomic.LoadInt64(&fake.calls); got != 2 {
		t.Errorf("backend calls = %d, want 2 (cold warm + one revalidation)", got)
	}
}

// TestCache_ColdFetchOutlivesCallerContext: a backend slower than the caller's
// context still warms the cache — the caller gets a miss error, but the detached
// background refresh completes and a later scrape hits. This is the core fix: a
// slow endpoint can cache even when every scrape-bound fetch would be cancelled.
func TestCache_ColdFetchOutlivesCallerContext(t *testing.T) {
	gate := make(chan struct{})
	fake := &ctrlClient{body: []byte("v"), gate: gate}
	refreshed := make(chan struct{}, 8)
	c := New(fake, time.Minute, WithMaxStale(time.Minute), WithFetchTimeout(5*time.Second))
	c.onRefresh = func() { refreshed <- struct{}{} }

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Get(ctx, "/p"); err == nil {
		t.Fatal("cold get with a short context should return a timeout error")
	}

	// The detached refresh is still running: release it and let it warm the cache.
	close(gate)
	<-refreshed

	if b, err := c.Get(context.Background(), "/p"); err != nil || string(b) != "v" {
		t.Fatalf("after background warm, get should hit cache: %v %q", err, b)
	}
	if got := atomic.LoadInt64(&fake.calls); got != 1 {
		t.Errorf("backend calls = %d, want 1 (one detached refresh warmed the cache)", got)
	}
}

// TestCache_SingleFlightCoalesces: while a refresh is in flight, another Get for
// the same path does not start a second backend call (two Services selected by one
// ServiceMonitor must not double the load on a slow endpoint).
func TestCache_SingleFlightCoalesces(t *testing.T) {
	gate := make(chan struct{})
	fake := &ctrlClient{body: []byte("v"), gate: gate}
	c := New(fake, time.Minute, WithMaxStale(0))

	done := make(chan struct{})
	go func() { _, _ = c.Get(context.Background(), "/p"); close(done) }()
	for atomic.LoadInt64(&fake.calls) == 0 { // wait until the background fetch has started
		runtime.Gosched()
	}

	// Second Get with an already-cancelled context: coalesces onto the in-flight
	// refresh and returns at once without firing a new backend call.
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	if _, err := c.Get(cctx, "/p"); err == nil {
		t.Fatal("want a context error from the coalesced get")
	}
	if got := atomic.LoadInt64(&fake.calls); got != 1 {
		t.Errorf("backend calls = %d, want 1 (single-flight)", got)
	}
	close(gate)
	<-done
}

// TestCache_StaleDroppedPastMaxStale: once an entry ages past ttl+maxStale it is
// no longer served stale — the caller goes cold and blocks on a fresh fetch, so a
// dead backend never serves ancient data forever.
func TestCache_StaleDroppedPastMaxStale(t *testing.T) {
	now := time.Unix(1000, 0)
	fake := &ctrlClient{body: []byte("v")}
	refreshed := make(chan struct{}, 8)
	c := New(fake, 30*time.Second,
		WithClock(func() time.Time { return now }),
		WithMaxStale(60*time.Second),
	)
	c.onRefresh = func() { refreshed <- struct{}{} }

	if _, err := c.Get(context.Background(), "/p"); err != nil { // warm at 1000
		t.Fatal(err)
	}
	<-refreshed

	now = now.Add(91 * time.Second) // age 91s > ttl(30)+maxStale(60)=90s -> cold
	if _, err := c.Get(context.Background(), "/p"); err != nil {
		t.Fatal(err)
	}
	<-refreshed
	if got := atomic.LoadInt64(&fake.calls); got != 2 {
		t.Errorf("backend calls = %d, want 2 (entry past maxStale must be refetched)", got)
	}
}

func TestCache_HitWithinTTLSkipsBackend(t *testing.T) {
	fake := &fakeClient{body: []byte("v")}
	var hits, misses int
	c := New(fake, time.Minute, WithHooks(func() { hits++ }, func() { misses++ }))

	for i := 0; i < 3; i++ {
		b, err := c.Get(context.Background(), "/p")
		if err != nil || string(b) != "v" {
			t.Fatalf("get #%d: %v %q", i, err, b)
		}
	}
	if got := atomic.LoadInt64(&fake.calls); got != 1 {
		t.Errorf("backend calls = %d, want 1 (cached)", got)
	}
	if hits != 2 || misses != 1 {
		t.Errorf("hits/misses = %d/%d, want 2/1", hits, misses)
	}
}

func TestCache_ExpiredRefetches(t *testing.T) {
	fake := &fakeClient{body: []byte("v")}
	now := time.Unix(1000, 0)
	c := New(fake, 30*time.Second, WithClock(func() time.Time { return now }))

	if _, err := c.Get(context.Background(), "/p"); err != nil { // miss, store at 1000
		t.Fatal(err)
	}
	now = now.Add(31 * time.Second)                              // expired
	if _, err := c.Get(context.Background(), "/p"); err != nil { // miss, refetch
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&fake.calls); got != 2 {
		t.Errorf("backend calls = %d, want 2 (expired entry refetched)", got)
	}
}

func TestCache_ErrorNotCached(t *testing.T) {
	fake := &fakeClient{err: errors.New("boom")}
	c := New(fake, time.Minute)

	for i := 0; i < 2; i++ {
		if _, err := c.Get(context.Background(), "/p"); err == nil {
			t.Fatalf("get #%d: expected error", i)
		}
	}
	if got := atomic.LoadInt64(&fake.calls); got != 2 {
		t.Errorf("backend calls = %d, want 2 (errors must not be cached)", got)
	}
}

func TestCache_BackwardClockNotFreshForever(t *testing.T) {
	fake := &fakeClient{body: []byte("v")}
	now := time.Unix(1000, 0)
	c := New(fake, time.Minute, WithClock(func() time.Time { return now }))

	if _, err := c.Get(context.Background(), "/p"); err != nil { // store at 1000
		t.Fatal(err)
	}
	now = time.Unix(900, 0)                                      // clock stepped backward
	if _, err := c.Get(context.Background(), "/p"); err != nil { // age < 0 -> refetch
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&fake.calls); got != 2 {
		t.Errorf("backend calls = %d, want 2 (backward clock must not serve stale)", got)
	}
}

func TestCache_SweepsAgedEntriesOnMiss(t *testing.T) {
	fake := &fakeClient{body: []byte("v")}
	now := time.Unix(1000, 0)
	c := New(fake, 30*time.Second, WithClock(func() time.Time { return now }))

	if _, err := c.Get(context.Background(), "/a"); err != nil { // store /a at 1000
		t.Fatal(err)
	}
	now = now.Add(31 * time.Second)                              // /a aged out
	if _, err := c.Get(context.Background(), "/b"); err != nil { // miss for /b sweeps /a
		t.Fatal(err)
	}
	c.mu.Lock()
	_, hasA := c.entries["/a"]
	n := len(c.entries)
	c.mu.Unlock()
	if hasA {
		t.Error("aged-out entry /a should have been swept on the /b miss")
	}
	if n != 1 {
		t.Errorf("cache size = %d, want 1 (only /b)", n)
	}
}

func TestCache_ConcurrentRaceClean(t *testing.T) {
	fake := &fakeClient{body: []byte("v")}
	c := New(fake, time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Get(context.Background(), "/p")
		}()
	}
	wg.Wait()
}
