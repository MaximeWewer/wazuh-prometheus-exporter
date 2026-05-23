package cache

import (
	"context"
	"errors"
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
