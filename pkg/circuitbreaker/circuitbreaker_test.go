package circuitbreaker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/logger"
)

type fakeClient struct {
	mu    sync.Mutex
	calls int
	err   error
	body  []byte
}

func (f *fakeClient) Get(_ context.Context, _ string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.body, f.err
}

func (f *fakeClient) setErr(err error) {
	f.mu.Lock()
	f.err = err
	f.mu.Unlock()
}

func (f *fakeClient) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestBreaker_OpensAfterThresholdAndShortCircuits(t *testing.T) {
	fake := &fakeClient{err: errors.New("boom")}
	b := New(fake, WithFailureThreshold(3), WithLogger(logger.New("error")))

	for i := 0; i < 3; i++ {
		if _, err := b.Get(context.Background(), "/x"); err == nil {
			t.Fatalf("call %d: expected backend error", i)
		}
	}
	if b.State() != Open {
		t.Fatalf("state = %d, want Open", b.State())
	}
	if _, err := b.Get(context.Background(), "/x"); !errors.Is(err, ErrOpen) {
		t.Fatalf("err = %v, want ErrOpen", err)
	}
	if got := fake.callCount(); got != 3 {
		t.Errorf("backend calls = %d, want 3 (open must short-circuit)", got)
	}
}

func TestBreaker_OpenErrorEmbedsCause(t *testing.T) {
	cause := errors.New("tls: certificate signed by unknown authority")
	fake := &fakeClient{err: cause}
	b := New(fake, WithFailureThreshold(1), WithLogger(logger.New("error")))

	if _, err := b.Get(context.Background(), "/x"); err == nil { // trips open
		t.Fatal("expected backend error")
	}
	// While open, the short-circuit error must still match ErrOpen AND surface the
	// underlying cause so the operator isn't left with an opaque "circuit breaker open".
	_, err := b.Get(context.Background(), "/x")
	if !errors.Is(err, ErrOpen) {
		t.Errorf("err = %v, want errors.Is(ErrOpen)", err)
	}
	if !errors.Is(err, cause) {
		t.Errorf("open error must embed the cause; err = %v", err)
	}
}

func TestBreaker_HalfOpenClosesOnSuccess(t *testing.T) {
	fake := &fakeClient{err: errors.New("boom")}
	now := time.Unix(1000, 0)
	b := New(fake, WithFailureThreshold(1), WithCooldown(30*time.Second),
		WithClock(func() time.Time { return now }), WithLogger(logger.New("error")))

	if _, err := b.Get(context.Background(), "/x"); err == nil { // trips open (threshold 1)
		t.Fatal("expected error")
	}
	if b.State() != Open {
		t.Fatalf("state = %d, want Open", b.State())
	}
	now = now.Add(31 * time.Second) // cooldown elapsed
	fake.setErr(nil)
	if _, err := b.Get(context.Background(), "/x"); err != nil { // half-open trial succeeds
		t.Fatalf("half-open trial: %v", err)
	}
	if b.State() != Closed {
		t.Fatalf("state = %d, want Closed after a successful trial", b.State())
	}
}

func TestBreaker_ContextErrorsDoNotTrip(t *testing.T) {
	fake := &fakeClient{err: context.Canceled}
	b := New(fake, WithFailureThreshold(2), WithLogger(logger.New("error")))
	for i := 0; i < 5; i++ {
		if _, err := b.Get(context.Background(), "/x"); err == nil {
			t.Fatal("expected the ctx error to surface")
		}
	}
	if b.State() != Closed {
		t.Fatalf("state = %d, want Closed (context cancellation must not trip the breaker)", b.State())
	}
}

func TestBreaker_StateIsReadOnly(t *testing.T) {
	fake := &fakeClient{err: errors.New("boom")}
	now := time.Unix(1000, 0)
	b := New(fake, WithFailureThreshold(1), WithCooldown(30*time.Second),
		WithClock(func() time.Time { return now }), WithLogger(logger.New("error")))

	_, _ = b.Get(context.Background(), "/x") // open
	now = now.Add(31 * time.Second)          // cooldown elapsed
	for i := 0; i < 3; i++ {                 // observing must not consume the trial
		if b.State() != HalfOpen {
			t.Fatalf("State() = %d, want HalfOpen", b.State())
		}
	}
	fake.setErr(nil)
	if _, err := b.Get(context.Background(), "/x"); err != nil { // trial still available
		t.Fatalf("trial must survive State() reads: %v", err)
	}
	if b.State() != Closed {
		t.Fatalf("state = %d, want Closed", b.State())
	}
}

func TestBreaker_HalfOpenReopensOnFailure(t *testing.T) {
	fake := &fakeClient{err: errors.New("boom")}
	now := time.Unix(1000, 0)
	b := New(fake, WithFailureThreshold(1), WithCooldown(30*time.Second),
		WithClock(func() time.Time { return now }), WithLogger(logger.New("error")))

	_, _ = b.Get(context.Background(), "/x") // open
	now = now.Add(31 * time.Second)          // half-open eligible
	_, _ = b.Get(context.Background(), "/x") // trial fails -> reopen
	if b.State() != Open {
		t.Fatalf("state = %d, want Open after a failed trial", b.State())
	}
	if _, err := b.Get(context.Background(), "/x"); !errors.Is(err, ErrOpen) {
		t.Fatalf("err = %v, want ErrOpen (cooldown restarted)", err)
	}
}
