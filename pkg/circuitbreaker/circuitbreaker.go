// Package circuitbreaker wraps an api.APIClient with a 3-state circuit breaker
// (closed → open after consecutive failures → half-open after a cooldown). It
// shields the Wazuh API from repeated calls while it is failing. It carries no
// Prometheus dependency: the live state is exposed via State() for monitoring to
// read through a GaugeFunc.
package circuitbreaker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/wazuh/api"
)

// State is the breaker state. Values match the self-metric encoding.
type State int

const (
	Closed   State = iota // 0: requests pass through
	HalfOpen              // 1: a single trial request is allowed
	Open                  // 2: requests are short-circuited
)

// ErrOpen is returned when the breaker is open and a call is short-circuited.
var ErrOpen = errors.New("circuit breaker open")

const (
	defaultFailureThreshold = 5
	defaultCooldown         = 30 * time.Second
)

// Option configures a Breaker.
type Option func(*Breaker)

// WithFailureThreshold sets the consecutive-failure count that opens the breaker.
func WithFailureThreshold(n int) Option {
	return func(b *Breaker) {
		if n > 0 {
			b.failureThreshold = n
		}
	}
}

// WithCooldown sets how long the breaker stays open before allowing a trial.
func WithCooldown(d time.Duration) Option {
	return func(b *Breaker) {
		if d > 0 {
			b.cooldown = d
		}
	}
}

// WithClock injects a clock (tests).
func WithClock(clock func() time.Time) Option {
	return func(b *Breaker) {
		if clock != nil {
			b.clock = clock
		}
	}
}

// WithLogger sets the logger used for state-transition messages.
func WithLogger(log zerolog.Logger) Option {
	return func(b *Breaker) { b.log = log }
}

// Breaker wraps an api.APIClient and implements api.APIClient.
type Breaker struct {
	next             api.APIClient
	failureThreshold int
	cooldown         time.Duration
	clock            func() time.Time
	log              zerolog.Logger

	mu       sync.Mutex
	state    State
	failures int
	openedAt time.Time
	probing  bool  // a half-open trial is in flight
	lastErr  error // the failure that tripped the breaker, surfaced while open
}

// New builds a Breaker wrapping next.
func New(next api.APIClient, opts ...Option) *Breaker {
	b := &Breaker{
		next:             next,
		failureThreshold: defaultFailureThreshold,
		cooldown:         defaultCooldown,
		clock:            time.Now,
		state:            Closed,
	}
	for _, o := range opts {
		o(b)
	}
	return b
}

// State returns the current state. It is read-only: when Open and the cooldown
// has elapsed it reports HalfOpen (readiness to retry) WITHOUT performing the
// transition — only Get advances the real state, so observing the metric never
// changes breaker behavior.
func (b *Breaker) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == Open && !b.clock().Before(b.openedAt.Add(b.cooldown)) {
		return HalfOpen
	}
	return b.state
}

func (b *Breaker) maybeHalfOpenLocked() {
	if b.state == Open && !b.clock().Before(b.openedAt.Add(b.cooldown)) {
		b.state = HalfOpen
		b.probing = false
		b.log.Info().Str("component", "circuitbreaker").Msg("cooldown elapsed; half-open (one trial allowed)")
	}
}

// Get passes through to the wrapped client unless the breaker is open. An
// upstream error counts as a failure; a nil error as a success. Context
// cancellation/timeout is a caller-side condition and is NOT counted.
func (b *Breaker) Get(ctx context.Context, path string) ([]byte, error) {
	trial, err := b.allow()
	if err != nil {
		return nil, err
	}
	if trial {
		// Clear the single-trial flag even if next.Get panics, so the breaker
		// can never get wedged in half-open.
		defer b.clearProbing()
	}

	body, gerr := b.next.Get(ctx, path)
	b.record(gerr)
	if gerr != nil {
		return nil, gerr
	}
	return body, nil
}

// allow decides whether the call may proceed; trial is true when this call is
// the single permitted half-open probe.
func (b *Breaker) allow() (trial bool, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.maybeHalfOpenLocked()
	switch b.state {
	case Open:
		return false, b.openErrorLocked()
	case HalfOpen:
		if b.probing {
			return false, b.openErrorLocked() // another trial is already in flight
		}
		b.probing = true
		return true, nil
	}
	return false, nil
}

// openErrorLocked returns the short-circuit error, embedding the failure that
// tripped the breaker so the real cause (e.g. a TLS verification failure) is
// visible on every masked scrape, not only in the logs before the breaker opened.
// errors.Is(err, ErrOpen) still holds.
func (b *Breaker) openErrorLocked() error {
	if b.lastErr != nil {
		return fmt.Errorf("%w (last error: %w)", ErrOpen, b.lastErr)
	}
	return ErrOpen
}

func (b *Breaker) clearProbing() {
	b.mu.Lock()
	b.probing = false
	b.mu.Unlock()
}

// record applies a call result to the breaker state. Context cancellation or
// deadline is a caller-side condition (e.g. scrape timeout/shutdown), so it
// neither trips nor resets the breaker.
func (b *Breaker) record(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		b.lastErr = err
		b.onFailureLocked()
		return
	}
	b.onSuccessLocked()
}

func (b *Breaker) onSuccessLocked() {
	if b.state != Closed {
		b.log.Info().Str("component", "circuitbreaker").Msg("trial succeeded; closing circuit")
	}
	b.state = Closed
	b.failures = 0
	b.lastErr = nil
}

func (b *Breaker) onFailureLocked() {
	switch b.state {
	case HalfOpen:
		b.tripLocked()
	case Closed:
		b.failures++
		if b.failures >= b.failureThreshold {
			b.tripLocked()
		}
	}
}

func (b *Breaker) tripLocked() {
	b.state = Open
	b.openedAt = b.clock()
	b.log.Warn().Str("component", "circuitbreaker").Int("failures", b.failures).
		Err(b.lastErr).Msg("circuit opened")
}
