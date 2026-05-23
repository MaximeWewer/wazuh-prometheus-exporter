package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/config"
)

const (
	authPath = "/security/user/authenticate"
	// refreshMargin re-authenticates this long before the token's exp.
	refreshMargin = 30 * time.Second
	// fallbackTokenTTL is used when the JWT carries no readable exp claim.
	fallbackTokenTTL = 15 * time.Minute
)

// tokenManager caches the Wazuh JWT and refreshes it proactively. It is safe for
// concurrent use (scrapes run collectors in parallel).
type tokenManager struct {
	baseURL  string
	username string
	password *config.SecureString
	httpc    *http.Client
	log      zerolog.Logger

	mu    sync.Mutex
	token string
	exp   time.Time
}

// get returns a valid token, (re)authenticating if the cache is empty or within
// refreshMargin of expiry. The authenticate call runs under the lock so that
// concurrent callers coalesce onto a single auth request.
func (tm *tokenManager) get(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err // fast-fail an already-cancelled caller before contending for the lock
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if tm.token != "" && time.Now().Before(tm.exp.Add(-refreshMargin)) {
		return tm.token, nil
	}
	if err := tm.authenticateLocked(ctx); err != nil {
		return "", err
	}
	return tm.token, nil
}

// invalidate drops the cached token (called after a 401 so the next get re-auths).
func (tm *tokenManager) invalidate() {
	tm.mu.Lock()
	tm.token = ""
	tm.exp = time.Time{}
	tm.mu.Unlock()
}

func (tm *tokenManager) authenticateLocked(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tm.baseURL+authPath, nil)
	if err != nil {
		return fmt.Errorf("building auth request: %w", err)
	}
	req.SetBasicAuth(tm.username, tm.password.Reveal())

	resp, err := tm.httpc.Do(req) //nolint:gosec // G704: URL targets the operator-configured Wazuh API base; path is internal, not attacker-controlled
	if err != nil {
		return fmt.Errorf("authenticating to Wazuh API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authenticating to Wazuh API: unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("reading auth response: %w", err)
	}
	var ar authResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		return fmt.Errorf("decoding auth response: %w", err)
	}
	if strings.TrimSpace(ar.Data.Token) == "" {
		return fmt.Errorf("no token in Wazuh auth response")
	}
	tm.token = ar.Data.Token
	tm.exp = jwtExpiry(ar.Data.Token, time.Now().Add(fallbackTokenTTL), tm.log)
	return nil
}

// jwtExpiry reads the `exp` claim from a JWT without verifying its signature,
// returning fallback if the token is not a readable 3-segment JWT or lacks exp.
func jwtExpiry(token string, fallback time.Time, log zerolog.Logger) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		log.Debug().Msg("JWT not in header.payload.signature form; using fallback token TTL")
		return fallback
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		log.Debug().Err(err).Msg("decoding JWT payload failed; using fallback token TTL")
		return fallback
	}
	// exp is an RFC 7519 NumericDate (may be fractional) — decode as float64.
	var claims struct {
		Exp float64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		log.Debug().Msg("JWT has no usable exp claim; using fallback token TTL")
		return fallback
	}
	exp := time.Unix(int64(claims.Exp), 0)
	if !exp.After(time.Now()) {
		// Past/zero-skew exp would force re-auth on every call; use the fallback.
		log.Debug().Msg("JWT exp is not in the future (clock skew?); using fallback token TTL")
		return fallback
	}
	return exp
}
