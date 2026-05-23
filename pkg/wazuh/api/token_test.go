package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/logger"
)

// makeJWT builds an unsigned 3-segment JWT carrying the given exp (0 = omit).
func makeJWT(exp int64) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := enc(map[string]string{"alg": "none", "typ": "JWT"})
	var payload string
	if exp == 0 {
		payload = enc(map[string]string{"sub": "x"})
	} else {
		payload = enc(map[string]int64{"exp": exp})
	}
	return header + "." + payload + ".sig"
}

func TestJWTExpiry(t *testing.T) {
	log := logger.New("error")
	fb := time.Now().Add(time.Hour).Truncate(time.Second)
	exp := time.Now().Add(10 * time.Minute).Unix()

	if got := jwtExpiry(makeJWT(exp), fb, log); got.Unix() != exp {
		t.Errorf("exp = %d, want %d", got.Unix(), exp)
	}
	if got := jwtExpiry("only.two", fb, log); !got.Equal(fb) {
		t.Error("non-3-segment token should fall back")
	}
	if got := jwtExpiry("aaa.@@@.ccc", fb, log); !got.Equal(fb) {
		t.Error("bad base64 payload should fall back")
	}
	if got := jwtExpiry(makeJWT(0), fb, log); !got.Equal(fb) {
		t.Error("token without exp should fall back")
	}
	if got := jwtExpiry(makeJWT(time.Now().Add(-time.Hour).Unix()), fb, log); !got.Equal(fb) {
		t.Error("past exp should fall back (avoids re-auth thrash)")
	}
}

func TestTokenManager_ConcurrentSingleAuth(t *testing.T) {
	srv, authHits := newFakeWazuh(makeJWT(time.Now().Add(time.Hour).Unix()))
	defer srv.Close()
	c := testClient(t, srv.URL, false)

	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.tm.get(context.Background()); err != nil {
				t.Errorf("get: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(authHits); got != 1 {
		t.Errorf("auth hits = %d, want 1 (concurrent callers coalesce on the cache)", got)
	}
}

func TestTokenManager_RefreshesNearExpiry(t *testing.T) {
	// First token expires within the refresh margin, so the next get re-auths.
	tokens := []string{
		makeJWT(time.Now().Add(10 * time.Second).Unix()), // < refreshMargin (30s) → stale almost immediately
		makeJWT(time.Now().Add(time.Hour).Unix()),
	}
	srv, authHits := newFakeWazuhRotating(tokens)
	defer srv.Close()
	c := testClient(t, srv.URL, false)

	if _, err := c.tm.get(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.tm.get(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(authHits); got != 2 {
		t.Errorf("auth hits = %d, want 2 (near-expiry token must trigger refresh)", got)
	}
}
