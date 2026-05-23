package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/config"
	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/logger"
)

// TestNewClient_TLSMaterialErrors covers the buildTLSConfig failure paths: an
// unreadable CA, a CA file with no parseable certs, and a bad client keypair —
// each must make NewClient fail closed rather than silently misconfigure TLS.
func TestNewClient_TLSMaterialErrors(t *testing.T) {
	dir := t.TempDir()
	badPEM := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := func() Options {
		return Options{
			BaseURL:  "https://wazuh:55000",
			Username: "u",
			Password: config.NewSecureString("p"),
			Timeout:  time.Second,
			Logger:   logger.New("error"),
		}
	}

	t.Run("unreadable CA file", func(t *testing.T) {
		o := base()
		o.CAFile = filepath.Join(dir, "does-not-exist.pem")
		if _, err := NewClient(o); err == nil {
			t.Error("expected error for unreadable CA file")
		}
	})
	t.Run("CA file with no certs", func(t *testing.T) {
		o := base()
		o.CAFile = badPEM
		if _, err := NewClient(o); err == nil {
			t.Error("expected error for CA file with no parseable certificates")
		}
	})
	t.Run("invalid client keypair", func(t *testing.T) {
		o := base()
		o.CertFile, o.KeyFile = badPEM, badPEM
		if _, err := NewClient(o); err == nil {
			t.Error("expected error for invalid client TLS keypair")
		}
	})
	t.Run("skip-verify builds successfully", func(t *testing.T) {
		o := base()
		o.SkipVerify = true
		c, err := NewClient(o)
		if err != nil || c == nil {
			t.Errorf("skip-verify client should build, got client=%v err=%v", c, err)
		}
	})
}

// newFakeWazuh returns an httptest server simulating the Wazuh API auth endpoint
// plus a few test endpoints, and a counter of authentication hits.
func newFakeWazuh(token string) (*httptest.Server, *int64) {
	var authHits int64
	var protectedHits int64
	mux := http.NewServeMux()
	mux.HandleFunc(authPath, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&authHits, 1)
		if u, p, ok := r.BasicAuth(); !ok || u == "" || p == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, `{"data":{"token":%q}}`, token)
	})
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	// /protected returns 401 on the first hit, 200 afterwards (exercises re-auth+retry).
	mux.HandleFunc("/protected", func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt64(&protectedHits, 1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/boom", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	return httptest.NewServer(mux), &authHits
}

// newFakeWazuhRotating returns a server whose auth endpoint hands out the next
// token from tokens on each call (last one repeats), plus the auth hit counter.
func newFakeWazuhRotating(tokens []string) (*httptest.Server, *int64) {
	var authHits int64
	mux := http.NewServeMux()
	mux.HandleFunc(authPath, func(w http.ResponseWriter, _ *http.Request) {
		i := int(atomic.AddInt64(&authHits, 1)) - 1
		if i >= len(tokens) {
			i = len(tokens) - 1
		}
		fmt.Fprintf(w, `{"data":{"token":%q}}`, tokens[i])
	})
	return httptest.NewServer(mux), &authHits
}

func testClient(t *testing.T, baseURL string, skipVerify bool) *Client {
	t.Helper()
	c, err := NewClient(Options{
		BaseURL:    baseURL,
		Username:   "u",
		Password:   config.NewSecureString("p"),
		SkipVerify: skipVerify,
		Timeout:    2 * time.Second,
		Logger:     logger.New("error"),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func futureJWT() string { return makeJWT(time.Now().Add(time.Hour).Unix()) }

func TestGet_AuthThenSuccessAndCachesToken(t *testing.T) {
	srv, authHits := newFakeWazuh(futureJWT())
	defer srv.Close()
	c := testClient(t, srv.URL, false)

	for i := 0; i < 3; i++ {
		body, err := c.Get(context.Background(), "/ok")
		if err != nil {
			t.Fatalf("Get #%d: %v", i, err)
		}
		if !strings.Contains(string(body), `"ok":true`) {
			t.Fatalf("unexpected body: %s", body)
		}
	}
	if got := atomic.LoadInt64(authHits); got != 1 {
		t.Errorf("auth hits = %d, want 1 (token must be cached)", got)
	}
}

func TestGet_ReauthOn401AndRetryOnce(t *testing.T) {
	srv, authHits := newFakeWazuh(futureJWT())
	defer srv.Close()
	c := testClient(t, srv.URL, false)

	body, err := c.Get(context.Background(), "/protected")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
	if got := atomic.LoadInt64(authHits); got != 2 {
		t.Errorf("auth hits = %d, want 2 (initial + re-auth on 401)", got)
	}
}

func TestGet_Non2xxWrapsStatus(t *testing.T) {
	srv, _ := newFakeWazuh(futureJWT())
	defer srv.Close()
	c := testClient(t, srv.URL, false)

	_, err := c.Get(context.Background(), "/boom")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("error = %v, want one mentioning 500", err)
	}
}

func TestGet_UnreachableWrapsError(t *testing.T) {
	srv, _ := newFakeWazuh(futureJWT())
	url := srv.URL
	srv.Close() // now unreachable
	c := testClient(t, url, false)

	if _, err := c.Get(context.Background(), "/ok"); err == nil {
		t.Fatal("expected an error for an unreachable server")
	}
}

func TestGet_NormalizesLeadingSlash(t *testing.T) {
	srv, _ := newFakeWazuh(futureJWT())
	defer srv.Close()
	c := testClient(t, srv.URL, false)
	body, err := c.Get(context.Background(), "ok") // no leading slash
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestGet_BlankTokenRejected(t *testing.T) {
	srv, _ := newFakeWazuh(" ") // auth returns a whitespace-only token
	defer srv.Close()
	c := testClient(t, srv.URL, false)
	if _, err := c.Get(context.Background(), "/ok"); err == nil {
		t.Fatal("a blank token must be rejected, not cached")
	}
}

func TestGet_TLSVerification(t *testing.T) {
	var token = futureJWT()
	mux := http.NewServeMux()
	mux.HandleFunc(authPath, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"data":{"token":%q}}`, token)
	})
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	// skip-verify accepts the self-signed cert.
	if _, err := testClient(t, srv.URL, true).Get(context.Background(), "/ok"); err != nil {
		t.Errorf("skip-verify Get failed: %v", err)
	}
	// default verification rejects the untrusted cert.
	if _, err := testClient(t, srv.URL, false).Get(context.Background(), "/ok"); err == nil {
		t.Error("expected TLS verification to reject the self-signed cert")
	}
}
