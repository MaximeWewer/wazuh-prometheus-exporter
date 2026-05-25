package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/config"
)

// tlsHint annotates a TLS certificate-verification failure with the config knobs
// that fix it, so the cause is actionable rather than an opaque x509 message.
func tlsHint(err error) error {
	var ce *tls.CertificateVerificationError
	if errors.As(err, &ce) {
		return fmt.Errorf("%w [TLS verification failed: set WAZUH_API_CA_FILE to the CA that signed the Wazuh API certificate, or WAZUH_API_TLS_SKIP_VERIFY=true for a self-signed cert]", err)
	}
	return err
}

// maxResponseBytes caps how much of a response body the client will read, to
// bound memory use against a misbehaving or hostile endpoint.
const maxResponseBytes = 32 << 20 // 32 MiB

// APIClient performs authenticated GET requests against the Wazuh REST API and
// returns the raw response body. Callers unmarshal it themselves.
type APIClient interface {
	Get(ctx context.Context, path string) ([]byte, error)
}

// Options configure a Client.
type Options struct {
	BaseURL    string
	Username   string
	Password   *config.SecureString
	CAFile     string
	CertFile   string
	KeyFile    string
	SkipVerify bool
	Timeout    time.Duration
	Logger     zerolog.Logger
}

// Client is the Wazuh REST API client with a managed JWT and validated TLS.
type Client struct {
	baseURL string
	httpc   *http.Client
	tm      *tokenManager
	log     zerolog.Logger
}

// NewClient builds a Client. It fails if the configured TLS material cannot be loaded.
func NewClient(opts Options) (*Client, error) {
	tlsCfg, err := buildTLSConfig(opts)
	if err != nil {
		return nil, err
	}
	httpc := &http.Client{
		Timeout:   opts.Timeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		// The Wazuh API does not redirect; do not follow 3xx (a cross-host
		// redirect would drop the Bearer and hit an unintended endpoint).
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	base := strings.TrimRight(opts.BaseURL, "/")
	if opts.SkipVerify {
		msg := "Wazuh API TLS verification disabled (skip-verify)"
		if opts.CAFile != "" {
			msg += "; the configured CA file is ignored"
		}
		opts.Logger.Warn().Str("component", "api").Msg(msg)
	}
	return &Client{
		baseURL: base,
		httpc:   httpc,
		log:     opts.Logger,
		tm: &tokenManager{
			baseURL:  base,
			username: opts.Username,
			password: opts.Password,
			httpc:    httpc,
			log:      opts.Logger,
		},
	}, nil
}

func buildTLSConfig(opts Options) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: opts.SkipVerify, //nolint:gosec // operator-set (WAZUH_API_TLS_SKIP_VERIFY), logged as a risk at config load
	}
	if opts.CAFile != "" {
		pem, err := os.ReadFile(opts.CAFile) //nolint:gosec // operator-configured CA path
		if err != nil {
			return nil, fmt.Errorf("reading CA file %q: %w", opts.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates parsed from CA file %q", opts.CAFile)
		}
		cfg.RootCAs = pool
	}
	if opts.CertFile != "" && opts.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client TLS keypair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// Get fetches path (appended to the base URL) with a Bearer token. On a 401 it
// re-authenticates once and retries a single time. Non-2xx (other than the
// retried 401) and transport errors are returned wrapped.
func (c *Client) Get(ctx context.Context, path string) ([]byte, error) {
	body, status, err := c.doGet(ctx, path)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized {
		c.tm.invalidate() // token likely stale: re-auth and retry once
		body, status, err = c.doGet(ctx, path)
		if err != nil {
			return nil, err
		}
		if status == http.StatusUnauthorized {
			return nil, fmt.Errorf("GET %s: still unauthorized after re-auth (check credentials/RBAC)", path)
		}
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("GET %s: unexpected status %d", path, status)
	}
	return body, nil
}

func (c *Client) doGet(ctx context.Context, path string) ([]byte, int, error) {
	token, err := c.tm.get(ctx)
	if err != nil {
		return nil, 0, err
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("building request GET %s: %w", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpc.Do(req) //nolint:gosec // G704: URL targets the operator-configured Wazuh API base; path is internal/derived, not attacker-controlled
	if err != nil {
		return nil, 0, fmt.Errorf("GET %s: %w", path, tlsHint(err))
	}
	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading GET %s body: %w", path, err)
	}
	return b, resp.StatusCode, nil
}
