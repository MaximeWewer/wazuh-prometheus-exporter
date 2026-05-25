// Package config loads exporter configuration from environment variables
// (with _FILE secret support and a SecureString credential type) into a typed
// Config with bounds clamping.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/rs/zerolog"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/logger"
)

// Config holds all runtime configuration, loaded from WAZUH_* environment
// variables. Secrets are held in SecureString and zeroed by Clear.
type Config struct {
	APIURL           string
	APIUsername      string
	APIPassword      *SecureString
	APITLSSkipVerify bool
	APICAFile        string
	APICertFile      string
	APIKeyFile       string

	// NodeName is the `node` label for the cluster-level gauges (wazuh_up,
	// wazuh_cluster_enabled) and for the single node in standalone mode. In a
	// cluster, set it to the master's cluster node name so those metrics share the
	// `node` value used by the per-node metrics discovered from /cluster/healthcheck
	// (otherwise joining agent/up metrics to per-node metrics on `node` breaks).
	NodeName      string
	ListenAddress string
	LogLevel      string
	WebConfigFile string

	CacheTTL      time.Duration
	ScrapeTimeout time.Duration

	ServerReadTimeout     time.Duration
	ServerWriteTimeout    time.Duration
	ServerIdleTimeout     time.Duration
	ServerShutdownTimeout time.Duration
}

// Defaults and clamp bounds.
const (
	defaultAPIURL        = "https://localhost:55000"
	defaultNodeName      = "manager"
	defaultListenAddress = ":9555"
	defaultLogLevel      = "info"

	defaultCacheTTL = 30 * time.Second
	minCacheTTL     = 5 * time.Second
	maxCacheTTL     = 5 * time.Minute

	defaultScrapeTimeout = 10 * time.Second
	minScrapeTimeout     = 1 * time.Second
	maxScrapeTimeout     = 5 * time.Minute

	defaultServerReadTimeout     = 10 * time.Second
	defaultServerWriteTimeout    = 30 * time.Second
	defaultServerIdleTimeout     = 60 * time.Second
	defaultServerShutdownTimeout = 10 * time.Second
	minServerTimeout             = 1 * time.Second
	maxServerTimeout             = 5 * time.Minute
	maxIdleTimeout               = 10 * time.Minute
	maxShutdownTimeout           = 2 * time.Minute
)

// Load reads configuration from the environment. It never errors for absent
// optional settings (no field is mandatory at startup — with no API credentials
// the exporter serves only its self-metrics). It returns an error only for
// malformed or unreadable config, e.g. an unreadable *_FILE secret. Bootstrap
// warnings use a logger built from WAZUH_LOG_LEVEL.
func Load() (*Config, error) {
	level := getEnvOrDefault("WAZUH_LOG_LEVEL", defaultLogLevel)
	log := logger.New(level)

	cfg := &Config{
		APIURL:                getEnvOrDefault("WAZUH_API_URL", defaultAPIURL),
		APIUsername:           getEnvOrDefault("WAZUH_API_USERNAME", ""),
		APITLSSkipVerify:      getEnvBoolOrDefault(log, "WAZUH_API_TLS_SKIP_VERIFY", false),
		APICAFile:             getEnvOrDefault("WAZUH_API_CA_FILE", ""),
		APICertFile:           getEnvOrDefault("WAZUH_API_CERT_FILE", ""),
		APIKeyFile:            getEnvOrDefault("WAZUH_API_KEY_FILE", ""),
		NodeName:              getEnvOrDefault("WAZUH_NODE_NAME", defaultNodeName),
		ListenAddress:         getEnvOrDefault("WAZUH_LISTEN_ADDRESS", defaultListenAddress),
		LogLevel:              level,
		WebConfigFile:         getEnvOrDefault("WAZUH_WEB_CONFIG_FILE", ""),
		ServerReadTimeout:     clampDuration(log, "WAZUH_SERVER_READ_TIMEOUT", getEnvDurationOrDefault(log, "WAZUH_SERVER_READ_TIMEOUT", defaultServerReadTimeout), minServerTimeout, maxServerTimeout),
		ServerWriteTimeout:    clampDuration(log, "WAZUH_SERVER_WRITE_TIMEOUT", getEnvDurationOrDefault(log, "WAZUH_SERVER_WRITE_TIMEOUT", defaultServerWriteTimeout), minServerTimeout, maxServerTimeout),
		ServerIdleTimeout:     clampDuration(log, "WAZUH_SERVER_IDLE_TIMEOUT", getEnvDurationOrDefault(log, "WAZUH_SERVER_IDLE_TIMEOUT", defaultServerIdleTimeout), minServerTimeout, maxIdleTimeout),
		ServerShutdownTimeout: clampDuration(log, "WAZUH_SERVER_SHUTDOWN_TIMEOUT", getEnvDurationOrDefault(log, "WAZUH_SERVER_SHUTDOWN_TIMEOUT", defaultServerShutdownTimeout), minServerTimeout, maxShutdownTimeout),
		CacheTTL:              clampDuration(log, "WAZUH_CACHE_TTL", getEnvDurationOrDefault(log, "WAZUH_CACHE_TTL", defaultCacheTTL), minCacheTTL, maxCacheTTL),
		ScrapeTimeout:         clampDuration(log, "WAZUH_SCRAPE_TIMEOUT", getEnvDurationOrDefault(log, "WAZUH_SCRAPE_TIMEOUT", defaultScrapeTimeout), minScrapeTimeout, maxScrapeTimeout),
	}

	var errs []error

	pw, err := resolveSecret("WAZUH_API_PASSWORD", "WAZUH_API_PASSWORD_FILE")
	if err != nil {
		errs = append(errs, err)
	}
	cfg.APIPassword = pw

	if cfg.APITLSSkipVerify {
		log.Warn().Msg("WAZUH_API_TLS_SKIP_VERIFY is enabled: Wazuh API TLS certificate verification is disabled (insecure)")
	}

	if cfg.APIUsername == "" || cfg.APIPassword.Empty() {
		log.Warn().Msg("Wazuh API credentials not fully configured: no domain metrics will be collected (the exporter serves only its self-metrics)")
	}

	if len(errs) > 0 {
		cfg.Clear() // do not leave a populated secret on the floor on the error path
		return nil, errors.Join(errs...)
	}
	return cfg, nil
}

// Clear zeroes all sensitive material. Intended for use with `defer cfg.Clear()`.
func (c *Config) Clear() {
	if c == nil {
		return
	}
	c.APIPassword.Clear()
}

// resolveSecret resolves a secret from its *_FILE variant (preferred) or its
// inline env var. A set-but-unreadable *_FILE path is an error.
func resolveSecret(inlineKey, fileKey string) (*SecureString, error) {
	if path, ok := os.LookupEnv(fileKey); ok && path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // operator-configured secret file path (_FILE convention)
		if err != nil {
			return NewSecureString(""), fmt.Errorf("%s: reading secret file %q: %w", fileKey, path, err)
		}
		data = bytes.TrimRight(data, "\r\n")
		if len(data) > 0 {
			ss := NewSecureStringFromBytes(data)
			for i := range data { // zero the bytes we just read
				data[i] = 0
			}
			return ss, nil
		}
		// File is present but empty/whitespace-only: fall through to the inline
		// var rather than silently ending up with no secret.
	}
	if v, ok := os.LookupEnv(inlineKey); ok {
		return NewSecureString(v), nil
	}
	return NewSecureString(""), nil
}

// --- typed environment helpers ---

func getEnvOrDefault(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func getEnvBoolOrDefault(log zerolog.Logger, key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		log.Warn().Str("var", key).Str("value", v).Bool("default", def).Msg("invalid boolean; using default")
		return def
	}
	return b
}

func getEnvDurationOrDefault(log zerolog.Logger, key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Warn().Str("var", key).Str("value", v).Dur("default", def).Msg("invalid duration; using default")
		return def
	}
	return d
}

func clampDuration(log zerolog.Logger, name string, val, lo, hi time.Duration) time.Duration {
	switch {
	case val < lo:
		log.Warn().Str("var", name).Dur("value", val).Dur("clamped_to", lo).Msg("value below minimum; clamped")
		return lo
	case val > hi:
		log.Warn().Str("var", name).Dur("value", val).Dur("clamped_to", hi).Msg("value above maximum; clamped")
		return hi
	}
	return val
}
