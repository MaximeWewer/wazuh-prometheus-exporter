package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad_Defaults(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.APIURL != "https://localhost:55000" {
		t.Errorf("APIURL = %q, want default", cfg.APIURL)
	}
	if cfg.ListenAddress != ":9555" {
		t.Errorf("ListenAddress = %q, want :9555", cfg.ListenAddress)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", cfg.LogLevel)
	}
	if cfg.CacheTTL != 30*time.Second {
		t.Errorf("CacheTTL = %v, want 30s", cfg.CacheTTL)
	}
	if cfg.ScrapeTimeout != 10*time.Second {
		t.Errorf("ScrapeTimeout = %v, want 10s", cfg.ScrapeTimeout)
	}
	if cfg.APITLSSkipVerify {
		t.Error("APITLSSkipVerify = true, want false")
	}
	if !cfg.APIPassword.Empty() {
		t.Error("APIPassword should be empty by default")
	}
	if cfg.WebConfigFile != "" {
		t.Errorf("WebConfigFile = %q, want empty default", cfg.WebConfigFile)
	}
	if cfg.NodeName != "manager" {
		t.Errorf("NodeName = %q, want manager", cfg.NodeName)
	}
	if cfg.ServerReadTimeout != 10*time.Second {
		t.Errorf("ServerReadTimeout = %v, want 10s", cfg.ServerReadTimeout)
	}
	if cfg.ServerWriteTimeout != 30*time.Second {
		t.Errorf("ServerWriteTimeout = %v, want 30s", cfg.ServerWriteTimeout)
	}
	if cfg.ServerIdleTimeout != 60*time.Second {
		t.Errorf("ServerIdleTimeout = %v, want 60s", cfg.ServerIdleTimeout)
	}
	if cfg.ServerShutdownTimeout != 10*time.Second {
		t.Errorf("ServerShutdownTimeout = %v, want 10s", cfg.ServerShutdownTimeout)
	}
}

func TestLoad_ClampsServerShutdownTimeout(t *testing.T) {
	t.Setenv("WAZUH_SERVER_SHUTDOWN_TIMEOUT", "10m") // above 2m maximum
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ServerShutdownTimeout != 2*time.Minute {
		t.Errorf("ServerShutdownTimeout = %v, want clamped to 2m", cfg.ServerShutdownTimeout)
	}
}

func TestLoad_Overrides(t *testing.T) {
	t.Setenv("WAZUH_API_URL", "https://wazuh.example:55000")
	t.Setenv("WAZUH_API_USERNAME", "exporter")
	t.Setenv("WAZUH_API_PASSWORD", "s3cret")
	t.Setenv("WAZUH_API_TLS_SKIP_VERIFY", "true")
	t.Setenv("WAZUH_LISTEN_ADDRESS", ":9999")
	t.Setenv("WAZUH_LOG_LEVEL", "debug")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.APIURL != "https://wazuh.example:55000" {
		t.Errorf("APIURL = %q", cfg.APIURL)
	}
	if cfg.APIUsername != "exporter" {
		t.Errorf("APIUsername = %q", cfg.APIUsername)
	}
	if cfg.APIPassword.Reveal() != "s3cret" {
		t.Errorf("APIPassword = %q", cfg.APIPassword.Reveal())
	}
	if !cfg.APITLSSkipVerify {
		t.Error("APITLSSkipVerify = false, want true")
	}
	if cfg.ListenAddress != ":9999" {
		t.Errorf("ListenAddress = %q", cfg.ListenAddress)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q", cfg.LogLevel)
	}
}

func TestLoad_PasswordFilePrecedence(t *testing.T) {
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw")
	if err := os.WriteFile(pwFile, []byte("filesecret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WAZUH_API_PASSWORD", "inlinesecret")
	t.Setenv("WAZUH_API_PASSWORD_FILE", pwFile)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.APIPassword.Reveal(); got != "filesecret" {
		t.Errorf("APIPassword = %q, want %q (file takes precedence, newline trimmed)", got, "filesecret")
	}
	cfg.Clear()
	if !cfg.APIPassword.Empty() {
		t.Error("APIPassword not cleared after Config.Clear()")
	}
}

func TestLoad_EmptyPasswordFileFallsBackToInline(t *testing.T) {
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "empty")
	if err := os.WriteFile(pwFile, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WAZUH_API_PASSWORD", "inlinesecret")
	t.Setenv("WAZUH_API_PASSWORD_FILE", pwFile)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.APIPassword.Reveal(); got != "inlinesecret" {
		t.Errorf("APIPassword = %q, want inline fallback when file is empty", got)
	}
}

func TestLoad_PasswordFileUnreadable(t *testing.T) {
	t.Setenv("WAZUH_API_PASSWORD_FILE", filepath.Join(t.TempDir(), "does-not-exist"))
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want error for unreadable secret file")
	}
}

func TestLoad_ClampsDurationBelowMin(t *testing.T) {
	t.Setenv("WAZUH_CACHE_TTL", "1s") // below 5s minimum
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.CacheTTL != 5*time.Second {
		t.Errorf("CacheTTL = %v, want clamped to 5s", cfg.CacheTTL)
	}
}

func TestLoad_InvalidDurationFallsBackToDefault(t *testing.T) {
	t.Setenv("WAZUH_SCRAPE_TIMEOUT", "not-a-duration")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ScrapeTimeout != 10*time.Second {
		t.Errorf("ScrapeTimeout = %v, want default 10s on invalid input", cfg.ScrapeTimeout)
	}
}
