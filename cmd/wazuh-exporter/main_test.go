package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/config"
	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/logger"
	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/monitoring"
)

func TestRun_VersionFlagPrintsVersionAndExitsZero(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })
	Version = "1.2.3-test"

	var stdout bytes.Buffer
	code := run([]string{"--version"}, &stdout, io.Discard)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if got := strings.TrimSpace(stdout.String()); got != "1.2.3-test" {
		t.Fatalf("stdout = %q, want %q", got, "1.2.3-test")
	}
}

func TestRun_BadFlagReturnsNonZero(t *testing.T) {
	code := run([]string{"--definitely-not-a-flag"}, io.Discard, io.Discard)
	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero for unknown flag")
	}
}

func TestRun_HelpFlagExitsZero(t *testing.T) {
	for _, arg := range []string{"-h", "--help"} {
		if code := run([]string{arg}, io.Discard, io.Discard); code != 0 {
			t.Fatalf("run(%q) exit code = %d, want 0", arg, code)
		}
	}
}

func TestNewServer_AppliesTimeouts(t *testing.T) {
	cfg := &config.Config{
		ListenAddress:      ":9555",
		ServerReadTimeout:  11 * time.Second,
		ServerWriteTimeout: 22 * time.Second,
		ServerIdleTimeout:  33 * time.Second,
	}
	srv := newServer(cfg, logger.New("error"))
	if srv.ReadTimeout != 11*time.Second || srv.WriteTimeout != 22*time.Second || srv.IdleTimeout != 33*time.Second {
		t.Fatalf("timeouts not applied: read=%v write=%v idle=%v", srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
	if srv.Addr != ":9555" {
		t.Errorf("Addr = %q, want :9555", srv.Addr)
	}
	if srv.Handler == nil {
		t.Error("Handler not set")
	}
}

func TestNewServer_NoCredentialsServesSelfMetricsOnly(t *testing.T) {
	cfg := &config.Config{
		ListenAddress: ":9555",
		NodeName:      "manager",
		ScrapeTimeout: time.Second,
		APIPassword:   config.NewSecureString(""), // no credentials → domain collectors disabled
	}
	ts := httptest.NewServer(newServer(cfg, logger.New("error")).Handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)

	// No collectors → wazuh_up=0 and no domain series.
	if !strings.Contains(s, `wazuh_up{node="manager"} 0`) {
		t.Errorf("expected wazuh_up=0 with no credentials; body:\n%s", s)
	}
	if strings.Contains(s, "wazuh_cluster_enabled") || strings.Contains(s, "wazuh_agents{") {
		t.Error("no domain metrics should be emitted without credentials")
	}
}

func TestNewAPIChain_BadTLSReturnsNil(t *testing.T) {
	dir := t.TempDir()
	badCA := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(badCA, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		APIURL:        "https://wazuh:55000",
		APIUsername:   "u",
		APIPassword:   config.NewSecureString("p"),
		APICAFile:     badCA, // unparseable → api.NewClient fails
		ScrapeTimeout: time.Second,
		NodeName:      "manager",
	}
	if cs := newAPIChain(cfg, monitoring.New("test", time.Now()), logger.New("error")); cs != nil {
		t.Errorf("newAPIChain with bad TLS material must return nil (graceful degradation), got %d collectors", len(cs))
	}
}

// serve blocks until the context is cancelled (signal) or the server fails, so
// it is tested directly rather than through run() (which would block on a real
// signal). A cancelled context must trigger a clean shutdown returning 0.
func TestServe_GracefulShutdownOnContextCancel(t *testing.T) {
	cfg := &config.Config{
		ListenAddress:         "127.0.0.1:0",
		ServerShutdownTimeout: 2 * time.Second,
	}
	srv := &http.Server{Handler: testMux()}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond) // let the server come up first
		cancel()
	}()

	done := make(chan int, 1)
	go func() { done <- serve(ctx, srv, cfg, logger.New("error")) }()

	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve = %d, want 0 on graceful shutdown", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not shut down within the timeout")
	}
}
