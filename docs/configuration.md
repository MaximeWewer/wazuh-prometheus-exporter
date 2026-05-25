# Configuration

The exporter is configured entirely through environment variables. Invalid or
out-of-range values fall back to the default (and durations are clamped to the
documented range) — the exporter never fails to start on a bad value, it logs a
warning and continues.

## Server & logging

| Variable | Default | Range / notes | Description |
|----------|---------|---------------|-------------|
| `WAZUH_LISTEN_ADDRESS` | `:9555` | host:port | Address the HTTP server binds to. |
| `WAZUH_LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error` | Log level (empty/invalid → `info`). |
| `WAZUH_WEB_CONFIG_FILE` | _(unset)_ | path | exporter-toolkit web config (TLS / basic-auth) for the metrics server. |
| `WAZUH_SERVER_READ_TIMEOUT` | `10s` | `1s`–`5m` | HTTP read timeout. |
| `WAZUH_SERVER_WRITE_TIMEOUT` | `30s` | `1s`–`5m` | HTTP write timeout. |
| `WAZUH_SERVER_IDLE_TIMEOUT` | `60s` | `1s`–`10m` | HTTP idle timeout. |
| `WAZUH_SERVER_SHUTDOWN_TIMEOUT` | `10s` | `1s`–`2m` | Graceful-shutdown deadline. |

## Collection

| Variable | Default | Range / notes | Description |
|----------|---------|---------------|-------------|
| `WAZUH_SCRAPE_TIMEOUT` | `10s` | `1s`–`5m` | Per-scrape timeout (also the API HTTP client timeout). |
| `WAZUH_STARTUP_GRACE` | `0` (off) | `0`–`10m` | Quiet-startup window for a slow-to-boot Wazuh: until the first successful collection (or this window elapses), collection failures log at `warn` ("waiting for Wazuh API") instead of `error`. Metrics (`wazuh_up=0`, `collector_errors_total`) and readiness are unaffected. |
| `WAZUH_CACHE_TTL` | `30s` | `5s`–`5m` | TTL of the API response cache between scrapes. The exporter makes several API calls per scrape (a few cluster-level calls plus ~7 per node), so keep this **≥ your Prometheus scrape interval** to serve repeat scrapes from cache and avoid hammering the Wazuh API. |

## Wazuh API

| Variable | Default | Notes | Description |
|----------|---------|-------|-------------|
| `WAZUH_API_URL` | `https://localhost:55000` | URL | Wazuh API base URL (the master). |
| `WAZUH_API_USERNAME` | _(unset)_ | string | API user. API collectors are disabled if username or password is unset. |
| `WAZUH_API_PASSWORD` | _(unset)_ | secret | API password. Prefer the `_FILE` form below. |
| `WAZUH_API_PASSWORD_FILE` | _(unset)_ | path | Path to a file containing the password (takes precedence; the `_FILE` secret convention). |
| `WAZUH_API_TLS_SKIP_VERIFY` | `false` | bool | Disable TLS certificate verification (insecure; logged as a risk). |
| `WAZUH_API_CA_FILE` | _(unset)_ | path | CA bundle to verify the API certificate. |
| `WAZUH_API_CERT_FILE` | _(unset)_ | path | Client certificate (mTLS); used with `WAZUH_API_KEY_FILE`. |
| `WAZUH_API_KEY_FILE` | _(unset)_ | path | Client private key (mTLS). |

### Secret-file (`_FILE`) convention

Any password may be supplied via a `*_FILE` variable pointing at a file (e.g. a
mounted Docker/Kubernetes secret). The file content is read at startup and the
in-memory value is zeroed on shutdown. Prefer `WAZUH_API_PASSWORD_FILE` over an
inline `WAZUH_API_PASSWORD`.

## Wazuh API RBAC — read permissions required

When the API collectors are enabled, the API user must be able to read the
endpoints the exporter calls:

| Endpoint | Used by | Required read access (Wazuh RBAC) |
|----------|---------|-----------------------------------|
| `GET /security/user/authenticate` | auth | any valid API user |
| `GET /agents/summary/status`, `GET /overview/agents`, `GET /agents/outdated` | agent fleet (status, group/version/OS, last registered, outdated) | `agent:read` |
| `GET /manager/{daemons/stats,info,configuration/validation,stats,stats/hourly,stats/weekly,status,logs/summary}` | standalone node: analysisd/remoted/wazuh-db stats, manager info, config validity, daily totals + hourly/weekly alert profiles, daemon status, log levels | `manager:read` |
| `GET /cluster/local/info`, `GET /cluster/status`, `GET /cluster/healthcheck`, `GET /cluster/ruleset/synchronization`, `GET /cluster/configuration/validation` | local node name (the `node` label), cluster detection/health, ruleset sync, per-node config validity (one call validates the whole cluster) | `cluster:read` |
| `GET /cluster/<node>/{daemons/stats,status,logs/summary,info,stats,stats/hourly,stats/weekly}` | per-node daemon stats, daemon health, log levels, info, daily totals + hourly/weekly profiles — every cluster node (master included) | `cluster:read` |

> The RBAC action names above are a best-effort mapping — verify them against
> your Wazuh version's RBAC policy. A read-only role scoped to these resources is
> sufficient; the exporter never writes. The exporter is **API-only**: if no API
> credentials are configured, no domain metrics are collected (only self-metrics).
