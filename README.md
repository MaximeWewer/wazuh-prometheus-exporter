# wazuh-prometheus-exporter

A **Prometheus exporter for [Wazuh](https://wazuh.com/)**.

## Features

- **Per-node manager health** via the API — `analysisd` (events, dropped, decode breakdown by module, queue saturation), `remoted` (sessions, bytes, messages), `wazuh-db` query throughput, daemon up/down, config validity, log-level rates, daily totals and hourly/weekly alert-volume profiles. Collected from `/manager/*` on a standalone manager, or from `/cluster/<node>/*` for **every** node (master included) in a cluster — so everything is reported **per cluster node**.
- **API-based fleet visibility**: agent connection summary + group/version/OS/outdated/last-registered, multi-node cluster discovery, per-node ruleset sync, and cluster-wide config validation.
- **Hardened API client**: JWT auth with token caching + proactive refresh, validated TLS (custom CA / mTLS / opt-in skip-verify), a short-TTL response cache, and a circuit breaker — so frequent scrapes never overload the Wazuh API.
- **Self-observability**: `wazuh_up`, scrape duration, per-collector success/error counters, cache hit/miss, circuit-breaker state, plus Go runtime + process metrics on a separate endpoint.
- Operationally tidy: env-based config with `_FILE` secrets, structured logging, distroless static non-root image, graceful shutdown, optional TLS/basic-auth on the metrics server.

## Quick start

### Docker

```sh
docker run --rm -p 9555:9555 \
  -e WAZUH_API_URL=https://your-wazuh-manager:55000 \
  -e WAZUH_API_USERNAME=wazuh-wui \
  -e WAZUH_API_PASSWORD=... \
  -e WAZUH_API_TLS_SKIP_VERIFY=true \
  ghcr.io/maximewewer/wazuh-prometheus-exporter:latest
```

### Docker compose

```yaml
services:
  wazuh-exporter:
    image: ghcr.io/maximewewer/wazuh-prometheus-exporter:latest
    restart: unless-stopped
    environment:
      WAZUH_LISTEN_ADDRESS: "0.0.0.0:9555"
      WAZUH_NODE_NAME: "wazuh-manager" # `node` label for wazuh_up/cluster_enabled + the standalone node
      WAZUH_API_URL: "https://your-wazuh-manager:55000"
      WAZUH_API_USERNAME: "wazuh-wui"
      WAZUH_API_PASSWORD: ""
      WAZUH_API_TLS_SKIP_VERIFY: "true"
    ports:
      - "9555:9555"
```

### From source

```sh
make build           # → dist/wazuh-exporter (static binary)
./dist/wazuh-exporter --version
```

## Endpoints

| Path                | Purpose                                                         |
|---------------------|-----------------------------------------------------------------|
| `/`                 | HTML info page                                                  |
| `/health`           | JSON health/uptime                                              |
| `/metrics`          | Wazuh domain metrics (`wazuh_*`)                                |
| `/internal/metrics` | Exporter self-metrics (`wazuh_exporter_*`, `go_*`, `process_*`) |

Default listen address: `:9555`.

## Documentation

- **[Configuration](docs/configuration.md)** — every environment variable, defaults, and the Wazuh API RBAC read permissions required.
- **[Metrics](docs/metrics.md)** — every exported metric, its type and labels.
- **[Dashboards](#dashboards)** — three ready-to-import Grafana dashboards in [`grafana/dashboards/`](grafana/dashboards/) (previewed below).

## Dashboards

Three Grafana dashboards ship in [`grafana/dashboards/`](grafana/dashboards/) — import them or provision the folder (they use a `DS_PROMETHEUS` datasource variable).

### Wazuh — Fleet
All nodes at a glance: health overview, cluster topology, per-node throughput comparison, manager activity, and cluster-wide agents. Per-node panels use tables / bar charts that stay readable as the cluster grows.

![Wazuh — Fleet dashboard](assets/wazuh-fleet.png)

### Wazuh — Node
Single-node deep dive (pick a node from the dropdown): daemon run-state, the analysisd / remoted / wazuh-db internals, logs, and the hourly/weekly alert-volume profiles.

![Wazuh — Node dashboard](assets/wazuh-node.png)

### Wazuh Exporter — Internal
The exporter's own health: scrape latency, per-collector errors/success, circuit-breaker state, cache hit ratio, and Go runtime / process resources.

![Wazuh Exporter — Internal dashboard](assets/wazuh-exporter-internal.png)

## License

Apache 2.0 — see [LICENSE](LICENSE).
