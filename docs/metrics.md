# Metrics

The exporter serves two endpoints:

- **`/metrics`** — Wazuh domain metrics (`wazuh_*`).
- **`/internal/metrics`** — exporter self-metrics (`wazuh_exporter_*`) plus Go runtime (`go_*`) and process (`process_*`) metrics.

Almost every domain metric carries a `node` label (the manager/worker node it describes); the node name is discovered from the Wazuh API (`/cluster/local/info` for the local node, `/cluster/healthcheck` for the others), not configured. The exception is `wazuh_up`, which is exporter-global (no label). Counters end in `_total` and should be queried with `rate()`.

All metrics come from the Wazuh **API** — the exporter no longer reads the deprecated local `.state` files, so it needs no shared volume. Per-node metrics (analysisd, remoted, wazuh-db, daemon status, logs, info, daily totals) come from `/manager/*` on a standalone manager, or from `/cluster/<node>/*` for **every** node (master included) when clustered — so they are reported per cluster node.

## Domain metrics — `/metrics`

### Availability

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `wazuh_up` | gauge | _(none)_ | `1` if at least one collector succeeded this scrape, else `0`. No label: it reports the exporter's own collection health, not a per-node property (and must be emittable when the API — and thus the node name — is unreachable). |

### analysisd (API: `daemons/stats`)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `wazuh_analysisd_events_received_total` | counter | `node` | Events received by analysisd. |
| `wazuh_analysisd_events_processed_total` | counter | `node` | Events processed by analysisd. |
| `wazuh_analysisd_events_dropped_total` | counter | `node` | Events dropped (sum of the dropped breakdown). |
| `wazuh_analysisd_alerts_written_total` | counter | `node` | Alerts written. |
| `wazuh_analysisd_firewall_written_total` | counter | `node` | Firewall logs written. |
| `wazuh_analysisd_fts_written_total` | counter | `node` | FTS entries written. |
| `wazuh_analysisd_queue_size` | gauge | `node`, `queue` | Current depth of an analysisd queue (events queued). |
| `wazuh_analysisd_queue_capacity` | gauge | `node`, `queue` | Capacity of an analysisd queue (maximum events). |
| `wazuh_analysisd_queue_usage_ratio` | gauge | `node`, `queue` | Queue fill ratio in `[0,1]` (depth/capacity). |
| `wazuh_analysisd_events_decoded_total` | counter | `node`, `module` | Events decoded, by module (flattened from the API decode breakdown: `dbsync`, `syscheck`, `syscollector`, `rootcheck`, `sca`, `agent`, `logcollector_*`, …). EDPS via `rate()`. |

### remoted (API: `daemons/stats`)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `wazuh_remoted_tcp_sessions` | gauge | `node` | Active agent TCP sessions. |
| `wazuh_remoted_recv_bytes_total` | counter | `node` | Bytes received from agents. |
| `wazuh_remoted_evt_count_total` | counter | `node` | Events forwarded to analysisd. |
| `wazuh_remoted_discarded_count_total` | counter | `node` | Messages discarded. |
| `wazuh_remoted_ctrl_msg_count_total` | counter | `node` | Control messages received. |
| `wazuh_remoted_msg_sent_total` | counter | `node` | Messages sent. |
| `wazuh_remoted_queue_size` | gauge | `node` | Current depth of the remoted receive queue. |
| `wazuh_remoted_queue_capacity` | gauge | `node` | Capacity of the remoted receive queue. |
| `wazuh_remoted_sent_bytes_total` | counter | `node` | Bytes sent by remoted. |
| `wazuh_remoted_dequeued_after_close_total` | counter | `node` | Messages dequeued after the agent closed the connection. |

> **Note:** `logcollector` per-source metrics are not exported. The Wazuh API does not expose logcollector statistics (only the deprecated local `.state` file did), so the API-only exporter cannot collect them.

### agents (API: `/agents/summary/status`, `/overview/agents`)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `wazuh_agents` | gauge | `node`, `status` | Agents by connection status (`active`, `disconnected`, `never_connected`, `pending`). |
| `wazuh_agents_count` | gauge | `node` | Total number of agents. |
| `wazuh_agents_config` | gauge | `node`, `state` | Agents by configuration sync state (`synced`, `not_synced`). |
| `wazuh_agents_group` | gauge | `node`, `group` | Agents by group. |
| `wazuh_agents_version` | gauge | `node`, `version` | Agents by reported version. |
| `wazuh_agents_os` | gauge | `node`, `os` | Agents by operating system. |
| `wazuh_agents_outdated` | gauge | `node` | Agents running an outdated version (`/agents/outdated`). |
| `wazuh_last_registered_agent_info` | gauge | `node`, `agent_id`, `agent_name`, `agent_version`, `status` | Metadata of the most recently registered agent (constant `1`). |

### manager (API: `/manager/*` standalone, `/cluster/<node>/*` per node when clustered; config validity from `/cluster/configuration/validation` in a cluster)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `wazuh_manager_info` | gauge | `node`, `type`, `version` | Manager metadata (constant `1`). |
| `wazuh_manager_max_agents` | gauge | `node` | Maximum agents the manager accepts (omitted when non-numeric, e.g. `unlimited`). |
| `wazuh_manager_config_valid` | gauge | `node` | `1` if the configuration validates, `0` on errors. Per node in a cluster (one `/cluster/configuration/validation` call validates every node). |
| `wazuh_manager_alerts_total` | counter | `node` | Alerts logged today (sum of hourly totals from `/manager/stats`). |
| `wazuh_manager_events_total` | counter | `node` | Events processed today (sum of hourly totals). |
| `wazuh_manager_syscheck_total` | counter | `node` | Syscheck events logged today (sum of hourly totals). |
| `wazuh_manager_firewall_total` | counter | `node` | Firewall events logged today (sum of hourly totals). |
| `wazuh_manager_daemon_up` | gauge | `node`, `daemon` | `1` if a manager daemon is running, else `0` (from `…/status`). |
| `wazuh_manager_logs_total` | counter | `node`, `tag`, `level` | Log entries by component and level (`/manager/logs/summary`); `rate()` to spot error spikes. |
| `wazuh_manager_hourly_alerts_average` | gauge | `node`, `hour` | Average alerts per hour of the day (`hour` = `00`…`23`), from Wazuh's hourly stats profile (`…/stats/hourly`). 24 series per node. |
| `wazuh_manager_weekly_alerts_average` | gauge | `node`, `day`, `hour` | Average alerts per weekday (`Sun`…`Sat`) and hour (`00`…`23`), from Wazuh's weekly stats profile (`…/stats/weekly`). 168 series per node. |

> The `wazuh_manager_*_total` daily aggregates come from `/manager/stats`, which returns no data (Wazuh error 1308) until the daily totals file is generated (around noon), so they may be absent early in the day.
>
> The `wazuh_manager_*_average` profiles are historical averages Wazuh maintains (alerts by hour-of-day and by weekday-hour); they are gauges (not counters) and stay near `0` on a fresh manager until enough history accumulates.

### wazuh-db (API: `daemons/stats`)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `wazuh_db_queries_received_total` | counter | `node` | Queries received by wazuh-db. |
| `wazuh_db_queries_breakdown_total` | counter | `node`, `category` | Queries received by wazuh-db, by category. |

### cluster (API: `/cluster/status`, `/cluster/healthcheck`)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `wazuh_cluster_enabled` | gauge | `node` | `1` if cluster mode is enabled, `0` if standalone. |
| `wazuh_cluster_node_info` | gauge | `node`, `type`, `version` | Cluster node metadata (constant `1`). |
| `wazuh_cluster_node_active_agents` | gauge | `node` | Active agents reported for a cluster node. |
| `wazuh_cluster_ruleset_synced` | gauge | `node` | `1` if a node's ruleset (rules + decoders + CDB lists) is synchronized, else `0` (clustered only). |

## Self-metrics — `/internal/metrics`

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `wazuh_exporter_build_info` | gauge | `version` | Build info (constant `1`). |
| `wazuh_exporter_uptime_seconds` | gauge | — | Seconds since the exporter started. |
| `wazuh_exporter_scrape_duration_seconds` | histogram | — | Duration of a collector scrape (`_bucket`/`_sum`/`_count`). |
| `wazuh_exporter_collector_success_total` | counter | `collector` | Successful collections per collector. |
| `wazuh_exporter_collector_errors_total` | counter | `collector`, `error_type` | Collection errors per collector and type. |
| `wazuh_exporter_cache_hits_total` | counter | — | Wazuh API response cache hits. |
| `wazuh_exporter_cache_misses_total` | counter | — | Wazuh API response cache misses. |
| `wazuh_exporter_circuit_breaker_state` | gauge | — | API circuit-breaker state: `0` closed, `1` half-open, `2` open. |

Plus the standard `go_*` (Go runtime) and `process_*` (process) collector metrics.
