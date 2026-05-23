# Local integration + observability stack (local-only)

A self-contained **Wazuh cluster** to exercise the exporter end-to-end and browse
the Grafana dashboards. Deliberately minimal — **no TLS certificate tree** (a
single indexer with the OpenSearch security plugin disabled, managers without
filebeat TLS, the manager API on its own self-signed cert). **Local-only**, never
run in CI (a real Wazuh cluster is far too heavy on runner time and disk).

## Layout

```
tests/
  docker-compose.yml          # the whole stack (run from the repo root)
  integration_test.go         # build-tagged (`integration`) Go assertions
  config/
    indexer.yml               # single indexer, security disabled (HTTP, no certs)
    prometheus.yml            # scrapes /metrics + /internal/metrics
    cluster/
      master.conf             # master ossec.conf (cluster enabled, shared key)
      worker.conf             # worker ossec.conf (same key)
    grafana/provisioning/     # Prometheus datasource + dashboard provider
```

The Grafana dashboards themselves live in the repo at [`../grafana/dashboards`](../grafana/dashboards).

## Services

| Service        | Image                           | Role / URL                                           |
|----------------|---------------------------------|------------------------------------------------------|
| wazuh.indexer  | `wazuh/wazuh-indexer:4.14.5`    | single indexer, security disabled (`:9200`)          |
| wazuh.master   | `wazuh/wazuh-manager:4.14.5`    | cluster master + API `https://localhost:55000`       |
| wazuh.worker   | `wazuh/wazuh-manager:4.14.5`    | cluster worker (joins via the shared key)            |
| wazuh.agent    | `wazuh/wazuh-agent:4.14.5`      | a real agent, to populate agent metrics              |
| exporter       | built from this repo            | `http://localhost:9555/metrics`, `/internal/metrics` |
| prometheus     | `prom/prometheus:latest`        | `http://localhost:9090`                              |
| grafana        | `grafana/grafana:latest`        | `http://localhost:3000` (admin/admin)                |

## Run

```sh
# from the repo root
docker compose -f tests/docker-compose.yml up -d --build
# → Grafana http://localhost:3000 (admin/admin): "Wazuh — Fleet", "Wazuh — Node" + "… Internal" dashboards
go test -tags=integration -count=1 ./tests/...   # optional assertions
docker compose -f tests/docker-compose.yml down -v
```

No certificate prerequisite — everything boots from this directory.

### Note: master daemons on first boot

The Wazuh manager image sometimes leaves only filebeat running on the very first
boot (the core starts before the indexer is reachable). If the API on `:55000`
does not answer after a couple of minutes, nudge it once:

```sh
docker exec tests-wazuh.master-1 /var/ossec/bin/wazuh-control start
```

The cluster (master + worker), the agent enrollment, and all exporter metrics
then come up. Default credentials are throwaway placeholders — change them for
anything beyond a local sandbox.
