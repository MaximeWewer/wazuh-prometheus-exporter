# wazuh-prometheus-exporter (Helm chart)

Deploys the [Wazuh Prometheus exporter](https://github.com/MaximeWewer/wazuh-prometheus-exporter)
as a Deployment + Service. API-only: it just needs network access to the Wazuh
manager API (`:55000`).

## Install (OCI / GHCR)

```bash
helm install wazuh-prometheus-exporter \
  oci://ghcr.io/maximewewer/charts/wazuh-prometheus-exporter \
  --version <chart-version> \
  --namespace monitoring --create-namespace \
  --set wazuh.apiUrl=https://wazuh-manager.wazuh.svc:55000 \
  --set wazuh.existingSecret=wazuh-api   # Secret with key "password"
```

Inline password (dev only — chart creates the Secret):
```bash
--set wazuh.password='MyS3cr37P450r.*-'
```

## TLS

Prefer verifying a self-signed API cert over skipping verification:
```bash
--set wazuh.caSecret=wazuh-api-ca         # Secret holding the CA bundle (key ca.crt)
```
Last resort: `--set wazuh.tlsSkipVerify=true`.

## Key values

| Key | Default | Description |
|-----|---------|-------------|
| `image.repository` / `image.tag` | `ghcr.io/maximewewer/wazuh-prometheus-exporter` / chart appVersion | Exporter image |
| `wazuh.apiUrl` | `https://wazuh-manager.wazuh.svc:55000` | Wazuh API base URL |
| `wazuh.apiUsername` | `wazuh-wui` | API user |
| `wazuh.existingSecret` / `wazuh.password` | `""` | API password (existing Secret key `password`, or inline) |
| `wazuh.tlsSkipVerify` | `false` | Disable TLS verification (insecure) |
| `wazuh.caSecret` / `wazuh.caSecretKey` | `""` / `ca.crt` | CA bundle Secret to verify the API cert (sets `WAZUH_API_CA_FILE`) |
| `wazuh.cacheTtl` / `wazuh.scrapeTimeout` | `30s` / `10s` | Cache TTL (≥ scrape interval) / per-scrape timeout |
| `wazuh.startupGrace` | `60s` | Quiet logs while a slow Wazuh API boots |
| `wazuh.logLevel` | `info` | Log level |
| `service.type` / `service.port` | `ClusterIP` / `9555` | Service |
| `serviceMonitor.enabled` | `false` | Prometheus Operator ServiceMonitor |
| `prometheusScrapeAnnotations` | `false` | `prometheus.io/scrape` annotations on the Service |
| `startupProbe` / `livenessProbe` / `readinessProbe` | enabled | `/ready` (startup+readiness), `/health` (liveness) |
| `resources` | 25m/32Mi → 200m/128Mi | Requests/limits |

The pod runs hardened by default: non-root (UID 65532), read-only rootfs, all
caps dropped, `RuntimeDefault` seccomp.

## Endpoints

`/metrics` (Wazuh metrics), `/internal/metrics` (exporter self-metrics),
`/health` (liveness), `/ready` (readiness), `/` (info page).
