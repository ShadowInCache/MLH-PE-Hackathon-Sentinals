# GhostLink Incident Runbook

This runbook covers first-response workflows for GhostLink operational and cyber-defense alerts.

## Failure Modes

## 1) ServiceDown Alert Fires

### Symptoms
- `ServiceDown` alert firing.
- Missing backend time series in Grafana.
- `/health` intermittently fails through Nginx.

### Metrics to Check
- `up{job="ghostlink-backends"}`
- `rate(url_redirects_total[1m])`
- `sum(rate(destination_dead_total[5m])) / clamp_min(sum(rate(url_redirects_total[5m])), 0.001)`

### Logs to Inspect
- `docker compose logs app1 --tail 200`
- `docker compose logs app2 --tail 200`
- `docker compose logs nginx --tail 200`

### Recovery Steps
1. Identify unhealthy backend with `docker ps`.
2. Restart affected app replica (`docker compose restart app1` or `app2`).
3. Validate `curl -i http://localhost/health`.
4. Verify alert auto-resolves.

## 2) CanaryFailureDetected Alert Fires

### Symptoms
- `CanaryFailureDetected` alert firing.
- One or more canary short codes return non-200/non-302.

### Metrics to Check
- `increase(ghostlink_canary_failures_total[5m])`
- `ghostlink_canary_status{short_code=...}`
- `ghostlink_canary_latency_seconds{short_code=...}`

### Logs to Inspect
- `docker compose logs canary-runner --tail 200`
- `docker compose logs nginx --tail 200`
- `docker compose logs app1 --tail 200`
- `docker compose logs app2 --tail 200`

### Recovery Steps
1. Probe all canaries manually:
   ```bash
   for c in health-demo promo-demo checkout-demo dashboard-demo support-demo; do curl -i "http://localhost/$c"; done
   ```
2. Validate Nginx config and reload if needed:
   ```bash
   docker compose exec -T nginx nginx -t
   docker compose exec -T nginx nginx -s reload
   ```
3. Restart canary pipeline:
   ```bash
   docker compose restart canary-runner security-exporter
   ```

## 3) SuspiciousClientSpike Alert Fires

### Symptoms
- `SuspiciousClientSpike` alert firing.
- Threat Timeline shows sharp suspicious-client increase.

### Metrics to Check
- `ghostlink_suspicious_clients_total`
- `ghostlink_invalid_short_code_hits_total`
- `ghostlink_repeated_user_agent_hits_total`
- `topk(10, ghostlink_suspicious_ip_score)`

### Logs to Inspect
- `docker compose logs nginx --tail 500`

### Recovery Steps
1. Review top abusive clients in Grafana table panel.
2. Quarantine top probed codes:
   ```bash
   ./scripts/quarantine_code.sh <short_code>
   ```
3. Confirm blocked responses return JSON 410 payload.
4. Continue monitoring `ghostlink_blocked_requests_total` and suspicious-client trend.

## 4) BlockedRequestSpike Alert Fires

### Symptoms
- `BlockedRequestSpike` alert firing.
- Rapid increase in blocked 410 responses.

### Metrics to Check
- `increase(ghostlink_blocked_requests_total[5m])`
- `ghostlink_quarantined_urls_total`
- `rate(ghost_probes_total[1m])`

### Recovery Steps
1. Validate quarantine list:
   ```bash
   cat nginx/blocked_codes.conf
   ```
2. Remove accidental quarantines if needed:
   ```bash
   ./scripts/unquarantine_code.sh <short_code>
   ```
3. Keep known malicious short codes quarantined and monitor stabilization.

## 5) ThreatLinkSurge Alert Fires

### Symptoms
- `ThreatLinkSurge` alert firing.
- Executive Summary "Threat Links" panel elevated.

### Metrics to Check
- `ghostlink_threat_links_total`
- `ghostlink_watchlist_links_total`
- `ghostlink_risk_score{risk_level="THREAT"}`
- `ghostlink_estimated_user_impact`

### Recovery Steps
1. Review highest `ghostlink_risk_score` series in Prometheus or Grafana Explore.
2. Quarantine high-risk short codes involved in probe spikes.
3. Trigger cleanup and re-check risk totals after 10 minutes.

## Multi-instance Compose Evidence (2026-04-05)

This section captures verification for the hackathon evidence item "Multi-instance compose setup".

### Compose Configuration Proof

- `docker-compose.yml` defines two app replicas: `app1` and `app2`
- `nginx/nginx.conf` load-balances both replicas via `upstream ghostlink_backend`

### Runtime Verification Commands

```bash
docker compose config --services
docker compose ps --format "table {{.Service}}\t{{.Name}}\t{{.State}}\t{{.Status}}"
```

### Verified Runtime State

| Service | Container | State | Status |
|---|---|---|---|
| app1 | ghostlink-app1 | running | Up 34 minutes (healthy) |
| app2 | ghostlink-app2 | running | Up 34 minutes (healthy) |
| nginx | ghostlink-nginx | running | Up 34 minutes (healthy) |

Result: multi-instance backend (`app1` + `app2`) is active and healthy behind Nginx in Docker Compose.

## Redis Cache Evidence (2026-04-05)

This section captures verification for the hackathon evidence item "Repository/configuration shows Redis caching implementation".

### Repository Implementation Proof

- `app/services/cache.py` implements Redis-backed cache helpers:
   - URL cache with `SHORT_CODE_TTL = 300` (5 minutes)
   - risk-score cache with `RISK_SCORE_TTL = 600` (10 minutes)
   - graceful degradation when Redis is unavailable

### Configuration Proof

- `docker-compose.yml` defines the Redis service (`redis:7-alpine`)
- app services use `REDIS_URL: redis://redis:6379/0`
- apps depend on Redis health (`depends_on -> redis -> condition: service_healthy`)

### Runtime Verification Commands

```bash
docker compose ps redis --format "table {{.Service}}\t{{.Name}}\t{{.State}}\t{{.Status}}"
docker compose exec -T redis redis-cli ping
```

### Verified Runtime Output

- redis service: running (healthy)
- ping response: `PONG`

Result: Redis caching is implemented in application code, wired in compose configuration, and operational at runtime.
