# GhostLink Infrastructure Guide

Production Engineering Hackathon deliverable for Team Sentinals (Amogh + Akshay).
This document covers the production stack that turns GhostLink into a cyber-defense style platform: ingress controls, quarantine automation, canary monitoring, threat scoring, and executive observability.

## One-Command Setup

```bash
git clone https://github.com/stealthwhizz/MLH-PE-Hackathon-Sentinals.git && cd MLH-PE-Hackathon-Sentinals && DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/your/webhook" docker compose up --build
```

## Service Endpoints

- App (Nginx entrypoint): http://localhost
- Grafana: http://localhost:3000
- Prometheus: http://localhost:9090
- Alertmanager: http://localhost:9093
- Security exporter metrics: http://localhost:9101/metrics

## Canonical File Paths

- docker-compose.yml
- nginx/nginx.conf
- nginx/blocked_codes.conf
- prometheus/prometheus.yml
- prometheus/alert_rules.yml
- alertmanager/alertmanager.yml
- grafana/provisioning/datasources/prometheus.yml
- grafana/provisioning/dashboards/dashboard.yml
- grafana/dashboards/ghostlink.json
- k6/load_test.js
- scripts/quarantine_code.sh
- scripts/unquarantine_code.sh
- scripts/canary_check.sh
- scripts/security_metrics_exporter.py
- Makefile
- docs/README.md
- docs/RUNBOOK.md
- docs/CAPACITY.md

## Service and Container Names

| Docker Compose service | Container name |
|---|---|
| nginx | ghostlink-nginx |
| app1 | ghostlink-app1 |
| app2 | ghostlink-app2 |
| redis | ghostlink-redis |
| postgres | ghostlink-postgres |
| alertmanager | ghostlink-alertmanager |
| canary-runner | ghostlink-canary-runner |
| security-exporter | ghostlink-security-exporter |
| prometheus | ghostlink-prometheus |
| grafana | ghostlink-grafana |

## Automatic Quarantine Mode

Blocked short codes are managed through `nginx/blocked_codes.conf` and served as HTTP 410 with JSON:

```json
{
  "error": "This short code has been quarantined due to suspicious activity"
}
```

### Helper Commands

```bash
./scripts/quarantine_code.sh abc123
./scripts/unquarantine_code.sh abc123
```

Both scripts:

- update `nginx/blocked_codes.conf`
- reload the running Nginx container automatically
- write audit records to `security/quarantine_actions.log`

## Synthetic Canary URLs

The stack exposes five canary short codes that proxy to backend health checks:

- health-demo
- promo-demo
- checkout-demo
- dashboard-demo
- support-demo

`scripts/canary_check.sh` runs inside `canary-runner` and executes checks every minute through Nginx. It writes state consumed by `security-exporter`, which exposes:

- ghostlink_canary_success_total
- ghostlink_canary_failures_total
- ghostlink_canary_latency_seconds

If failures increase, `CanaryFailureDetected` alert fires.

## Threat Timeline and Security Metrics

Threat timeline metrics exposed by `security-exporter`:

- ghostlink_quarantined_urls_total
- ghostlink_risk_score
- ghostlink_suspicious_clients_total
- ghostlink_blocked_requests_total
- ghostlink_invalid_short_code_hits_total
- ghostlink_repeated_user_agent_hits_total
- ghostlink_safe_links_total
- ghostlink_watchlist_links_total
- ghostlink_threat_links_total
- ghostlink_affected_redirects_total

Grafana includes:

- Executive Summary row (Healthy Links, Threat Links, Dead Links, Active Alerts, Estimated User Impact)
- Threat Timeline panel
- Risk Score Distribution pie chart (SAFE/WATCHLIST/THREAT)
- Suspicious Client Fingerprints table

Estimated User Impact uses:

- `sum(rate(ghostlink_affected_redirects_total[5m])) * 0.35`

## Link Risk Score Model

Risk scoring is implemented in `scripts/security_metrics_exporter.py`.

Weights:

- +30 dead destination signal (inactive or quarantined)
- +20 redirect chain depth heuristic (>3 path segments)
- +15 many ghost probes against the short code
- +20 suspicious TLD
- +15 repeated delete/recreate behavior

Classification:

- 0-30: SAFE
- 31-60: WATCHLIST
- 61-100: THREAT

## Chaos Demo Commands

Use the `Makefile` targets:

```bash
make chaos-kill-app1
make chaos-kill-app2
make chaos-stop-redis
make chaos-stop-postgres
make chaos-spike-errors
make chaos-reset
make quarantine-demo
```

## Environment Variables

Set before startup:

- DISCORD_WEBHOOK_URL: Discord incoming webhook for alert delivery

Compose-managed env highlights:

- app1/app2:
  - DATABASE_URL=postgresql://ghostlink:ghostlink@postgres:5432/ghostlink
  - REDIS_URL=redis://redis:6379/0
  - DISCORD_WEBHOOK_URL=${DISCORD_WEBHOOK_URL}
- postgres:
  - POSTGRES_DB=ghostlink
  - POSTGRES_USER=ghostlink
  - POSTGRES_PASSWORD=ghostlink
- grafana:
  - GF_SECURITY_ADMIN_PASSWORD=ghostlink
  - GF_USERS_ALLOW_SIGN_UP=false
- security-exporter:
  - SECURITY_LOG_TAIL_BYTES=4000000
  - MAX_RISK_SCORE_SERIES=250

## Quick Validation Commands

```bash
docker compose config
docker compose exec -T nginx nginx -t
docker compose exec -T prometheus promtool check config /etc/prometheus/prometheus.yml
docker compose exec -T prometheus promtool check rules /etc/prometheus/alert_rules.yml
```

## Run the k6 Load Test

```bash
k6 run k6/load_test.js
```
