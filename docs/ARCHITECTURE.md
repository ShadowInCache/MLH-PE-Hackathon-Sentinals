# GhostLink Architecture Notes

## Purpose

The infrastructure layer provides resilient ingress, observability, and alerting around the GhostLink API contracts:

- `GET /health`
- `GET /metrics`
- `POST /shorten`
- `GET /{short_code}`

## Components

- Nginx:
  - Weighted canary routing to `app1:5000` and `app2:5000` (90/10 split)
  - Global rate limiting at 10 requests/second per IP with burst 20
  - Structured JSON access logs
  - Automatic quarantine mode for short codes listed in `blocked_codes.conf`
  - Canary short-code endpoints (`health-demo`, `promo-demo`, `checkout-demo`, `dashboard-demo`, `support-demo`)
  - Pass-through for `/health` and `/metrics`
- app1/app2:
  - Identical container image
  - Per-instance release metadata surfaced via `X-GhostLink-Version` and `/health`
  - Feature flags govern quarantine, risk scoring, canary ingestion, and probe telemetry
  - Horizontal redundancy for failure tolerance and throughput
- PostgreSQL:
  - Primary data store for URLs, events, and user metadata
- Redis:
  - Fast-path cache and transient state backend
- Prometheus:
  - 15-second scrape cadence
  - Rule-based alerting for availability and abuse patterns
- Canary Runner:
  - Executes synthetic canary checks every minute through Nginx
  - Persists canary state for the security exporter
- Security Exporter:
  - Parses Nginx access logs and quarantine state
  - Exposes cyber-defense metrics (risk score, suspicious clients, blocked requests)
- Rollback Automation:
  - `scripts/rollback.sh` updates compose release vars and restarts selected services
  - `--dry-run` mode previews compose and recovery-state changes before execution
  - Recovery state persists in `security/rollback_state.env` and is exported via `/metrics`
- Alertmanager:
  - Alert grouping and Discord notification delivery
- Grafana:
  - Pre-provisioned Prometheus datasource and GhostLink dashboard
- k6:
  - Load profile matching observed event distribution

## Data Flow

1. Client traffic enters Nginx on port 80.
2. Nginx forwards to app1/app2 using weighted canary scheduling.
3. App services read/write PostgreSQL and Redis.
4. Canary Runner checks canary short-code URLs every minute and writes canary state.
5. Security Exporter reads canary state, quarantine list, and Nginx logs to expose security metrics.
6. Prometheus scrapes `/metrics` from app replicas, security-exporter, and itself every 15 seconds.
7. Prometheus evaluates alert and recording rules and sends firing alerts to Alertmanager.
8. Alertmanager groups and dispatches alert payloads to Discord.
9. Grafana visualizes live Prometheus data through the provisioned dashboard.

## Reliability Design

- Two app replicas reduce single-instance outage impact.
- Healthchecks gate startup dependencies and improve compose startup order.
- Release metadata and feature-flag state are exposed in health and metrics for rollout traceability.
- Rollback dry-run preview reduces operator error before restart actions.
- Alert rules include both platform health and GhostLink-specific abuse signals.
- Synthetic canaries provide early warning for user-facing route failures.
- Persistent volumes protect Postgres and Grafana state across restarts.

## Security and Abuse Controls

- Nginx per-IP rate limiting protects backend services from floods.
- `blocked_codes.conf` allows rapid quarantine of abusive short codes.
- Quarantine enforcement can be controlled by feature flags for controlled rollout/diagnostics.
- Threat timeline, suspicious-client fingerprinting, and risk-score metrics provide triage context.

## Release and Recovery Observability

- Traffic split by release: `sum by (app_version) (rate(url_redirects_total[5m]))`
- Release metadata gauge: `ghostlink_release_info{version,git_sha,deployed_at,release_owner,release_notes_url}`
- Recovery scorecard metrics:
  - `ghostlink_rollbacks_total`
  - `ghostlink_mean_time_to_detect_minutes`
  - `ghostlink_mean_time_to_recover_minutes`
  - `ghostlink_recovery_attempts_total`
  - `ghostlink_recovery_success_total`
