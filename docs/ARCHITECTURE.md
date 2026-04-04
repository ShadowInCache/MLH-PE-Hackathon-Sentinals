# GhostLink Architecture Notes

## Purpose

The infrastructure layer provides resilient ingress, observability, and alerting around the GhostLink API contracts:

- `GET /health`
- `GET /metrics`
- `POST /shorten`
- `GET /{short_code}`

## Components

- Nginx:
  - Round-robin load balancing to `app1:5000` and `app2:5000`
  - Global rate limiting at 10 requests/second per IP with burst 20
  - Structured JSON access logs
  - Automatic quarantine mode for short codes listed in `blocked_codes.conf`
  - Canary short-code endpoints (`health-demo`, `promo-demo`, `checkout-demo`, `dashboard-demo`, `support-demo`)
  - Pass-through for `/health` and `/metrics`
- app1/app2:
  - Identical container image
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
- Alertmanager:
  - Alert grouping and Discord notification delivery
- Grafana:
  - Pre-provisioned Prometheus datasource and GhostLink dashboard
- k6:
  - Load profile matching observed event distribution

## Data Flow

1. Client traffic enters Nginx on port 80.
2. Nginx forwards to app1/app2 using round-robin scheduling.
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
- Alert rules include both platform health and GhostLink-specific abuse signals.
- Synthetic canaries provide early warning for user-facing route failures.
- Persistent volumes protect Postgres and Grafana state across restarts.

## Security and Abuse Controls

- Nginx per-IP rate limiting protects backend services from floods.
- `blocked_codes.conf` allows rapid quarantine of abusive short codes.
- Threat timeline, suspicious-client fingerprinting, and risk-score metrics provide triage context.
