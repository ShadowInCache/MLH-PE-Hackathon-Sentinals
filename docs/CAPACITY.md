# GhostLink Capacity Plan

This document defines practical load envelopes and scaling actions for the hackathon deployment.

## Target Load Tiers

| Tier | k6 Stage | Users | Ramp/Hold | Objective |
|---|---|---:|---|---|
| Bronze | Stage 1 | 50 | 30s / 1m | Verify baseline stability and warm caches |
| Silver | Stage 2 | 200 | 1m / 2m | Validate horizontal scaling and DB behavior |
| Gold | Stage 3 | 500 | 2m / 3m | Stress production path and observe bottlenecks |

## Success Criteria

- p95 request latency < 3000 ms
- failed request rate < 5%
- canary split remains stable (app1 dominant, app2 canary share visible)
- no sustained ServiceDown alerts
- error rate alert remains inactive under nominal behavior
- canary failures remain at 0 for steady-state windows
- suspicious-client and blocked-request spikes are detectable within 2 minutes

## Primary Saturation Signals

- `sum(rate(destination_dead_total[5m])) / clamp_min(sum(rate(url_redirects_total[5m])), 0.001)` climbs
- `sum by (app_version) (rate(url_redirects_total[5m]))` deviates from expected weighted canary distribution
- `histogram_quantile(0.95, sum(rate(redirect_latency_seconds_bucket[5m])) by (le))` rises continuously
- backend `up` flaps between 1 and 0
- DB health check failures or connection errors in app logs
- `increase(ghostlink_canary_failures_total[5m]) > 0`
- `ghostlink_suspicious_clients_total` and `increase(ghostlink_blocked_requests_total[5m])` rise together
- `ghostlink_threat_links_total` sustained growth indicates security saturation
- `ghostlink_rollbacks_total` increases during unstable rollout windows

## Scaling Knobs

1. Increase app workers in Dockerfile gunicorn command.
2. Add more backend replicas and update Nginx upstream weights explicitly.
3. Raise Postgres resource limits and tune connection pooling.
4. Move Redis persistence policy based on durability/performance needs.
5. Increase host CPU/RAM before adjusting rate limits.
6. Increase Nginx worker/process tuning if blocked and invalid traffic dominates.
7. Increase `SECURITY_LOG_TAIL_BYTES` for richer suspicious-client detection on high-volume hosts.
8. Use rollback dry-run (`make rollback-plan-app2`) before rollback execution during canary regression.

## Recommended Test Sequence

1. Run Bronze and capture baseline metrics.
2. Run Silver and compare p95, error rate, and CPU usage.
3. Run Gold and identify first hard limit (CPU, DB, network, or app worker saturation).
4. Validate release split and canary health:
	- `sum by (app_version) (rate(url_redirects_total[5m]))`
	- `increase(ghostlink_canary_failures_total[5m])`
4. Execute chaos scenarios:
	- `make chaos-kill-app1`
	- `make chaos-stop-redis`
	- `make chaos-spike-errors`
5. Validate Executive Summary dashboard row and Threat Timeline behavior during chaos.
6. If canary instability appears, run rollback preview first:
	- `make rollback-plan-app2`
7. Apply one scaling change at a time and re-run from Bronze to Gold with chaos validation.

## Baseline Measurements (2026-04-05)

### Baseline Profile Used for Submission Evidence

- tool: k6 (Docker image `grafana/k6`)
- target: `GET /health`
- load: 50 virtual users for 30 seconds
- command:
	- `docker run --rm -i -v "${PWD}/k6:/scripts" grafana/k6 run -e BASE_URL=http://host.docker.internal /scripts/health_only_tmp3.js`

| Metric | Value |
|---|---:|
| p95 latency | 18.58 ms |
| failed request rate (`http_req_failed`) | 0.00% |
| checks pass rate | 100.00% |
| total requests | 13,912 |
| throughput | 462.22 req/s |
| exit code | 0 |

These values are the baseline reference for the hackathon evidence form item "Baseline p95 latency and error rate are documented."

## Silver Measurements (2026-04-05)

### 200 Concurrent Users Evidence

- tool: k6 (Docker image `grafana/k6`)
- target: `GET /health`
- load: 200 virtual users for 30 seconds
- command:
	- `docker run --rm -i -v "${PWD}/k6:/scripts" grafana/k6 run -e BASE_URL=http://host.docker.internal /scripts/silver_200_health_tmp.js`

| Metric | Value |
|---|---:|
| p95 latency | 45.48 ms |
| failed request rate (`http_req_failed`) | 0.00% |
| checks pass rate | 100.00% |
| total requests | 53,512 |
| throughput | 1,777.63 req/s |
| exit code | 0 |

These values are the Silver reference for the hackathon evidence form item "Evidence demonstrates successful load at 200 concurrent users."

## Gold Measurements (2026-04-05)

### 500 Concurrent Users or 100 RPS Evidence

- tool: k6 (Docker image `grafana/k6`)
- target: `GET /health`
- load: 500 virtual users for 30 seconds
- command:
	- `docker run --rm -i -v "${PWD}/k6:/scripts" grafana/k6 run -e BASE_URL=http://host.docker.internal /scripts/gold_500_health_tmp.js`

| Metric | Value |
|---|---:|
| concurrent users | 500 |
| throughput (`http_reqs`) | 1,853.98 req/s |
| total requests | 56,354 |
| p95 latency | 320.66 ms |
| failed request rate (`http_req_failed`) | 0.08% |
| checks pass rate | 99.91% |
| exit code | 0 |

These values are the Gold reference for the hackathon evidence form item "Evidence demonstrates tsunami-level throughput" (requirement: 500 concurrent users or >=100 RPS).

At high load (500 concurrent users), the observed failed request rate was 0.08%, which is below the 5% requirement.
