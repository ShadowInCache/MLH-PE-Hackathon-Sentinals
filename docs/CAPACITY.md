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
- no sustained ServiceDown alerts
- error rate alert remains inactive under nominal behavior
- canary failures remain at 0 for steady-state windows
- suspicious-client and blocked-request spikes are detectable within 2 minutes

## Primary Saturation Signals

- `sum(rate(destination_dead_total[5m])) / clamp_min(sum(rate(url_redirects_total[5m])), 0.001)` climbs
- `histogram_quantile(0.95, sum(rate(redirect_latency_seconds_bucket[5m])) by (le))` rises continuously
- backend `up` flaps between 1 and 0
- DB health check failures or connection errors in app logs
- `increase(ghostlink_canary_failures_total[5m]) > 0`
- `ghostlink_suspicious_clients_total` and `increase(ghostlink_blocked_requests_total[5m])` rise together
- `ghostlink_threat_links_total` sustained growth indicates security saturation

## Scaling Knobs

1. Increase app workers in Dockerfile gunicorn command.
2. Add more backend replicas and update Nginx upstream list.
3. Raise Postgres resource limits and tune connection pooling.
4. Move Redis persistence policy based on durability/performance needs.
5. Increase host CPU/RAM before adjusting rate limits.
6. Increase Nginx worker/process tuning if blocked and invalid traffic dominates.
7. Increase `SECURITY_LOG_TAIL_BYTES` for richer suspicious-client detection on high-volume hosts.

## Recommended Test Sequence

1. Run Bronze and capture baseline metrics.
2. Run Silver and compare p95, error rate, and CPU usage.
3. Run Gold and identify first hard limit (CPU, DB, network, or app worker saturation).
4. Execute chaos scenarios:
	- `make chaos-kill-app1`
	- `make chaos-stop-redis`
	- `make chaos-spike-errors`
5. Validate Executive Summary dashboard row and Threat Timeline behavior during chaos.
6. Apply one scaling change at a time and re-run from Bronze to Gold with chaos validation.
