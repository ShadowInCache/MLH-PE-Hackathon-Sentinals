# GhostLink Bottleneck Analysis Report

Date: 2026-04-05

## Scope

This report summarizes where bottlenecks appear under increasing load and identifies the first likely hard limits for the current Docker Compose deployment.

## Test Inputs

- Tool: k6 (Docker image `grafana/k6`)
- Endpoint under sustained load: `GET /health`
- Environment: Nginx ingress with `app1` + `app2` backend replicas, PostgreSQL, Redis

## Observed Results by Tier

| Tier | Load Profile | Throughput | p95 Latency | Failed Request Rate | Outcome |
|---|---|---:|---:|---:|---|
| Bronze | 50 VUs, 30s | 462.22 req/s | 18.58 ms | 0.00% | Stable |
| Silver | 200 VUs, 30s | 1,777.63 req/s | 45.48 ms | 0.00% | Stable |
| Gold | 500 VUs, 30s | 1,853.98 req/s | 320.66 ms | 0.08% | Stable with minor connection pressure |

## Bottleneck Findings

1. No hard application bottleneck reached at tested limits.
- At 500 concurrent users, p95 latency remained 320.66 ms, which is far below the 3-second target.
- Error rate remained low at 0.08%.

2. First observable pressure point is at ingress connection handling.
- During the 500 VU run, 46 connection-refused events were observed from the k6 container to the host ingress path.
- This pattern indicates short-lived connection pressure at or before Nginx ingress acceptance, not sustained backend failure.

3. Throughput scaling begins to flatten between Silver and Gold.
- Silver to Gold increases concurrency by 2.5x (200 -> 500 VUs), while throughput increases modestly (1,777.63 -> 1,853.98 req/s).
- This suggests the deployment is nearing an ingress/network or worker-limit boundary before a DB-bound ceiling.

## Most Likely Near-Term Bottlenecks

- Nginx ingress socket acceptance and worker tuning under bursty high-concurrency traffic.
- App worker count per replica if ingress tuning is increased without scaling backend worker capacity.
- Host-level CPU scheduling and network stack limits under containerized high-connection churn.

## Mitigation Plan (Priority Order)

1. Tune Nginx workers and connection limits.
- Increase worker process/connection settings and validate with repeated Gold runs.

2. Increase backend concurrency capacity.
- Raise Gunicorn worker settings and re-test for p95 and error-rate movement.

3. Scale replicas and rebalance.
- Add additional backend instances and update upstream pool.

4. Verify dependency headroom.
- Track DB and Redis latency while replaying Gold profile to confirm when dependency contention begins.

## Acceptance Criteria for Next Capacity Step

- Maintain p95 latency < 1000 ms at 500+ VUs.
- Keep failed request rate < 1% at Gold profile.
- Show throughput growth proportional to added replicas/workers after tuning.

## Source References

- Measurements and tier summaries: `docs/CAPACITY.md`
- Multi-instance verification: `docs/RUNBOOK.md`
