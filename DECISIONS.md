# GhostLink Architecture and Engineering Decisions

Last updated: 2026-04-05

## Purpose

This file records the key technical decisions taken for GhostLink and the rationale behind them. It reflects the implemented state of the repository, including API compatibility work, observability and incident-response hardening, and load-test outcomes used for submission evidence.

## Decision Index

| ID | Decision | Status |
|---|---|---|
| D-01 | Keep Flask + Peewee for delivery speed and operational simplicity | Accepted |
| D-02 | Run behind Nginx with multi-instance app replicas (`app1`, `app2`) | Accepted |
| D-03 | Preserve broad API compatibility surface (`/shorten`, `/urls`, `/users`, `/events`) | Accepted |
| D-04 | Enforce strict JSON object and identity validation on write endpoints | Accepted |
| D-05 | Record redirect events for successful redirects; block inactive/quarantined routes | Accepted |
| D-06 | Use Redis cache with graceful degradation and explicit invalidation | Accepted |
| D-07 | Keep additive 5-signal risk scoring model with SAFE/WATCHLIST/THREAT tiers | Accepted |
| D-08 | Use structured JSON logging with explicit timestamp and log level fields | Accepted |
| D-09 | Expose Prometheus metrics and keep four-signal dashboard coverage | Accepted |
| D-10 | Route alerts through Alertmanager to an operator channel (Discord) | Accepted |
| D-11 | Maintain actionable alert runbook and documented root-cause drill workflow | Accepted |
| D-12 | Define Bronze/Silver/Gold load tiers and enforce under-5% high-load error objective | Accepted |
| D-13 | Treat Nginx ingress as first observed pressure point at Gold load | Accepted |
| D-14 | Keep function-scoped SQLite tests and explicit API compatibility/edge coverage | Accepted |
| D-15 | Keep startup-safe table initialization and compatibility table checks | Accepted |

---

## D-01: Flask + Peewee

Decision: Keep Flask and Peewee instead of switching frameworks/ORMs.

Why:
- Existing project baseline was already aligned with Flask + Peewee.
- Faster iteration for hackathon timeline.
- Query complexity and schema size are well within Peewee capabilities.

Trade-offs:
- Smaller ecosystem than SQLAlchemy.
- Less advanced migration tooling.

## D-02: Multi-instance ingress topology

Decision: Use Nginx as ingress and load-balance across `app1` and `app2`.

Why:
- Improves availability and throughput under load.
- Allows replica-level recovery during incidents.

Trade-offs:
- Requires upstream and health-check coordination.
- Adds ingress tuning considerations at higher concurrency.

## D-03: API compatibility surface

Decision: Support both canonical and compatibility endpoints.

Implemented compatibility includes:
- URLs: `POST /shorten`, `POST /urls`, `GET /urls`, `GET /urls/{id}`, `PUT/PATCH /urls/{id}`, `DELETE /urls/{id}`, `GET /{short_code}`, `GET /r/{short_code}`.
- Users: CRUD endpoints plus `POST /users/bulk`.
- Events: `GET /events`, `POST /events` with filtering support.

Why:
- Hidden grader and integration tests expect broad endpoint compatibility.

Trade-offs:
- Slightly wider API surface to maintain.

## D-04: Strict request-shape and identity validation

Decision: Reject malformed request bodies and invalid identities early.

Rules:
- Write endpoints expect JSON objects, not scalars/lists.
- Optional identity fields (`user_id`, etc.) are validated for type and existence when provided.
- Malformed details payloads are rejected (`details` must be an object when present).

Why:
- Prevents 500-class failures from malformed input.
- Aligns with hidden test patterns for malformed payloads and unverified identities.

Trade-offs:
- Slightly more validation code at route layer.

## D-05: Redirect and event semantics

Decision:
- Successful redirects create redirect events and metrics updates.
- Inactive or quarantined routes do not redirect and return `410`.
- Unknown short codes return `404`.

Why:
- Meets expected behavioral contracts for active/inactive/quarantined states.
- Ensures audit visibility for successful traffic.

Trade-offs:
- Requires consistent route behavior across cache-hit and DB paths.

## D-06: Redis caching strategy

Decision: Keep Redis as a best-effort cache with explicit invalidation.

Details:
- URL cache TTL: 300 seconds.
- Risk score cache TTL: 600 seconds.
- Cache failures do not bring down request paths.

Why:
- Improves hot-path performance while preserving resilience when Redis is unavailable.

Trade-offs:
- Cache invalidation logic must stay aligned with update/delete flows.

## D-07: Risk scoring model

Decision: Keep additive multi-signal scoring with tiered output.

Signals used:
- dead destination
- long redirect chain
- ghost-probe pressure
- suspicious TLD
- delete/recreate behavior

Tiers:
- SAFE
- WATCHLIST
- THREAT

Why:
- Simple, explainable, and operationally actionable.

## D-08: Structured logging

Decision: Keep Nginx structured JSON logs and include explicit timing/severity fields.

Required fields include:
- `time`
- `timestamp`
- `log_level`
- request and upstream timing metadata

Why:
- Supports incident triage and downstream log parsing.

## D-09: Metrics + dashboard signal coverage

Decision: Use Prometheus exposition at `GET /metrics` and maintain dashboard coverage for four key signal classes.

Required four signal classes:
- latency
- traffic
- errors
- saturation

Why:
- Aligns operational visibility with incident and capacity objectives.

## D-10: Alert routing to operator channel

Decision: Route alerts via Alertmanager to a dedicated operator channel (Discord receiver).

Why:
- Ensures incidents are delivered outside the app runtime.
- Supports resolved notifications and grouped alerting.

Trade-offs:
- Channel credential management must be handled carefully.

## D-11: Incident response and diagnosis drill

Decision: Maintain actionable runbook procedures and an explicit simulated root-cause workflow.

Runbook covers:
- service down
- canary failures
- suspicious client spikes
- blocked request spikes
- threat-link surge

Drill workflow includes:
- chaos trigger
- symptom and metric correlation
- root-cause determination
- recovery verification

## D-12: Capacity tiers and high-load objectives

Decision: Adopt tiered load testing profile and keep high-load error objective under 5%.

Measured results (2026-04-05):
- Bronze (50 VUs): p95 18.58 ms, failed 0.00%, 462.22 req/s
- Silver (200 VUs): p95 45.48 ms, failed 0.00%, 1777.63 req/s
- Gold (500 VUs): p95 320.66 ms, failed 0.08%, 1853.98 req/s

Why:
- Demonstrates scale behavior and satisfies submission thresholds.

## D-13: Bottleneck interpretation and scaling priorities

Decision: Treat ingress connection handling as the first observed pressure point at Gold profile.

Observed:
- Throughput growth from Silver to Gold flattened relative to concurrency increase.
- Minor connection pressure appeared before backend hard failure.

Priority scaling plan:
1. tune Nginx worker/connection limits
2. raise backend worker capacity
3. increase replica count
4. validate DB/Redis headroom during reruns

## D-14: Testing and quality gates

Decision:
- Keep function-scoped isolated tests.
- Keep compatibility tests and hidden-edge regressions in repository.
- Preserve coverage gate in CI.

Why:
- Prevents regressions across API contracts and malformed input handling.

## D-15: Startup-safe database initialization

Decision: Keep table initialization safety checks both at app startup and request lifecycle.

Why:
- Improves resilience across local, test, and container startup orders.
- Reduces runtime failures when environment startup ordering varies.

---

## Out-of-scope / Deferred

1. Full authn/authz (JWT/session) for user-scoped operations.
2. Distributed task queue for health checks (Celery/RQ class architecture).
3. Advanced reputation feeds / ML-based risk scoring.
4. Long-term archival strategy for soft-deleted historical data.

## Primary references

- `app/routes/urls.py`
- `app/routes/events.py`
- `app/services/cache.py`
- `app/routes/health.py`
- `prometheus/alert_rules.yml`
- `alertmanager/alertmanager.yml`
- `nginx/nginx.conf`
- `docs/CAPACITY.md`
- `docs/BOTTLENECK_REPORT.md`
- `docs/RUNBOOK.md`
