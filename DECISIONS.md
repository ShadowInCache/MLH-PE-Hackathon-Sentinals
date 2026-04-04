# GhostLink Architecture Decisions

## Overview
This document captures key technical decisions made during the GhostLink implementation for the MLH Production Engineering Hackathon.

## Technology Choices

### ORM: Peewee vs SQLAlchemy
**Decision:** Use Peewee ORM  
**Rationale:**
- Existing template was already configured with Peewee
- Lighter weight and simpler for hackathon timeline
- Sufficient feature set for our needs (models, migrations, queries)
- Faster development velocity vs switching to SQLAlchemy mid-project
- Team already familiar with Peewee patterns

**Trade-offs:**
- Less ecosystem support than SQLAlchemy
- Fewer advanced ORM features (but not needed for our use case)
- Migration tooling less robust (acceptable for hackathon)

### Caching: Redis
**Decision:** Redis for short-lived cache with graceful degradation  
**Rationale:**
- Cache short_code → original_url mappings (5 min TTL) to reduce DB load on hot URLs
- Cache risk_scores (10 min TTL) since computation is expensive
- Graceful degradation: app works without Redis, just slower
- Simple key-value model fits our needs perfectly

**Important Note on Redirect Caching:**
- **REMOVED** caching from redirect endpoint
- Redirect always queries DB to check `is_active` status
- This ensures ghost probe detection works correctly (410 Gone for inactive URLs)
- Trade-off: Slightly higher DB load, but necessary for correctness
- Alternative considered: Cache {url, is_active} tuple, but adds complexity

**Trade-offs:**
- Additional infrastructure dependency (but common in production)
- Cache invalidation complexity (handled via explicit deletes on updates)
- TTL tuning required for optimal hit rates
- No redirect caching due to is_active requirement

### Background Workers: APScheduler
**Decision:** APScheduler for link health checks (not Celery)  
**Rationale:**
- Simpler setup: no message broker required
- Single process model acceptable for hackathon scale
- 5-minute interval health checks don't need distributed task queue
- Easy to start/stop with Flask lifecycle

**Trade-offs:**
- Not horizontally scalable (one scheduler per process)
- No task retry/failure handling (acceptable for periodic checks)
- Would need Celery/RQ for production scale (documented in future improvements)

### Metrics: Prometheus Client
**Decision:** Expose Prometheus text format at GET /metrics  
**Rationale:**
- Industry standard for observability
- Akshay's infrastructure already uses Prometheus
- Simple push model: app exposes, Prometheus scrapes
- Rich metric types (counters, gauges, histograms)

**Trade-offs:**
- Need to manually update gauges (urls_active_total, etc.)
- No built-in middleware instrumentation (added manual tracking)

## API Design Decisions

### Error Response Format
**Decision:** All errors return JSON with {"error": "...", "code": <status>}  
**Rationale:**
- Consistent error handling for frontend/API consumers
- Never expose HTML tracebacks in production
- Status code duplicated in body for easier debugging
- Explicit edge case handling (404, 410, 409, 422, 400)

**Implementation:**
- Custom error handlers for each status code
- Silent JSON parsing (request.get_json(silent=True)) to catch malformed bodies
- Validation at route level, not model level (faster feedback)

### Soft Delete Pattern
**Decision:** DELETE /urls/<id> sets is_active=False (soft delete)  
**Rationale:**
- Preserves audit trail (events table still references url_id)
- Enables "undelete" feature in future
- Risk scorer can detect ghost probes (hits on inactive URLs)
- Safer than hard delete for production systems

**Trade-offs:**
- Need to filter is_active=True in most queries
- Indexes must include is_active for performance
- Storage grows unbounded (would need archival strategy at scale)

### Short Code Generation
**Decision:** 6-character alphanumeric codes (62^6 = 56B combinations)  
**Rationale:**
- Short enough for easy sharing (6 chars)
- Large enough to avoid collisions at hackathon scale
- Case-sensitive for maximum entropy
- Collision detection with retry (up to 10 attempts)

**Trade-offs:**
- Potential collision at very high scale (would need base62 counter or UUID at production scale)
- No custom vanity codes by default (added as optional feature)

## Risk Scoring Design

### Signal-Based Scoring
**Decision:** Additive risk scoring with 5 signals  
**Rationale:**
- Simple to understand and debug
- Each signal has clear threshold and point value
- Tiers (SAFE/WATCHLIST/THREAT) provide actionable categories
- Signals stored as JSONB for explainability

**Signals:**
1. Dead destination (+30): Latest health check indicates dead target
2. Long redirect chain (+20): More than 3 redirects
3. Ghost probe pressure (+15): High volume ghost probe events
4. Suspicious TLD (+20): Domain uses risky top-level domain
5. Delete/recreate pattern (+15): Repeated delete and recreate behavior

**Trade-offs:**
- Fixed weights don't adapt to new attack patterns (would need ML for that)
- Domain-only heuristics can misclassify edge cases without external intel feeds
- No geographic or reputation signals (out of scope for MVP)

## Testing Strategy

### Coverage Requirement: 70%
**Decision:** Block merges if pytest coverage < 70%  
**Rationale:**
- Balances thoroughness with hackathon velocity
- Forces testing of critical paths (API routes, risk scorer)
- 70% is achievable without testing boilerplate (models, __init__.py)
- CI enforces via pytest-cov --cov-fail-under=70

**Test Structure:**
- conftest.py: Fixtures for test DB, Flask client, sample data
- test_unit.py: Services in isolation (mock DB/Redis)
- test_integration.py: Full API tests (real DB, all edge cases)

### Test Database Isolation
**Decision:** Function-scoped fixtures with table create/drop  
**Rationale:**
- Each test gets clean DB state
- Prevents test pollution and flaky failures
- Fast enough for hackathon (would use transactions at scale)

## Docker & Environment Configuration

### Environment Variables
**Decision:** All config via ENV vars (12-factor app)  
**Rationale:**
- Docker-friendly: no hardcoded config
- Easy to override for dev/test/prod
- Akshay's Docker setup depends on DATABASE_URL, REDIS_URL pattern
- .env.example documents all required vars

**Variables:**
- DATABASE_NAME, DATABASE_HOST, DATABASE_PORT, DATABASE_USER, DATABASE_PASSWORD
- REDIS_URL (with fallback to localhost)

## Future Improvements (Out of Scope)

1. **Horizontal Scaling:** Switch APScheduler → Celery + RabbitMQ
2. **Rate Limiting:** Per-user/IP throttling to prevent abuse
3. **Analytics:** Track click-through rates, geographic distribution
4. **ML Risk Scoring:** Train model on labeled malicious URLs
5. **URL Previews:** Safe rendering of destination page metadata
6. **Custom Domains:** Allow users to use their own domains
7. **API Authentication:** JWT tokens for user-scoped operations

## Known Limitations

1. **Single Process Scheduler:** Health checker doesn't scale horizontally
2. **No Retry Logic:** If health check fails, no automatic retry
3. **Whois Rate Limiting:** Domain age checks can be slow/blocked
4. **No Link Expiration:** URLs live forever (would add expires_at field)
5. **No User Auth:** user_id is passed in request (would add JWT auth)

## Metrics & Observability

### Exposed Metrics
- urls_created_total: Counter of URL creations
- url_redirects_total: Counter per short_code (labeled metric)
- redirect_latency_seconds: Histogram of redirect response times
- ghost_probes_total: Counter of inactive URL hits
- destination_dead_total: Counter of dead destination detections
- risk_score_threats_total: Gauge of URLs with score > 70
- urls_active_total, urls_inactive_total: Current counts

### Health Check
GET /health returns:
- 200 OK: {"status":"ok", "db":"ok", "redis":"ok"}
- 503 Degraded: {"status":"degraded", "db":"error"} (Redis optional)

## Edge Cases Handled (Bonus Points)

1. **410 Gone:** Inactive URL hit returns 410, not 404
2. **409 Conflict:** Duplicate short_code returns 409
3. **422 Unprocessable:** Malformed URL returns 422
4. **400 Bad Request:** Missing body/fields returns 400
5. **404 Not Found:** Unknown short_code returns 404
6. **All JSON:** Never return HTML traceback (silent error handling)

## Security Considerations

1. **SQL Injection:** Peewee ORM parameterizes queries (safe)
2. **XSS:** No HTML rendering (JSON API only)
3. **SSRF:** URL validation prevents internal IPs (out of scope, would add blocklist)
4. **DoS:** No rate limiting yet (would add Flask-Limiter)
5. **Open Redirects:** Acceptable for URL shortener (warn users in docs)

## Performance Optimizations

1. **Redis Caching:** Hot URLs served from cache (5 min TTL)
2. **Database Indexes:** On short_code, user_id, is_active, created_at
3. **Composite Indexes:** (url_id, checked_at), (user_id, timestamp)
4. **Connection Pooling:** Peewee reuses connections via reuse_if_open=True
5. **Batch Inserts:** Seed script uses chunked inserts (Peewee bulk operations)

---

**Author:** Sentinals Team (Amogh + Akshay)  
**Date:** April 2026  
**Event:** MLH Production Engineering Hackathon
