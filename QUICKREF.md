# GhostLink Quick Reference

## 🚀 Quick Start

```bash
# 1. Install
uv sync

# 2. Setup DB
python scripts/setup_db.py

# 3. Run
uv run run.py
```

## 📡 API Quick Reference

```bash
# Create short URL
curl -X POST http://localhost:5000/shorten \
  -H "Content-Type: application/json" \
  -d '{"original_url":"https://example.com"}'
# → {"id":1, "short_code":"abc123"}

# Redirect
curl -I http://localhost:5000/abc123
# → 302 Location: https://example.com

# List URLs
curl http://localhost:5000/urls

# Update URL
curl -X PATCH http://localhost:5000/urls/1 \
  -H "Content-Type: application/json" \
  -d '{"title":"New Title"}'

# Delete URL (soft delete)
curl -X DELETE http://localhost:5000/urls/1

# Health Check
curl http://localhost:5000/health
# → {"status":"ok","db":"ok","redis":"ok"}

# Metrics
curl http://localhost:5000/metrics
```

## 🎯 Status Codes

| Code | Meaning | When |
|------|---------|------|
| 200 | OK | Successful GET/PATCH/DELETE |
| 201 | Created | URL shortened successfully |
| 302 | Redirect | Short code found, redirecting |
| 400 | Bad Request | Missing body or required fields |
| 404 | Not Found | Short code doesn't exist |
| 409 | Conflict | Short code already taken |
| 410 | Gone | Link is inactive (soft deleted) |
| 422 | Unprocessable | Invalid URL format |
| 503 | Degraded | Database connection error |

## 🛡️ Risk Scoring

| Signal | Points | Trigger |
|--------|--------|---------|
| Destination Dead | +30 | Latest health check indicates dead target |
| Long Chain | +20 | Redirect chain >3 |
| Ghost Probe Pressure | +15 | High volume ghost probe events |
| Suspicious TLD | +20 | Domain TLD in suspicious set |
| Delete/Recreate Pattern | +15 | Repeated delete/create behavior |

**Tiers:**
- 0-30: SAFE ✅
- 31-60: WATCHLIST ⚠️
- 61-100: THREAT 🚨

## 📊 Prometheus Metrics

```
# Counters
urls_created_total
url_redirects_total{short_code="abc123"}
ghost_probes_total
destination_dead_total

# Gauges
urls_active_total
urls_inactive_total
risk_score_threats_total

# Histogram
redirect_latency_seconds
```

## 🧪 Testing

```bash
# All tests
pytest --cov=app app/tests/

# Unit tests only
pytest app/tests/test_unit.py

# Integration tests only
pytest app/tests/test_integration.py

# Coverage report
pytest --cov=app --cov-report=html app/tests/
```

## 🔧 Configuration

### Environment Variables

```bash
DATABASE_NAME=hackathon_db
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_USER=postgres
DATABASE_PASSWORD=postgres
REDIS_URL=redis://localhost:6379/0
```

### Database Tables

- `urls` - URL mappings
- `users` - User accounts
- `events` - Audit trail
- `health_checks` - URL health records
- `risk_scores` - Risk analysis data

## 📦 Project Structure

```
app/
├── models/         # 5 Peewee models
├── routes/         # 2 Flask blueprints
├── services/       # 4 business logic modules
└── tests/          # 43 pytest tests

scripts/
├── seed.py         # Load CSV data
└── setup_db.py     # Create tables
```

## 🐛 Troubleshooting

### Redis Connection Failed
```
WARNING: Redis connection failed: ... Continuing without cache.
```
**Fix:** App works without Redis, just slower. Install Redis or ignore.

### Database Connection Error
```
503 {"status":"degraded","db":"error"}
```
**Fix:** Check DATABASE_* env vars, ensure PostgreSQL is running.

### Import Errors
```
ModuleNotFoundError: No module named 'redis'
```
**Fix:** Run `uv sync` or `pip install -r requirements.txt`

### Tests Failing
```
pytest app/tests/
```
**Fix:** Ensure test database exists: `createdb test_ghostlink`

## 📝 Common Tasks

### Add Seed Data
```python
# Place CSVs in ./data/
# - users.csv
# - urls.csv  
# - events.csv
python scripts/seed.py
```

### Create Tables
```bash
python scripts/setup_db.py
```

### Manual Risk Score Calculation
```python
from app.services.risk_scorer import compute_risk_score
result = compute_risk_score(url_id=1)
print(result)  # {'score': 35, 'tier': 'WATCHLIST', ...}
```

### Check Link Health
```python
from app.services.link_health import check_url_health
status_code, latency_ms, health_status, chain = check_url_health(
    1, "https://example.com"
)
```

## 🔗 Useful Links

- **README**: `README_GHOSTLINK.md` - Full user guide
- **Architecture**: `DECISIONS.md` - Design rationale
- **Deployment**: `DEPLOYMENT_CHECKLIST.md` - Production checklist
- **CI**: `.github/workflows/ci.yml` - GitHub Actions config

## 🎓 Team

**Sentinals** - MLH PE Hackathon 2026
- Amogh: Backend (this codebase)
- Akshay: DevOps (Docker, Prometheus, Grafana)
