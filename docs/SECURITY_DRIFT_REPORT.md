# Security Drift Detection Report

This document describes the configuration drift checks for GhostLink production infrastructure.

## Script

- Path: [scripts/security_drift_check.py](scripts/security_drift_check.py)

## What It Verifies

- Docker Compose schema version is `3.9`
- Required services are present
- `restart: always` and `healthcheck` are present for app services
- Feature flag environment variables are present in app services
- `APP_VERSION` is present in app services
- Nginx rate limiting directives exist
- Prometheus scrape targets exist
- Alertmanager route block exists
- Grafana Prometheus datasource exists
- Redis and Postgres services are present

## Usage

```bash
python scripts/security_drift_check.py
```

## Output Format

The script prints:

- `PASS` or `FAIL`
- `Critical Issues`
- `Warnings`
- `Suggested Fixes`

Example structure:

```text
PASS

Critical Issues:
- None

Warnings:
- None

Suggested Fixes:
- None
```

## Operational Guidance

- Run this check before deployment and after infrastructure changes.
- Treat any `FAIL` as a release blocker.
- Use suggested fixes to restore baseline security and reliability posture.
