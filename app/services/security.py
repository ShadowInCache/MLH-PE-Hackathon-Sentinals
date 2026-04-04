import os
import re
from collections import defaultdict
from datetime import timedelta

from peewee import fn

from app.models.request_fingerprint import RequestFingerprint
from app.utils import utc_now_naive

CANARY_CODES = [
    "health-demo",
    "promo-demo",
    "checkout-demo",
    "dashboard-demo",
    "support-demo",
]

CANARY_STATE_FILE = os.environ.get(
    "CANARY_STATE_FILE", "/var/lib/ghostlink-security/canary_state.env"
)
BLOCKED_CODES_PATH = os.environ.get("BLOCKED_CODES_PATH", "/app/nginx/blocked_codes.conf")
BLOCKED_CODE_PATTERN = re.compile(r"~\^/([A-Za-z0-9_-]+)\$\s+1;")


def read_quarantined_codes(blocked_codes_path=None):
    path = blocked_codes_path or BLOCKED_CODES_PATH
    quarantined = set()

    if not os.path.exists(path):
        return quarantined

    with open(path, "r", encoding="utf-8") as file_handle:
        for raw_line in file_handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            match = BLOCKED_CODE_PATTERN.match(line)
            if match:
                quarantined.add(match.group(1))
            elif line.isalnum() or all(c.isalnum() or c in "_-" for c in line):
                quarantined.add(line)

    return quarantined


def is_quarantined_code(short_code):
    return short_code in read_quarantined_codes()


def parse_canary_state(state_file=None):
    path = state_file or CANARY_STATE_FILE
    metrics = {
        "success_total": 0.0,
        "failure_total": 0.0,
        "status": defaultdict(float),
        "latency": defaultdict(float),
    }

    if not os.path.exists(path):
        return metrics

    with open(path, "r", encoding="utf-8") as file_handle:
        for raw_line in file_handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()

            if key == "CANARY_SUCCESS_TOTAL":
                metrics["success_total"] = _safe_float(value)
                continue

            if key == "CANARY_FAILURE_TOTAL":
                metrics["failure_total"] = _safe_float(value)
                continue

            if key.endswith("_STATUS") and key.startswith("CANARY_"):
                code = _decode_canary_key(key, suffix="_STATUS")
                if code:
                    metrics["status"][code] = _safe_float(value)
                continue

            if key.endswith("_LATENCY") and key.startswith("CANARY_"):
                code = _decode_canary_key(key, suffix="_LATENCY")
                if code:
                    metrics["latency"][code] = _safe_float(value)

    for code in CANARY_CODES:
        metrics["status"][code] = metrics["status"].get(code, 0.0)
        metrics["latency"][code] = metrics["latency"].get(code, 0.0)

    return metrics


def record_request_fingerprint(
    short_code,
    status_code,
    client_ip,
    user_agent,
    is_invalid_short_code=False,
    is_ghost_probe=False,
    is_quarantined=False,
):
    RequestFingerprint.create(
        short_code=short_code,
        client_ip=client_ip,
        user_agent=(user_agent or "unknown")[:512],
        status_code=status_code,
        is_invalid_short_code=is_invalid_short_code,
        is_ghost_probe=is_ghost_probe,
        is_quarantined=is_quarantined,
        is_dead_link=status_code in (404, 410),
    )


def suspicious_clients_count(window_minutes=30):
    since = utc_now_naive() - timedelta(minutes=window_minutes)

    query = (
        RequestFingerprint.select(
            RequestFingerprint.client_ip,
            fn.SUM(RequestFingerprint.is_invalid_short_code.cast("int")).alias(
                "invalid_hits"
            ),
            fn.SUM(RequestFingerprint.is_ghost_probe.cast("int")).alias("ghost_hits"),
            fn.COUNT(RequestFingerprint.id).alias("request_count"),
            fn.SUM(RequestFingerprint.is_quarantined.cast("int")).alias("blocked_hits"),
        )
        .where(RequestFingerprint.created_at >= since)
        .group_by(RequestFingerprint.client_ip)
    )

    suspicious_total = 0
    for row in query:
        invalid_hits = int(row.invalid_hits or 0)
        ghost_hits = int(row.ghost_hits or 0)
        request_count = int(row.request_count or 0)
        blocked_hits = int(row.blocked_hits or 0)

        if (
            invalid_hits >= 20
            or ghost_hits >= 30
            or request_count >= 300
            or blocked_hits >= 10
        ):
            suspicious_total += 1

    return suspicious_total


def top_suspicious_ip_scores(limit=10, window_minutes=30):
    since = utc_now_naive() - timedelta(minutes=window_minutes)

    query = (
        RequestFingerprint.select(
            RequestFingerprint.client_ip,
            fn.SUM(RequestFingerprint.is_invalid_short_code.cast("int")).alias(
                "invalid_hits"
            ),
            fn.SUM(RequestFingerprint.is_ghost_probe.cast("int")).alias("ghost_hits"),
            fn.COUNT(RequestFingerprint.id).alias("request_count"),
            fn.SUM(RequestFingerprint.is_quarantined.cast("int")).alias("blocked_hits"),
        )
        .where(RequestFingerprint.created_at >= since)
        .group_by(RequestFingerprint.client_ip)
    )

    scored = []
    for row in query:
        score = 0
        if int(row.invalid_hits or 0) >= 20:
            score += 40
        if int(row.ghost_hits or 0) >= 30:
            score += 25
        if int(row.request_count or 0) >= 300:
            score += 20
        if int(row.blocked_hits or 0) >= 10:
            score += 15

        if score > 0:
            scored.append((row.client_ip or "unknown", float(min(score, 100))))

    scored.sort(key=lambda item: item[1], reverse=True)
    return scored[:limit]


def top_suspicious_user_agents(limit=10, window_minutes=30):
    since = utc_now_naive() - timedelta(minutes=window_minutes)

    query = (
        RequestFingerprint.select(
            RequestFingerprint.user_agent,
            fn.COUNT(RequestFingerprint.id).alias("hits"),
        )
        .where(
            (RequestFingerprint.created_at >= since)
            & (RequestFingerprint.is_dead_link == True)
        )
        .group_by(RequestFingerprint.user_agent)
        .order_by(fn.COUNT(RequestFingerprint.id).desc())
        .limit(limit)
    )

    return [
        ((row.user_agent or "unknown")[:180], float(row.hits or 0)) for row in query
    ]


def top_probed_short_codes(limit=10, window_minutes=30):
    since = utc_now_naive() - timedelta(minutes=window_minutes)

    query = (
        RequestFingerprint.select(
            RequestFingerprint.short_code,
            fn.COUNT(RequestFingerprint.id).alias("hits"),
        )
        .where(
            (RequestFingerprint.created_at >= since)
            & (RequestFingerprint.is_dead_link == True)
            & (RequestFingerprint.short_code.is_null(False))
        )
        .group_by(RequestFingerprint.short_code)
        .order_by(fn.COUNT(RequestFingerprint.id).desc())
        .limit(limit)
    )

    return [((row.short_code or "unknown"), float(row.hits or 0)) for row in query]


def total_invalid_short_code_hits():
    return RequestFingerprint.select().where(
        RequestFingerprint.is_invalid_short_code == True
    ).count()


def total_blocked_requests():
    return RequestFingerprint.select().where(RequestFingerprint.is_quarantined == True).count()


def repeated_user_agent_hits_total(threshold=25, window_minutes=30):
    since = utc_now_naive() - timedelta(minutes=window_minutes)

    query = (
        RequestFingerprint.select(
            RequestFingerprint.user_agent,
            fn.COUNT(RequestFingerprint.id).alias("hits"),
        )
        .where(
            (RequestFingerprint.created_at >= since)
            & (RequestFingerprint.is_dead_link == True)
        )
        .group_by(RequestFingerprint.user_agent)
    )

    total = 0
    for row in query:
        if int(row.hits or 0) >= threshold:
            total += int(row.hits or 0)

    return total


def _decode_canary_key(key, suffix):
    inner = key[len("CANARY_") : -len(suffix)]
    if not inner:
        return None
    return inner.lower().replace("_", "-")


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
