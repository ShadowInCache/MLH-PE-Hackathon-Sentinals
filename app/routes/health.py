from flask import Blueprint, Response, jsonify
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

from app.config.feature_flags import get_feature_flags
from app.config.release_info import get_recovery_state, get_release_info
from app.database import db, get_redis
from app.models.event import Event
from app.models.health_check import HealthCheck
from app.models.risk_score import RiskScore
from app.models.url import Url
from app.services.security import (
    CANARY_CODES,
    parse_canary_state,
    read_quarantined_codes,
    repeated_user_agent_hits_total,
    suspicious_clients_count,
    top_probed_short_codes,
    top_suspicious_ip_scores,
    top_suspicious_user_agents,
    total_blocked_requests,
    total_invalid_short_code_hits,
)

health_bp = Blueprint("health", __name__)

registry = CollectorRegistry()

urls_created_total = Counter(
    "urls_created_total", "Total number of URLs created", registry=registry
)

url_redirects_total = Counter(
    "url_redirects_total",
    "Total number of URL redirects",
    ["short_code", "app_version"],
    registry=registry,
)

redirect_latency_seconds = Histogram(
    "redirect_latency_seconds",
    "Redirect response time in seconds",
    registry=registry,
)

ghost_probes_total = Counter(
    "ghost_probes_total", "Total hits on inactive URLs", registry=registry
)

destination_dead_total = Gauge(
    "destination_dead_total", "Total number of dead destination detections",
    registry=registry,
)

risk_score_threats_total = Gauge(
    "risk_score_threats_total", "Number of URLs with risk score > 60", registry=registry
)

urls_active_total = Gauge(
    "urls_active_total", "Total number of active URLs", registry=registry
)

urls_inactive_total = Gauge(
    "urls_inactive_total", "Total number of inactive URLs", registry=registry
)

urls_deleted_total = Counter(
    "urls_deleted_total", "Total number of URL soft deletes", registry=registry
)

ghostlink_canary_success_total = Gauge(
    "ghostlink_canary_success_total",
    "Total successful synthetic canary checks",
    registry=registry,
)

ghostlink_canary_failures_total = Gauge(
    "ghostlink_canary_failures_total",
    "Total failed synthetic canary checks",
    registry=registry,
)

ghostlink_canary_latency_seconds = Gauge(
    "ghostlink_canary_latency_seconds",
    "Latest latency observed for each synthetic canary",
    ["short_code"],
    registry=registry,
)

ghostlink_canary_status = Gauge(
    "ghostlink_canary_status",
    "Latest HTTP status observed for each synthetic canary",
    ["short_code"],
    registry=registry,
)

ghostlink_quarantined_urls_total = Gauge(
    "ghostlink_quarantined_urls_total",
    "Current number of quarantined short codes",
    registry=registry,
)

ghostlink_risk_score = Gauge(
    "ghostlink_risk_score",
    "Link risk score from 0 to 100",
    ["short_code", "risk_level"],
    registry=registry,
)

ghostlink_safe_links_total = Gauge(
    "ghostlink_safe_links_total",
    "Count of links currently classified as SAFE",
    registry=registry,
)

ghostlink_watchlist_links_total = Gauge(
    "ghostlink_watchlist_links_total",
    "Count of links currently classified as WATCHLIST",
    registry=registry,
)

ghostlink_threat_links_total = Gauge(
    "ghostlink_threat_links_total",
    "Count of links currently classified as THREAT",
    registry=registry,
)

ghostlink_suspicious_clients_total = Gauge(
    "ghostlink_suspicious_clients_total",
    "Number of currently flagged suspicious client IPs",
    registry=registry,
)

ghostlink_blocked_requests_total = Gauge(
    "ghostlink_blocked_requests_total",
    "Total blocked requests served with HTTP 410",
    registry=registry,
)

ghostlink_invalid_short_code_hits_total = Gauge(
    "ghostlink_invalid_short_code_hits_total",
    "Total invalid short-code hits observed by the app",
    registry=registry,
)

ghostlink_repeated_user_agent_hits_total = Gauge(
    "ghostlink_repeated_user_agent_hits_total",
    "Total dead-link hits from repeatedly abusive user agents",
    registry=registry,
)

ghostlink_affected_redirects_total = Gauge(
    "ghostlink_affected_redirects_total",
    "Total redirects observed for affected short codes",
    registry=registry,
)

ghostlink_suspicious_ip_score = Gauge(
    "ghostlink_suspicious_ip_score",
    "Risk score for suspicious client IPs",
    ["ip"],
    registry=registry,
)

ghostlink_suspicious_user_agent_hits = Gauge(
    "ghostlink_suspicious_user_agent_hits",
    "Dead-link hits observed for suspicious user agents",
    ["user_agent"],
    registry=registry,
)

ghostlink_probed_short_code_hits = Gauge(
    "ghostlink_probed_short_code_hits",
    "Most probed short codes observed by the app",
    ["short_code"],
    registry=registry,
)

ghostlink_feature_flag_enabled = Gauge(
    "ghostlink_feature_flag_enabled",
    "Feature flag status (1=enabled, 0=disabled)",
    ["flag"],
    registry=registry,
)

ghostlink_release_info = Gauge(
    "ghostlink_release_info",
    "Release metadata for this application instance",
    ["version", "git_sha", "deployed_at", "release_owner", "release_notes_url"],
    registry=registry,
)

ghostlink_rollbacks_total = Gauge(
    "ghostlink_rollbacks_total",
    "Total rollback operations executed",
    registry=registry,
)

ghostlink_mean_time_to_detect_minutes = Gauge(
    "ghostlink_mean_time_to_detect_minutes",
    "Mean time to detect incidents in minutes",
    registry=registry,
)

ghostlink_mean_time_to_recover_minutes = Gauge(
    "ghostlink_mean_time_to_recover_minutes",
    "Mean time to recover incidents in minutes",
    registry=registry,
)

ghostlink_recovery_attempts_total = Gauge(
    "ghostlink_recovery_attempts_total",
    "Total recovery attempts",
    registry=registry,
)

ghostlink_recovery_success_total = Gauge(
    "ghostlink_recovery_success_total",
    "Total successful recoveries",
    registry=registry,
)


@health_bp.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint with DB and Redis status."""
    release = get_release_info()
    status = {
        "status": "ok",
        **release.to_dict(),
        "feature_flags": get_feature_flags(),
    }

    try:
        db.execute_sql("SELECT 1")
        status["db"] = "ok"
    except Exception as e:
        status["status"] = "degraded"
        status["db"] = "error"
        return jsonify(status), 503

    redis_client = get_redis()
    if redis_client:
        try:
            redis_client.ping()
            status["redis"] = "ok"
        except Exception:
            status["redis"] = "error"
    else:
        status["redis"] = "unavailable"

    return jsonify(status), 200


@health_bp.route("/health-demo", methods=["GET"])
def canary_health_demo():
    return jsonify({"status": "ok", "canary": "health-demo"}), 200


@health_bp.route("/promo-demo", methods=["GET"])
def canary_promo_demo():
    return jsonify({"status": "ok", "canary": "promo-demo"}), 200


@health_bp.route("/checkout-demo", methods=["GET"])
def canary_checkout_demo():
    return jsonify({"status": "ok", "canary": "checkout-demo"}), 200


@health_bp.route("/dashboard-demo", methods=["GET"])
def canary_dashboard_demo():
    return jsonify({"status": "ok", "canary": "dashboard-demo"}), 200


@health_bp.route("/support-demo", methods=["GET"])
def canary_support_demo():
    return jsonify({"status": "ok", "canary": "support-demo"}), 200


@health_bp.route("/metrics", methods=["GET"])
def metrics():
    """Prometheus metrics endpoint."""
    release = get_release_info()
    flags = get_feature_flags()

    ghostlink_feature_flag_enabled.clear()
    for flag_name, enabled in flags.items():
        ghostlink_feature_flag_enabled.labels(flag=flag_name).set(1 if enabled else 0)

    ghostlink_release_info.clear()
    ghostlink_release_info.labels(
        version=release.version,
        git_sha=release.git_sha,
        deployed_at=release.deployed_at,
        release_owner=release.release_owner,
        release_notes_url=release.release_notes_url,
    ).set(1)

    recovery_state = get_recovery_state()
    ghostlink_rollbacks_total.set(float(recovery_state["rollbacks_total"]))
    ghostlink_mean_time_to_detect_minutes.set(
        float(recovery_state["mean_time_to_detect_minutes"])
    )
    ghostlink_mean_time_to_recover_minutes.set(
        float(recovery_state["mean_time_to_recover_minutes"])
    )
    ghostlink_recovery_attempts_total.set(
        float(recovery_state["recovery_attempts_total"])
    )
    ghostlink_recovery_success_total.set(
        float(recovery_state["recovery_success_total"])
    )

    active_count = Url.select().where(Url.is_active == True).count()
    inactive_count = Url.select().where(Url.is_active == False).count()

    urls_active_total.set(active_count)
    urls_inactive_total.set(inactive_count)

    threat_count = RiskScore.select().where(RiskScore.score > 60).count()
    risk_score_threats_total.set(threat_count)

    dead_count = HealthCheck.select().where(
        HealthCheck.health_status.in_(["DEAD", "SSL_INVALID"])
    ).count()
    destination_dead_total.set(dead_count)

    quarantined_codes = read_quarantined_codes() if flags["ENABLE_QUARANTINE_MODE"] else set()
    ghostlink_quarantined_urls_total.set(len(quarantined_codes))

    safe_count = RiskScore.select().where(RiskScore.tier == "SAFE").count()
    watchlist_count = RiskScore.select().where(RiskScore.tier == "WATCHLIST").count()
    threat_count = RiskScore.select().where(RiskScore.tier == "THREAT").count()

    ghostlink_safe_links_total.set(safe_count)
    ghostlink_watchlist_links_total.set(watchlist_count)
    ghostlink_threat_links_total.set(threat_count)

    ghostlink_risk_score.clear()
    risk_scores = (
        RiskScore.select(
            RiskScore.url_id,
            RiskScore.score,
            RiskScore.tier,
            Url.short_code.alias("short_code"),
        )
        .join(Url, on=(RiskScore.url_id == Url.id))
        .dicts()
    )
    threat_url_ids = []
    for item in risk_scores:
        tier = item["tier"] or "SAFE"
        ghostlink_risk_score.labels(short_code=item["short_code"], risk_level=tier).set(
            float(item["score"])
        )
        if tier == "THREAT":
            threat_url_ids.append(item["url_id"])

    affected_codes = set(quarantined_codes)
    if threat_url_ids:
        threat_codes = Url.select(Url.short_code).where(Url.id.in_(threat_url_ids))
        affected_codes.update(row.short_code for row in threat_codes)

    affected_redirects = 0
    if affected_codes:
        affected_code_list = list(affected_codes)
        affected_redirects = (
            Event.select()
            .join(Url, on=(Event.url_id == Url.id))
            .where(
                (Event.event_type == "redirect")
                & (Url.short_code.in_(affected_code_list))
            )
            .count()
        )
    ghostlink_affected_redirects_total.set(float(affected_redirects))

    canary_state = parse_canary_state() if flags["ENABLE_CANARY_MONITORING"] else {
        "success_total": 0.0,
        "failure_total": 0.0,
        "status": {code: 0.0 for code in CANARY_CODES},
        "latency": {code: 0.0 for code in CANARY_CODES},
    }
    ghostlink_canary_success_total.set(canary_state["success_total"])
    ghostlink_canary_failures_total.set(canary_state["failure_total"])
    ghostlink_canary_latency_seconds.clear()
    ghostlink_canary_status.clear()
    for canary_code in CANARY_CODES:
        ghostlink_canary_latency_seconds.labels(short_code=canary_code).set(
            canary_state["latency"][canary_code]
        )
        ghostlink_canary_status.labels(short_code=canary_code).set(
            canary_state["status"][canary_code]
        )

    if flags["ENABLE_GHOST_PROBE_ALERTS"]:
        ghostlink_suspicious_clients_total.set(float(suspicious_clients_count()))
        ghostlink_blocked_requests_total.set(float(total_blocked_requests()))
        ghostlink_invalid_short_code_hits_total.set(float(total_invalid_short_code_hits()))
        ghostlink_repeated_user_agent_hits_total.set(
            float(repeated_user_agent_hits_total())
        )
    else:
        ghostlink_suspicious_clients_total.set(0.0)
        ghostlink_blocked_requests_total.set(0.0)
        ghostlink_invalid_short_code_hits_total.set(0.0)
        ghostlink_repeated_user_agent_hits_total.set(0.0)

    ghostlink_suspicious_ip_score.clear()
    if flags["ENABLE_GHOST_PROBE_ALERTS"]:
        for ip, score in top_suspicious_ip_scores():
            ghostlink_suspicious_ip_score.labels(ip=ip).set(score)

    ghostlink_suspicious_user_agent_hits.clear()
    if flags["ENABLE_GHOST_PROBE_ALERTS"]:
        for user_agent, hits in top_suspicious_user_agents():
            ghostlink_suspicious_user_agent_hits.labels(user_agent=user_agent).set(hits)

    ghostlink_probed_short_code_hits.clear()
    if flags["ENABLE_GHOST_PROBE_ALERTS"]:
        for short_code, hits in top_probed_short_codes():
            ghostlink_probed_short_code_hits.labels(short_code=short_code).set(hits)

    return Response(generate_latest(registry), mimetype="text/plain")


def increment_urls_created():
    """Helper to increment URLs created counter."""
    urls_created_total.inc()


def increment_url_redirects(short_code):
    """Helper to increment redirect counter for a short code."""
    app_version = get_release_info().version
    url_redirects_total.labels(short_code=short_code, app_version=app_version).inc()


def record_redirect_latency(seconds):
    """Helper to record redirect latency."""
    redirect_latency_seconds.observe(seconds)


def increment_ghost_probes():
    """Helper to increment ghost probe counter."""
    ghost_probes_total.inc()


def increment_destination_dead():
    """Helper to increment dead destination counter."""
    destination_dead_total.inc()


def increment_urls_deleted():
    """Helper to increment URL delete counter."""
    urls_deleted_total.inc()
