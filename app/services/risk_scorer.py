import json
from urllib.parse import urlparse

from app.models.event import Event
from app.models.health_check import HealthCheck
from app.models.risk_score import RiskScore
from app.models.url import Url
from app.services import cache
from app.utils import utc_now_naive

SUSPICIOUS_TLDS = {
    "zip",
    "top",
    "click",
    "xyz",
    "gq",
    "tk",
    "ml",
    "work",
    "link",
}


def compute_risk_score(url_id):
    """
    Compute a 0-100 risk score for a URL based on multiple signals.

    Scoring rules:
    - +30: destination domain is dead
    - +20: redirect chain > 3 hops
    - +15: link receives many ghost probes
    - +20: suspicious TLD detected
    - +15: repeated delete/recreate behavior detected

    Tiers: 0-30 SAFE, 31-60 WATCHLIST, 61-100 THREAT
    """
    url = Url.select().where(Url.id == url_id).first()
    if not url:
        return None

    score = 0
    signals = {}

    latest_health = (
        HealthCheck.select()
        .where(HealthCheck.url_id == url_id)
        .order_by(HealthCheck.checked_at.desc())
        .first()
    )

    if latest_health:
        is_dead_destination = (
            latest_health.health_status in {"DEAD", "SSL_INVALID"}
            or (
                latest_health.status_code is not None
                and 400 <= latest_health.status_code < 600
            )
        )

        if is_dead_destination:
            score += 30
            signals["destination_dead"] = True
            signals["status_code"] = latest_health.status_code

        if latest_health.redirect_chain_length > 3:
            score += 20
            signals["long_redirect_chain"] = True
            signals["chain_length"] = latest_health.redirect_chain_length

    ghost_probe_count = Event.select().where(
        (Event.url_id == url_id) & (Event.event_type == "ghost_probe")
    ).count()
    if ghost_probe_count >= 10:
        score += 15
        signals["ghost_probe_pressure"] = True
        signals["ghost_probe_count"] = ghost_probe_count

    parsed = urlparse(url.original_url)
    hostname = (parsed.hostname or "").lower()
    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        score += 20
        signals["suspicious_tld"] = tld

    delete_count = Event.select().where(
        (Event.url_id == url_id) & (Event.event_type == "deleted")
    ).count()
    create_count = Event.select().where(
        (Event.url_id == url_id) & (Event.event_type == "created")
    ).count()

    if delete_count >= 2 or (delete_count >= 1 and create_count >= 2):
        score += 15
        signals["delete_recreate_pattern"] = True
        signals["delete_count"] = delete_count
        signals["create_count"] = create_count

    score = min(score, 100)

    if score <= 30:
        tier = "SAFE"
    elif score <= 60:
        tier = "WATCHLIST"
    else:
        tier = "THREAT"

    risk_data = {
        "url_id": url_id,
        "score": score,
        "signals": json.dumps(signals),
        "tier": tier,
        "computed_at": utc_now_naive(),
    }

    RiskScore.insert(**risk_data).on_conflict(
        conflict_target=[RiskScore.url_id],
        update={
            RiskScore.score: score,
            RiskScore.signals: json.dumps(signals),
            RiskScore.tier: tier,
            RiskScore.computed_at: utc_now_naive(),
        },
    ).execute()

    cache_data = {"score": score, "tier": tier, "signals": signals}
    cache.cache_risk_score(url_id, cache_data)

    return risk_data


def get_risk_score(url_id):
    """
    Get risk score for a URL.
    Checks cache first, then database, computes if missing.
    """
    cached = cache.get_cached_risk_score(url_id)
    if cached:
        return cached

    risk = RiskScore.select().where(RiskScore.url_id == url_id).first()
    if risk:
        data = {
            "score": risk.score,
            "tier": risk.tier,
            "signals": json.loads(risk.signals) if risk.signals else {},
        }
        cache.cache_risk_score(url_id, data)
        return data

    return compute_risk_score(url_id)
