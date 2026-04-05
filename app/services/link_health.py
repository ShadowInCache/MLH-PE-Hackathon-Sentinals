import time

import requests
from apscheduler.schedulers.background import BackgroundScheduler

from app.config.feature_flags import ENABLE_RISK_SCORING
from app.models.health_check import HealthCheck
from app.models.url import Url
from app.services.risk_scorer import compute_risk_score
from app.utils import utc_now_naive

scheduler = None


def check_url_health(url_id, original_url):
    """
    Perform a HEAD request to check URL health.
    Returns tuple: (status_code, latency_ms, health_status, redirect_chain_length)
    """
    try:
        start = time.time()
        response = requests.head(
            original_url, allow_redirects=True, timeout=10, verify=True
        )
        latency_ms = int((time.time() - start) * 1000)

        status_code = response.status_code
        redirect_count = len(response.history)

        if 400 <= status_code < 600:
            health_status = "DEAD"
        elif redirect_count > 2:
            health_status = "CHAINED"
        else:
            health_status = "OK"

        return status_code, latency_ms, health_status, redirect_count

    except requests.exceptions.SSLError:
        return None, None, "SSL_INVALID", 0
    except Exception:
        return None, None, "DEAD", 0


def check_all_urls():
    """Background worker: check health of all active URLs."""
    urls = Url.select().where(Url.is_active == True)

    for url in urls:
        status_code, latency_ms, health_status, chain_length = check_url_health(
            url.id, url.original_url
        )

        HealthCheck.create(
            url_id=url.id,
            checked_at=utc_now_naive(),
            status_code=status_code,
            latency_ms=latency_ms,
            health_status=health_status,
            redirect_chain_length=chain_length,
        )

        # Keep risk signals fresh as new health observations are collected.
        if ENABLE_RISK_SCORING:
            compute_risk_score(url.id)


def start_health_checker():
    """Start the background health checker (runs every 5 minutes)."""
    global scheduler

    if scheduler is not None:
        return

    scheduler = BackgroundScheduler()
    scheduler.add_job(check_all_urls, "interval", minutes=5, id="health_checker")
    scheduler.start()


def stop_health_checker():
    """Stop the background health checker."""
    global scheduler

    if scheduler:
        scheduler.shutdown()
        scheduler = None
