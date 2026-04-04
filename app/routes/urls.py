import time
from urllib.parse import urlparse

from flask import Blueprint, jsonify, redirect, request
from peewee import IntegrityError
from playhouse.shortcuts import model_to_dict

from app.models.event import Event
from app.models.url import Url
from app.routes.health import (
    increment_ghost_probes,
    increment_url_redirects,
    increment_urls_created,
    increment_urls_deleted,
    record_redirect_latency,
)
from app.services import cache, shortener
from app.services.risk_scorer import compute_risk_score, get_risk_score
from app.services.security import is_quarantined_code, record_request_fingerprint
from app.utils import utc_now_naive

urls_bp = Blueprint("urls", __name__)


def is_valid_url(url):
    """Validate URL format."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme in ["http", "https"]
    except Exception:
        return False


def get_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


@urls_bp.route("/shorten", methods=["POST"])
def shorten_url():
    """Create a shortened URL."""
    data = request.get_json(silent=True)

    if data is None:
        return jsonify({"error": "Missing request body", "code": 400}), 400

    original_url = data.get("original_url")
    if not original_url:
        return jsonify({"error": "Missing original_url", "code": 400}), 400

    if not is_valid_url(original_url):
        return jsonify({"error": "Invalid URL", "code": 422}), 422

    custom_code = data.get("short_code")
    user_id = data.get("user_id")
    title = data.get("title")

    if custom_code:
        if not shortener.is_code_available(custom_code):
            return jsonify({"error": "Short code exists", "code": 409}), 409
        short_code = custom_code
    else:
        try:
            short_code = shortener.generate_short_code()
        except ValueError:
            return jsonify({"error": "Failed to generate short code", "code": 500}), 500

    try:
        url = Url.create(
            user_id=user_id,
            short_code=short_code,
            original_url=original_url,
            title=title,
            is_active=True,
        )

        Event.create(url_id=url.id, user_id=user_id, event_type="created")

        cache.cache_url(short_code, original_url)

        compute_risk_score(url.id)
        increment_urls_created()

        return jsonify({"id": url.id, "short_code": short_code}), 201

    except IntegrityError:
        return jsonify({"error": "Short code exists", "code": 409}), 409


@urls_bp.route("/<short_code>", methods=["GET"])
def redirect_url(short_code):
    """Redirect to the original URL."""
    start_time = time.perf_counter()
    client_ip = get_client_ip()
    user_agent = request.headers.get("User-Agent", "unknown")

    if is_quarantined_code(short_code):
        record_request_fingerprint(
            short_code=short_code,
            status_code=410,
            client_ip=client_ip,
            user_agent=user_agent,
            is_quarantined=True,
        )
        return (
            jsonify(
                {
                    "error": "This short code has been quarantined due to suspicious activity",
                    "code": 410,
                }
            ),
            410,
        )

    cached = cache.get_cached_url(short_code)
    if cached:
        url = Url.select().where(Url.short_code == short_code).first()
        if url and url.is_active:
            Event.create(url_id=url.id, user_id=url.user_id, event_type="redirect")

        increment_url_redirects(short_code)
        record_redirect_latency(max(time.perf_counter() - start_time, 0.0))
        record_request_fingerprint(
            short_code=short_code,
            status_code=302,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        return redirect(cached, code=302)

    url = Url.select().where(Url.short_code == short_code).first()

    if not url:
        record_request_fingerprint(
            short_code=short_code,
            status_code=404,
            client_ip=client_ip,
            user_agent=user_agent,
            is_invalid_short_code=True,
        )
        return jsonify({"error": "Not found", "code": 404}), 404

    if not url.is_active:
        increment_ghost_probes()
        Event.create(url_id=url.id, user_id=url.user_id, event_type="ghost_probe")
        record_request_fingerprint(
            short_code=short_code,
            status_code=410,
            client_ip=client_ip,
            user_agent=user_agent,
            is_ghost_probe=True,
        )
        compute_risk_score(url.id)
        return jsonify({"error": "Link inactive", "code": 410}), 410

    cache.cache_url(short_code, url.original_url)

    Event.create(url_id=url.id, user_id=url.user_id, event_type="redirect")
    increment_url_redirects(short_code)
    record_redirect_latency(max(time.perf_counter() - start_time, 0.0))
    record_request_fingerprint(
        short_code=short_code,
        status_code=302,
        client_ip=client_ip,
        user_agent=user_agent,
    )

    return redirect(url.original_url, code=302)


@urls_bp.route("/urls/<int:url_id>", methods=["PATCH"])
def update_url(url_id):
    """Update a URL (title, original_url, is_active)."""
    data = request.get_json(silent=True)

    if data is None:
        return jsonify({"error": "Missing request body", "code": 400}), 400

    url = Url.select().where(Url.id == url_id).first()
    if not url:
        return jsonify({"error": "Not found", "code": 404}), 404

    if "original_url" in data:
        if not is_valid_url(data["original_url"]):
            return jsonify({"error": "Invalid URL", "code": 422}), 422
        url.original_url = data["original_url"]
        cache.delete_cached_url(url.short_code)

    if "title" in data:
        url.title = data["title"]

    if "is_active" in data:
        url.is_active = data["is_active"]
        if not url.is_active:
            cache.delete_cached_url(url.short_code)

    url.updated_at = utc_now_naive()
    url.save()

    Event.create(url_id=url.id, user_id=data.get("user_id"), event_type="updated")
    compute_risk_score(url.id)

    return jsonify({"message": "updated"}), 200


@urls_bp.route("/urls/<int:url_id>", methods=["DELETE"])
def delete_url(url_id):
    """Soft delete a URL (set is_active=False)."""
    url = Url.select().where(Url.id == url_id).first()
    if not url:
        return jsonify({"error": "Not found", "code": 404}), 404

    url.is_active = False
    url.updated_at = utc_now_naive()
    url.save()

    cache.delete_cached_url(url.short_code)

    user_id = request.get_json(silent=True).get("user_id") if request.get_json(silent=True) else None
    Event.create(url_id=url.id, user_id=user_id, event_type="deleted")
    increment_urls_deleted()
    compute_risk_score(url.id)

    return jsonify({"message": "deleted"}), 200


@urls_bp.route("/urls/<int:url_id>/risk", methods=["GET"])
def get_url_risk(url_id):
    """Return risk score details for a URL."""
    url = Url.select().where(Url.id == url_id).first()
    if not url:
        return jsonify({"error": "Not found", "code": 404}), 404

    risk = get_risk_score(url_id)
    if not risk:
        return jsonify({"error": "Risk score unavailable", "code": 404}), 404

    return jsonify({"url_id": url_id, **risk}), 200


@urls_bp.route("/urls", methods=["GET"])
def list_urls():
    """List all URLs, optionally filtered by user_id."""
    user_id = request.args.get("user_id", type=int)

    query = Url.select()
    if user_id:
        query = query.where(Url.user_id == user_id)

    urls = [model_to_dict(url) for url in query]
    return jsonify(urls), 200
