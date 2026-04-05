import time
from urllib.parse import urlparse

from flask import Blueprint, jsonify, redirect, request
from peewee import IntegrityError

from app.models.event import Event
from app.models.url import Url
from app.models.user import User
from app.routes.health import (
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


def parse_json_object(required=True):
    data = request.get_json(silent=True)
    if data is None:
        has_payload = bool((request.get_data(cache=True, as_text=False) or b"").strip())
        if has_payload:
            return None, (jsonify({"error": "Missing request body", "code": 400}), 400)
        if required:
            return None, (jsonify({"error": "Missing request body", "code": 400}), 400)
        return {}, None
    if not isinstance(data, dict):
        return None, (jsonify({"error": "Missing request body", "code": 400}), 400)
    return data, None


def coerce_optional_user_id(data):
    user_id = data.get("user_id")
    if user_id is None:
        return None, None

    if isinstance(user_id, bool):
        return None, (jsonify({"error": "Invalid user_id", "code": 400}), 400)

    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        return None, (jsonify({"error": "Invalid user_id", "code": 400}), 400)

    if user_id <= 0:
        return None, (jsonify({"error": "Invalid user_id", "code": 400}), 400)

    if not User.select().where(User.id == user_id).exists():
        return None, (jsonify({"error": "Invalid user_id", "code": 400}), 400)

    return user_id, None


def coerce_optional_short_code(data):
    has_short_code = "short_code" in data or "shortcode" in data
    custom_code = data.get("short_code") if "short_code" in data else data.get("shortcode")

    if not has_short_code:
        return None, None

    if not isinstance(custom_code, str):
        return None, (jsonify({"error": "Invalid short_code", "code": 422}), 422)

    custom_code = custom_code.strip()
    if not custom_code:
        return None, (jsonify({"error": "Invalid short_code", "code": 422}), 422)

    if len(custom_code) > 10 or not custom_code.isalnum():
        return None, (jsonify({"error": "Invalid short_code", "code": 422}), 422)

    return custom_code, None


def url_to_dict(url):
    return {
        "id": url.id,
        "short_code": url.short_code,
        "original_url": url.original_url,
        "title": url.title,
        "is_active": url.is_active,
        "user_id": url.user_id,
    }


@urls_bp.route("/shorten", methods=["POST"])
def shorten_url():
    data, error_response = parse_json_object(required=True)
    if error_response:
        return error_response

    original_url = data.get("original_url")
    if original_url is None or original_url == "":
        return jsonify({"error": "Missing original_url", "code": 400}), 400

    if not isinstance(original_url, str) or not is_valid_url(original_url):
        return jsonify({"error": "Invalid URL", "code": 422}), 422

    custom_code, error_response = coerce_optional_short_code(data)
    if error_response:
        return error_response

    user_id, error_response = coerce_optional_user_id(data)
    if error_response:
        return error_response

    title = data.get("title")
    if title is not None and not isinstance(title, str):
        return jsonify({"error": "Invalid title", "code": 400}), 400

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


@urls_bp.route("/urls", methods=["POST"])
def create_url():
    data, error_response = parse_json_object(required=True)
    if error_response:
        return error_response

    original_url = data.get("original_url")
    if original_url is None or original_url == "":
        return jsonify({"error": "Missing original_url", "code": 400}), 400

    if not isinstance(original_url, str) or not is_valid_url(original_url):
        return jsonify({"error": "Invalid URL", "code": 422}), 422

    if data.get("user_id") is None:
        return jsonify({"error": "Missing user_id", "code": 400}), 400

    user_id, error_response = coerce_optional_user_id(data)
    if error_response:
        return error_response

    title = data.get("title")
    if title is not None and not isinstance(title, str):
        return jsonify({"error": "Invalid title", "code": 400}), 400

    custom_code, error_response = coerce_optional_short_code(data)
    if error_response:
        return error_response

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
        return jsonify(url_to_dict(url)), 201
    except IntegrityError:
        return jsonify({"error": "Short code exists", "code": 409}), 409


@urls_bp.route("/<short_code>", methods=["GET"])
def redirect_url(short_code):
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
        cache.delete_cached_url(short_code)

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


@urls_bp.route("/urls/<int:url_id>", methods=["GET"])
def get_url(url_id):
    url = Url.select().where(Url.id == url_id).first()
    if not url:
        return jsonify({"error": "Not found", "code": 404}), 404
    return jsonify(url_to_dict(url)), 200


@urls_bp.route("/urls/<short_code>", methods=["GET"])
def redirect_by_shortcode(short_code):
    """Redirect via /urls/<short_code> path."""
    return redirect_url(short_code)


@urls_bp.route("/urls/<int:url_id>", methods=["PATCH", "PUT"])
def update_url(url_id):
    data, error_response = parse_json_object(required=True)
    if error_response:
        return error_response

    mutable_fields = {"original_url", "title", "is_active"}
    allowed_fields = set(mutable_fields)
    allowed_fields.add("user_id")

    unknown_fields = [field for field in data.keys() if field not in allowed_fields]
    if unknown_fields:
        return jsonify({"error": "Invalid request body", "code": 400}), 400

    if not any(field in data for field in mutable_fields):
        return jsonify({"error": "Missing update fields", "code": 400}), 400

    url = Url.select().where(Url.id == url_id).first()
    if not url:
        return jsonify({"error": "Not found", "code": 404}), 404

    event_user_id, error_response = coerce_optional_user_id(data)
    if error_response:
        return error_response

    if (
        event_user_id is not None
        and url.user_id is not None
        and event_user_id != url.user_id
    ):
        return jsonify({"error": "Forbidden", "code": 403}), 403

    if "original_url" in data:
        original_url = data["original_url"]
        if not isinstance(original_url, str) or not is_valid_url(original_url):
            return jsonify({"error": "Invalid URL", "code": 422}), 422
        url.original_url = original_url
        cache.delete_cached_url(url.short_code)

    if "title" in data:
        title = data.get("title")
        if title is not None and not isinstance(title, str):
            return jsonify({"error": "Invalid title", "code": 400}), 400
        url.title = title

    if "is_active" in data:
        is_active = data["is_active"]
        if not isinstance(is_active, bool):
            return jsonify({"error": "Invalid is_active", "code": 400}), 400
        url.is_active = is_active
        if not url.is_active:
            cache.delete_cached_url(url.short_code)

    url.updated_at = utc_now_naive()
    url.save()

    Event.create(
        url_id=url.id,
        user_id=event_user_id if event_user_id is not None else url.user_id,
        event_type="updated",
    )
    compute_risk_score(url.id)

    result = url_to_dict(url)
    result["message"] = "updated"
    return jsonify(result), 200


@urls_bp.route("/urls/<int:url_id>", methods=["DELETE"])
def delete_url(url_id):
    url = Url.select().where(Url.id == url_id).first()
    if not url:
        return jsonify({"error": "Not found", "code": 404}), 404

    body, error_response = parse_json_object(required=False)
    if error_response:
        return error_response

    event_user_id, error_response = coerce_optional_user_id(body)
    if error_response:
        return error_response

    if (
        event_user_id is not None
        and url.user_id is not None
        and event_user_id != url.user_id
    ):
        return jsonify({"error": "Forbidden", "code": 403}), 403

    url.is_active = False
    url.updated_at = utc_now_naive()
    url.save()

    cache.delete_cached_url(url.short_code)

    Event.create(
        url_id=url.id,
        user_id=event_user_id if event_user_id is not None else url.user_id,
        event_type="deleted",
    )
    increment_urls_deleted()
    compute_risk_score(url.id)

    return jsonify({"message": "deleted"}), 200


@urls_bp.route("/urls/<int:url_id>/risk", methods=["GET"])
def get_url_risk(url_id):
    url = Url.select().where(Url.id == url_id).first()
    if not url:
        return jsonify({"error": "Not found", "code": 404}), 404

    risk = get_risk_score(url_id)
    if not risk:
        return jsonify({"error": "Risk score unavailable", "code": 404}), 404

    return jsonify({"url_id": url_id, **risk}), 200


@urls_bp.route("/urls", methods=["GET"])
def list_urls():
    user_id = request.args.get("user_id", type=int)
    is_active_param = request.args.get("is_active")

    query = Url.select()
    if user_id is not None:
        query = query.where(Url.user_id == user_id)

    if is_active_param is not None:
        normalized = is_active_param.strip().lower()
        if normalized in ("1", "true", "yes"):
            query = query.where(Url.is_active == True)
        elif normalized in ("0", "false", "no"):
            query = query.where(Url.is_active == False)

    urls = [url_to_dict(u) for u in query]
    return jsonify(urls), 200


@urls_bp.route("/r/<short_code>", methods=["GET"])
def redirect_url_r(short_code):
    """Alias redirect route at /r/<short_code>."""
    return redirect_url(short_code)
