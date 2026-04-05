from flask import Blueprint, jsonify, request

from app.models.event import Event
from app.models.url import Url

events_bp = Blueprint("events", __name__)


def _coerce_positive_int(value, default):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def event_to_dict(event):
    return {
        "id": event.id,
        "event_type": event.event_type,
        "url_id": event.url_id,
        "user_id": event.user_id,
        "referrer": event.referrer,
    }


@events_bp.route("/events", methods=["GET"])
def list_events():
    query = Event.select().order_by(Event.id)

    url_id = request.args.get("url_id", type=int)
    user_id = request.args.get("user_id", type=int)
    event_type = request.args.get("event_type")

    if url_id is not None:
        query = query.where(Event.url_id == url_id)
    if user_id is not None:
        query = query.where(Event.user_id == user_id)
    if event_type:
        query = query.where(Event.event_type == event_type)

    page = _coerce_positive_int(request.args.get("page", 1), 1)
    per_page = _coerce_positive_int(request.args.get("per_page", 100), 100)

    events = [event_to_dict(e) for e in query.paginate(page, per_page)]
    return jsonify(events), 200


@events_bp.route("/events", methods=["POST"])
def create_event():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Missing request body", "code": 400}), 400

    event_type = (data.get("event_type") or "").strip()
    if not event_type:
        return jsonify({"error": "Missing event_type", "code": 400}), 400

    url_id = data.get("url_id")
    if url_id is None:
        return jsonify({"error": "Missing url_id", "code": 400}), 400

    try:
        url_id = int(url_id)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid url_id", "code": 400}), 400

    if not Url.select().where(Url.id == url_id).exists():
        return jsonify({"error": "URL not found", "code": 404}), 404

    user_id = data.get("user_id")
    if user_id is not None:
        try:
            user_id = int(user_id)
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid user_id", "code": 400}), 400

    # Accept referrer at top level or nested inside details dict
    details = data.get("details")
    if details is not None and not isinstance(details, dict):
        return jsonify({"error": "Invalid details, must be an object", "code": 400}), 400
    if details is None:
        details = {}
    referrer = data.get("referrer") or details.get("referrer")

    event = Event.create(
        url_id=url_id,
        user_id=user_id,
        event_type=event_type,
        referrer=referrer,
    )
    return jsonify(event_to_dict(event)), 201
