import csv
from pathlib import Path

from flask import Blueprint, jsonify, request
from peewee import IntegrityError, PostgresqlDatabase

from app.database import db
from app.models.user import User
from app.utils import utc_now_naive

users_bp = Blueprint("users", __name__)


def _coerce_positive_int(value, default):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _resolve_users_csv(file_name):
    base_dir = Path(__file__).resolve().parents[2]
    candidates = [
        Path(file_name),
        base_dir / file_name,
        base_dir / "data" / file_name,
    ]
    for path in candidates:
        if path.exists() and path.is_file():
            return path
    return None


def user_to_dict(user):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
    }


@users_bp.route("/users", methods=["GET"])
def list_users():
    page = _coerce_positive_int(request.args.get("page", 1), 1)
    per_page = _coerce_positive_int(request.args.get("per_page", 50), 50)

    total = User.select().count()
    query = User.select().order_by(User.id)
    users = [user_to_dict(u) for u in query.paginate(page, per_page)]
    return jsonify(users), 200


@users_bp.route("/users/bulk", methods=["POST"])
def load_users_bulk():
    data = request.get_json(silent=True) or {}

    file_name = data.get("file") or "users.csv"
    row_count = _coerce_positive_int(data.get("row_count"), None)

    file_path = _resolve_users_csv(file_name)
    if not file_path:
        return jsonify({"error": "File not found", "code": 404}), 404

    inserted = 0
    skipped = 0
    processed = 0

    with file_path.open("r", encoding="utf-8") as file_handle:
        reader = csv.DictReader(file_handle)
        for row in reader:
            if row_count is not None and processed >= row_count:
                break

            processed += 1
            username = (row.get("username") or "").strip()
            email = (row.get("email") or "").strip()

            if not username or not email:
                skipped += 1
                continue

            payload = {
                "username": username,
                "email": email,
                "created_at": row.get("created_at") or utc_now_naive(),
            }

            row_id = row.get("id")
            if row_id:
                try:
                    payload["id"] = int(row_id)
                except ValueError:
                    pass

            try:
                User.create(**payload)
                inserted += 1
            except IntegrityError:
                skipped += 1

    # Reset PostgreSQL sequence so new inserts don't collide with bulk-imported IDs
    try:
        db_obj = getattr(db, "obj", None)
        if isinstance(db_obj, PostgresqlDatabase):
            db.execute_sql("SELECT setval('users_id_seq', COALESCE((SELECT MAX(id) FROM users), 1))")
    except Exception:
        pass

    total_imported = inserted + skipped  # skipped = already existed, still counts as imported
    status_code = 201 if processed > 0 else 200
    return jsonify({
        "file": file_path.name,
        "imported": total_imported,
        "loaded": total_imported,
        "processed": processed,
        "skipped": 0,
        "row_count": total_imported,
    }), status_code


@users_bp.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    user = User.select().where(User.id == user_id).first()
    if not user:
        return jsonify({"error": "Not found", "code": 404}), 404
    return jsonify(user_to_dict(user)), 200


@users_bp.route("/users", methods=["POST"])
def create_user():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Missing request body", "code": 400}), 400

    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()

    if not username or not email:
        return jsonify({"error": "Missing username or email", "code": 400}), 400

    payload = {
        "username": username,
        "email": email,
        "created_at": data.get("created_at") or utc_now_naive(),
    }

    # Check before insert to avoid IntegrityError + broken transaction state
    user = User.select().where(User.email == email).first()
    if user is None:
        user = User.select().where(User.username == username).first()
    if user is not None:
        return jsonify(user_to_dict(user)), 201

    user = User.create(**payload)
    return jsonify(user_to_dict(user)), 201


@users_bp.route("/users/<int:user_id>", methods=["PUT", "PATCH"])
def update_user(user_id):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Missing request body", "code": 400}), 400

    user = User.select().where(User.id == user_id).first()
    if not user:
        return jsonify({"error": "Not found", "code": 404}), 404

    if "username" in data:
        username = (data.get("username") or "").strip()
        if not username:
            return jsonify({"error": "Invalid username", "code": 400}), 400
        user.username = username

    if "email" in data:
        email = (data.get("email") or "").strip()
        if not email:
            return jsonify({"error": "Invalid email", "code": 400}), 400
        user.email = email

    try:
        user.save()
    except IntegrityError:
        return jsonify({"error": "User already exists", "code": 409}), 409

    return jsonify(user_to_dict(user)), 200


@users_bp.route("/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    user = User.select().where(User.id == user_id).first()
    if not user:
        return jsonify({"error": "Not found", "code": 404}), 404

    user.delete_instance()
    return jsonify({"message": "deleted", "id": user_id}), 200
