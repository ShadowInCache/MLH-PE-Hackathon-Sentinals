import os

from dotenv import load_dotenv
from flask import Flask

from app.database import ensure_tables, init_db
from app.routes import register_routes
from app.services.link_health import start_health_checker


def _is_truthy(value):
    return str(value).strip().lower() not in {"0", "false", "no", "off", ""}


def _should_start_health_checker(app):
    if app.config.get("TESTING") or os.environ.get("PYTEST_CURRENT_TEST"):
        return False

    enabled = os.environ.get("ENABLE_HEALTH_CHECKER", "1")
    return _is_truthy(enabled)


def create_app(testing=False):
    load_dotenv()

    app = Flask(__name__)
    app.config["TESTING"] = bool(testing)

    init_db(app)

    from app.database import db

    try:
        db.connect(reuse_if_open=True)
        ensure_tables()
    except Exception as exc:
        app.logger.warning("Could not create tables on startup: %s", exc)
    finally:
        if not db.is_closed():
            db.close()

    register_routes(app)

    if _should_start_health_checker(app):
        start_health_checker()

    return app
