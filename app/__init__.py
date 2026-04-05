from dotenv import load_dotenv
from flask import Flask

from app.database import init_db
from app.routes import register_routes
from app.services.link_health import start_health_checker


def create_app():
    load_dotenv()

    app = Flask(__name__)

    init_db(app)

    from app import models
    from app.database import db
    from app.models import Event, HealthCheck, RiskScore, Url, User

    try:
        db.connect(reuse_if_open=True)
        db.create_tables([User, Url, Event, HealthCheck, RiskScore], safe=True)
        db.close()
    except Exception as e:
        import logging
        logging.warning(f"Could not create tables on startup: {e}")

    register_routes(app)

    start_health_checker()

    return app
