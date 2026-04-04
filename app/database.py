import os

import redis
from peewee import DatabaseProxy, Model, PostgresqlDatabase

db = DatabaseProxy()
redis_client = None


class BaseModel(Model):
    class Meta:
        database = db


def init_db(app):
    global redis_client

    database = PostgresqlDatabase(
        os.environ.get("DATABASE_NAME", "hackathon_db"),
        host=os.environ.get("DATABASE_HOST", "localhost"),
        port=int(os.environ.get("DATABASE_PORT", 5432)),
        user=os.environ.get("DATABASE_USER", "postgres"),
        password=os.environ.get("DATABASE_PASSWORD", "postgres"),
    )
    db.initialize(database)

    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    try:
        redis_client = redis.from_url(
            redis_url, decode_responses=True, socket_connect_timeout=2, socket_timeout=2
        )
        redis_client.ping()
        app.logger.info("Redis connection established")
    except Exception as e:
        app.logger.warning(f"Redis connection failed: {e}. Continuing without cache.")
        redis_client = None

    @app.before_request
    def _db_connect():
        db.connect(reuse_if_open=True)

    @app.teardown_appcontext
    def _db_close(exc):
        if not db.is_closed():
            db.close()


def get_redis():
    return redis_client
