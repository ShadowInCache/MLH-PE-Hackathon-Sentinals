import os

import pytest
from peewee import SqliteDatabase

from app import create_app
from app.database import db
from app.models import Event, HealthCheck, RequestFingerprint, RiskScore, Url, User


@pytest.fixture(scope="function")
def app():
    """Create and configure a test Flask app instance."""
    os.environ["DATABASE_NAME"] = "test_ghostlink"
    os.environ["REDIS_URL"] = "redis://localhost:6379/15"

    test_app = create_app()
    test_app.config["TESTING"] = True

    with test_app.app_context():
        test_db = SqliteDatabase(
            ":memory:", pragmas={"foreign_keys": 1}, check_same_thread=False
        )
        db.initialize(test_db)
        db.connect(reuse_if_open=True)
        db.create_tables([Url, User, Event, HealthCheck, RiskScore, RequestFingerprint])
        yield test_app
        db.drop_tables([Url, User, Event, HealthCheck, RiskScore, RequestFingerprint])
        db.close()


@pytest.fixture(scope="function")
def client(app):
    """Create a test client for the app."""
    return app.test_client()


@pytest.fixture(scope="function")
def sample_user():
    """Create a sample user in the database."""
    user = User.create(username="testuser", email="test@example.com")
    return user


@pytest.fixture(scope="function")
def sample_url(sample_user):
    """Create a sample URL in the database."""
    url = Url.create(
        user_id=sample_user.id,
        short_code="abc123",
        original_url="https://example.com",
        title="Example Site",
        is_active=True,
    )
    return url
