import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from app.models import Event, HealthCheck, RiskScore, Url, User
from app.services import cache, risk_scorer, shortener


class TestShortener:
    def test_generate_short_code_length(self, app):
        """Test that generated short codes are 6 characters."""
        with app.app_context():
            code = shortener.generate_short_code()
            assert len(code) == 7

    def test_generate_short_code_alphanumeric(self, app):
        """Test that generated short codes are alphanumeric."""
        with app.app_context():
            code = shortener.generate_short_code()
            assert code.isalnum()

    def test_generate_short_code_unique(self, app, sample_url):
        """Test that collision detection works."""
        with app.app_context():
            code = shortener.generate_short_code()
            assert code != sample_url.short_code

    def test_is_code_available_true(self, app):
        """Test code availability check for available code."""
        with app.app_context():
            assert shortener.is_code_available("xyz789") is True

    def test_is_code_available_false(self, app, sample_url):
        """Test code availability check for taken code."""
        with app.app_context():
            assert shortener.is_code_available(sample_url.short_code) is False


class TestCache:
    def test_cache_and_get_url(self, app):
        """Test URL caching and retrieval."""
        with app.app_context():
            cache.cache_url("test123", "https://example.com")
            result = cache.get_cached_url("test123")
            if result:
                assert result == "https://example.com"

    def test_delete_cached_url(self, app):
        """Test URL cache deletion."""
        with app.app_context():
            cache.cache_url("test456", "https://example.com")
            cache.delete_cached_url("test456")
            result = cache.get_cached_url("test456")
            assert result is None

    def test_cache_and_get_risk_score(self, app):
        """Test risk score caching and retrieval."""
        with app.app_context():
            score_data = {"score": 50, "tier": "WATCHLIST", "signals": {}}
            cache.cache_risk_score(1, score_data)
            result = cache.get_cached_risk_score(1)
            if result:
                assert result["score"] == 50
                assert result["tier"] == "WATCHLIST"


class TestRiskScorer:
    def test_compute_risk_score_safe(self, app, sample_url):
        """Test risk score computation for safe URL."""
        with app.app_context():
            HealthCheck.create(
                url_id=sample_url.id,
                status_code=200,
                health_status="OK",
                redirect_chain_length=0,
            )

            result = risk_scorer.compute_risk_score(sample_url.id)
            assert result["score"] <= 30
            assert result["tier"] == "SAFE"

    def test_compute_risk_score_dead_destination(self, app, sample_url):
        """Test risk score with dead destination."""
        with app.app_context():
            HealthCheck.create(
                url_id=sample_url.id,
                status_code=404,
                health_status="DEAD",
                redirect_chain_length=0,
            )

            result = risk_scorer.compute_risk_score(sample_url.id)
            assert result["score"] >= 30
            signals = json.loads(result["signals"])
            assert signals.get("destination_dead") is True

    def test_compute_risk_score_ghost_probe(self, app, sample_url):
        """Test risk score with ghost probe detection."""
        with app.app_context():
            for _ in range(10):
                Event.create(
                    url_id=sample_url.id,
                    user_id=sample_url.user_id,
                    event_type="ghost_probe",
                )

            result = risk_scorer.compute_risk_score(sample_url.id)
            assert result["score"] >= 15
            signals = json.loads(result["signals"])
            assert signals.get("ghost_probe_pressure") is True

    def test_compute_risk_score_long_chain(self, app, sample_url):
        """Test risk score with long redirect chain."""
        with app.app_context():
            HealthCheck.create(
                url_id=sample_url.id,
                status_code=200,
                health_status="CHAINED",
                redirect_chain_length=5,
            )

            result = risk_scorer.compute_risk_score(sample_url.id)
            signals = json.loads(result["signals"])
            assert signals.get("long_redirect_chain") is True

    def test_compute_risk_score_deletion_spike(self, app, sample_user):
        """Test risk score with user deletion spike."""
        with app.app_context():
            url = Url.create(
                user_id=sample_user.id,
                short_code="del123",
                original_url="https://example.com",
                is_active=True,
            )

            for _ in range(4):
                Event.create(
                    url_id=url.id, user_id=sample_user.id, event_type="deleted"
                )

            result = risk_scorer.compute_risk_score(url.id)
            assert result["score"] >= 15
            signals = json.loads(result["signals"])
            assert signals.get("delete_recreate_pattern") is True

    def test_compute_risk_score_threat_tier(self, app, sample_url):
        """Test risk score reaches THREAT tier."""
        with app.app_context():
            for _ in range(12):
                Event.create(
                    url_id=sample_url.id,
                    user_id=sample_url.user_id,
                    event_type="ghost_probe",
                )

            HealthCheck.create(
                url_id=sample_url.id,
                status_code=404,
                health_status="DEAD",
                redirect_chain_length=5,
            )

            result = risk_scorer.compute_risk_score(sample_url.id)
            assert result["score"] >= 61
            assert result["tier"] == "THREAT"

    def test_get_risk_score_from_cache(self, app, sample_url):
        """Test risk score retrieval from cache."""
        with app.app_context():
            RiskScore.create(
                url_id=sample_url.id,
                score=40,
                tier="WATCHLIST",
                signals=json.dumps({}),
            )

            cache_data = {"score": 40, "tier": "WATCHLIST", "signals": {}}
            cache.cache_risk_score(sample_url.id, cache_data)

            result = risk_scorer.get_risk_score(sample_url.id)
            assert result["score"] == 40
            assert result["tier"] == "WATCHLIST"
