import json
import os
import tempfile

import pytest

from app.models import Event, Url
from app.services import cache, security


class TestShortenURL:
    def test_shorten_url_success(self, client):
        """Test successful URL shortening."""
        response = client.post(
            "/shorten",
            json={"original_url": "https://example.com", "title": "Test Site"},
        )

        assert response.status_code == 201
        data = response.get_json()
        assert "id" in data
        assert "short_code" in data
        assert len(data["short_code"]) == 6

    def test_shorten_url_custom_code(self, client):
        """Test URL shortening with custom short code."""
        response = client.post(
            "/shorten",
            json={
                "original_url": "https://example.com",
                "short_code": "custom1",
            },
        )

        assert response.status_code == 201
        data = response.get_json()
        assert data["short_code"] == "custom1"

    def test_shorten_url_duplicate_code(self, client, sample_url):
        """Test 409 error when short code already exists."""
        response = client.post(
            "/shorten",
            json={
                "original_url": "https://example.com",
                "short_code": sample_url.short_code,
            },
        )

        assert response.status_code == 409
        data = response.get_json()
        assert data["error"] == "Short code exists"
        assert data["code"] == 409

    def test_shorten_url_invalid_url(self, client):
        """Test 422 error for invalid URL."""
        response = client.post("/shorten", json={"original_url": "not-a-url"})

        assert response.status_code == 422
        data = response.get_json()
        assert data["error"] == "Invalid URL"
        assert data["code"] == 422

    def test_shorten_url_missing_body(self, client):
        """Test 400 error for missing request body."""
        response = client.post("/shorten")

        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "Missing request body"
        assert data["code"] == 400

    def test_shorten_url_missing_field(self, client):
        """Test 400 error for missing original_url."""
        response = client.post("/shorten", json={"title": "No URL"})

        assert response.status_code == 400
        data = response.get_json()
        assert data["code"] == 400

    def test_shorten_url_creates_event(self, client, sample_user):
        """Test that URL creation creates an event."""
        response = client.post(
            "/shorten",
            json={
                "original_url": "https://example.com",
                "user_id": sample_user.id,
            },
        )

        assert response.status_code == 201
        data = response.get_json()

        event = Event.select().where(Event.url_id == data["id"]).first()
        assert event is not None
        assert event.event_type == "created"


class TestRedirectURL:
    def test_redirect_success(self, client, sample_url):
        """Test successful URL redirect."""
        response = client.get(f"/{sample_url.short_code}", follow_redirects=False)

        assert response.status_code == 302
        assert response.location == sample_url.original_url

    def test_redirect_not_found(self, client):
        """Test 404 error for unknown short code."""
        response = client.get("/unknown")

        assert response.status_code == 404
        data = response.get_json()
        assert data["error"] == "Not found"
        assert data["code"] == 404

    def test_redirect_inactive_url(self, client, sample_url):
        """Test 410 error for inactive URL."""
        sample_url.is_active = False
        sample_url.save()

        response = client.get(f"/{sample_url.short_code}")

        assert response.status_code == 410
        data = response.get_json()
        assert data["error"] == "Link inactive"
        assert data["code"] == 410

    def test_redirect_inactive_url_with_stale_cache(self, client, sample_url, monkeypatch):
        """Test inactive URL does not redirect when stale cache entry exists."""
        sample_url.is_active = False
        sample_url.save()

        monkeypatch.setattr(
            cache, "get_cached_url", lambda _: sample_url.original_url
        )

        response = client.get(f"/{sample_url.short_code}")

        assert response.status_code == 410
        data = response.get_json()
        assert data["error"] == "Link inactive"
        assert data["code"] == 410

    def test_redirect_quarantined_url(self, client, sample_url):
        """Test 410 error for quarantined short code."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as tmp:
            tmp.write("~^/abc123$ 1;\n")
            blocked_path = tmp.name

        original_path = security.BLOCKED_CODES_PATH
        security.BLOCKED_CODES_PATH = blocked_path
        try:
            response = client.get(f"/{sample_url.short_code}")
        finally:
            security.BLOCKED_CODES_PATH = original_path
            try:
                os.remove(blocked_path)
            except OSError:
                pass

        assert response.status_code == 410
        data = response.get_json()
        assert data["error"] == "This short code has been quarantined due to suspicious activity"
        assert data["code"] == 410


class TestUpdateURL:
    def test_update_url_title(self, client, sample_url):
        """Test updating URL title."""
        response = client.patch(
            f"/urls/{sample_url.id}", json={"title": "Updated Title"}
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["message"] == "updated"

        sample_url = Url.get_by_id(sample_url.id)
        assert sample_url.title == "Updated Title"

    def test_update_url_original_url(self, client, sample_url):
        """Test updating original URL."""
        response = client.patch(
            f"/urls/{sample_url.id}",
            json={"original_url": "https://newexample.com"},
        )

        assert response.status_code == 200

        sample_url = Url.get_by_id(sample_url.id)
        assert sample_url.original_url == "https://newexample.com"

    def test_update_url_invalid_url(self, client, sample_url):
        """Test 422 error when updating with invalid URL."""
        response = client.patch(
            f"/urls/{sample_url.id}", json={"original_url": "invalid"}
        )

        assert response.status_code == 422
        data = response.get_json()
        assert data["error"] == "Invalid URL"
        assert data["code"] == 422

    def test_update_url_not_found(self, client):
        """Test 404 error when updating non-existent URL."""
        response = client.patch("/urls/99999", json={"title": "Test"})

        assert response.status_code == 404
        data = response.get_json()
        assert data["error"] == "Not found"

    def test_update_url_missing_body(self, client, sample_url):
        """Test 400 error for missing request body."""
        response = client.patch(f"/urls/{sample_url.id}")

        assert response.status_code == 400


class TestDeleteURL:
    def test_delete_url_success(self, client, sample_url):
        """Test successful URL deletion (soft delete)."""
        response = client.delete(f"/urls/{sample_url.id}")

        assert response.status_code == 200
        data = response.get_json()
        assert data["message"] == "deleted"

        sample_url = Url.get_by_id(sample_url.id)
        assert sample_url.is_active is False

    def test_delete_url_not_found(self, client):
        """Test 404 error when deleting non-existent URL."""
        response = client.delete("/urls/99999")

        assert response.status_code == 404
        data = response.get_json()
        assert data["error"] == "Not found"

    def test_delete_url_creates_event(self, client, sample_url):
        """Test that URL deletion creates an event."""
        response = client.delete(f"/urls/{sample_url.id}")

        assert response.status_code == 200

        event = (
            Event.select()
            .where((Event.url_id == sample_url.id) & (Event.event_type == "deleted"))
            .first()
        )
        assert event is not None


class TestListURLs:
    def test_list_urls_all(self, client, sample_url):
        """Test listing all URLs."""
        response = client.get("/urls")

        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_list_urls_by_user(self, client, sample_url, sample_user):
        """Test listing URLs filtered by user_id."""
        response = client.get(f"/urls?user_id={sample_user.id}")

        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, list)
        assert all(url["user_id"] == sample_user.id for url in data)


class TestRiskEndpoint:
    def test_get_url_risk(self, client, sample_url):
        """Test retrieving computed risk score for URL."""
        response = client.get(f"/urls/{sample_url.id}/risk")

        assert response.status_code == 200
        data = response.get_json()
        assert data["url_id"] == sample_url.id
        assert "score" in data
        assert "tier" in data

    def test_get_url_risk_not_found(self, client):
        """Test risk endpoint returns 404 for unknown URL."""
        response = client.get("/urls/999999/risk")

        assert response.status_code == 404
        data = response.get_json()
        assert data["error"] == "Not found"


class TestHealthEndpoint:
    def test_health_check_ok(self, client):
        """Test health check returns OK."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] in ["ok", "degraded"]
        assert "db" in data

    def test_health_check_has_db_status(self, client):
        """Test health check includes database status."""
        response = client.get("/health")

        data = response.get_json()
        assert "db" in data


class TestMetricsEndpoint:
    def test_metrics_endpoint(self, client):
        """Test Prometheus metrics endpoint."""
        response = client.get("/metrics")

        assert response.status_code == 200
        assert response.content_type == "text/plain; charset=utf-8"

    def test_metrics_contains_counters(self, client):
        """Test metrics endpoint contains expected counters."""
        response = client.get("/metrics")
        data = response.data.decode("utf-8")

        assert "urls_active_total" in data
        assert "urls_inactive_total" in data
