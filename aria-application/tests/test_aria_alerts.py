import pytest
from fastapi.testclient import TestClient
from api.app import app

client = TestClient(app)


class TestAriaAlertsAPI:
    def test_stats_returns_counts(self):
        response = client.get("/api/v1/aria-alerts/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "by_severity" in data
        assert "unacknowledged" in data

    def test_list_returns_alerts(self):
        response = client.get("/api/v1/aria-alerts/?limit=5")
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
        assert "total" in data

    def test_acknowledge_requires_admin_secret(self):
        response = client.post("/api/v1/aria-alerts/123/acknowledge")
        assert response.status_code == 403

    def test_delete_requires_admin_secret(self):
        response = client.delete("/api/v1/aria-alerts/123")
        assert response.status_code == 403

    def test_wrong_admin_secret_returns_403(self):
        headers = {"X-ARIA-Admin-Secret": "wrong"}
        response = client.post("/api/v1/aria-alerts/123/acknowledge", headers=headers)
        assert response.status_code == 403
