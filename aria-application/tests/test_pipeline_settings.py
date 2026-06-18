"""Tests for pipeline settings (intervals, cursor controls, dedup, diff)."""
from __future__ import annotations

import json
import pytest
from fastapi.testclient import TestClient

from api.app import app
from config.settings import get_settings

client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def valid_admin_secret(monkeypatch):
    monkeypatch.setenv("ARIA_ADMIN_SECRET", "test-secret-123")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class TestSafetyPolicyDiff:
    def test_diff_no_changes(self):
        from response.safety_policy import _default_policy
        policy = _default_policy()
        res = client.post("/api/v1/settings/safety-policy/diff", json={"policy": policy, "compare_to": "default"})
        assert res.status_code == 200
        data = res.json()
        assert data["modified"] is False
        assert data["counts"]["added"] == 0
        assert data["counts"]["removed"] == 0

    def test_diff_added_rule(self):
        from response.safety_policy import _default_policy
        policy = _default_policy()
        policy["soft_block_rules"].append({
            "id": "test-new-rule",
            "name": "Test Rule",
            "description": "",
            "tier": "soft_block",
            "enabled": True,
            "category": "custom",
            "match_type": "contains",
            "pattern": "test",
            "reason_message": "test",
            "applies_to": "both",
            "created_by": "admin",
            "is_default": False,
            "updated_at": "2026-01-01T00:00:00Z",
        })
        res = client.post("/api/v1/settings/safety-policy/diff", json={"policy": policy, "compare_to": "default"})
        assert res.status_code == 200
        data = res.json()
        assert data["modified"] is True
        assert data["counts"]["added"] == 1
        assert data["added"][0]["id"] == "test-new-rule"

    def test_diff_enabled_changed(self):
        from response.safety_policy import _default_policy
        policy = _default_policy()
        if policy["soft_block_rules"]:
            policy["soft_block_rules"][0]["enabled"] = not policy["soft_block_rules"][0].get("enabled", True)
        res = client.post("/api/v1/settings/safety-policy/diff", json={"policy": policy, "compare_to": "default"})
        assert res.status_code == 200
        data = res.json()
        assert data["modified"] is True
        assert data["counts"]["enabled_changed"] >= 1


class TestPipelineSettingsInGetSettings:
    def test_per_source_poll_intervals_present(self):
        res = client.get("/api/v1/settings")
        assert res.status_code == 200
        data = res.json()
        sections = {s["section"]: [v["key"] for v in s["values"]] for s in data["sections"]}
        pipeline = sections.get("pipeline", [])
        for key in ["wazuh_poll_interval_seconds", "falco_poll_interval_seconds",
                    "filebeat_poll_interval_seconds", "suricata_poll_interval_seconds"]:
            assert key in pipeline, f"{key} missing from pipeline settings"

    def test_poll_interval_defaults(self):
        res = client.get("/api/v1/settings")
        assert res.status_code == 200
        data = res.json()
        sections = {s["section"]: {v["key"]: v["value"] for v in s["values"]} for s in data["sections"]}
        pipeline = sections.get("pipeline", {})
        for key in ["wazuh_poll_interval_seconds", "falco_poll_interval_seconds",
                    "filebeat_poll_interval_seconds", "suricata_poll_interval_seconds"]:
            assert pipeline.get(key) == 10, f"{key} default should be 10"


class TestPipelineCursorStatus:
    def test_cursor_status_endpoint_exists(self):
        res = client.get("/api/v1/settings/pipeline/cursors")
        assert res.status_code == 200
        data = res.json()
        assert "cursors" in data
        assert "sources" in data
        assert "dedup_mode" in data
        assert "cursor_dir" in data
        assert "seen_ids_dir" in data

    def test_cursor_status_has_all_sources(self):
        res = client.get("/api/v1/settings/pipeline/cursors")
        assert res.status_code == 200
        data = res.json()
        for source in ["wazuh", "falco", "filebeat", "suricata"]:
            assert source in data["cursors"], f"{source} missing from cursors"
            cs = data["cursors"][source]
            assert "redis_present" in cs
            assert "file_present" in cs


class TestPipelineCursorReset:
    def test_reset_without_admin_secret_returns_403(self):
        res = client.post("/api/v1/settings/pipeline/cursors/wazuh/reset", json={"confirmation": "RESET CURSOR"})
        assert res.status_code == 403

    def test_reset_wrong_confirmation_returns_400(self, valid_admin_secret):
        res = client.post(
            "/api/v1/settings/pipeline/cursors/wazuh/reset",
            json={"confirmation": "WRONG"},
            headers={"X-ARIA-Admin-Secret": "test-secret-123"},
        )
        assert res.status_code == 400

    def test_reset_invalid_source_returns_400(self, valid_admin_secret):
        res = client.post(
            "/api/v1/settings/pipeline/cursors/invalid/reset",
            json={"confirmation": "RESET CURSOR"},
            headers={"X-ARIA-Admin-Secret": "test-secret-123"},
        )
        assert res.status_code == 400

    def test_reset_valid_source_returns_ok(self, valid_admin_secret, tmp_path, monkeypatch):
        monkeypatch.setenv("CURSOR_DIR", str(tmp_path / "cursors"))
        get_settings.cache_clear()
        res = client.post(
            "/api/v1/settings/pipeline/cursors/wazuh/reset",
            json={"confirmation": "RESET CURSOR"},
            headers={"X-ARIA-Admin-Secret": "test-secret-123"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["result"]["source"] == "wazuh"
