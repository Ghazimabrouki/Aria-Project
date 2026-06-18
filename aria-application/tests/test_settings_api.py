"""Tests for the Settings API."""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.app import app
from config.settings import get_settings

client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_settings_cache(monkeypatch):
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def valid_admin_secret(monkeypatch):
    monkeypatch.setenv("ARIA_ADMIN_SECRET", "test-secret-123")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class TestGetSettings:
    def test_get_settings_returns_sanitized_values(self):
        res = client.get("/api/v1/settings")
        assert res.status_code == 200
        data = res.json()
        assert "sections" in data
        sections = {s["section"]: s["values"] for s in data["sections"]}
        assert "data_sources" in sections
        assert "security" in sections

    def test_secrets_are_never_returned(self):
        res = client.get("/api/v1/settings")
        assert res.status_code == 200
        data = res.json()
        for section in data["sections"]:
            for val in section["values"]:
                if val["secret"]:
                    assert val["value"] is None or (isinstance(val["value"], dict) and val["value"].get("value") is None)


class TestPatchSettings:
    def test_patch_without_admin_secret_returns_403(self):
        res = client.patch("/api/v1/settings", json={"changes": {"elasticsearch_url": "http://localhost:9200"}})
        assert res.status_code == 403

    def test_patch_wrong_admin_secret_returns_403(self, valid_admin_secret):
        res = client.patch("/api/v1/settings", json={"changes": {"elasticsearch_url": "http://localhost:9200"}}, headers={"X-ARIA-Admin-Secret": "wrong"})
        assert res.status_code == 403

    def test_patch_correct_admin_secret_saves_allowed_field(self, valid_admin_secret, tmp_path, monkeypatch):
        import api.routes.settings as settings_module
        called_with = {}
        def fake_update(updates):
            called_with.update(updates)
        monkeypatch.setattr(settings_module, "_update_env_file", fake_update)

        res = client.patch("/api/v1/settings", json={"changes": {"elasticsearch_url": "https://new:9200"}, "reload": False}, headers={"X-ARIA-Admin-Secret": "test-secret-123"})
        assert res.status_code == 200
        data = res.json()
        assert "elasticsearch_url" in data["applied"]
        assert "ELASTICSEARCH_URL" in called_with

    def test_invalid_url_rejected(self, valid_admin_secret):
        res = client.patch("/api/v1/settings", json={"changes": {"elasticsearch_url": "not-a-url"}, "reload": False}, headers={"X-ARIA-Admin-Secret": "test-secret-123"})
        assert res.status_code == 200
        data = res.json()
        assert any("URL" in e for e in data["errors"])

    def test_invalid_port_rejected(self, valid_admin_secret):
        res = client.patch("/api/v1/settings", json={"changes": {"redis_port": 99999}, "reload": False}, headers={"X-ARIA-Admin-Secret": "test-secret-123"})
        assert res.status_code == 200
        data = res.json()
        assert any("port" in e.lower() for e in data["errors"])

    def test_invalid_timeout_rejected(self, valid_admin_secret):
        res = client.patch("/api/v1/settings", json={"changes": {"ollama_timeout": -1}, "reload": False}, headers={"X-ARIA-Admin-Secret": "test-secret-123"})
        assert res.status_code == 200
        data = res.json()
        assert any("timeout" in e.lower() or "least" in e.lower() for e in data["errors"])


class TestPreview:
    def test_preview_masks_secrets(self, valid_admin_secret):
        res = client.post("/api/v1/settings/preview", json={"changes": {"elasticsearch_password": "new-pass"}})
        assert res.status_code == 200
        data = res.json()
        preview = {p["key"]: p for p in data["preview"]}
        assert "elasticsearch_password" in preview
        assert "replaced" in preview["elasticsearch_password"]["new"]


class TestReload:
    def test_reload_endpoint_returns_applied_and_requires_restart(self, valid_admin_secret):
        res = client.post("/api/v1/settings/reload", headers={"X-ARIA-Admin-Secret": "test-secret-123"})
        assert res.status_code == 200
        data = res.json()
        assert "applied" in data
        assert "requires_restart" in data


class TestConnectionTests:
    def test_test_elasticsearch_endpoint_exists(self):
        res = client.post("/api/v1/settings/test/elasticsearch")
        assert res.status_code in (200, 500, 502)

    def test_test_redis_endpoint_exists(self):
        res = client.post("/api/v1/settings/test/redis")
        assert res.status_code in (200, 500, 502)

    def test_test_ai_endpoint_exists(self):
        res = client.post("/api/v1/settings/test/ai")
        assert res.status_code in (200, 500, 502)

    def test_test_ansible_preflight_endpoint_exists(self):
        res = client.post("/api/v1/settings/test/ansible-preflight")
        assert res.status_code in (200, 500, 502)


class TestSafetyPolicy:
    def test_validate_empty_soft_block_policy(self):
        res = client.post("/api/v1/settings/safety-policy/validate", json={"policy": {"soft_block_rules": []}})
        assert res.status_code == 200
        data = res.json()
        assert data["valid"] is True

    def test_restore_default_safety_policy_requires_confirmation(self, valid_admin_secret):
        res = client.post("/api/v1/settings/safety-policy/restore-default", json={"confirmation": "WRONG"}, headers={"X-ARIA-Admin-Secret": "test-secret-123"})
        assert res.status_code == 400

    def test_restore_default_safety_policy_works(self, valid_admin_secret, monkeypatch):
        import api.routes.settings as settings_module
        called = []
        def fake_update(updates):
            called.append(updates)
        monkeypatch.setattr(settings_module, "_update_env_file", fake_update)
        res = client.post("/api/v1/settings/safety-policy/restore-default", json={"confirmation": "RESTORE DEFAULT SAFETY POLICY"}, headers={"X-ARIA-Admin-Secret": "test-secret-123"})
        assert res.status_code == 200
        assert len(called) > 0


class TestAtomicWrite:
    def test_save_failure_keeps_old_env_unchanged(self, valid_admin_secret, monkeypatch):
        import api.routes.settings as settings_module
        def fake_update_fail(updates):
            raise RuntimeError("disk full")
        monkeypatch.setattr(settings_module, "_update_env_file", fake_update_fail)
        res = client.patch("/api/v1/settings", json={"changes": {"elasticsearch_url": "https://new:9200"}, "reload": False}, headers={"X-ARIA-Admin-Secret": "test-secret-123"})
        assert res.status_code == 200
        data = res.json()
        assert any("disk full" in e.lower() for e in data["errors"])


class TestAdminSecretStatus:
    def test_admin_secret_configured_true_when_set(self, monkeypatch):
        monkeypatch.setenv("ARIA_ADMIN_SECRET", "my-real-secret")
        get_settings.cache_clear()
        res = client.get("/api/v1/settings")
        assert res.status_code == 200
        data = res.json()
        sections = {s["section"]: {v["key"]: v["value"] for v in s["values"]} for s in data["sections"]}
        assert sections["security"]["admin_secret_configured"] is True
        assert sections["security"]["protected_endpoints_enabled"] is True
        assert sections["security"]["internal_trusted_active"] is True

    def test_admin_secret_configured_false_when_default(self, monkeypatch):
        for bad in ["changeme", "default", "admin", ""]:
            monkeypatch.setenv("ARIA_ADMIN_SECRET", bad)
            get_settings.cache_clear()
            res = client.get("/api/v1/settings")
            assert res.status_code == 200
            data = res.json()
            sections = {s["section"]: {v["key"]: v["value"] for v in s["values"]} for s in data["sections"]}
            assert sections["security"]["admin_secret_configured"] is False, f"failed for {bad!r}"
            assert sections["security"]["protected_endpoints_enabled"] is False, f"failed for {bad!r}"

    def test_admin_secret_never_returned_plaintext(self, monkeypatch):
        monkeypatch.setenv("ARIA_ADMIN_SECRET", "super-secret-123")
        get_settings.cache_clear()
        res = client.get("/api/v1/settings")
        assert res.status_code == 200
        data = res.json()
        for section in data["sections"]:
            for val in section["values"]:
                if val["key"] == "aria_admin_secret":
                    assert val["secret"] is True
                    assert val["value"] == {"configured": True, "value": None}
                    assert "super-secret-123" not in str(data)


class TestDataSources:
    def test_telegraf_index_pattern_in_get_settings(self):
        res = client.get("/api/v1/settings")
        assert res.status_code == 200
        data = res.json()
        sections = {s["section"]: [v["key"] for v in s["values"]] for s in data["sections"]}
        assert "telegraf_index_pattern" in sections.get("data_sources", [])

    def test_all_five_source_patterns_present(self):
        res = client.get("/api/v1/settings")
        assert res.status_code == 200
        data = res.json()
        sections = {s["section"]: [v["key"] for v in s["values"]] for s in data["sections"]}
        ds = sections.get("data_sources", [])
        for key in ["wazuh_index_pattern", "falco_index_pattern", "filebeat_index_pattern", "suricata_index_pattern", "telegraf_index_pattern"]:
            assert key in ds, f"{key} missing from data_sources"


class TestAIProvider:
    def test_active_ai_provider_computed(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "nvidia")
        get_settings.cache_clear()
        res = client.get("/api/v1/settings")
        assert res.status_code == 200
        data = res.json()
        sections = {s["section"]: {v["key"]: v["value"] for v in s["values"]} for s in data["sections"]}
        assert sections["ai"]["active_ai_provider"] == "nvidia"

    def test_ai_provider_mismatch_warning_when_nvidia_with_ollama_url(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "nvidia")
        monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434")
        get_settings.cache_clear()
        res = client.get("/api/v1/settings")
        assert res.status_code == 200
        data = res.json()
        sections = {s["section"]: {v["key"]: v["value"] for v in s["values"]} for s in data["sections"]}
        warning = sections["ai"].get("ai_provider_mismatch_warning")
        assert warning and "NVIDIA" in warning and "Ollama" in warning

    def test_ai_provider_mismatch_warning_none_when_consistent(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "ollama")
        monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434")
        get_settings.cache_clear()
        res = client.get("/api/v1/settings")
        assert res.status_code == 200
        data = res.json()
        sections = {s["section"]: {v["key"]: v["value"] for v in s["values"]} for s in data["sections"]}
        warning = sections["ai"].get("ai_provider_mismatch_warning")
        assert warning is None


class TestAnsibleAuthModes:
    def test_ansible_connection_auth_mode_local_for_localhost(self, monkeypatch):
        monkeypatch.setenv("ANSIBLE_REMOTE_HOST", "localhost")
        monkeypatch.setenv("ANSIBLE_SSH_KEY", "")
        monkeypatch.setenv("ANSIBLE_SSH_PASSWORD", "")
        get_settings.cache_clear()
        res = client.get("/api/v1/settings")
        assert res.status_code == 200
        data = res.json()
        sections = {s["section"]: {v["key"]: v["value"] for v in s["values"]} for s in data["sections"]}
        assert sections["ansible"]["ansible_connection_auth_mode"] == "local"

    def test_ansible_connection_auth_mode_ssh_key_when_key_set(self, monkeypatch):
        monkeypatch.setenv("ANSIBLE_REMOTE_HOST", "192.168.1.10")
        monkeypatch.setenv("ANSIBLE_SSH_KEY", "/root/.ssh/id_rsa")
        get_settings.cache_clear()
        res = client.get("/api/v1/settings")
        assert res.status_code == 200
        data = res.json()
        sections = {s["section"]: {v["key"]: v["value"] for v in s["values"]} for s in data["sections"]}
        assert sections["ansible"]["ansible_connection_auth_mode"] == "ssh_key"

    def test_ansible_become_mode_none_when_no_method(self, monkeypatch):
        monkeypatch.setenv("ANSIBLE_BECOME_METHOD", "none")
        monkeypatch.setenv("ANSIBLE_BECOME_PASSWORD", "")
        get_settings.cache_clear()
        res = client.get("/api/v1/settings")
        assert res.status_code == 200
        data = res.json()
        sections = {s["section"]: {v["key"]: v["value"] for v in s["values"]} for s in data["sections"]}
        assert sections["ansible"]["ansible_become_mode"] == "none"

    def test_ansible_become_mode_sudo_password_when_password_set(self, monkeypatch):
        monkeypatch.setenv("ANSIBLE_BECOME_METHOD", "sudo")
        monkeypatch.setenv("ANSIBLE_BECOME_PASSWORD", "secret")
        get_settings.cache_clear()
        res = client.get("/api/v1/settings")
        assert res.status_code == 200
        data = res.json()
        sections = {s["section"]: {v["key"]: v["value"] for v in s["values"]} for s in data["sections"]}
        assert sections["ansible"]["ansible_become_mode"] == "sudo_password"

    def test_ansible_become_mode_passwordless_when_no_password(self, monkeypatch):
        monkeypatch.setenv("ANSIBLE_BECOME_METHOD", "sudo")
        monkeypatch.setenv("ANSIBLE_BECOME_PASSWORD", "")
        get_settings.cache_clear()
        res = client.get("/api/v1/settings")
        assert res.status_code == 200
        data = res.json()
        sections = {s["section"]: {v["key"]: v["value"] for v in s["values"]} for s in data["sections"]}
        assert sections["ansible"]["ansible_become_mode"] == "passwordless"
