"""Tests for safety policy CRUD operations."""
from __future__ import annotations

import json
import pytest
from fastapi.testclient import TestClient

from api.app import app
from response.safety_policy import (
    _default_policy,
    validate_safety_policy,
    clear_safety_policy_cache,
    VALID_CATEGORIES,
    VALID_MATCH_TYPES,
    VALID_TIERS,
    VALID_APPLIES_TO,
)
from response.playbook_safety import validate_playbook_safety


client = TestClient(app)

from config.settings import get_settings
ADMIN_SECRET = get_settings().aria_admin_secret or "test-admin-secret-123"


@pytest.fixture(autouse=True)
def _clear_cache():
    clear_safety_policy_cache()


@pytest.fixture
def default_policy():
    return _default_policy()


# ── GET safety policy ─────────────────────────────────────────────────────────

class TestGetSafetyPolicy:
    def test_returns_default_soft_rules(self):
        res = client.get("/api/v1/settings/safety-policy")
        assert res.status_code == 200
        data = res.json()
        assert "soft_block_rules" in data
        assert len(data["soft_block_rules"]) > 0
        # Check required fields on first soft block rule
        rule = data["soft_block_rules"][0]
        assert "id" in rule
        assert "name" in rule
        assert "tier" in rule
        assert "enabled" in rule
        assert "category" in rule
        assert "match_type" in rule
        assert "pattern" in rule
        assert "reason_message" in rule
        assert "applies_to" in rule
        assert "created_by" in rule
        assert "is_default" in rule
        assert "updated_at" in rule


# ── Validation ────────────────────────────────────────────────────────────────

class TestValidateSafetyPolicy:
    def test_valid_default_policy(self, default_policy):
        res = client.post("/api/v1/settings/safety-policy/validate", json={"policy": default_policy})
        assert res.status_code == 200
        assert res.json()["valid"] is True
        assert res.json()["errors"] == []

    def test_invalid_regex_rejected(self, default_policy):
        policy = json.loads(json.dumps(default_policy))
        policy["soft_block_rules"][0]["pattern"] = "[invalid("
        res = validate_safety_policy(policy)
        assert res["valid"] is False
        assert any("invalid regex" in e.lower() for e in res["errors"])

    def test_empty_pattern_rejected(self, default_policy):
        policy = json.loads(json.dumps(default_policy))
        policy["soft_block_rules"][0]["pattern"] = ""
        res = validate_safety_policy(policy)
        assert res["valid"] is False
        assert any("empty pattern" in e.lower() for e in res["errors"])

    def test_empty_reason_rejected(self, default_policy):
        policy = json.loads(json.dumps(default_policy))
        policy["soft_block_rules"][0]["reason_message"] = ""
        res = validate_safety_policy(policy)
        assert res["valid"] is False
        assert any("empty reason" in e.lower() for e in res["errors"])

    def test_duplicate_rule_ids_rejected(self, default_policy):
        policy = json.loads(json.dumps(default_policy))
        policy["soft_block_rules"][1]["id"] = policy["soft_block_rules"][0]["id"]
        res = validate_safety_policy(policy)
        assert res["valid"] is False
        assert any("duplicate" in e.lower() for e in res["errors"])

    def test_invalid_tier_rejected(self, default_policy):
        policy = json.loads(json.dumps(default_policy))
        policy["soft_block_rules"][0]["tier"] = "invalid"
        res = validate_safety_policy(policy)
        assert res["valid"] is False
        assert any("invalid tier" in e.lower() for e in res["errors"])

    def test_invalid_category_rejected(self, default_policy):
        policy = json.loads(json.dumps(default_policy))
        policy["soft_block_rules"][0]["category"] = "invalid"
        res = validate_safety_policy(policy)
        assert res["valid"] is False
        assert any("invalid category" in e.lower() for e in res["errors"])

    def test_invalid_match_type_rejected(self, default_policy):
        policy = json.loads(json.dumps(default_policy))
        policy["soft_block_rules"][0]["match_type"] = "invalid"
        res = validate_safety_policy(policy)
        assert res["valid"] is False
        assert any("invalid match_type" in e.lower() for e in res["errors"])

    def test_invalid_applies_to_rejected(self, default_policy):
        policy = json.loads(json.dumps(default_policy))
        policy["soft_block_rules"][0]["applies_to"] = "invalid"
        res = validate_safety_policy(policy)
        assert res["valid"] is False
        assert any("invalid applies_to" in e.lower() for e in res["errors"])


# ── Custom rule blocking behavior ─────────────────────────────────────────────

class TestCustomRuleBlocking:
    def test_custom_soft_block_rule_blocks_playbook(self, default_policy, monkeypatch):
        policy = json.loads(json.dumps(default_policy))
        policy["soft_block_rules"].append({
            "id": "custom-soft-test",
            "name": "Test soft block",
            "description": "test",
            "tier": "soft_block",
            "enabled": True,
            "category": "custom",
            "match_type": "contains",
            "pattern": "example-soft-test",
            "reason_message": "SOFT BLOCK: example-soft-test detected",
            "applies_to": "both",
            "created_by": "admin",
            "is_default": False,
            "updated_at": "2024-01-01T00:00:00Z",
        })
        monkeypatch.setattr("response.safety_policy.get_safety_policy", lambda: policy)
        monkeypatch.setattr("response.playbook_safety.get_safety_policy", lambda: policy)

        pb = """---
- hosts: target
  tasks:
    - shell: "echo example-soft-test"
"""
        result = validate_playbook_safety(pb)
        assert result["safe"] is False
        assert any("example-soft-test" in r for r in result["reasons"])

    def test_custom_soft_block_rule_blocks_playbook_via_generic(self, default_policy, monkeypatch):
        policy = json.loads(json.dumps(default_policy))
        policy["soft_block_rules"].append({
            "id": "custom-hard-test",
            "name": "Test hard block",
            "description": "test",
            "tier": "soft_block",
            "enabled": True,
            "category": "custom",
            "match_type": "contains",
            "pattern": "example-hard-test",
            "reason_message": "Warning: example-hard-test detected",
            "applies_to": "both",
            "created_by": "admin",
            "is_default": False,
            "updated_at": "2024-01-01T00:00:00Z",
        })
        monkeypatch.setattr("response.safety_policy.get_safety_policy", lambda: policy)
        monkeypatch.setattr("response.playbook_safety.get_safety_policy", lambda: policy)

        pb = """---
- hosts: target
  tasks:
    - shell: "echo example-hard-test"
"""
        result = validate_playbook_safety(pb)
        assert result["safe"] is False
        assert any("example-hard-test" in r for r in result["reasons"])

    def test_disabled_rule_does_not_match(self, default_policy, monkeypatch):
        policy = json.loads(json.dumps(default_policy))
        policy["soft_block_rules"].append({
            "id": "custom-disabled",
            "name": "Disabled rule",
            "description": "test",
            "tier": "soft_block",
            "enabled": False,
            "category": "custom",
            "match_type": "contains",
            "pattern": "disabled-pattern",
            "reason_message": "Should not appear",
            "applies_to": "both",
            "created_by": "admin",
            "is_default": False,
            "updated_at": "2024-01-01T00:00:00Z",
        })
        monkeypatch.setattr("response.safety_policy.get_safety_policy", lambda: policy)
        monkeypatch.setattr("response.playbook_safety.get_safety_policy", lambda: policy)

        pb = """---
- hosts: target
  tasks:
    - shell: "echo disabled-pattern"
"""
        result = validate_playbook_safety(pb)
        # Should be safe because the only matching rule is disabled
        assert result["safe"] is True


# ── Default rules still block ─────────────────────────────────────────────────

class TestDefaultRulesStillBlock:
    def test_unresolved_jinja_still_blocked(self):
        pb = """---
- hosts: target
  tasks:
    - shell: "iptables -A INPUT -s {{ attacker_ips[0] }} -j DROP"
"""
        result = validate_playbook_safety(pb)
        assert result["safe"] is False
        assert any("unresolved Jinja2" in r for r in result["reasons"])

    def test_ssh_restart_still_blocked(self):
        pb = """---
- hosts: target
  tasks:
    - service:
        name: sshd
        state: stopped
"""
        result = validate_playbook_safety(pb)
        assert result["safe"] is False
        assert any("ssh" in r.lower() for r in result["reasons"])

    def test_rm_rf_still_blocked(self):
        pb = """---
- hosts: target
  tasks:
    - shell: "rm -rf /tmp/old"
"""
        result = validate_playbook_safety(pb)
        assert result["safe"] is False
        assert any("rm -rf" in r for r in result["reasons"])

    def test_nuclear_rollback_still_blocked(self):
        pb = """---
- hosts: target
  tasks:
    - shell: "iptables -F"
"""
        result = validate_playbook_safety(pb)
        assert result["safe"] is False
        assert any("iptables" in r.lower() for r in result["reasons"])


# ── API endpoints ─────────────────────────────────────────────────────────────

class TestSafetyPolicyAPI:
    def test_patch_without_admin_secret_fails(self, default_policy):
        res = client.patch("/api/v1/settings/safety-policy", json={
            "policy": default_policy,
        })
        assert res.status_code == 403

    def test_patch_with_bad_confirmation_fails(self, default_policy):
        policy = json.loads(json.dumps(default_policy))
        policy["soft_block_rules"][0]["enabled"] = False
        res = client.patch("/api/v1/settings/safety-policy", json={
            "policy": policy,
        }, headers={"X-ARIA-Admin-Secret": ADMIN_SECRET})
        assert res.status_code == 400
        assert "I UNDERSTAND THE RISK" in res.json()["detail"]

    def test_patch_soft_block_without_risk_confirmation(self, default_policy):
        policy = json.loads(json.dumps(default_policy))
        policy["soft_block_rules"].append({
            "id": "custom-soft-api",
            "name": "API test soft",
            "description": "test",
            "tier": "soft_block",
            "enabled": True,
            "category": "custom",
            "match_type": "contains",
            "pattern": "api-soft-pattern",
            "reason_message": "SOFT BLOCK: api test",
            "applies_to": "both",
            "created_by": "admin",
            "is_default": False,
            "updated_at": "2024-01-01T00:00:00Z",
        })
        res = client.patch("/api/v1/settings/safety-policy", json={
            "policy": policy,
        }, headers={"X-ARIA-Admin-Secret": ADMIN_SECRET})
        assert res.status_code == 200
        assert res.json()["status"] == "ok"

    def test_patch_soft_block_with_custom_rule(self, default_policy):
        policy = json.loads(json.dumps(default_policy))
        policy["soft_block_rules"].append({
            "id": "custom-soft-api",
            "name": "API test soft",
            "description": "test",
            "tier": "soft_block",
            "enabled": True,
            "category": "custom",
            "match_type": "contains",
            "pattern": "api-soft-pattern",
            "reason_message": "SOFT BLOCK: api test",
            "applies_to": "both",
            "created_by": "admin",
            "is_default": False,
            "updated_at": "2024-01-01T00:00:00Z",
        })
        res = client.patch("/api/v1/settings/safety-policy", json={
            "policy": policy,
        }, headers={"X-ARIA-Admin-Secret": ADMIN_SECRET})
        assert res.status_code == 200
        assert res.json()["status"] == "ok"

    def test_restore_default_requires_confirmation(self):
        res = client.post("/api/v1/settings/safety-policy/restore-default", json={
            "confirmation": "wrong"
        }, headers={"X-ARIA-Admin-Secret": ADMIN_SECRET})
        assert res.status_code == 400

    def test_restore_default_works(self):
        res = client.post("/api/v1/settings/safety-policy/restore-default", json={
            "confirmation": "RESTORE DEFAULT SAFETY POLICY"
        }, headers={"X-ARIA-Admin-Secret": ADMIN_SECRET})
        assert res.status_code == 200
        assert res.json()["status"] == "ok"

    def test_get_after_restore_matches_default(self):
        res = client.get("/api/v1/settings/safety-policy")
        assert res.status_code == 200
        data = res.json()
        default = _default_policy()
        assert len(data["soft_block_rules"]) == len(default["soft_block_rules"])
