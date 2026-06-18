"""
Test operational readiness: heartbeat, remote preflight, verifier robustness.
"""
import pytest
import yaml
from datetime import datetime, timezone, timedelta

from response.worker_heartbeat import update_worker_heartbeat, get_all_worker_heartbeats
from response.models import WorkerHeartbeat
from response.ansible_exec import _extract_verification_plan
from response.fix_verifier import _verify_system_state


class TestWorkerHeartbeat:
    """Test worker heartbeat tracking."""

    @pytest.mark.asyncio
    async def test_heartbeat_create_and_update(self):
        await update_worker_heartbeat("test_worker", status="running", duration_ms=100)
        hbs = await get_all_worker_heartbeats()
        hb = next((h for h in hbs if h.worker_name == "test_worker"), None)
        assert hb is not None
        assert hb.status == "running"
        assert hb.last_duration_ms == 100
        assert hb.last_success_at is not None

    @pytest.mark.asyncio
    async def test_heartbeat_error_tracking(self):
        await update_worker_heartbeat("test_worker_error", status="failed", error="something broke")
        hbs = await get_all_worker_heartbeats()
        hb = next((h for h in hbs if h.worker_name == "test_worker_error"), None)
        assert hb is not None
        assert hb.status == "failed"
        assert "something broke" in hb.last_error
        assert hb.last_error_at is not None

    @pytest.mark.asyncio
    async def test_heartbeat_stale_detection(self):
        await update_worker_heartbeat("test_worker_stale", status="running")
        hbs = await get_all_worker_heartbeats()
        hb = next((h for h in hbs if h.worker_name == "test_worker_stale"), None)
        assert hb is not None
        # Check that last_success_at is recent (SQLite may return naive datetime)
        last_success = hb.last_success_at
        if last_success and last_success.tzinfo is None:
            last_success = last_success.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - last_success).total_seconds()
        assert age < 5


class TestVerificationPlanExtraction:
    """Test verification plan extraction from playbooks."""

    def test_extract_iptables_plan(self):
        pb = """---
- name: Block IP
  hosts: all
  tasks:
    - name: Drop traffic
      ansible.builtin.iptables:
        chain: INPUT
        source: 192.0.2.1
        jump: DROP
"""
        plan = _extract_verification_plan(pb)
        assert plan is not None
        assert plan["type"] == "iptables_rule"
        assert plan["chain"] == "INPUT"
        assert plan["source"] == "192.0.2.1"
        assert plan["jump"] == "DROP"

    def test_extract_file_quarantine_plan(self):
        pb = """---
- name: Quarantine
  hosts: all
  tasks:
    - name: Move to quarantine
      ansible.builtin.copy:
        src: /etc/malware
        dest: /tmp/quarantine/malware
        remote_src: yes
"""
        plan = _extract_verification_plan(pb)
        assert plan is not None
        assert plan["type"] == "file_quarantine"
        assert plan["original_path"] == "/etc/malware"
        assert plan["quarantine_path"] == "/tmp/quarantine/malware"

    def test_no_plan_for_diagnostic(self):
        pb = """---
- name: Diagnostic
  hosts: all
  tasks:
    - name: List files
      ansible.builtin.shell: ls /
      changed_when: false
"""
        plan = _extract_verification_plan(pb)
        assert plan is None

    def test_empty_playbook_returns_none(self):
        assert _extract_verification_plan("") is None
        assert _extract_verification_plan(None) is None


class TestVerifierRobustness:
    """Test fix verifier prefers stored plan and handles edge cases."""

    @pytest.mark.asyncio
    async def test_verifier_prefers_stored_plan(self):
        # Mock investigation with stored plan
        inv = type("Inv", (), {
            "id": "inv-test-1",
            "playbook_yaml": "irrelevant",
            "verification_plan_json": {
                "type": "iptables_rule",
                "chain": "INPUT",
                "source": "192.0.2.1",
                "jump": "DROP",
            },
            "source_ips": "192.0.2.1",
            "target_host": "localhost",
            "target_user": "root",
        })()
        result = await _verify_system_state(inv, "localhost", "root", inv.verification_plan_json)
        assert len(result["checks"]) > 0
        # Should use the plan, not parse YAML
        assert result["checks"][0]["check_type"] == "iptables"

    @pytest.mark.asyncio
    async def test_verifier_fallback_to_yaml_for_legacy(self):
        inv = type("Inv", (), {
            "id": "inv-test-2",
            "playbook_yaml": """---
- name: Block
  hosts: all
  tasks:
    - name: Drop
      ansible.builtin.iptables:
        chain: INPUT
        source: 192.0.2.1
        jump: DROP
""",
            "verification_plan_json": None,
            "source_ips": "192.0.2.1",
            "target_host": "localhost",
            "target_user": "root",
        })()
        result = await _verify_system_state(inv, "localhost", "root", None)
        assert len(result["checks"]) > 0
        assert result["checks"][0]["check_type"] == "iptables"

    @pytest.mark.asyncio
    async def test_malformed_yaml_gives_inconclusive(self):
        inv = type("Inv", (), {
            "playbook_yaml": "not: valid: yaml: [[",
            "verification_plan_json": None,
            "source_ips": None,
            "target_host": "localhost",
            "target_user": "root",
        })()
        result = await _verify_system_state(inv, "localhost", "root", None)
        assert any(c["result"] == "inconclusive" for c in result["checks"])

    @pytest.mark.asyncio
    async def test_missing_plan_and_unknown_type_gives_inconclusive(self):
        inv = type("Inv", (), {
            "playbook_yaml": """---
- name: Unknown
  hosts: all
  tasks:
    - name: Echo
      ansible.builtin.debug:
        msg: hello
""",
            "verification_plan_json": None,
            "source_ips": None,
            "target_host": "localhost",
            "target_user": "root",
        })()
        result = await _verify_system_state(inv, "localhost", "root", None)
        assert any(c["result"] == "inconclusive" for c in result["checks"])
