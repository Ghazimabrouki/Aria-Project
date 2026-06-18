"""
Advanced tests for the AI Operator feature covering:
  - Diagnostic task hardening (failed_when: false injection)
  - Rich result analysis (memory, disk, processes, iptables, service)
  - Session context building with command extraction
  - End-to-end workflows
"""

import pytest
import yaml

from api.routes.operator import (
    _normalize_playbook_hosts,
    _validate_playbook_yaml,
    _harden_diagnostic_tasks,
    _build_simple_analysis,
    _build_conversation_context,
)


# ---------------------------------------------------------------------------
# Diagnostic Hardening Tests
# ---------------------------------------------------------------------------

class TestDiagnosticHardening:
    """Test that diagnostic tasks get failed_when: false automatically"""

    def test_dpkg_l_gets_hardened(self):
        playbook = yaml.safe_load("""---
- name: Check nginx
  hosts: target
  tasks:
    - name: dpkg check
      shell: dpkg -l nginx
""")
        _harden_diagnostic_tasks(playbook)
        task = playbook[0]["tasks"][0]
        assert task.get("failed_when") is False
        assert task.get("changed_when") is False

    def test_systemctl_status_gets_hardened(self):
        playbook = yaml.safe_load("""---
- name: Check service
  hosts: target
  tasks:
    - name: ssh status
      shell: systemctl status sshd
""")
        _harden_diagnostic_tasks(playbook)
        task = playbook[0]["tasks"][0]
        assert task.get("failed_when") is False
        assert task.get("changed_when") is False

    def test_free_command_gets_hardened(self):
        playbook = yaml.safe_load("""---
- name: Check RAM
  hosts: target
  tasks:
    - name: free
      shell: free -m
""")
        _harden_diagnostic_tasks(playbook)
        task = playbook[0]["tasks"][0]
        assert task.get("failed_when") is False
        assert task.get("changed_when") is False

    def test_iptables_list_gets_hardened(self):
        playbook = yaml.safe_load("""---
- name: List rules
  hosts: target
  tasks:
    - name: iptables
      shell: iptables -L
""")
        _harden_diagnostic_tasks(playbook)
        task = playbook[0]["tasks"][0]
        assert task.get("failed_when") is False
        assert task.get("changed_when") is False

    def test_non_diagnostic_not_hardened(self):
        playbook = yaml.safe_load("""---
- name: Install nginx
  hosts: target
  tasks:
    - name: apt install
      shell: apt install -y nginx
""")
        _harden_diagnostic_tasks(playbook)
        task = playbook[0]["tasks"][0]
        assert "failed_when" not in task
        assert "changed_when" not in task

    def test_multiple_tasks_mixed(self):
        playbook = yaml.safe_load("""---
- name: Mixed tasks
  hosts: target
  tasks:
    - name: Check RAM
      shell: free -m
    - name: Install package
      shell: apt install -y nginx
    - name: Check disk
      shell: df -h
""")
        _harden_diagnostic_tasks(playbook)
        tasks = playbook[0]["tasks"]
        assert tasks[0].get("failed_when") is False  # free
        assert "failed_when" not in tasks[1]          # apt install
        assert tasks[2].get("failed_when") is False  # df

    def test_full_normalization_pipeline_includes_hardening(self):
        raw = """---
- name: Check nginx
  hosts: ghazi
  tasks:
    - name: dpkg
      shell: dpkg -l nginx
"""
        fixed = _normalize_playbook_hosts(raw)
        parsed = yaml.safe_load(fixed)
        task = parsed[0]["tasks"][0]
        assert parsed[0]["hosts"] == "target"
        assert task.get("failed_when") is False
        assert task.get("changed_when") is False


# ---------------------------------------------------------------------------
# Rich Analysis Tests
# ---------------------------------------------------------------------------

class TestRichAnalysisMemory:
    """Test _build_simple_analysis for memory data"""

    def test_memory_healthy(self):
        data = {"memory_usage": {"mem": {"total": "128000", "used": "30000", "free": "98000"}}}
        result = _build_simple_analysis(0, data)
        assert result is not None
        assert "healthy" in result["explanation"].lower()
        assert "30%" in result["explanation"] or "30000" in result["explanation"]
        assert result["outcome"] == "success"

    def test_memory_critical(self):
        data = {"memory_usage": {"mem": {"total": "128000", "used": "120000", "free": "8000"}}}
        result = _build_simple_analysis(0, data)
        assert result is not None
        assert "critical" in result["explanation"].lower()
        assert result["recommendations"]

    def test_memory_no_recommendation_when_healthy(self):
        data = {"memory_usage": {"mem": {"total": "128000", "used": "30000", "free": "98000"}}}
        result = _build_simple_analysis(0, data)
        assert result["recommendations"] == []


class TestRichAnalysisDisk:
    """Test _build_simple_analysis for disk data"""

    def test_disk_normal(self):
        data = {
            "disk_usage": [
                {"mounted_on": "/", "use_percent": "45%", "used": "35G", "size": "79G"},
                {"mounted_on": "/run", "use_percent": "1%", "used": "3M", "size": "13G"},
            ]
        }
        result = _build_simple_analysis(0, data)
        assert result is not None
        assert "/" in result["explanation"]
        assert "45%" in result["explanation"]
        assert result["recommendations"] == []

    def test_disk_critical_warning(self):
        data = {
            "disk_usage": [
                {"mounted_on": "/", "use_percent": "92%", "used": "72G", "size": "79G"},
            ]
        }
        result = _build_simple_analysis(0, data)
        assert result is not None
        assert "critically" in result["explanation"].lower() or "⚠️" in result["explanation"]
        assert result["recommendations"]

    def test_disk_high_warning(self):
        data = {
            "disk_usage": [
                {"mounted_on": "/var", "use_percent": "85%", "used": "42G", "size": "50G"},
            ]
        }
        result = _build_simple_analysis(0, data)
        assert result is not None
        assert result["recommendations"]


class TestRichAnalysisProcesses:
    """Test _build_simple_analysis for process data"""

    def test_processes_formatted(self):
        data = {
            "top_processes": [
                {"command": "/usr/bin/java -Xmx1G", "pid": "1234", "cpu": "25.5", "mem": "15.2", "user": "root"},
                {"command": "/usr/bin/python app.py", "pid": "5678", "cpu": "10.0", "mem": "8.5", "user": "app"},
            ]
        }
        result = _build_simple_analysis(0, data)
        assert result is not None
        assert "Top Processes" in result["explanation"]
        assert "PID 1234" in result["explanation"]
        assert "java" in result["explanation"]
        assert result["outcome"] == "success"

    def test_long_command_truncated(self):
        data = {
            "top_processes": [
                {"command": "a" * 100, "pid": "1", "cpu": "1.0", "mem": "1.0", "user": "root"},
            ]
        }
        result = _build_simple_analysis(0, data)
        assert result is not None
        # Should be truncated to 50 chars in the command display
        assert len(result["explanation"]) < 500


class TestRichAnalysisIptables:
    """Test _build_simple_analysis for iptables data"""

    def test_iptables_drop_rules_highlighted(self):
        data = {
            "iptables_rules": [
                "Chain INPUT (policy ACCEPT)",
                "target     prot opt source               destination",
                "DROP       all  --  1.2.3.4              0.0.0.0/0",
                "DROP       all  --  5.6.7.8              0.0.0.0/0",
                "ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0",
            ]
        }
        result = _build_simple_analysis(0, data)
        assert result is not None
        assert "DROP" in result["explanation"]
        assert "2 found" in result["explanation"] or "found" in result["explanation"]
        assert "ACCEPT" in result["explanation"]


class TestRichAnalysisService:
    """Test _build_simple_analysis for service status"""

    def test_service_active(self):
        data = {"service_status": {"service": "sshd", "active_state": "active", "status_text": "running since Mon"}}
        result = _build_simple_analysis(0, data)
        assert result is not None
        assert "active" in result["explanation"].lower()
        assert "sshd" in result["explanation"]

    def test_service_inactive(self):
        data = {"service_status": {"service": "nginx", "active_state": "inactive", "status_text": "dead"}}
        result = _build_simple_analysis(0, data)
        assert result is not None
        assert "inactive" in result["explanation"].lower()


class TestRichAnalysisUnknown:
    """Test that unknown data falls back to None (LLM analysis)"""

    def test_unrecognized_data_returns_none(self):
        data = {"some_random_key": "value"}
        result = _build_simple_analysis(0, data)
        assert result is None

    def test_nonzero_exit_returns_none(self):
        data = {"memory_usage": {"mem": {"total": "100", "used": "50", "free": "50"}}}
        result = _build_simple_analysis(1, data)
        assert result is None


# ---------------------------------------------------------------------------
# Session Context Tests
# ---------------------------------------------------------------------------

class MockMessage:
    """Minimal mock for OperatorMessage"""
    def __init__(self, role, content="", execution_summary="", status="", playbook_yaml="", result_json=None):
        self.role = role
        self.content = content
        self.execution_summary = execution_summary
        self.status = status
        self.playbook_yaml = playbook_yaml
        self.result_json = result_json


class TestConversationContext:
    """Test _build_conversation_context extracts commands and results"""

    def test_empty_messages(self):
        ctx = _build_conversation_context([])
        assert "No previous conversation" in ctx

    def test_user_message_included(self):
        msgs = [MockMessage("user", content="check RAM")]
        ctx = _build_conversation_context(msgs)
        assert "User asked: check RAM" in ctx

    def test_assistant_with_playbook_extracts_commands(self):
        msgs = [
            MockMessage(
                "assistant",
                execution_summary="Check RAM",
                status="completed",
                playbook_yaml="tasks:\n  - shell: free -m\n  - shell: df -h",
                result_json={"analysis": {"explanation": "Memory OK", "outcome": "success"}},
            )
        ]
        ctx = _build_conversation_context(msgs)
        assert "free -m" in ctx
        assert "df -h" in ctx
        assert "Memory OK" in ctx
        assert "completed" in ctx

    def test_result_without_analysis_uses_output(self):
        msgs = [
            MockMessage(
                "assistant",
                execution_summary="Check disk",
                status="completed",
                playbook_yaml="tasks:\n  - shell: df -h",
                result_json={"output": "Disk full warning"},
            )
        ]
        ctx = _build_conversation_context(msgs)
        assert "Disk full warning" in ctx

    def test_multiple_messages_combined(self):
        msgs = [
            MockMessage("user", content="check RAM"),
            MockMessage("assistant", execution_summary="RAM check", status="completed",
                       playbook_yaml="tasks:\n  - shell: free -m",
                       result_json={"analysis": {"explanation": "64GB total", "outcome": "success"}}),
            MockMessage("user", content="what processes"),
        ]
        ctx = _build_conversation_context(msgs)
        assert "check RAM" in ctx
        assert "free -m" in ctx
        assert "64GB total" in ctx
        assert "what processes" in ctx


# ---------------------------------------------------------------------------
# End-to-End Workflow Tests
# ---------------------------------------------------------------------------

class TestEndToEndAdvanced:
    """Full pipeline tests"""

    def test_diagnostic_playbook_full_pipeline(self):
        """A diagnostic playbook gets normalized, hardened, and validated"""
        raw = """---
- name: Check nginx install
  hosts: ghazi
  tasks:
    - name: dpkg check
      shell: dpkg -l nginx
    - name: which check
      command: which nginx
"""
        fixed = _normalize_playbook_hosts(raw)
        parsed = yaml.safe_load(fixed)

        # Normalization
        assert parsed[0]["hosts"] == "target"

        # Hardening
        _harden_diagnostic_tasks(parsed)
        for task in parsed[0]["tasks"]:
            assert task.get("failed_when") is False
            assert task.get("changed_when") is False

        # Validation
        ok, err = _validate_playbook_yaml(fixed)
        assert ok is True, f"Validation failed: {err}"

    def test_mixed_playbook_partial_hardening(self):
        """Only diagnostic tasks get hardened, install tasks don't"""
        raw = """---
- name: Setup
  hosts: ghazi
  tasks:
    - name: check
      shell: free -m
    - name: install
      shell: apt install nginx
"""
        fixed = _normalize_playbook_hosts(raw)
        parsed = yaml.safe_load(fixed)
        _harden_diagnostic_tasks(parsed)

        assert parsed[0]["tasks"][0].get("failed_when") is False
        assert "failed_when" not in parsed[0]["tasks"][1]


# ---------------------------------------------------------------------------
# SS / Port Parsing Tests
# ---------------------------------------------------------------------------

class TestSsPortParsing:
    """Test parsing of ss -tulnp output"""

    def test_parse_ss_tcp_listeners(self):
        from api.routes.operator import _parse_ss_output
        sample = """Netid  State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port  Process
tcp    LISTEN  0       128     0.0.0.0:22           0.0.0.0:*          users:(("sshd",pid=1234,fd=3))
tcp    LISTEN  0       128     127.0.0.1:8001       0.0.0.0:*          users:(("python3",pid=5678,fd=4))
udp    UNCONN  0       0       0.0.0.0:68           0.0.0.0:*          users:(("dhclient",pid=901,fd=3))
"""
        result = _parse_ss_output(sample)
        assert len(result) == 3
        assert result[0]["protocol"] == "tcp"
        assert result[0]["port"] == "22"
        assert result[0]["process"] == "sshd"
        assert result[1]["port"] == "8001"
        assert result[1]["process"] == "python3"
        assert result[2]["protocol"] == "udp"
        assert result[2]["port"] == "68"

    def test_parse_ss_empty_output(self):
        from api.routes.operator import _parse_ss_output
        assert _parse_ss_output("") == []
        assert _parse_ss_output("Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process") == []

    def test_build_simple_analysis_ports(self):
        parsed = {
            "open_ports": [
                {"protocol": "tcp", "state": "LISTEN", "local_address": "0.0.0.0:22", "port": "22", "process": "sshd"},
                {"protocol": "tcp", "state": "LISTEN", "local_address": "127.0.0.1:8001", "port": "8001", "process": "python3"},
                {"protocol": "udp", "state": "UNCONN", "local_address": "0.0.0.0:68", "port": "68", "process": "dhclient"},
            ]
        }
        result = _build_simple_analysis(0, parsed)
        assert result is not None
        assert result["outcome"] == "success"
        assert "Port `22`" in result["explanation"]
        assert "sshd" in result["explanation"]
        assert "python3" in result["explanation"]
        assert "dhclient" in result["explanation"]

    def test_build_simple_analysis_no_listeners(self):
        parsed = {"open_ports": []}
        result = _build_simple_analysis(0, parsed)
        assert result is not None
        assert "No listening sockets found" in result["explanation"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
