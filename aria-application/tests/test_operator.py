"""
Unit tests for AI Operator helper functions.

These import directly from api.routes.operator to test the real implementation.
"""

import pytest
import yaml

from api.routes.operator import (
    _normalize_playbook_hosts,
    _validate_playbook_yaml,
    _resolve_target_from_inventory,
    _extract_json,
    _get_inventory_hosts,
    _get_inventory_status,
    _validate_targets_against_inventory,
    _get_first_target_from_inventory,
)


# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

PLAYBOOK_GHAZI = """---
- name: Block IP
  hosts: ghazi
  gather_facts: no
  tasks:
    - name: Drop traffic
      shell: iptables -A INPUT -s 1.2.3.4 -j DROP
"""

PLAYBOOK_TARGET = """---
- name: Check logs
  hosts: target
  gather_facts: no
  tasks:
    - name: Grep auth log
      shell: grep "1.2.3.4" /var/log/auth.log
"""

PLAYBOOK_IP = """---
- name: Check RAM
  hosts: 193.95.30.97
  gather_facts: no
  tasks:
    - name: Run free
      shell: free -m
"""

PLAYBOOK_ALL = """---
- name: Check disk
  hosts: all
  tasks:
    - name: Run df
      shell: df -h
"""

PLAYBOOK_LOCALHOST = """---
- name: Local check
  hosts: localhost
  tasks:
    - name: Echo
      shell: echo hello
"""

PLAYBOOK_MULTI = """---
- name: First play
  hosts: ghazi
  tasks:
    - name: Task 1
      shell: echo 1

- name: Second play
  hosts: webserver
  tasks:
    - name: Task 2
      shell: echo 2
"""

PLAYBOOK_MISSING_HOSTS = """---
- name: Missing hosts
  gather_facts: no
  tasks:
    - name: Task
      shell: echo ok
"""

PLAYBOOK_NOT_A_LIST = """
name: Single dict
hosts: target
tasks:
  - name: Task
    shell: echo ok
"""

PLAYBOOK_EMPTY = ""

PLAYBOOK_HOSTS_IN_STRING = """---
- name: Check something
  hosts: target
  tasks:
    - name: Debug
      debug:
        msg: "hosts: ghazi is just a string"
"""

PLAYBOOK_MULTILINE_HOSTS = """---
- name: Check processes
  hosts:
    ghazi
  gather_facts: no
  tasks:
    - name: ps aux
      shell: ps aux | head
"""

PLAYBOOK_LIST_HOSTS = """---
- name: Check services
  hosts:
    - ghazi
    - webserver
  gather_facts: no
  tasks:
    - name: systemctl
      shell: systemctl status sshd
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestInventoryResolution:
    """Tests for _resolve_target_from_inventory"""

    def test_resolve_ghazi(self):
        host, user = _resolve_target_from_inventory("ghazi")
        assert host == "193.95.30.97"
        assert user == "ghazi"

    def test_resolve_unknown_alias_returns_empty(self):
        host, user = _resolve_target_from_inventory("nonexistent")
        # Strict enforcement: unknown aliases return ('', '')
        assert host == ""
        assert user == ""

    def test_resolve_localhost_not_in_inventory(self):
        host, user = _resolve_target_from_inventory("localhost")
        # localhost is only valid if it exists in the inventory
        if "localhost" in {h["alias"] for h in _get_inventory_hosts()}:
            assert host == "localhost"
        else:
            assert host == ""
            assert user == ""


class TestJsonExtraction:
    """Tests for _extract_json"""

    def test_extract_clean_json(self):
        raw = '{"intent": "block_ip", "risk_level": "medium"}'
        result = _extract_json(raw)
        assert result["intent"] == "block_ip"

    def test_extract_json_with_markdown(self):
        raw = 'Some text\n```json\n{"intent": "test"}\n```\nMore text'
        result = _extract_json(raw)
        assert result["intent"] == "test"

    def test_extract_invalid_json(self):
        raw = "This is not json"
        result = _extract_json(raw)
        assert result == {}


class TestPlaybookHostNormalization:
    """Tests for _normalize_playbook_hosts — THE CORE BUG FIX"""

    def test_ghazi_becomes_target(self):
        fixed = _normalize_playbook_hosts(PLAYBOOK_GHAZI)
        parsed = yaml.safe_load(fixed)
        assert parsed[0]["hosts"] == "target"
        assert "iptables -A INPUT -s 1.2.3.4 -j DROP" in fixed

    def test_ip_address_becomes_target(self):
        fixed = _normalize_playbook_hosts(PLAYBOOK_IP)
        parsed = yaml.safe_load(fixed)
        assert parsed[0]["hosts"] == "target"

    def test_all_becomes_target(self):
        fixed = _normalize_playbook_hosts(PLAYBOOK_ALL)
        parsed = yaml.safe_load(fixed)
        assert parsed[0]["hosts"] == "target"

    def test_localhost_becomes_target(self):
        fixed = _normalize_playbook_hosts(PLAYBOOK_LOCALHOST)
        parsed = yaml.safe_load(fixed)
        assert parsed[0]["hosts"] == "target"

    def test_target_stays_target(self):
        fixed = _normalize_playbook_hosts(PLAYBOOK_TARGET)
        parsed = yaml.safe_load(fixed)
        assert parsed[0]["hosts"] == "target"
        assert fixed.count("hosts: target") == 1

    def test_multi_play_normalization(self):
        fixed = _normalize_playbook_hosts(PLAYBOOK_MULTI)
        parsed = yaml.safe_load(fixed)
        assert len(parsed) == 2
        for play in parsed:
            assert play["hosts"] == "target"

    def test_hosts_inside_string_not_touched(self):
        fixed = _normalize_playbook_hosts(PLAYBOOK_HOSTS_IN_STRING)
        parsed = yaml.safe_load(fixed)
        assert parsed[0]["hosts"] == "target"
        # The string inside debug.msg should still have "hosts: ghazi"
        assert "hosts: ghazi is just a string" in fixed

    def test_multiline_hosts_normalized(self):
        """hosts:\n    ghazi  (YAML folded style)"""
        fixed = _normalize_playbook_hosts(PLAYBOOK_MULTILINE_HOSTS)
        parsed = yaml.safe_load(fixed)
        assert parsed[0]["hosts"] == "target"
        assert "ps aux | head" in fixed

    def test_list_hosts_normalized(self):
        """hosts:\n    - ghazi\n    - webserver"""
        fixed = _normalize_playbook_hosts(PLAYBOOK_LIST_HOSTS)
        parsed = yaml.safe_load(fixed)
        assert parsed[0]["hosts"] == "target"
        assert "systemctl status sshd" in fixed


class TestPlaybookYamlValidation:
    """Tests for _validate_playbook_yaml"""

    def test_valid_playbook(self):
        ok, err = _validate_playbook_yaml(PLAYBOOK_TARGET)
        assert ok is True
        assert err == ""

    def test_empty_playbook(self):
        ok, err = _validate_playbook_yaml(PLAYBOOK_EMPTY)
        assert ok is False
        assert "empty" in err.lower()

    def test_not_a_list(self):
        ok, err = _validate_playbook_yaml(PLAYBOOK_NOT_A_LIST)
        assert ok is False
        assert "list" in err.lower()

    def test_missing_hosts_key(self):
        ok, err = _validate_playbook_yaml(PLAYBOOK_MISSING_HOSTS)
        assert ok is False
        assert "hosts" in err.lower()

    def test_bad_yaml_syntax(self):
        bad = "---\n- name: Broken\n  hosts: target\n  tasks:\n    - name: x\n      shell: 'unclosed string\n    - name: y\n      shell: echo"
        ok, err = _validate_playbook_yaml(bad)
        assert ok is False
        assert "yaml" in err.lower() or "syntax" in err.lower()


class TestFullOperatorFlow:
    """Integration-style tests that simulate the operator execution flow"""

    def test_playbook_generated_with_wrong_host_is_fixable(self):
        llm_playbook = PLAYBOOK_GHAZI
        ok, err = _validate_playbook_yaml(llm_playbook)
        assert ok is True, f"Unexpected YAML error: {err}"
        fixed = _normalize_playbook_hosts(llm_playbook)
        ok, err = _validate_playbook_yaml(fixed)
        assert ok is True, f"Normalized playbook invalid: {err}"
        parsed = yaml.safe_load(fixed)
        assert parsed[0]["hosts"] == "target"

    def test_malformed_playbook_is_rejected(self):
        truly_broken = "---\n- name: x\n  hosts: target\n  tasks:\n    - name: y\n      shell: 'unclosed"
        ok, err = _validate_playbook_yaml(truly_broken)
        assert ok is False, f"Should have rejected malformed playbook: {err}"

    def test_inventory_matches_normalized_playbook(self):
        for original in [PLAYBOOK_GHAZI, PLAYBOOK_IP, PLAYBOOK_ALL, PLAYBOOK_LOCALHOST]:
            fixed = _normalize_playbook_hosts(original)
            parsed = yaml.safe_load(fixed)
            for play in parsed:
                assert play.get("hosts") == "target", (
                    f"Playbook still has hosts={play.get('hosts')} after normalization"
                )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestInventoryHosts:
    def test_get_inventory_hosts_returns_ghazi(self):
        hosts = _get_inventory_hosts()
        assert len(hosts) >= 1
        aliases = {h["alias"] for h in hosts}
        assert "ghazi" in aliases

    def test_validate_targets_valid(self):
        is_valid, error, valid = _validate_targets_against_inventory(["ghazi"])
        assert is_valid is True
        assert error == ""
        assert valid == ["ghazi"]

    def test_validate_targets_invalid(self):
        is_valid, error, valid = _validate_targets_against_inventory(["host1", "host2"])
        assert is_valid is False
        assert "Unknown target host(s): host1, host2" in error
        assert valid == []

    def test_validate_targets_empty(self):
        is_valid, error, valid = _validate_targets_against_inventory([])
        assert is_valid is False
        assert "No target hosts specified" in error
        assert valid == []


class TestInventoryStatus:
    def test_inventory_status_ok(self):
        status = _get_inventory_status()
        assert status["state"] == "ok"
        assert status["readable"] is True
        assert len(status["hosts"]) >= 1
        assert "Found" in status["message"]

    def test_inventory_status_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr("api.routes.operator.Path", lambda p: tmp_path / "nonexistent_inventory")
        status = _get_inventory_status()
        assert status["state"] == "missing"
        assert status["readable"] is False
        assert status["hosts"] == []

    def test_inventory_status_empty(self, tmp_path, monkeypatch):
        inv = tmp_path / "ansible_inventory"
        inv.write_text("""[targets]\n""")
        monkeypatch.setattr("api.routes.operator.Path", lambda p: inv)
        status = _get_inventory_status()
        assert status["state"] == "empty"
        assert status["readable"] is True
        assert status["hosts"] == []

    def test_inventory_status_malformed(self, tmp_path, monkeypatch):
        inv = tmp_path / "ansible_inventory"
        inv.write_text("""this is not an ini file\nwith no groups\n""")
        monkeypatch.setattr("api.routes.operator.Path", lambda p: inv)
        status = _get_inventory_status()
        assert status["state"] == "malformed"
        assert status["readable"] is True
        assert status["hosts"] == []


class TestStrictFirstTarget:
    def test_first_target_no_fallback(self, tmp_path, monkeypatch):
        monkeypatch.setattr("api.routes.operator.Path", lambda p: tmp_path / "nonexistent")
        host, user = _get_first_target_from_inventory()
        assert host == ""
        assert user == ""
