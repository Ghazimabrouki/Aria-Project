"""
Scenario-based tests for the AI Operator feature.

These import directly from api.routes.operator to test the real implementation.
"""

import pytest
import yaml

from api.routes.operator import (
    _normalize_playbook_hosts,
    _validate_playbook_yaml,
    _resolve_target_from_inventory,
)


# ---------------------------------------------------------------------------
# Real-world playbook scenarios from actual user failures
# ---------------------------------------------------------------------------

SCENARIO_BLOCK_IP_GHAZI = """---
- name: Block IP address 1.2.3.4
  hosts: ghazi
  gather_facts: no
  become: yes
  tasks:
    - name: Drop SSH traffic from IP
      shell: iptables -A INPUT -s 1.2.3.4 -p tcp --dport 22 -j DROP
      changed_when: false

    - name: Drop ICMP traffic from IP
      shell: iptables -A INPUT -s 1.2.3.4 -p icmp -j DROP
      changed_when: false
"""

SCENARIO_CHECK_RAM_GHAZI = """---
- name: Check RAM status
  hosts: ghazi
  gather_facts: no
  tasks:
    - name: Run free -m
      shell: free -m
      changed_when: false
      register: memory_output

    - name: Display memory
      debug:
        var: memory_output.stdout
"""

SCENARIO_NSLOOKUP_TARGET = """---
- name: Query DNS for 8.8.8.8
  hosts: target
  gather_facts: no
  tasks:
    - name: Run nslookup
      shell: nslookup 8.8.8.8
      changed_when: false
      register: nslookup_result

    - name: Show result
      debug:
        var: nslookup_result.stdout
"""

SCENARIO_HOSTS_ALL = """---
- name: Check disk on all hosts
  hosts: all
  tasks:
    - name: Run df -h
      shell: df -h
      changed_when: false
"""

SCENARIO_HOSTS_IP = """---
- name: Check logs on 193.95.30.97
  hosts: 193.95.30.97
  gather_facts: no
  tasks:
    - name: Check auth.log
      shell: grep "1.2.3.4" /var/log/auth.log
      changed_when: false
"""

SCENARIO_LOCALHOST = """---
- name: Local diagnostic
  hosts: localhost
  tasks:
    - name: Echo
      shell: echo hello
      changed_when: false
"""

SCENARIO_MULTI_PLAY_DIFFERENT_HOSTS = """---
- name: Check RAM on ghazi
  hosts: ghazi
  tasks:
    - name: Task 1
      shell: echo 1

- name: Check disk on webserver
  hosts: webserver
  tasks:
    - name: Task 2
      shell: echo 2

- name: Check processes on dbserver
  hosts: dbserver
  gather_facts: no
  tasks:
    - name: Task 3
      shell: echo 3
"""

SCENARIO_HOSTS_IN_COMMAND = """---
- name: Generate report
  hosts: ghazi
  gather_facts: no
  tasks:
    - name: Create report with host info
      shell: |
        echo "hosts: ghazi is the target server" > /tmp/report.txt
        cat /tmp/report.txt
      changed_when: false
"""

SCENARIO_MISSING_HOSTS = """---
- name: Broken play
  gather_facts: no
  tasks:
    - name: Echo
      shell: echo hello
"""

SCENARIO_DICT_NOT_LIST = """
name: Single dict
hosts: target
tasks:
  - name: Task
    shell: echo ok
"""

SCENARIO_UNCLOSED_STRING = """---
- name: Broken
  hosts: ghazi
  tasks:
    - name: Bad string
      shell: 'unclosed string here
"""

SCENARIO_MULTILINE_HOSTS = """---
- name: Top processes
  hosts:
    ghazi
  gather_facts: no
  tasks:
    - name: ps aux
      shell: ps aux | head
"""

SCENARIO_LIST_HOSTS = """---
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
# Test classes
# ---------------------------------------------------------------------------

class TestScenarioBlockIP:
    """Scenario: User asks to block an IP address"""

    def test_block_ip_ghazi_normalized(self):
        fixed = _normalize_playbook_hosts(SCENARIO_BLOCK_IP_GHAZI)
        parsed = yaml.safe_load(fixed)
        assert parsed[0]["hosts"] == "target"
        assert "iptables -A INPUT -s 1.2.3.4" in fixed

    def test_block_ip_valid_yaml(self):
        fixed = _normalize_playbook_hosts(SCENARIO_BLOCK_IP_GHAZI)
        ok, err = _validate_playbook_yaml(fixed)
        assert ok is True, f"Validation failed: {err}"

    def test_block_ip_parses_correctly(self):
        fixed = _normalize_playbook_hosts(SCENARIO_BLOCK_IP_GHAZI)
        parsed = yaml.safe_load(fixed)
        assert len(parsed[0]["tasks"]) == 2


class TestScenarioCheckRAM:
    """Scenario: User asks to check RAM status"""

    def test_ram_check_ghazi_normalized(self):
        fixed = _normalize_playbook_hosts(SCENARIO_CHECK_RAM_GHAZI)
        parsed = yaml.safe_load(fixed)
        assert parsed[0]["hosts"] == "target"
        assert "free -m" in fixed

    def test_ram_check_valid_yaml(self):
        fixed = _normalize_playbook_hosts(SCENARIO_CHECK_RAM_GHAZI)
        ok, err = _validate_playbook_yaml(fixed)
        assert ok is True, f"Validation failed: {err}"


class TestScenarioNslookup:
    """Scenario: User asks about an IP address (nslookup)"""

    def test_nslookup_target_unchanged(self):
        fixed = _normalize_playbook_hosts(SCENARIO_NSLOOKUP_TARGET)
        parsed = yaml.safe_load(fixed)
        assert parsed[0]["hosts"] == "target"

    def test_nslookup_valid_yaml(self):
        ok, err = _validate_playbook_yaml(SCENARIO_NSLOOKUP_TARGET)
        assert ok is True, f"Validation failed: {err}"


class TestScenarioMalformed:
    """Scenario: LLM generates malformed or garbage output"""

    def test_missing_hosts_rejected(self):
        ok, err = _validate_playbook_yaml(SCENARIO_MISSING_HOSTS)
        assert ok is False
        assert "hosts" in err.lower()

    def test_dict_not_list_rejected(self):
        ok, err = _validate_playbook_yaml(SCENARIO_DICT_NOT_LIST)
        assert ok is False
        assert "list" in err.lower()

    def test_unclosed_string_rejected(self):
        ok, err = _validate_playbook_yaml(SCENARIO_UNCLOSED_STRING)
        assert ok is False


class TestScenarioHostsVariations:
    """Scenario: LLM uses different host values"""

    def test_hosts_all_becomes_target(self):
        fixed = _normalize_playbook_hosts(SCENARIO_HOSTS_ALL)
        parsed = yaml.safe_load(fixed)
        assert parsed[0]["hosts"] == "target"

    def test_hosts_ip_becomes_target(self):
        fixed = _normalize_playbook_hosts(SCENARIO_HOSTS_IP)
        parsed = yaml.safe_load(fixed)
        assert parsed[0]["hosts"] == "target"
        assert "grep \"1.2.3.4\" /var/log/auth.log" in fixed

    def test_hosts_localhost_becomes_target(self):
        fixed = _normalize_playbook_hosts(SCENARIO_LOCALHOST)
        parsed = yaml.safe_load(fixed)
        assert parsed[0]["hosts"] == "target"


class TestScenarioMultiPlay:
    """Scenario: Multi-play playbook with different hosts"""

    def test_all_plays_normalized(self):
        fixed = _normalize_playbook_hosts(SCENARIO_MULTI_PLAY_DIFFERENT_HOSTS)
        parsed = yaml.safe_load(fixed)
        assert len(parsed) == 3
        for play in parsed:
            assert play["hosts"] == "target"

    def test_tasks_preserved(self):
        fixed = _normalize_playbook_hosts(SCENARIO_MULTI_PLAY_DIFFERENT_HOSTS)
        assert "echo 1" in fixed
        assert "echo 2" in fixed
        assert "echo 3" in fixed

    def test_multi_play_valid_yaml(self):
        fixed = _normalize_playbook_hosts(SCENARIO_MULTI_PLAY_DIFFERENT_HOSTS)
        ok, err = _validate_playbook_yaml(fixed)
        assert ok is True, f"Validation failed: {err}"


class TestScenarioHostsInCommand:
    """Scenario: Shell command contains the string 'hosts: ghazi'"""

    def test_command_string_not_modified(self):
        fixed = _normalize_playbook_hosts(SCENARIO_HOSTS_IN_COMMAND)
        parsed = yaml.safe_load(fixed)
        assert parsed[0]["hosts"] == "target"
        # The string inside the shell command should be untouched
        assert "hosts: ghazi is the target server" in fixed

    def test_valid_yaml(self):
        fixed = _normalize_playbook_hosts(SCENARIO_HOSTS_IN_COMMAND)
        ok, err = _validate_playbook_yaml(fixed)
        assert ok is True, f"Validation failed: {err}"


class TestScenarioMultilineHosts:
    """Scenario: LLM puts host on separate line (YAML folded style)"""

    def test_multiline_host_normalized(self):
        fixed = _normalize_playbook_hosts(SCENARIO_MULTILINE_HOSTS)
        parsed = yaml.safe_load(fixed)
        assert parsed[0]["hosts"] == "target"
        assert "ps aux | head" in fixed

    def test_list_hosts_normalized(self):
        fixed = _normalize_playbook_hosts(SCENARIO_LIST_HOSTS)
        parsed = yaml.safe_load(fixed)
        assert parsed[0]["hosts"] == "target"
        assert "systemctl status sshd" in fixed


class TestInventoryEdgeCases:
    """Edge cases for inventory resolution"""

    def test_ghazi_resolves_correctly(self):
        host, user = _resolve_target_from_inventory("ghazi")
        assert host == "193.95.30.97"
        assert user == "ghazi"

    def test_unknown_alias(self):
        host, user = _resolve_target_from_inventory("nonexistent_host")
        # Strict enforcement: unknown aliases return ('', '')
        assert host == ""
        assert user == ""

    def test_numeric_alias(self):
        host, user = _resolve_target_from_inventory("192.168.1.1")
        # Strict enforcement: numeric alias is also unknown unless in inventory
        assert host == ""
        assert user == ""


class TestEndToEndFlow:
    """Simulate the full operator execution flow"""

    def test_full_flow_block_ip(self):
        original = SCENARIO_BLOCK_IP_GHAZI
        normalized = _normalize_playbook_hosts(original)
        valid, error = _validate_playbook_yaml(normalized)
        assert valid is True
        parsed = yaml.safe_load(normalized)
        assert parsed[0]["hosts"] == "target"
        assert len(parsed[0]["tasks"]) == 2

    def test_full_flow_malformed_caught_early(self):
        broken = SCENARIO_UNCLOSED_STRING
        valid, error = _validate_playbook_yaml(broken)
        assert valid is False

    def test_full_flow_multiline_host(self):
        """The exact edge case that caused 'what proceeses' to fail"""
        normalized = _normalize_playbook_hosts(SCENARIO_MULTILINE_HOSTS)
        parsed = yaml.safe_load(normalized)
        assert parsed[0]["hosts"] == "target"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
