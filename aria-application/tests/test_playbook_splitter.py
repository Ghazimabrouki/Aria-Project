"""Unit tests for playbook phase splitter and rollback generator."""

import pytest
import yaml

from response.ai_engine.playbook_splitter import (
    split_playbook_into_phases,
    generate_rollback_playbook,
    _classify_task,
)


class TestSplitPlaybookIntoPhases:
    """Test splitting monolithic playbooks into phases."""

    def test_empty_playbook(self):
        result = split_playbook_into_phases("")
        assert result["containment"] != ""
        assert "no tasks" in result["containment"].lower()

    def test_perfect_four_phase_playbook(self):
        playbook = """---
- name: Remediation
  hosts: target
  become: yes
  tasks:
    - name: Block attacker IP
      ansible.builtin.iptables:
        chain: INPUT
        source: "1.2.3.4"
        jump: DROP

    - name: Update firewall rules
      ansible.builtin.iptables:
        chain: INPUT
        policy: DROP

    - name: Collect auth logs
      ansible.builtin.shell: "cat /var/log/auth.log"

    - name: Verify service is running
      ansible.builtin.service:
        name: ssh
        state: started
"""
        result = split_playbook_into_phases(playbook)
        # Containment should have "Block attacker IP"
        assert "Block attacker IP" in result["containment"]
        # Hardening should have "Update firewall rules"
        assert "Update firewall rules" in result["hardening"]
        # Forensics should have "Collect auth logs"
        assert "Collect auth logs" in result["forensics"]
        # Verification should have "Verify service is running"
        assert "Verify service is running" in result["verification"]

    def test_variant_headers_accepted(self):
        playbook = """---
- name: Test
  hosts: target
  tasks:
    - name: Quarantine infected host
      ansible.builtin.shell: "echo quarantine"

    - name: Install security patch
      ansible.builtin.shell: "echo patch"

    - name: Audit user accounts
      ansible.builtin.shell: "echo audit"

    - name: Confirm no suspicious processes
      ansible.builtin.shell: "echo confirm"
"""
        result = split_playbook_into_phases(playbook)
        assert "Quarantine" in result["containment"] or "quarantine" in result["containment"]
        assert "patch" in result["hardening"] or "Install" in result["hardening"]

    def test_unknown_tasks_distributed(self):
        playbook = """---
- name: Test
  hosts: target
  tasks:
    - name: Some random task
      ansible.builtin.debug:
        msg: "hello"

    - name: Another random task
      ansible.builtin.debug:
        msg: "world"
"""
        result = split_playbook_into_phases(playbook)
        # Unknown tasks should be distributed to the phases with fewest tasks
        # All phases should have non-empty content
        for phase in ("containment", "hardening", "forensics", "verification"):
            assert result[phase] != ""

    def test_yaml_list_preserved(self):
        playbook = """---
- name: Test
  hosts: target
  tasks:
    - name: Block IP
      ansible.builtin.iptables:
        chain: INPUT
        source: "1.2.3.4"
        jump: DROP
"""
        result = split_playbook_into_phases(playbook)
        parsed = yaml.safe_load(result["containment"])
        assert isinstance(parsed, list)
        assert len(parsed) > 0
        assert parsed[0]["tasks"][0]["name"] == "Block IP"

    def test_malformed_yaml_fallback(self):
        # YAML that parses but isn't a list should use fallback
        playbook = "not a list: true\n"
        result = split_playbook_into_phases(playbook)
        assert result["containment"] == playbook
        assert result["hardening"] != ""


class TestGenerateRollbackPlaybook:
    """Test rollback playbook generation."""

    def test_iptables_drop_rollback(self):
        containment = """---
- name: Containment
  hosts: target
  tasks:
    - name: Drop attacker IP
      ansible.builtin.iptables:
        chain: INPUT
        source: "1.2.3.4"
        jump: DROP
"""
        rollback = generate_rollback_playbook(containment)
        assert rollback is not None
        assert "Rollback" in rollback
        parsed = yaml.safe_load(rollback)
        assert parsed[0]["tasks"][0]["ansible.builtin.iptables"]["state"] == "absent"

    def test_service_stop_rollback(self):
        containment = """---
- name: Containment
  hosts: target
  tasks:
    - name: Stop suspicious service
      ansible.builtin.service:
        name: nginx
        state: stopped
"""
        rollback = generate_rollback_playbook(containment)
        assert rollback is not None
        parsed = yaml.safe_load(rollback)
        assert parsed[0]["tasks"][0]["ansible.builtin.service"]["state"] == "started"

    def test_no_reversible_tasks(self):
        containment = """---
- name: Containment
  hosts: target
  tasks:
    - name: Delete suspicious file
      ansible.builtin.file:
        path: /tmp/malware
        state: absent
"""
        rollback = generate_rollback_playbook(containment)
        # File deletion is not reversible — should return empty
        assert rollback == ""

    def test_empty_containment(self):
        rollback = generate_rollback_playbook("")
        assert rollback == ""


class TestClassifyTask:
    """Test individual task classification."""

    def test_containment_keywords(self):
        task = {"name": "Block attacker IP", "ansible.builtin.iptables": {"chain": "INPUT"}}
        assert _classify_task(task) == "containment"

    def test_hardening_keywords(self):
        task = {"name": "Enable fail2ban", "ansible.builtin.service": {"name": "fail2ban", "state": "started"}}
        assert _classify_task(task) == "hardening"

    def test_forensics_keywords(self):
        task = {"name": "Collect auth logs", "ansible.builtin.shell": "cat /var/log/auth.log"}
        assert _classify_task(task) == "forensics"

    def test_verification_keywords(self):
        task = {"name": "Verify firewall rules", "ansible.builtin.shell": "iptables -L"}
        assert _classify_task(task) == "verification"

    def test_unknown_task(self):
        task = {"name": "Do something random", "ansible.builtin.debug": {"msg": "hello"}}
        assert _classify_task(task) == "unknown"

    def test_service_state_heuristic(self):
        # Stopped service = containment
        task = {"name": "Stop nginx", "ansible.builtin.service": {"name": "nginx", "state": "stopped"}}
        assert _classify_task(task) == "containment"

        # Started service = hardening
        task = {"name": "Start nginx", "ansible.builtin.service": {"name": "nginx", "state": "started"}}
        assert _classify_task(task) == "hardening"
