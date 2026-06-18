"""Tests for comprehensive playbook safety validation."""
from __future__ import annotations

import pytest

from response.playbook_safety import validate_playbook_safety


SAFE_PLAYBOOK = """---
- name: Safe remediation
  hosts: target
  become: yes
  tasks:
    - name: Block attacker IP
      ansible.builtin.shell: "iptables -A INPUT -s '10.0.0.1' -j DROP"
"""


def test_safe_playbook_passes():
    result = validate_playbook_safety(SAFE_PLAYBOOK)
    assert result["safe"] is True
    assert result["executable"] is True
    assert result["manual_review_required"] is False
    assert result["reasons"] == []


def test_tail_f_blocked():
    yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Watch logs
      ansible.builtin.shell: "tail -f /var/log/syslog"
"""
    result = validate_playbook_safety(yaml)
    assert result["safe"] is False
    assert result["executable"] is False
    assert any("tail -f" in r for r in result["reasons"])


def test_watch_blocked():
    yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Monitor
      ansible.builtin.command: "watch -n 1 ps aux"
"""
    result = validate_playbook_safety(yaml)
    assert result["safe"] is False
    assert any("watch" in r for r in result["reasons"])


def test_systemctl_isolate_blocked():
    yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Isolate
      ansible.builtin.shell: "systemctl isolate multi-user.target"
"""
    result = validate_playbook_safety(yaml)
    assert result["safe"] is False
    assert any("isolate" in r for r in result["reasons"])


def test_reboot_blocked():
    yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Reboot
      ansible.builtin.command: "reboot now"
"""
    result = validate_playbook_safety(yaml)
    assert result["safe"] is False
    assert any("reboot" in r for r in result["reasons"])


def test_dnf_update_blocked():
    yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Update
      ansible.builtin.shell: "dnf update -y"
"""
    result = validate_playbook_safety(yaml)
    assert result["safe"] is False
    assert any("dnf update" in r for r in result["reasons"])


def test_apt_upgrade_blocked():
    yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Upgrade
      ansible.builtin.shell: "apt upgrade -y"
"""
    result = validate_playbook_safety(yaml)
    assert result["safe"] is False
    assert any("apt upgrade" in r for r in result["reasons"])


def test_rm_rf_blocked():
    yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Clean
      ansible.builtin.shell: "rm -rf /tmp/old"
"""
    result = validate_playbook_safety(yaml)
    assert result["safe"] is False
    assert any("rm -rf" in r for r in result["reasons"])


def test_broad_chmod_blocked():
    yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Fix perms
      ansible.builtin.command: "chmod -R 777 /etc"
"""
    result = validate_playbook_safety(yaml)
    assert result["safe"] is False
    assert any("chmod" in r for r in result["reasons"])


def test_sudoers_edit_blocked():
    yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Add sudo
      ansible.builtin.lineinfile:
        path: /etc/sudoers
        line: "user ALL=(ALL) NOPASSWD:ALL"
"""
    result = validate_playbook_safety(yaml)
    assert result["safe"] is False
    assert any("sudoers" in r for r in result["reasons"])


def test_pam_edit_blocked():
    yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Configure PAM
      ansible.builtin.lineinfile:
        path: /etc/pam.d/sshd
        line: "auth required pam_test.so"
"""
    result = validate_playbook_safety(yaml)
    assert result["safe"] is False
    assert any("PAM" in r for r in result["reasons"])


def test_iptables_empty_jinja_blocked():
    yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Block
      ansible.builtin.shell: "iptables -A INPUT -s {{ attacker_ips[0] }} -j DROP"
"""
    result = validate_playbook_safety(yaml)
    assert result["safe"] is False
    assert any("unresolved Jinja2" in r for r in result["reasons"])


def test_iptables_unresolved_jinja_is_soft_block():
    yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Block with Jinja
      ansible.builtin.shell: "iptables -A INPUT -s '{{ attacker_ips[0] }}' -j DROP"
"""
    result = validate_playbook_safety(yaml)
    assert result["safe"] is False
    assert any("unresolved Jinja2" in r for r in result["reasons"])


def test_iptables_module_unresolved_jinja_is_soft_block():
    yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Block with module
      ansible.builtin.iptables:
        chain: INPUT
        source: "{{ item }}"
        jump: DROP
      loop: "{{ attacker_ips }}"
"""
    result = validate_playbook_safety(yaml)
    assert result["safe"] is False
    assert any("unresolved Jinja2" in r for r in result["reasons"])


def test_iptables_zero_zero_blocked():
    yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Block all
      ansible.builtin.shell: "iptables -A INPUT -s 0.0.0.0/0 -j DROP"
"""
    result = validate_playbook_safety(yaml)
    assert result["safe"] is False
    assert any("0.0.0.0/0" in r for r in result["reasons"])


def test_service_stop_ssh_blocked():
    yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Stop SSH
      ansible.builtin.service:
        name: sshd
        state: stopped
"""
    result = validate_playbook_safety(yaml)
    assert result["safe"] is False
    assert any("ssh" in r.lower() for r in result["reasons"])


def test_dangerous_file_mode_blocked():
    yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Make writable
      ansible.builtin.file:
        path: /tmp/test
        mode: "0777"
"""
    result = validate_playbook_safety(yaml)
    assert result["safe"] is False
    assert any("777" in r for r in result["reasons"])


def test_container_host_mismatch_blocked():
    yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Restart service
      ansible.builtin.shell: "systemctl restart nginx"
"""
    context = {"investigation_type": "security", "target_host": "abc123def456", "alert_sources": ["falco"]}
    result = validate_playbook_safety(yaml, context)
    assert result["safe"] is False
    assert any("container" in r.lower() for r in result["reasons"])


def test_while_true_blocked():
    yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Loop
      ansible.builtin.shell: "while true; do echo x; done"
"""
    result = validate_playbook_safety(yaml)
    assert result["safe"] is False
    assert any("while true" in r.lower() or "indefinite" in r.lower() for r in result["reasons"])


def test_invalid_yaml_returns_error():
    result = validate_playbook_safety("not: valid: yaml: [")
    assert result["safe"] is False
    assert result["executable"] is False
    assert any("Invalid YAML" in r for r in result["reasons"])


def test_empty_playbook_is_safe_but_not_executable():
    result = validate_playbook_safety("---\n")
    assert result["safe"] is True
    assert result["executable"] is False
    assert result["manual_review_required"] is True
    assert result["execution_mode"] == "none"
    assert any("Empty or missing playbook" in r for r in result["reasons"])


def test_unresolved_jinja_firewall_produces_single_soft_block_reason():
    """Unresolved Jinja2 firewall source should produce exactly one soft-block reason,
    not multiple duplicates from hardcoded + generic rules."""
    yaml = """---
- name: Block attacker
  hosts: target
  tasks:
    - name: Block
      ansible.builtin.shell: "iptables -A INPUT -s {{ attacker_ips[0] }} -j DROP"
"""
    result = validate_playbook_safety(yaml)
    assert result["safe"] is False
    jinja_reasons = [r for r in result["reasons"] if "unresolved Jinja2" in r]
    assert len(jinja_reasons) == 1, f"Expected 1 unresolved-jinja reason, got {len(jinja_reasons)}: {jinja_reasons}"


def test_unresolved_jinja_does_not_also_produce_soft_empty_source():
    """When unresolved Jinja is present, soft empty-source reasons for the same task
    should be suppressed."""
    yaml = """---
- name: Block attacker
  hosts: target
  tasks:
    - name: Block
      ansible.builtin.shell: "iptables -A INPUT -s {{ attacker_ips[0] }} -j DROP"
"""
    result = validate_playbook_safety(yaml)
    empty_source_reasons = [r for r in result["reasons"] if "empty or broad source" in r.lower()]
    assert len(empty_source_reasons) == 0, f"Soft empty-source should be suppressed when unresolved Jinja exists: {empty_source_reasons}"


def test_no_double_tier_prefix():
    """Generic rules should not produce '[HARD_BLOCK] HARD BLOCK' double prefix."""
    yaml = """---
- name: Block attacker
  hosts: target
  tasks:
    - name: Block
      ansible.builtin.shell: "iptables -A INPUT -s {{ attacker_ips[0] }} -j DROP"
"""
    result = validate_playbook_safety(yaml)
    for reason in result["reasons"]:
        assert "[HARD_BLOCK] HARD BLOCK" not in reason, f"Double prefix found: {reason}"
        assert "[SOFT_BLOCK] SOFT BLOCK" not in reason, f"Double prefix found: {reason}"
