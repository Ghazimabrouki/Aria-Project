"""Unit tests for Phase 3 staged remediation components."""

import pytest

from response.ai_engine.playbook_splitter import (
    split_playbook_into_phases,
    generate_rollback_playbook,
)


class TestEvidenceCollection:
    """Test evidence collection playbook generation."""

    def test_evidence_playbook_generated(self):
        from response.ansible_exec import _generate_evidence_playbook
        playbook = _generate_evidence_playbook("web1", "inv-123", "brute_force")
        assert "---" in playbook
        assert "hosts: target" in playbook
        assert "evidence directory" in playbook.lower()
        assert "data/evidence/inv-123" in playbook

    def test_brute_force_specific_evidence(self):
        from response.ansible_exec import _generate_evidence_playbook
        playbook = _generate_evidence_playbook("web1", "inv-123", "brute_force")
        assert "SSH auth failures" in playbook or "ssh_failures" in playbook
        assert "successful logins" in playbook.lower() or "ssh_success" in playbook

    def test_web_attack_specific_evidence(self):
        from response.ansible_exec import _generate_evidence_playbook
        playbook = _generate_evidence_playbook("web1", "inv-123", "web_attack")
        assert "web server error" in playbook.lower() or "web_errors" in playbook

    def test_malware_specific_evidence(self):
        from response.ansible_exec import _generate_evidence_playbook
        playbook = _generate_evidence_playbook("srv1", "inv-123", "malware")
        assert "suspicious processes" in playbook.lower() or "suspicious_procs" in playbook

    def test_generic_evidence_always_present(self):
        from response.ansible_exec import _generate_evidence_playbook
        playbook = _generate_evidence_playbook("srv1", "inv-123", "unknown")
        assert "network connections" in playbook.lower()
        assert "running processes" in playbook.lower()
        assert "firewall rules" in playbook.lower()


class TestRollbackPlaybook:
    """Test rollback playbook generation from containment."""

    def test_iptables_rollback(self):
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
        assert "state: absent" in rollback
        assert "Rollback" in rollback

    def test_service_rollback(self):
        containment = """---
- name: Containment
  hosts: target
  tasks:
    - name: Stop nginx
      ansible.builtin.service:
        name: nginx
        state: stopped
"""
        rollback = generate_rollback_playbook(containment)
        assert "state: started" in rollback

    def test_systemd_rollback(self):
        containment = """---
- name: Containment
  hosts: target
  tasks:
    - name: Disable service
      ansible.builtin.systemd:
        name: ssh
        state: stopped
        enabled: false
"""
        rollback = generate_rollback_playbook(containment)
        assert "state: started" in rollback

    def test_shell_iptables_rollback(self):
        containment = """---
- name: Containment
  hosts: target
  tasks:
    - name: Block IP via shell
      ansible.builtin.shell: "iptables -A INPUT -s 1.2.3.4 -j DROP"
"""
        rollback = generate_rollback_playbook(containment)
        assert "-D" in rollback
        assert "-A" not in rollback


class TestOSAwareFallback:
    """Test OS-aware fallback playbook generation."""

    def test_linux_default(self):
        from response.ai_engine.main import _generate_fallback_ai_result
        context = {
            "incident": {"title": "Test", "severity": "high"},
            "alerts": [],
            "source_ips": ["1.2.3.4"],
            "dest_ips": [],
            "hostnames": ["web1"],
            "mitre_tactics": [],
            "attack_type": "brute_force",
            "proof_of_compromise": {"compromised": False, "confidence": "low", "indicators": []},
            "all_iocs": {},
        }
        result = _generate_fallback_ai_result(context)
        # Fallback uses shell-based iptables commands for safety and compatibility
        assert "ansible.builtin.shell" in result["playbook_yaml"]
        assert "iptables -A INPUT" in result["playbook_yaml"]
        assert "target_os: \"linux\"" in result["playbook_yaml"]

    def test_windows_from_agent_os(self):
        from response.ai_engine.main import _generate_fallback_ai_result
        context = {
            "incident": {"title": "Test", "severity": "high"},
            "alerts": [{"metadata": {"agent_os_name": "Windows Server 2019"}}],
            "source_ips": ["1.2.3.4"],
            "dest_ips": [],
            "hostnames": ["win1"],
            "mitre_tactics": [],
            "attack_type": "brute_force",
            "proof_of_compromise": {"compromised": False, "confidence": "low", "indicators": []},
            "all_iocs": {},
        }
        result = _generate_fallback_ai_result(context)
        # Fallback uses win_shell with netsh for safety and compatibility
        assert "ansible.windows.win_shell" in result["playbook_yaml"]
        assert "netsh advfirewall" in result["playbook_yaml"]
        assert "target_os: \"windows\"" in result["playbook_yaml"]

    def test_windows_from_decoder(self):
        from response.ai_engine.main import _generate_fallback_ai_result
        context = {
            "incident": {"title": "Test", "severity": "high"},
            "alerts": [{"metadata": {"decoder_name": "windows_eventchannel"}}],
            "source_ips": ["1.2.3.4"],
            "dest_ips": [],
            "hostnames": ["win1"],
            "mitre_tactics": [],
            "attack_type": "malware",
            "proof_of_compromise": {"compromised": False, "confidence": "low", "indicators": []},
            "all_iocs": {},
        }
        result = _generate_fallback_ai_result(context)
        assert "ansible.windows.win_shell" in result["playbook_yaml"]


class TestPlaybookSplitterEdgeCases:
    """Test edge cases for playbook splitting."""

    def test_playbook_with_phase_comments(self):
        playbook = """---
- name: Remediation
  hosts: target
  tasks:
    # Phase 1: Immediate containment
    - name: Block attacker
      ansible.builtin.iptables:
        chain: INPUT
        source: "1.2.3.4"
        jump: DROP

    # Phase 2: Service-specific hardening
    - name: Update SSH config
      ansible.builtin.shell: "echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config"

    # Phase 3: Detection and forensics
    - name: Save auth logs
      ansible.builtin.shell: "cp /var/log/auth.log /tmp/auth.log.bak"

    # Phase 4: Verification
    - name: Check SSH service
      ansible.builtin.service:
        name: sshd
        state: started
"""
        result = split_playbook_into_phases(playbook)
        # The classifier uses task names, not comments, but the names still map
        assert "Block attacker" in result["containment"]
        assert "Update SSH config" in result["hardening"]
        assert "Save auth logs" in result["forensics"]
        assert "Check SSH service" in result["verification"]

    def test_multiple_plays(self):
        playbook = """---
- name: Containment play
  hosts: target
  tasks:
    - name: Block IP
      ansible.builtin.iptables:
        chain: INPUT
        source: "1.2.3.4"
        jump: DROP

- name: Verification play
  hosts: target
  tasks:
    - name: Check health
      ansible.builtin.shell: "systemctl status sshd"
"""
        result = split_playbook_into_phases(playbook)
        assert "Block IP" in result["containment"]
        assert "Check health" in result["verification"]

    def test_no_tasks_play(self):
        playbook = """---
- name: Empty play
  hosts: target
"""
        result = split_playbook_into_phases(playbook)
        # Should not crash
        for phase in ("containment", "hardening", "forensics", "verification"):
            assert result[phase] != ""
