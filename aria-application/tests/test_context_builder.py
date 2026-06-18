"""Unit tests for context_builder attack type detection."""

import pytest

from response.watcher.context_builder import _determine_attack_type


class TestDetermineAttackType:
    """Test _determine_attack_type with real-world alert patterns."""

    def test_real_brute_force_with_compromise(self):
        """Incident with failed logins + successful login from same IP = brute force."""
        behavioral = {
            "auth_failure": 8,
            "auth_success": 2,
            "reconnaissance": 0,
        }
        auth_analysis = {
            "is_suspicious": True,
            "risk_indicators": ["Possible compromised accounts: 1 IPs had failed then successful logins"],
        }
        result = _determine_attack_type(
            behavioral, {}, set(), set(), auth_analysis,
            {"wazuh": 10}, [], 10
        )
        assert result == "brute_force"

    def test_not_brute_force_session_events_only(self):
        """Login session open/close are NOT brute force."""
        behavioral = {
            "auth_failure": 0,  # Previously these were miscounted as auth_failure
            "auth_success": 3,
            "container_escape": 5,
        }
        auth_analysis = {
            "is_suspicious": False,
            "risk_indicators": [],
        }
        result = _determine_attack_type(
            behavioral, {}, set(), set(), auth_analysis,
            {"falco": 5, "wazuh": 3}, [], 8
        )
        # Container escape should win because auth failures are 0
        assert result == "container_escape"

    def test_falco_container_escape(self):
        """Falco alerts with container violations = container_escape."""
        behavioral = {
            "container_escape": 6,
            "privilege_escalation": 2,
            "auth_failure": 1,
        }
        auth_analysis = {"is_suspicious": False, "risk_indicators": []}
        result = _determine_attack_type(
            behavioral, {}, set(), set(), auth_analysis,
            {"falco": 7, "wazuh": 2}, [
                "Write below etc",
                "Read sensitive file untrusted",
                "BPF Program Not Profiled",
            ], 9
        )
        assert result == "container_escape"

    def test_port_scan_from_rule_names(self):
        """Suricata port scan rules should detect port_scan."""
        behavioral = {
            "reconnaissance": 3,
            "auth_failure": 2,
        }
        auth_analysis = {"is_suspicious": False, "risk_indicators": []}
        result = _determine_attack_type(
            behavioral, {}, set(), set(), auth_analysis,
            {"suricata": 5}, [
                "ET SCAN Suspicious inbound to Oracle SQL port 1521",
                "ET SCAN Suspicious inbound to mySQL port 3306",
            ], 5
        )
        assert result == "port_scan"

    def test_mixed_when_ambiguous(self):
        """When two attack types have similar scores, return mixed."""
        behavioral = {
            "auth_failure": 4,   # brute_force score: 4 * 1 = 4 (no suspicious auth)
            "execution": 4,      # execution score: 4 * 2 = 8
            "privilege_escalation": 2,  # privesc score: 2 * 4 = 8
        }
        auth_analysis = {"is_suspicious": False, "risk_indicators": []}
        result = _determine_attack_type(
            behavioral, {}, set(), set(), auth_analysis,
            {"wazuh": 5, "falco": 5}, [], 10
        )
        # execution=8, privilege_escalation=8 → ratio = 1.0 < 1.5 → mixed
        assert result == "mixed"

    def test_unknown_when_no_clear_pattern(self):
        """Low scores with no clear attack pattern = unknown."""
        behavioral = {
            "auth_success": 2,
            "network_anomaly": 1,
        }
        auth_analysis = {"is_suspicious": False, "risk_indicators": []}
        result = _determine_attack_type(
            behavioral, {}, set(), set(), auth_analysis,
            {"wazuh": 3}, [], 3
        )
        assert result == "unknown"

    def test_network_anomaly_from_reputation(self):
        """CINS/poor reputation IP alerts = network_anomaly."""
        behavioral = {
            "network_anomaly": 4,
            "reconnaissance": 1,
        }
        auth_analysis = {"is_suspicious": False, "risk_indicators": []}
        result = _determine_attack_type(
            behavioral, {}, set(), set(), auth_analysis,
            {"suricata": 5}, [
                "ET CINS Active Threat Intelligence Poor Reputation IP",
            ], 5
        )
        assert result == "network_anomaly"

    def test_file_integrity_from_checksum(self):
        """Integrity checksum changes = file_integrity."""
        behavioral = {
            "file_integrity": 3,
            "system_modification": 1,
        }
        auth_analysis = {"is_suspicious": False, "risk_indicators": []}
        result = _determine_attack_type(
            behavioral, {}, set(), set(), auth_analysis,
            {"wazuh": 4}, [
                "Integrity checksum changed.",
            ], 4
        )
        assert result == "file_integrity"

    def test_system_modification_from_packages(self):
        """Package installation + new users = system_modification."""
        behavioral = {
            "system_modification": 3,
            "auth_success": 1,
        }
        auth_analysis = {"is_suspicious": False, "risk_indicators": []}
        result = _determine_attack_type(
            behavioral, {}, set(), set(), auth_analysis,
            {"wazuh": 4}, [
                "New dpkg (Debian Package) installed.",
                "New user added to the system.",
            ], 4
        )
        assert result == "system_modification"

    def test_auth_failure_does_not_dominate_low_count(self):
        """Just 3 auth failures with no suspicious pattern should NOT be brute_force."""
        behavioral = {
            "auth_failure": 3,
            "auth_success": 1,
            "container_escape": 2,
        }
        auth_analysis = {"is_suspicious": False, "risk_indicators": []}
        result = _determine_attack_type(
            behavioral, {}, set(), set(), auth_analysis,
            {"wazuh": 4, "falco": 2}, [], 6
        )
        # With only 3 auth failures and no suspicious pattern, brute_force gets low score
        # container_escape might win, or it could be unknown
        assert result != "brute_force"

    def test_empty_alerts(self):
        """No alerts = unknown."""
        result = _determine_attack_type(
            {}, {}, set(), set(), {"is_suspicious": False, "risk_indicators": []},
            {}, [], 0
        )
        assert result == "unknown"

    def test_malware_high_confidence(self):
        """Malware alerts with explicit rule names = malware."""
        behavioral = {
            "malware": 2,
            "execution": 1,
            "auth_failure": 1,
        }
        auth_analysis = {"is_suspicious": False, "risk_indicators": []}
        result = _determine_attack_type(
            behavioral, {}, set(), set(), auth_analysis,
            {"wazuh": 3}, [
                "Trojan detected on endpoint",
            ], 4
        )
        assert result == "malware"

    def test_privilege_escalation_with_falco_and_sudo(self):
        """Falco violations + sudo to root = privilege_escalation."""
        behavioral = {
            "privilege_escalation": 4,
            "container_escape": 2,
            "auth_failure": 1,
        }
        auth_analysis = {"is_suspicious": True, "risk_indicators": ["Root access after auth failures"]}
        result = _determine_attack_type(
            behavioral, {}, set(), set(), auth_analysis,
            {"falco": 4, "wazuh": 3}, [
                "Write below root",
                "Successful sudo to ROOT executed.",
            ], 7
        )
        # privilege_escalation should win over brute_force because it's dominant
        assert result == "privilege_escalation"

    def test_web_attack_from_explicit_rules(self):
        """Explicit web attack rule names should win."""
        behavioral = {
            "web_attack": 2,
            "auth_failure": 2,
        }
        auth_analysis = {"is_suspicious": False, "risk_indicators": []}
        result = _determine_attack_type(
            behavioral, {}, set(), set(), auth_analysis,
            {"wazuh": 4}, [
                "SQL injection attempt detected",
            ], 4
        )
        assert result == "web_attack"

    def test_lateral_movement_from_rule_name(self):
        """Rule names mentioning lateral movement should detect it."""
        behavioral = {
            "lateral_movement": 2,
            "auth_failure": 1,
        }
        auth_analysis = {"is_suspicious": False, "risk_indicators": []}
        result = _determine_attack_type(
            behavioral, {}, set(), set(), auth_analysis,
            {"wazuh": 3}, [
                "Lateral movement detected via WMI",
            ], 3
        )
        assert result == "lateral_movement"
