"""
Tests for severity mapping across all sources and edge cases.
"""

import pytest
from pipeline.mappers.severity import map_severity


class TestWazuhSeverity:

    @pytest.mark.parametrize("level,expected", [
        (1, "low"), (2, "low"), (3, "low"),
        (4, "medium"), (5, "medium"), (6, "medium"),
        (7, "high"), (8, "high"), (9, "high"),
        (10, "critical"), (12, "critical"), (15, "critical"),
    ])
    def test_wazuh_levels(self, level, expected):
        assert map_severity(level, "wazuh") == expected

    def test_wazuh_zero(self):
        assert map_severity(0, "wazuh") == "low"

    def test_wazuh_string_level(self):
        """Level passed as string (from ES) should still work."""
        assert map_severity("10", "wazuh") == "critical"
        assert map_severity("3", "wazuh") == "low"


class TestFalcoSeverity:

    @pytest.mark.parametrize("priority,expected", [
        ("Emergency", "critical"),
        ("Alert", "critical"),
        ("Critical", "critical"),
        ("Error", "high"),
        ("Warning", "medium"),
        ("Notice", "medium"),
        ("Info", "low"),
        ("Debug", "low"),
    ])
    def test_falco_priorities(self, priority, expected):
        assert map_severity(priority, "falco") == expected

    def test_falco_case_insensitive(self):
        assert map_severity("CRITICAL", "falco") == "critical"
        assert map_severity("notice", "falco") == "medium"
        assert map_severity("WARNING", "falco") == "medium"

    def test_falco_unknown_priority(self):
        assert map_severity("unknown_priority", "falco") == "medium"

    def test_falco_none(self):
        assert map_severity(None, "falco") == "medium"


class TestSuricataSeverity:

    @pytest.mark.parametrize("level,expected", [
        (1, "low"),
        (2, "medium"),
        (3, "high"),
        (4, "critical"),
    ])
    def test_suricata_levels(self, level, expected):
        assert map_severity(level, "suricata") == expected

    def test_suricata_unknown_level(self):
        assert map_severity(0, "suricata") == "medium"
        assert map_severity(99, "suricata") == "medium"


class TestDefaultSeverity:

    @pytest.mark.parametrize("level,expected", [
        (0, "low"), (1, "low"), (3, "low"),
        (4, "medium"), (6, "medium"),
        (7, "high"), (9, "high"),
        (10, "critical"), (15, "critical"),
    ])
    def test_default_levels(self, level, expected):
        assert map_severity(level, "filebeat") == expected
        assert map_severity(level, "some_unknown_source") == expected

    def test_default_low_not_medium(self):
        """Bug fix: level 0-3 should be 'low', not 'medium'."""
        for level in range(0, 4):
            assert map_severity(level, "filebeat") == "low"


class TestEdgeCases:

    def test_none_level(self):
        assert map_severity(None, "wazuh") == "low"

    def test_empty_string_level(self):
        assert map_severity("", "wazuh") == "low"

    def test_non_numeric_string(self):
        assert map_severity("not_a_number", "wazuh") == "low"

    def test_float_level(self):
        """Floats should be truncated to int."""
        assert map_severity(7.9, "wazuh") == "high"

    def test_bool_level(self):
        """bool is int subclass in Python: True=1, False=0."""
        result = map_severity(True, "wazuh")
        assert result in ("low", "medium")  # 1 -> low
