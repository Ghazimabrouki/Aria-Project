"""Tests for fix verifier ES recurrence query source IP inclusion."""

import json
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from response.fix_verifier import _query_es_for_recurrence
from response.models import InvestigationAlert


class TestVerifierRecurrence:
    @pytest.fixture
    def run_finished_at(self):
        return datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    @pytest.mark.asyncio
    async def test_es_query_includes_source_ips(self, run_finished_at):
        alert = InvestigationAlert(
            investigation_id="inv-1",
            alert_id="alert-1",
            alert_json=json.dumps({
                "rule_name": "sshd brute force",
                "source_ip": "192.0.2.1",
            }),
        )

        mock_es = MagicMock()
        mock_es.count = AsyncMock(return_value={"count": 0})

        with patch("core.elasticsearch.get_es_client", AsyncMock(return_value=mock_es)):
            count, detail = await _query_es_for_recurrence([alert], run_finished_at)

        mock_es.count.assert_called()
        call_kwargs = mock_es.count.call_args.kwargs
        query = call_kwargs["body"]["query"]
        must_clauses = query["bool"]["must"]

        ip_filter = next((c for c in must_clauses if "terms" in c and "source_ip" in c.get("terms", {})), None)
        assert ip_filter is not None, "ES query must include source_ip terms filter"
        assert "192.0.2.1" in ip_filter["terms"]["source_ip"]

    @pytest.mark.asyncio
    async def test_es_query_without_source_ips_does_not_add_terms(self, run_finished_at):
        alert = InvestigationAlert(
            investigation_id="inv-1",
            alert_id="alert-1",
            alert_json=json.dumps({"rule_name": "sshd brute force"}),
        )

        mock_es = MagicMock()
        mock_es.count = AsyncMock(return_value={"count": 0})

        with patch("core.elasticsearch.get_es_client", AsyncMock(return_value=mock_es)):
            count, detail = await _query_es_for_recurrence([alert], run_finished_at)

        call_kwargs = mock_es.count.call_args.kwargs
        query = call_kwargs["body"]["query"]
        must_clauses = query["bool"]["must"]

        ip_filter = next((c for c in must_clauses if "terms" in c and "source_ip" in c.get("terms", {})), None)
        assert ip_filter is None, "ES query should not include source_ip filter when no IPs available"

    @pytest.mark.asyncio
    async def test_empty_alerts_skips_query(self, run_finished_at):
        mock_es = MagicMock()
        mock_es.count = AsyncMock(return_value={"count": 0})

        with patch("core.elasticsearch.get_es_client", AsyncMock(return_value=mock_es)):
            count, detail = await _query_es_for_recurrence([], run_finished_at)

        mock_es.count.assert_not_called()
        assert "skipped" in detail.lower() or count == 0
