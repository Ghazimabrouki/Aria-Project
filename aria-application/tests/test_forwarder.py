"""
Tests for the local poller: poll_source, cursor management, severity filtering,
local persistence, and upstream forwarding (when enabled).
"""

import pytest
import shutil
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock

from pipeline.poller import main as poller_main
from pipeline.poller import alert_processor
from pipeline.poller import cursor_manager


# ─── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _clear_dedup_state():
    """Clear dedup caches, seen-ids, pattern tracking and local DB alerts before every test."""
    from pipeline.poller.seen_ids import _SEEN_IDS_CACHE
    from pipeline.poller.alert_processor import _PATTERN_TRACKING, _THREAT_INTEL_IPS
    from pipeline.services.dedup import _memory_cache
    import asyncio

    _SEEN_IDS_CACHE.clear()
    _memory_cache.clear()
    _PATTERN_TRACKING.clear()
    _THREAT_INTEL_IPS.clear()

    # Also wipe the on-disk seen_ids files so prior test runs don't pollute
    seen_dir = Path("data/seen_ids")
    if seen_dir.exists():
        for f in seen_dir.glob("*.json"):
            f.unlink()

    yield


@pytest.fixture(autouse=True)
def _patch_dedup_redis():
    """Patch dedup Redis so tests never hit a real Redis server."""
    with patch("pipeline.services.dedup._redis_get", new_callable=AsyncMock, return_value=None), \
         patch("pipeline.services.dedup._redis_set", new_callable=AsyncMock):
        yield


@pytest.fixture
def mock_settings():
    class FakeSettings:
        upstream_enabled = False
        opensoar_enabled = False
        opensoar_url = "http://test-soar:8000"
        opensoar_username = "admin"
        opensoar_password = "pass"
        opensoar_webhook_secret = ""
        alert_poll_interval = 30
        es_batch_size = 25
        alert_first_run_lookback_hours = 24
        alert_min_severity = "low"
        local_ingestion_enabled = True
        wazuh_index_pattern = "wazuh-alerts-4.x-*"
        falco_index_pattern = "falco-events-*"
        filebeat_index_pattern = "filebeat-*"
        suricata_index_pattern = "suricata-*"
    return FakeSettings()


@pytest.fixture
def cursor_dir(tmp_path):
    """Use tmp_path for cursor files."""
    d = tmp_path / "cursors"
    d.mkdir()
    original = cursor_manager.CURSOR_DIR
    cursor_manager.CURSOR_DIR = d
    yield d
    cursor_manager.CURSOR_DIR = original


@pytest.fixture
def mock_redis_unavailable():
    """Simulate Redis being down."""
    with patch.object(cursor_manager, "_redis_get", new_callable=AsyncMock, return_value=None), \
         patch.object(cursor_manager, "_redis_set", new_callable=AsyncMock):
        yield


# ─── Cursor Management ─────────────────────────────────────────────────────

class TestCursorManagement:

    @pytest.mark.asyncio
    async def test_first_run_uses_large_lookback(self, mock_settings, cursor_dir, mock_redis_unavailable):
        with patch("config.get_settings", return_value=mock_settings):
            cursor = await cursor_manager._get_cursor("wazuh")

        expected = datetime.now(timezone.utc) - timedelta(hours=24)
        assert abs((cursor - expected).total_seconds()) < 5

    @pytest.mark.asyncio
    async def test_file_cursor_persists(self, mock_settings, cursor_dir, mock_redis_unavailable):
        ts = datetime(2026, 4, 5, 10, 0, 0, tzinfo=timezone.utc)

        with patch("config.get_settings", return_value=mock_settings):
            await cursor_manager._set_cursor("wazuh", ts)

        cursor_file = cursor_dir / "wazuh.cursor"
        assert cursor_file.exists()
        assert "2026-04-05" in cursor_file.read_text()

        with patch("config.get_settings", return_value=mock_settings):
            result = await cursor_manager._get_cursor("wazuh")
        assert result == ts

    @pytest.mark.asyncio
    async def test_redis_cursor_takes_priority(self, mock_settings, cursor_dir):
        redis_ts = "2026-04-05T12:00:00+00:00"
        file_ts = "2026-04-05T06:00:00+00:00"

        (cursor_dir / "falco.cursor").write_text(file_ts)

        with patch("config.get_settings", return_value=mock_settings), \
             patch.object(cursor_manager, "_redis_get", new_callable=AsyncMock, return_value=redis_ts):
            result = await cursor_manager._get_cursor("falco")

        assert result == datetime.fromisoformat(redis_ts)


# ─── poll_source (local-only mode) ──────────────────────────────────────────

class TestPollSourceLocal:

    @pytest.mark.asyncio
    async def test_poll_persists_mapped_alert_locally(
        self, mock_settings, cursor_dir, mock_redis_unavailable,
        wazuh_brute_force, make_es_response,
    ):
        es_response = make_es_response([wazuh_brute_force])
        mock_search = AsyncMock(return_value=es_response)

        with patch("pipeline.poller.main.get_settings", return_value=mock_settings), \
             patch("pipeline.poller.alert_processor.get_settings", return_value=mock_settings), \
             patch("pipeline.poller.main.search_alerts", mock_search), \
             patch("pipeline.sender.client.send_alert", new_callable=AsyncMock) as mock_send:

            sent, skipped = await poller_main.poll_source("wazuh", "wazuh-alerts-4.x-*")

        # In local-only mode, alert is persisted locally but NOT forwarded upstream
        assert sent == 1
        assert skipped == 0
        mock_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_poll_empty_index(
        self, mock_settings, cursor_dir, mock_redis_unavailable,
    ):
        mock_search = AsyncMock(return_value={"hits": {"total": {"value": 0}, "hits": []}})

        with patch("pipeline.poller.main.get_settings", return_value=mock_settings), \
             patch("pipeline.poller.alert_processor.get_settings", return_value=mock_settings), \
             patch("pipeline.poller.main.search_alerts", mock_search):

            sent, skipped = await poller_main.poll_source("falco", "falco-events-*")

        assert sent == 0
        assert skipped == 0

    @pytest.mark.asyncio
    async def test_severity_filtering(
        self, mock_settings, cursor_dir, mock_redis_unavailable,
        wazuh_low_level, make_es_response,
    ):
        mock_settings.alert_min_severity = "medium"
        es_response = make_es_response([wazuh_low_level])
        mock_search = AsyncMock(return_value=es_response)

        with patch("pipeline.poller.main.get_settings", return_value=mock_settings), \
             patch("pipeline.poller.alert_processor.get_settings", return_value=mock_settings), \
             patch("pipeline.poller.main.search_alerts", mock_search), \
             patch("pipeline.sender.client.send_alert", new_callable=AsyncMock) as mock_send:

            sent, skipped = await poller_main.poll_source("wazuh", "wazuh-alerts-4.x-*")

        assert sent == 0
        assert skipped == 1
        mock_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_severity_filtering_passes_high(
        self, mock_settings, cursor_dir, mock_redis_unavailable,
        wazuh_brute_force, make_es_response,
    ):
        mock_settings.alert_min_severity = "high"
        es_response = make_es_response([wazuh_brute_force])
        mock_search = AsyncMock(return_value=es_response)

        with patch("pipeline.poller.main.get_settings", return_value=mock_settings), \
             patch("pipeline.poller.alert_processor.get_settings", return_value=mock_settings), \
             patch("pipeline.poller.main.search_alerts", mock_search), \
             patch("pipeline.sender.client.send_alert", new_callable=AsyncMock) as mock_send:

            sent, skipped = await poller_main.poll_source("wazuh", "wazuh-alerts-4.x-*")

        assert sent == 1
        assert skipped == 0
        mock_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_cursor_advances_after_persist(
        self, mock_settings, cursor_dir, mock_redis_unavailable,
        wazuh_brute_force, make_es_response,
    ):
        from datetime import datetime, timezone
        es_response = make_es_response([wazuh_brute_force])
        mock_search = AsyncMock(return_value=es_response)

        # Pre-set cursor to before the alert so it will advance
        old_cursor = datetime(2026, 4, 5, 9, 0, 0, tzinfo=timezone.utc)

        with patch("pipeline.poller.main.get_settings", return_value=mock_settings), \
             patch("pipeline.poller.alert_processor.get_settings", return_value=mock_settings), \
             patch("pipeline.poller.main.search_alerts", mock_search), \
             patch("pipeline.sender.client.send_alert", new_callable=AsyncMock), \
             patch("pipeline.poller.main._get_cursor", new_callable=AsyncMock, return_value=old_cursor):

            await poller_main.poll_source("wazuh", "wazuh-alerts-4.x-*")

        cursor_file = cursor_dir / "wazuh.cursor"
        assert cursor_file.exists()
        assert "2026-04-05T10:23:45" in cursor_file.read_text()

    @pytest.mark.asyncio
    async def test_es_error_returns_zero(
        self, mock_settings, cursor_dir, mock_redis_unavailable,
    ):
        mock_search = AsyncMock(side_effect=Exception("ES connection refused"))

        with patch("pipeline.poller.main.get_settings", return_value=mock_settings), \
             patch("pipeline.poller.alert_processor.get_settings", return_value=mock_settings), \
             patch("pipeline.poller.main.search_alerts", mock_search):

            sent, skipped = await poller_main.poll_source("wazuh", "wazuh-alerts-4.x-*")

        assert sent == 0
        assert skipped == 0


# ─── Alert Processor (local persistence) ────────────────────────────────────

class TestAlertProcessorLocal:

    @pytest.mark.asyncio
    async def test_process_single_alert_persists_locally(
        self, mock_settings, wazuh_brute_force,
    ):
        from pipeline.mappers.wazuh import map_wazuh_alert
        mock_settings.upstream_enabled = False

        with patch("pipeline.poller.alert_processor.get_settings", return_value=mock_settings), \
             patch("pipeline.sender.client.send_alert", new_callable=AsyncMock) as mock_send:

            result = await alert_processor.process_single_alert(
                "wazuh-001", wazuh_brute_force, "wazuh", map_wazuh_alert,
                datetime(2026, 4, 5, 9, 0, 0, tzinfo=timezone.utc)
            )

        assert result.sent == 1
        mock_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_forwarder_disabled_exits_cleanly(self, mock_settings):
        mock_settings.local_ingestion_enabled = False

        with patch("pipeline.poller.main.get_settings", return_value=mock_settings):
            await poller_main.run_forwarder()
            # Should return immediately without error


# ─── Upstream mode still works ─────────────────────────────────────────────

class TestPollSourceUpstream:

    @pytest.mark.asyncio
    async def test_poll_forwards_to_upstream_when_enabled(
        self, mock_settings, cursor_dir, mock_redis_unavailable,
        wazuh_brute_force, make_es_response,
    ):
        mock_settings.upstream_enabled = True
        mock_settings.opensoar_enabled = True
        es_response = make_es_response([wazuh_brute_force])
        mock_search = AsyncMock(return_value=es_response)
        mock_send = AsyncMock(return_value={"alert_id": "uuid-1"})

        with patch("pipeline.poller.main.get_settings", return_value=mock_settings), \
             patch("pipeline.poller.alert_processor.get_settings", return_value=mock_settings), \
             patch("pipeline.poller.main.search_alerts", mock_search), \
             patch("pipeline.sender.client.send_alert", mock_send):

            sent, skipped = await poller_main.poll_source("wazuh", "wazuh-alerts-4.x-*")

        assert sent == 1
        mock_send.assert_called_once()
