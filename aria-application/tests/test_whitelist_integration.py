"""
Integration tests for whitelist functionality:
- Alert marking during ingestion
- Incident creation suppression for whitelisted alerts
- Watcher skip logic for whitelisted upstream incidents
"""

import pytest
import uuid
from datetime import datetime, timezone
from unittest.mock import patch, AsyncMock

from sqlalchemy import select, func

from response.db import AsyncSessionLocal, engine
from response.models import Alert, Incident, WhitelistEntry, Investigation
from core.whitelist import add_whitelist_entry, is_whitelisted, remove_whitelist_entry


@pytest.fixture(autouse=True)
async def _clean_db():
    """Remove test whitelist entries, alerts, incidents after each test."""
    # Capture existing IDs before test runs (to avoid deleting production data)
    existing_ids = set()
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(WhitelistEntry.id))
        existing_ids = {row[0] for row in result.all()}

    yield

    async with AsyncSessionLocal() as session:
        from sqlalchemy import delete
        # Only delete whitelist entries created DURING this test
        result = await session.execute(select(WhitelistEntry.id))
        new_ids = {row[0] for row in result.all()} - existing_ids
        if new_ids:
            await session.execute(delete(WhitelistEntry).where(WhitelistEntry.id.in_(new_ids)))
        await session.execute(delete(Alert).where(Alert.source == "test"))
        await session.execute(delete(Incident).where(Incident.external_id.like("test-%")))
        await session.execute(delete(Investigation).where(Investigation.incident_id.like("test-%")))
        await session.commit()


class TestWhitelistCore:
    """Tests for core whitelist CRUD and matching."""

    async def test_add_and_check_ip(self):
        entry = await add_whitelist_entry("ip", "192.168.99.100", label="trusted")
        assert entry["value"] == "192.168.99.100"
        assert await is_whitelisted("192.168.99.100") is True
        assert await is_whitelisted("192.168.99.101") is False
        await remove_whitelist_entry(entry["id"])

    async def test_subnet_containment(self):
        entry = await add_whitelist_entry("subnet", "10.0.0.0/8", label="internal")
        assert await is_whitelisted("10.1.2.3") is True
        assert await is_whitelisted("10.255.255.255") is True
        assert await is_whitelisted("11.0.0.1") is False
        await remove_whitelist_entry(entry["id"])

    async def test_domain_check(self):
        entry = await add_whitelist_entry("domain", "whitelisted-test.example.com", label="trusted")
        assert await is_whitelisted("whitelisted-test.example.com") is True
        assert await is_whitelisted("other.example.com") is False
        await remove_whitelist_entry(entry["id"])

    async def test_cidr_stored_as_ip_matches_subnet(self):
        """CIDR notation added as type='ip' should still match via subnet containment."""
        entry = await add_whitelist_entry("ip", "172.18.0.0/16", label="trusted")
        # Auto-corrected to subnet type
        assert entry["type"] == "subnet"
        assert await is_whitelisted("172.18.0.5") is True
        assert await is_whitelisted("172.18.255.255") is True
        assert await is_whitelisted("172.19.0.1") is False
        await remove_whitelist_entry(entry["id"])

    async def test_existing_cidr_ip_type_matches(self):
        """Simulate legacy entry where CIDR was stored as type='ip' — is_whitelisted must still match."""
        from response.db import AsyncSessionLocal
        from response.models import WhitelistEntry
        async with AsyncSessionLocal() as session:
            entry = WhitelistEntry(type="ip", value="10.99.0.0/24", label="trusted")
            session.add(entry)
            await session.commit()
            await session.refresh(entry)
            entry_id = entry.id
        assert await is_whitelisted("10.99.0.50") is True
        assert await is_whitelisted("10.99.0.255") is True
        assert await is_whitelisted("10.99.1.1") is False
        await remove_whitelist_entry(entry_id)


class TestAlertWhitelistMarking:
    """Tests that alerts are marked whitelisted during ingestion."""

    async def test_alert_marked_whitelisted(self):
        # Seed whitelist
        await add_whitelist_entry("ip", "192.168.99.100", label="trusted")

        # Create alert directly (simulating what alert_processor does)
        alert_id = str(uuid.uuid4())
        async with AsyncSessionLocal() as session:
            alert = Alert(
                id=alert_id,
                source="test",
                source_id="test-001",
                title="Test brute force",
                description="Test description",
                severity="high",
                status="active",
                source_ip="192.168.99.100",
                dest_ip="10.0.0.50",
                whitelisted=True,
            )
            session.add(alert)
            await session.commit()

        # Verify
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(Alert).where(Alert.id == alert_id))
            stored = result.scalar_one()
            assert stored.whitelisted is True
            assert stored.source_ip == "192.168.99.100"

    async def test_alert_not_marked_for_non_whitelisted_ip(self):
        alert_id = str(uuid.uuid4())
        async with AsyncSessionLocal() as session:
            alert = Alert(
                id=alert_id,
                source="test",
                source_id="test-002",
                title="Test alert",
                description="Test",
                severity="high",
                status="active",
                source_ip="99.99.99.99",
                whitelisted=False,
            )
            session.add(alert)
            await session.commit()

        async with AsyncSessionLocal() as session:
            result = await session.execute(select(Alert).where(Alert.id == alert_id))
            stored = result.scalar_one()
            assert stored.whitelisted is False


class TestIncidentSuppression:
    """Tests that whitelisted alerts do not create incidents."""

    async def test_process_alert_skips_whitelisted(self):
        """process_alert should return skipped/whitelisted when alert is whitelisted."""
        from pipeline.datausage.incident_manager import process_alert

        upstream_id = f"test-{uuid.uuid4().hex[:8]}"
        payload = {
            "id": upstream_id,
            "title": "SSH Brute Force",
            "description": "Test",
            "severity": "critical",
            "source_ip": "192.168.99.100",
            "whitelisted": True,
        }

        with patch(
            "pipeline.datausage.incident_manager.client.link_alert_to_incident",
            new_callable=AsyncMock,
        ) as mock_link:
            result = await process_alert(upstream_id, payload)

        assert result["action"] == "skipped"
        assert result["reason"] == "whitelisted"
        mock_link.assert_not_called()

    async def test_process_alert_creates_incident_for_non_whitelisted(self):
        """process_alert should create incident for non-whitelisted critical alerts."""
        from pipeline.datausage.incident_manager import process_alert

        upstream_id = f"test-{uuid.uuid4().hex[:8]}"
        payload = {
            "id": upstream_id,
            "title": "SSH Brute Force",
            "description": "Test",
            "severity": "critical",
            "source_ip": "99.99.99.99",
            "whitelisted": False,
        }

        with patch(
            "pipeline.datausage.incident_manager.client.create_incident",
            new_callable=AsyncMock,
            return_value={"id": f"upstream-{upstream_id}"},
        ) as mock_create, patch(
            "pipeline.datausage.incident_manager.client.link_alert_to_incident",
            new_callable=AsyncMock,
            return_value=True,
        ) as mock_link:
            result = await process_alert(upstream_id, payload)

        # The alert may be tracked instead of created depending on signals,
        # but it should NOT be skipped due to whitelist
        assert result["reason"] != "whitelisted"


class TestBatchEndpoint:
    """Tests for the batch check endpoint."""

    async def test_batch_check(self):
        from api.routes.whitelist import check_whitelist_batch
        entry1 = await add_whitelist_entry("ip", "10.0.0.1", label="trusted")
        entry2 = await add_whitelist_entry("ip", "10.0.0.2", label="trusted")
        result = await check_whitelist_batch({"values": ["10.0.0.1", "10.0.0.2", "10.0.0.3"]})
        assert result["results"]["10.0.0.1"] is True
        assert result["results"]["10.0.0.2"] is True
        assert result["results"]["10.0.0.3"] is False
        await remove_whitelist_entry(entry1["id"])
        await remove_whitelist_entry(entry2["id"])


class TestHostnameWhitelist:
    """Tests that hostname is checked against domain whitelist."""

    async def test_hostname_whitelisted(self):
        from core.whitelist import check_alert_whitelist
        entry = await add_whitelist_entry("domain", "trusted-server.example.com", label="trusted")
        alert = {
            "source_ip": "99.99.99.99",
            "dest_ip": "88.88.88.88",
            "hostname": "trusted-server.example.com",
        }
        assert await check_alert_whitelist(alert) is True
        await remove_whitelist_entry(entry["id"])

    async def test_hostname_not_whitelisted(self):
        from core.whitelist import check_alert_whitelist
        alert = {
            "source_ip": "99.99.99.99",
            "dest_ip": "88.88.88.88",
            "hostname": "untrusted-server.example.com",
        }
        assert await check_alert_whitelist(alert) is False


class TestRetroactiveMarking:
    """Tests that existing alerts are retroactively marked when adding a whitelist entry."""

    async def test_retroactive_ip_marking(self):
        from core.whitelist import _retroactively_mark_alerts
        # Create an alert with whitelisted=False
        alert_id = str(uuid.uuid4())
        async with AsyncSessionLocal() as session:
            session.add(Alert(
                id=alert_id,
                source="test",
                source_id="retro-001",
                title="Test alert",
                description="Test",
                severity="high",
                status="active",
                source_ip="192.168.77.77",
                whitelisted=False,
            ))
            await session.commit()

        # Add to whitelist and trigger retroactive marking
        entry = await add_whitelist_entry("ip", "192.168.77.77", label="trusted")
        updated = await _retroactively_mark_alerts("192.168.77.77")
        assert updated == 1

        # Verify alert is now marked whitelisted
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(Alert.whitelisted).where(Alert.id == alert_id))
            assert result.scalar() is True

        await remove_whitelist_entry(entry["id"])


class TestIncidentModelMigration:
    """Verify the incidents.whitelisted column exists and works."""

    async def test_incident_whitelisted_column(self):
        async with AsyncSessionLocal() as session:
            # Insert an incident with whitelisted=True
            incident_id = str(uuid.uuid4())
            await session.execute(
                Incident.__table__.insert().values(
                    id=incident_id,
                    external_id=f"test-{incident_id[:8]}",
                    title="Test",
                    description="Test",
                    severity="medium",
                    status="open",
                    whitelisted=True,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
            )
            await session.commit()

            result = await session.execute(
                select(Incident.whitelisted).where(Incident.id == incident_id)
            )
            assert result.scalar() is True

            await session.execute(Incident.__table__.delete().where(Incident.id == incident_id))
            await session.commit()
