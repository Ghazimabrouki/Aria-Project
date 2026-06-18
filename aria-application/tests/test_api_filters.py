"""
Tests for alerts and incidents API filter params, including whitelisted filter.
"""

import pytest
import uuid
from datetime import datetime, timezone

from response.db import AsyncSessionLocal
from response.models import Alert, Incident


@pytest.fixture(autouse=True)
async def _clean_test_data():
    """Remove test alerts and incidents after each test."""
    yield
    async with AsyncSessionLocal() as session:
        from sqlalchemy import delete
        await session.execute(delete(Alert).where(Alert.source == "filter_test"))
        await session.execute(delete(Incident).where(Incident.external_id.like("filter-test-%")))
        await session.commit()


class TestAlertsFilters:
    async def test_filter_whitelisted_true(self):
        from api.routes.alerts import list_alerts
        from response.db import get_session

        # Seed alerts
        async with AsyncSessionLocal() as session:
            session.add(Alert(
                id=str(uuid.uuid4()),
                source="filter_test",
                source_id="f-001",
                title="Whitelisted alert",
                description="Test",
                severity="high",
                status="active",
                whitelisted=True,
            ))
            session.add(Alert(
                id=str(uuid.uuid4()),
                source="filter_test",
                source_id="f-002",
                title="Normal alert",
                description="Test",
                severity="high",
                status="active",
                whitelisted=False,
            ))
            await session.commit()

        gen = get_session()
        db_session = await gen.__anext__()
        try:
            result = await list_alerts(whitelisted=True, limit=50, offset=0, session=db_session)
            assert all(a["whitelisted"] is True for a in result["alerts"])
            assert len(result["alerts"]) >= 1
        finally:
            await gen.aclose()

    async def test_filter_whitelisted_false(self):
        from api.routes.alerts import list_alerts
        from response.db import get_session

        gen = get_session()
        db_session = await gen.__anext__()
        try:
            result = await list_alerts(whitelisted=False, limit=50, offset=0, session=db_session)
            assert all(a["whitelisted"] is False for a in result["alerts"])
        finally:
            await gen.aclose()


class TestIncidentsFilters:
    async def test_filter_whitelisted_true(self):
        from api.routes.incidents import list_incidents
        from response.db import get_session

        # Seed incidents
        async with AsyncSessionLocal() as session:
            session.add(Incident(
                id=str(uuid.uuid4()),
                external_id="filter-test-1",
                title="Whitelisted incident",
                description="Test",
                severity="high",
                status="open",
                whitelisted=True,
            ))
            session.add(Incident(
                id=str(uuid.uuid4()),
                external_id="filter-test-2",
                title="Normal incident",
                description="Test",
                severity="high",
                status="open",
                whitelisted=False,
            ))
            await session.commit()

        gen = get_session()
        db_session = await gen.__anext__()
        try:
            result = await list_incidents(whitelisted=True, limit=50, offset=0, session=db_session)
            assert all(i["whitelisted"] is True for i in result["incidents"])
            assert len(result["incidents"]) >= 1
        finally:
            await gen.aclose()

    async def test_filter_whitelisted_false(self):
        from api.routes.incidents import list_incidents
        from response.db import get_session

        gen = get_session()
        db_session = await gen.__anext__()
        try:
            result = await list_incidents(whitelisted=False, limit=50, offset=0, session=db_session)
            assert all(i["whitelisted"] is False for i in result["incidents"])
        finally:
            await gen.aclose()
