import pytest
from sqlalchemy import select, func, delete

from response.db import AsyncSessionLocal
from response.models import Investigation, InvestigationAuditEvent, PlaybookApproval
from api.routes.investigations import (
    approve_investigation,
    decline_investigation,
    mark_reviewed,
    archive_investigation_endpoint,
)
from api.routes.investigations import (
    ApproveRequest,
    DeclineRequest,
    MarkReviewedRequest,
)


@pytest.fixture(autouse=True)
async def _clean_audit_rows():
    yield
    async with AsyncSessionLocal() as session:
        await session.execute(
            delete(InvestigationAuditEvent).where(
                InvestigationAuditEvent.investigation_id.like("audit-test-%")
            )
        )
        await session.execute(
            delete(PlaybookApproval).where(
                PlaybookApproval.investigation_id.like("audit-test-%")
            )
        )
        await session.execute(
            delete(Investigation).where(Investigation.id.like("audit-test-%"))
        )
        await session.commit()


@pytest.fixture
async def db_session():
    async with AsyncSessionLocal() as session:
        yield session


class TestAuditPersistence:
    @pytest.fixture
    async def inv_awaiting(self, db_session):
        inv = Investigation(
            id="audit-test-inv-1",
            incident_id="inc-1",
            status="awaiting_approval",
            playbook_yaml="""- hosts: target
  tasks:
    - name: Block malicious IP
      ansible.builtin.iptables:
        chain: INPUT
        source: 1.2.3.4
        jump: DROP""",
            rollback_playbook="""- hosts: target
  tasks:
    - name: Remove block
      ansible.builtin.iptables:
        chain: INPUT
        source: 1.2.3.4
        jump: DROP
        state: absent""",
            ai_summary="Valid summary with enough content for approval. SSH brute force from 1.2.3.4. No successful login.",
            ai_quality_status="passed",
        )
        db_session.add(inv)
        approval = PlaybookApproval(
            investigation_id="audit-test-inv-1",
            decision="approved",
            decided_by="test",
        )
        db_session.add(approval)
        await db_session.commit()
        return inv

    async def test_approve_creates_audit_event(self, mock_request, inv_awaiting, db_session):
        before = await db_session.scalar(select(func.count(InvestigationAuditEvent.id)))
        await approve_investigation("audit-test-inv-1", ApproveRequest(decided_by="test"), mock_request, session=db_session)
        after = await db_session.scalar(select(func.count(InvestigationAuditEvent.id)))
        assert after == before + 1
        event = await db_session.scalar(
            select(InvestigationAuditEvent).where(
                InvestigationAuditEvent.event_type == "approved",
                InvestigationAuditEvent.investigation_id == "audit-test-inv-1",
            )
        )
        assert event is not None
        assert event.actor == "test"
        assert event.auth_mode == "internal_trusted"

    async def test_decline_creates_audit_event(self, mock_request, inv_awaiting, db_session):
        before = await db_session.scalar(select(func.count(InvestigationAuditEvent.id)))
        await decline_investigation("audit-test-inv-1", DeclineRequest(decided_by="test", reason="no good"), mock_request, session=db_session)
        after = await db_session.scalar(select(func.count(InvestigationAuditEvent.id)))
        assert after == before + 1
        event = await db_session.scalar(
            select(InvestigationAuditEvent).where(
                InvestigationAuditEvent.event_type == "declined",
                InvestigationAuditEvent.investigation_id == "audit-test-inv-1",
            )
        )
        assert event is not None
        assert event.actor == "test"

    async def test_mark_reviewed_creates_audit_event(self, mock_request, inv_awaiting, db_session):
        before = await db_session.scalar(select(func.count(InvestigationAuditEvent.id)))
        await mark_reviewed("audit-test-inv-1", MarkReviewedRequest(decided_by="test"), mock_request, session=db_session)
        after = await db_session.scalar(select(func.count(InvestigationAuditEvent.id)))
        assert after == before + 1
        event = await db_session.scalar(
            select(InvestigationAuditEvent).where(
                InvestigationAuditEvent.event_type == "reviewed_no_action",
                InvestigationAuditEvent.investigation_id == "audit-test-inv-1",
            )
        )
        assert event is not None

    async def test_archive_creates_audit_event(self, mock_request, inv_awaiting, db_session):
        # First complete it so we can archive
        inv = await db_session.get(Investigation, "audit-test-inv-1")
        inv.status = "completed"
        await db_session.commit()
        before = await db_session.scalar(select(func.count(InvestigationAuditEvent.id)))
        await archive_investigation_endpoint("audit-test-inv-1", mock_request, session=db_session)
        after = await db_session.scalar(select(func.count(InvestigationAuditEvent.id)))
        assert after == before + 1
        event = await db_session.scalar(
            select(InvestigationAuditEvent).where(
                InvestigationAuditEvent.event_type == "archived",
                InvestigationAuditEvent.investigation_id == "audit-test-inv-1",
            )
        )
        assert event is not None

    async def test_audit_event_has_auth_mode(self, mock_request, inv_awaiting, db_session):
        await approve_investigation("audit-test-inv-1", ApproveRequest(decided_by="test"), mock_request, session=db_session)
        event = await db_session.scalar(
            select(InvestigationAuditEvent).where(
                InvestigationAuditEvent.event_type == "approved"
            )
        )
        assert event.auth_mode == "internal_trusted"
