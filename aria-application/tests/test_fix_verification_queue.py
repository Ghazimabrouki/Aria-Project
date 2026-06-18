"""Tests for persistent fix verification job queue."""
from __future__ import annotations

import pytest

from response.fix_verifier import schedule_verification_job, recover_pending_jobs
from response.models import FixVerificationJob
from response.db import AsyncSessionLocal
from sqlalchemy import select


@pytest.mark.asyncio
async def test_schedule_verification_job_creates_record():
    """Scheduling a verification job should create a FixVerificationJob row."""
    job = await schedule_verification_job("inv-test-123")
    assert job.investigation_id == "inv-test-123"
    assert job.status == "pending"
    assert job.next_run_at is not None

    # Verify in DB
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(FixVerificationJob).where(FixVerificationJob.investigation_id == "inv-test-123")
        )
        db_job = result.scalar_one_or_none()
        assert db_job is not None
        assert db_job.status == "pending"


@pytest.mark.asyncio
async def test_schedule_verification_job_is_idempotent():
    """Scheduling twice for same investigation should update existing job."""
    job1 = await schedule_verification_job("inv-test-456")
    job2 = await schedule_verification_job("inv-test-456")
    assert job1.id == job2.id
    assert job2.status == "pending"


@pytest.mark.asyncio
async def test_recover_pending_jobs_resets_overdue():
    """Recover should reset overdue jobs to run soon."""
    from datetime import datetime, timezone, timedelta
    job = await schedule_verification_job("inv-test-789")
    # Manually set next_run_at to the past
    job.next_run_at = datetime.now(timezone.utc) - timedelta(hours=1)
    async with AsyncSessionLocal() as session:
        session.add(job)
        await session.commit()

    await recover_pending_jobs()

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(FixVerificationJob).where(FixVerificationJob.investigation_id == "inv-test-789")
        )
        recovered = result.scalar_one()
        next_run = recovered.next_run_at
        if next_run and next_run.tzinfo is None:
            next_run = next_run.replace(tzinfo=timezone.utc)
        assert next_run <= datetime.now(timezone.utc) + timedelta(seconds=10)
