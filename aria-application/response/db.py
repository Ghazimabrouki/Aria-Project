"""
SQLAlchemy async engine and session factory for the response intelligence DB.
Database: SQLite at data/investigations.db
"""
import os
from pathlib import Path
import structlog
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from config import get_settings

logger = structlog.get_logger()

_settings = get_settings()
_db_path_setting = Path(_settings.db_path)
if _db_path_setting.is_absolute():
    DB_PATH = _db_path_setting
else:
    DB_PATH = Path(__file__).parent.parent / _db_path_setting

DB_PATH.parent.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False, "timeout": 30},
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def _migrate_db():
    """Lightweight migrations for SQLite (no Alembic)."""
    from sqlalchemy import text
    try:
        async with engine.begin() as conn:
            # Check if incidents.whitelisted column exists
            result = await conn.execute(text("PRAGMA table_info(incidents)"))
            columns = {row[1] for row in result.all()}
            if "whitelisted" not in columns:
                await conn.execute(text("ALTER TABLE incidents ADD COLUMN whitelisted BOOLEAN DEFAULT 0"))
                # Create index for performance
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_incidents_whitelisted ON incidents(whitelisted)"))
                logger.info("db_migration_applied", column="incidents.whitelisted")

            # Add audit trail columns to incidents
            if "created_by" not in columns:
                await conn.execute(text("ALTER TABLE incidents ADD COLUMN created_by VARCHAR(100)"))
                logger.info("db_migration_applied", column="incidents.created_by")
            if "updated_by" not in columns:
                await conn.execute(text("ALTER TABLE incidents ADD COLUMN updated_by VARCHAR(100)"))
                logger.info("db_migration_applied", column="incidents.updated_by")

            # Drop orphaned remediation_mode column (removed from model but left in DB)
            result = await conn.execute(text("PRAGMA table_info(investigations)"))
            inv_columns = {row[1] for row in result.all()}
            if "remediation_mode" in inv_columns:
                await conn.execute(text("ALTER TABLE investigations DROP COLUMN remediation_mode"))
                logger.info("db_migration_applied", column="investigations.remediation_mode", action="dropped")

            # Add audit trail columns to investigations
            if "created_by" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN created_by VARCHAR(100)"))
                logger.info("db_migration_applied", column="investigations.created_by")
            if "updated_by" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN updated_by VARCHAR(100)"))
                logger.info("db_migration_applied", column="investigations.updated_by")

            # Remove unique constraint from investigations.incident_id to allow reinvestigation
            result = await conn.execute(text("PRAGMA index_list(investigations)"))
            indices = result.all()
            unique_idx = None
            for idx in indices:
                # idx = (seq, name, unique, origin, partial)
                if idx[1] == "ix_investigations_incident_id" and idx[2] == 1:
                    unique_idx = idx[1]
                    break
            if unique_idx:
                await conn.execute(text(f"DROP INDEX {unique_idx}"))
                await conn.execute(text("CREATE INDEX ix_investigations_incident_id ON investigations(incident_id)"))
                logger.info("db_migration_applied", index="ix_investigations_incident_id", action="removed_unique")

            # Add resource_type for infrastructure investigations
            if "resource_type" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN resource_type VARCHAR(30)"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_investigations_resource_type ON investigations(resource_type)"))
                logger.info("db_migration_applied", column="investigations.resource_type")

            # Add local_incident_id and upstream_incident_id to investigations
            if "local_incident_id" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN local_incident_id VARCHAR(36)"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_investigations_local_incident_id ON investigations(local_incident_id)"))
                logger.info("db_migration_applied", column="investigations.local_incident_id")
            if "upstream_incident_id" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN upstream_incident_id VARCHAR(36)"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_investigations_upstream_incident_id ON investigations(upstream_incident_id)"))
                logger.info("db_migration_applied", column="investigations.upstream_incident_id")

            # Add correlation_key to incidents
            if "correlation_key" not in columns:
                await conn.execute(text("ALTER TABLE incidents ADD COLUMN correlation_key VARCHAR(255)"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_incidents_correlation_key ON incidents(correlation_key)"))
                logger.info("db_migration_applied", column="incidents.correlation_key")

            # Add occurrence_count to alerts
            result = await conn.execute(text("PRAGMA table_info(alerts)"))
            alert_columns = {row[1] for row in result.all()}
            if "occurrence_count" not in alert_columns:
                await conn.execute(text("ALTER TABLE alerts ADD COLUMN occurrence_count INTEGER DEFAULT 1"))
                logger.info("db_migration_applied", column="alerts.occurrence_count")

            # Add raw_source_json to alerts
            if "raw_source_json" not in alert_columns:
                await conn.execute(text("ALTER TABLE alerts ADD COLUMN raw_source_json TEXT"))
                logger.info("db_migration_applied", column="alerts.raw_source_json")

            # ═════════════════════════════════════════════════════════════════
            # Phase 3: Staged Remediation columns
            # ═════════════════════════════════════════════════════════════════
            # investigations.target_os
            if "target_os" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN target_os VARCHAR(20)"))
                logger.info("db_migration_applied", column="investigations.target_os")

            # investigations.evidence_json
            if "evidence_json" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN evidence_json JSON"))
                logger.info("db_migration_applied", column="investigations.evidence_json")

            # investigations.manual_override_json (admin override / manual remediation)
            if "manual_override_json" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN manual_override_json JSON"))
                logger.info("db_migration_applied", column="investigations.manual_override_json")

            # investigations.rollback_playbook
            if "rollback_playbook" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN rollback_playbook TEXT"))
                logger.info("db_migration_applied", column="investigations.rollback_playbook")

            # playbook_runs.current_phase
            result = await conn.execute(text("PRAGMA table_info(playbook_runs)"))
            run_columns = {row[1] for row in result.all()}
            if "current_phase" not in run_columns:
                await conn.execute(text("ALTER TABLE playbook_runs ADD COLUMN current_phase VARCHAR(30) DEFAULT 'pending'"))
                logger.info("db_migration_applied", column="playbook_runs.current_phase")

            # playbook_runs.phases_json
            if "phases_json" not in run_columns:
                await conn.execute(text("ALTER TABLE playbook_runs ADD COLUMN phases_json JSON"))
                logger.info("db_migration_applied", column="playbook_runs.phases_json")

            # ═════════════════════════════════════════════════════════════════
            # Phase 4: Infrastructure Intelligence columns
            # ═════════════════════════════════════════════════════════════════
            # investigations.investigation_type
            if "investigation_type" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN investigation_type VARCHAR(20) DEFAULT 'security'"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_investigations_investigation_type ON investigations(investigation_type)"))
                logger.info("db_migration_applied", column="investigations.investigation_type")

            # investigations.resource_context_json
            if "resource_context_json" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN resource_context_json JSON"))
                logger.info("db_migration_applied", column="investigations.resource_context_json")

            # Backfill: existing performance investigations → investigation_type = 'infrastructure'
            await conn.execute(text("UPDATE investigations SET investigation_type = 'infrastructure' WHERE source = 'performance' AND investigation_type = 'security'"))

            # ═════════════════════════════════════════════════════════════════
            # Phase 5: Diagnostic-First Infrastructure columns
            # ═════════════════════════════════════════════════════════════════
            # investigations.findings_json
            if "findings_json" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN findings_json JSON"))
                logger.info("db_migration_applied", column="investigations.findings_json")

            # investigations.diagnostic_output
            if "diagnostic_output" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN diagnostic_output TEXT"))
                logger.info("db_migration_applied", column="investigations.diagnostic_output")

            # investigations.diagnostic_started_at
            if "diagnostic_started_at" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN diagnostic_started_at TIMESTAMP WITH TIME ZONE"))
                logger.info("db_migration_applied", column="investigations.diagnostic_started_at")

            # investigations.diagnostic_finished_at
            if "diagnostic_finished_at" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN diagnostic_finished_at TIMESTAMP WITH TIME ZONE"))
                logger.info("db_migration_applied", column="investigations.diagnostic_finished_at")

            # ═════════════════════════════════════════════════════════════════
            # Phase 6: Execution Reliability & AI Quality columns
            # ═════════════════════════════════════════════════════════════════
            if "completion_quality" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN completion_quality VARCHAR(20) DEFAULT 'unknown'"))
                logger.info("db_migration_applied", column="investigations.completion_quality")
            if "failed_phase" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN failed_phase VARCHAR(30)"))
                logger.info("db_migration_applied", column="investigations.failed_phase")
            if "warning_phases" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN warning_phases JSON"))
                logger.info("db_migration_applied", column="investigations.warning_phases")
            if "verification_status" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN verification_status VARCHAR(30)"))
                logger.info("db_migration_applied", column="investigations.verification_status")
            if "ai_quality_status" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN ai_quality_status VARCHAR(20) DEFAULT 'unknown'"))
                logger.info("db_migration_applied", column="investigations.ai_quality_status")
            if "ai_quality_json" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN ai_quality_json JSON"))
                logger.info("db_migration_applied", column="investigations.ai_quality_json")

            # playbook_runs execution reliability columns
            result = await conn.execute(text("PRAGMA table_info(playbook_runs)"))
            run_columns = {row[1] for row in result.all()}
            if "completion_quality" not in run_columns:
                await conn.execute(text("ALTER TABLE playbook_runs ADD COLUMN completion_quality VARCHAR(20)"))
                logger.info("db_migration_applied", column="playbook_runs.completion_quality")
            if "failed_phase" not in run_columns:
                await conn.execute(text("ALTER TABLE playbook_runs ADD COLUMN failed_phase VARCHAR(30)"))
                logger.info("db_migration_applied", column="playbook_runs.failed_phase")
            if "warning_phases" not in run_columns:
                await conn.execute(text("ALTER TABLE playbook_runs ADD COLUMN warning_phases JSON"))
                logger.info("db_migration_applied", column="playbook_runs.warning_phases")

            if "verification_plan_json" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN verification_plan_json JSON"))
                logger.info("db_migration_applied", column="investigations.verification_plan_json")

            result = await conn.execute(text("PRAGMA table_info(playbook_runs)"))
            run_columns = {row[1] for row in result.all()}
            if "verification_plan_json" not in run_columns:
                await conn.execute(text("ALTER TABLE playbook_runs ADD COLUMN verification_plan_json JSON"))
                logger.info("db_migration_applied", column="playbook_runs.verification_plan_json")

            # ═════════════════════════════════════════════════════════════════
            # Phase 8: Analyst Control & Audit Trail tables
            # ═════════════════════════════════════════════════════════════════
            result = await conn.execute(text("PRAGMA table_info(investigation_audit_events)"))
            if not result.all():
                await conn.execute(text("""
                    CREATE TABLE investigation_audit_events (
                        id VARCHAR(36) PRIMARY KEY,
                        investigation_id VARCHAR(36) NOT NULL,
                        event_type VARCHAR(30) NOT NULL,
                        actor VARCHAR(100) DEFAULT 'system',
                        details TEXT,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
                    )
                """))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_events_investigation_id ON investigation_audit_events(investigation_id)"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_events_event_type ON investigation_audit_events(event_type)"))
                logger.info("db_migration_applied", table="investigation_audit_events")

            # Migrate investigation_audit_events columns if needed
            result = await conn.execute(text("PRAGMA table_info(investigation_audit_events)"))
            existing_cols = {row[1] for row in result.all()}
            new_cols = [
                ("operator_label", "VARCHAR(100)"),
                ("source_ip", "VARCHAR(50)"),
                ("user_agent", "TEXT"),
                ("request_id", "VARCHAR(100)"),
                ("auth_mode", "VARCHAR(30) DEFAULT 'internal_trusted'"),
            ]
            for col_name, col_type in new_cols:
                if col_name not in existing_cols:
                    await conn.execute(text(f"ALTER TABLE investigation_audit_events ADD COLUMN {col_name} {col_type}"))
                    logger.info("db_migration_applied", table="investigation_audit_events", column=col_name)

            result = await conn.execute(text("PRAGMA table_info(aria_alerts)"))
            if not result.all():
                await conn.execute(text("""
                    CREATE TABLE aria_alerts (
                        id VARCHAR(36) PRIMARY KEY,
                        alert_type VARCHAR(30) NOT NULL,
                        severity VARCHAR(20) DEFAULT 'medium',
                        investigation_id VARCHAR(36),
                        incident_id VARCHAR(36),
                        title TEXT NOT NULL,
                        description TEXT,
                        acknowledged BOOLEAN DEFAULT 0,
                        acknowledged_by VARCHAR(100),
                        acknowledged_at TIMESTAMP WITH TIME ZONE,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                """))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_aria_alerts_alert_type ON aria_alerts(alert_type)"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_aria_alerts_severity ON aria_alerts(severity)"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_aria_alerts_investigation_id ON aria_alerts(investigation_id)"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_aria_alerts_acknowledged ON aria_alerts(acknowledged)"))
                logger.info("db_migration_applied", table="aria_alerts")

            # ═════════════════════════════════════════════════════════════════
            # Phase 8: Admin override columns on playbook_approvals
            # ═════════════════════════════════════════════════════════════════
            result = await conn.execute(text("PRAGMA table_info(playbook_approvals)"))
            approval_columns = {row[1] for row in result.all()}
            for col, col_type in [
                ("override", "BOOLEAN DEFAULT 0"),
                ("override_by", "VARCHAR(255)"),
                ("override_at", "TIMESTAMP WITH TIME ZONE"),
                ("override_reason", "TEXT"),
                ("original_safety_tier", "VARCHAR(20)"),
                ("original_blocked_reasons", "TEXT"),
                ("feature_flag_used", "BOOLEAN DEFAULT 0"),
            ]:
                if col not in approval_columns:
                    await conn.execute(text(f"ALTER TABLE playbook_approvals ADD COLUMN {col} {col_type}"))
                    logger.info("db_migration_applied", column=f"playbook_approvals.{col}")

            # ═════════════════════════════════════════════════════════════════
            # Phase 7: Worker Heartbeat table
            # ═════════════════════════════════════════════════════════════════
            result = await conn.execute(text("PRAGMA table_info(worker_heartbeats)"))
            if not result.all():
                await conn.execute(text("""
                    CREATE TABLE worker_heartbeats (
                        id VARCHAR(36) PRIMARY KEY,
                        worker_name VARCHAR(100) UNIQUE NOT NULL,
                        status VARCHAR(20) DEFAULT 'unknown',
                        last_success_at TIMESTAMP WITH TIME ZONE,
                        last_error_at TIMESTAMP WITH TIME ZONE,
                        last_error TEXT,
                        last_duration_ms INTEGER,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                """))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_worker_heartbeats_worker_name ON worker_heartbeats(worker_name)"))
                logger.info("db_migration_applied", table="worker_heartbeats")

            # ═════════════════════════════════════════════════════════════════
            # Phase 9: Multi-server asset_id columns (nullable for backward compatibility)
            # ═════════════════════════════════════════════════════════════════
            result = await conn.execute(text("PRAGMA table_info(alerts)"))
            alert_cols = {row[1] for row in result.all()}
            if "asset_id" not in alert_cols:
                await conn.execute(text("ALTER TABLE alerts ADD COLUMN asset_id VARCHAR(36)"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_alerts_asset_id ON alerts(asset_id)"))
                logger.info("db_migration_applied", column="alerts.asset_id")

            result = await conn.execute(text("PRAGMA table_info(incidents)"))
            incident_cols = {row[1] for row in result.all()}
            if "asset_id" not in incident_cols:
                await conn.execute(text("ALTER TABLE incidents ADD COLUMN asset_id VARCHAR(36)"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_incidents_asset_id ON incidents(asset_id)"))
                logger.info("db_migration_applied", column="incidents.asset_id")

            if "asset_id" not in inv_columns:
                await conn.execute(text("ALTER TABLE investigations ADD COLUMN asset_id VARCHAR(36)"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_investigations_asset_id ON investigations(asset_id)"))
                logger.info("db_migration_applied", column="investigations.asset_id")

            result = await conn.execute(text("PRAGMA table_info(operator_sessions)"))
            op_session_cols = {row[1] for row in result.all()}
            if "asset_id" not in op_session_cols:
                await conn.execute(text("ALTER TABLE operator_sessions ADD COLUMN asset_id VARCHAR(36)"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_operator_sessions_asset_id ON operator_sessions(asset_id)"))
                logger.info("db_migration_applied", column="operator_sessions.asset_id")

            result = await conn.execute(text("PRAGMA table_info(operator_runs)"))
            op_run_cols = {row[1] for row in result.all()}
            if "asset_id" not in op_run_cols:
                await conn.execute(text("ALTER TABLE operator_runs ADD COLUMN asset_id VARCHAR(36)"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_operator_runs_asset_id ON operator_runs(asset_id)"))
                logger.info("db_migration_applied", column="operator_runs.asset_id")

            result = await conn.execute(text("PRAGMA table_info(monitored_assets)"))
            ma_cols = {row[1] for row in result.all()}
            if "asset_id" not in ma_cols:
                await conn.execute(text("ALTER TABLE monitored_assets ADD COLUMN asset_id VARCHAR(100)"))
                await conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_monitored_assets_asset_id ON monitored_assets(asset_id)"))
                logger.info("db_migration_applied", column="monitored_assets.asset_id")
            # Backfill asset_id for existing records (use id as fallback)
            await conn.execute(text("UPDATE monitored_assets SET asset_id = id WHERE asset_id IS NULL"))
            if "source_config_json" not in ma_cols:
                await conn.execute(text("ALTER TABLE monitored_assets ADD COLUMN source_config_json JSON"))
                logger.info("db_migration_applied", column="monitored_assets.source_config_json")
            if "ansible_config_json" not in ma_cols:
                await conn.execute(text("ALTER TABLE monitored_assets ADD COLUMN ansible_config_json JSON"))
                logger.info("db_migration_applied", column="monitored_assets.ansible_config_json")

            # ═════════════════════════════════════════════════════════════════
            # Phase 10: ARIA Authentication & Account System
            # ═════════════════════════════════════════════════════════════════
            result = await conn.execute(text("PRAGMA table_info(aria_accounts)"))
            if not result.all():
                await conn.execute(text("""
                    CREATE TABLE aria_accounts (
                        id VARCHAR(36) PRIMARY KEY,
                        username VARCHAR(255) UNIQUE NOT NULL,
                        email VARCHAR(255),
                        password_hash VARCHAR(255) NOT NULL,
                        role VARCHAR(30) NOT NULL,
                        asset_id VARCHAR(36),
                        is_active BOOLEAN DEFAULT 1,
                        is_banned BOOLEAN DEFAULT 0,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        last_login_at TIMESTAMP WITH TIME ZONE
                    )
                """))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_aria_accounts_username ON aria_accounts(username)"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_aria_accounts_role ON aria_accounts(role)"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_aria_accounts_asset_id ON aria_accounts(asset_id)"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_aria_accounts_is_active ON aria_accounts(is_active)"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_aria_accounts_is_banned ON aria_accounts(is_banned)"))
                logger.info("db_migration_applied", table="aria_accounts")
    except Exception as e:
        logger.warning("db_migration_failed", error=str(e))


async def _seed_default_asset_if_needed():
    """If no assets exist and legacy ansible_remote_host is configured,
    create a disabled placeholder so the admin can migrate it manually."""
    from sqlalchemy import select
    from response.models import MonitoredAsset
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(MonitoredAsset).limit(1))
            if result.scalar_one_or_none() is not None:
                return
            settings = get_settings()
            if not settings.ansible_remote_host:
                return
            legacy = MonitoredAsset(
                asset_id="legacy",
                name="Legacy Server",
                hostname=settings.ansible_remote_host,
                ip_address=settings.ansible_remote_host,
                enabled=False,
                description="Auto-created from legacy ansible_remote_host. Review and enable manually.",
                source_config_json={},
                ansible_config_json={
                    "ansible_host": settings.ansible_remote_host,
                    "ansible_user": settings.ansible_remote_user,
                    "ansible_port": settings.ansible_ssh_port,
                    "auth_type": "private_key" if settings.ansible_ssh_key else "password",
                    "ssh_key_ref": settings.ansible_ssh_key,
                    "password_secret_ref": "ARIA_LEGACY_ANSIBLE_SSH_PASSWORD",
                    "become_method": settings.ansible_become_method,
                    "become_password_secret_ref": "ARIA_LEGACY_ANSIBLE_BECOME_PASSWORD",
                    "remediation_enabled": settings.ansible_enabled,
                },
                remediation_enabled=False,
                validation_status="pending",
            )
            session.add(legacy)
            await session.commit()
            logger.info("default_legacy_asset_seeded", asset_id=legacy.asset_id)
    except Exception as e:
        logger.warning("default_asset_seed_failed", error=str(e))


async def _seed_super_admin_if_needed():
    """Ensure the predefined super_admin account exists."""
    from sqlalchemy import select, or_
    from response.models import AriaAccount
    from response.auth import hash_password
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(AriaAccount).where(
                    or_(
                        AriaAccount.username == "ghazi",
                        AriaAccount.email == "ghazi.mabrouki@esprit.tn",
                    )
                )
            )
            if result.scalar_one_or_none() is not None:
                return
            admin = AriaAccount(
                username="ghazi",
                email="ghazi.mabrouki@esprit.tn",
                password_hash=hash_password("Ghozz1470@"),
                role="super_admin",
                asset_id=None,
                is_active=True,
                is_banned=False,
            )
            session.add(admin)
            await session.commit()
            logger.info("super_admin_seeded", username=admin.username)
    except Exception as e:
        logger.warning("super_admin_seed_failed", error=str(e))


async def _ensure_asset_accounts():
    """Ensure every monitored asset with an IP has a default server_user account."""
    from sqlalchemy import select
    from response.models import AriaAccount, MonitoredAsset
    from response.auth import hash_password
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(MonitoredAsset))
            assets = result.scalars().all()
            for asset in assets:
                if not asset.ip_address:
                    continue
                username = asset.ip_address
                existing = await session.execute(
                    select(AriaAccount).where(AriaAccount.username == username)
                )
                if existing.scalar_one_or_none() is not None:
                    continue
                account = AriaAccount(
                    username=username,
                    email=None,
                    password_hash=hash_password(f"ARIA-{username}"),
                    role="server_user",
                    asset_id=asset.asset_id,
                    is_active=True,
                    is_banned=False,
                )
                session.add(account)
                logger.info("asset_account_created", username=username, asset_id=asset.asset_id)
            await session.commit()
    except Exception as e:
        logger.warning("asset_account_ensure_failed", error=str(e))


async def init_db():
    """Create all tables on startup."""
    from sqlalchemy import text as _text
    from response.models import (  # noqa: F401 — imported for side effects
        Investigation,
        InvestigationAlert,
        InvestigationAuditEvent,
        AriaAlert,
        PlaybookApproval,
        PlaybookRun,
        FixVerification,
        FixVerificationJob,
        Archive,
        AssistantConversation,
        AssistantMessage,
        Alert,
        Incident,
        AlertIncidentLink,
        WhitelistEntry,
        OperatorRun,
        OperatorSession,
        OperatorMessage,
        MonitoredAsset,
        AriaAccount,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Enable WAL mode for better concurrent read/write performance
        await conn.execute(_text("PRAGMA journal_mode=WAL"))
        await conn.execute(_text("PRAGMA synchronous=NORMAL"))
    await _migrate_db()

    # Seed default legacy asset if multi-server is not yet configured
    await _seed_default_asset_if_needed()

    # Seed predefined super_admin account
    await _seed_super_admin_if_needed()

    # Ensure every monitored asset has a default server_user account
    await _ensure_asset_accounts()

    # Initialize FTS5 full-text search tables
    try:
        from response.search_fts import init_fts5_tables, backfill_fts5
        await init_fts5_tables()
        await backfill_fts5()
    except Exception as e:
        logger.warning("fts5_init_failed", error=str(e))


async def get_session() -> AsyncSession:
    """Dependency for FastAPI routes."""
    async with AsyncSessionLocal() as session:
        yield session
