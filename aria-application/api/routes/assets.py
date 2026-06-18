"""
Monitored Asset API routes — manual server CRUD, source checks, Ansible config.
"""

import os
import structlog
from datetime import datetime, timezone
from typing import Optional

logger = structlog.get_logger()

from fastapi import APIRouter, Depends, HTTPException, Header, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession

from response.db import get_session
from response.models import MonitoredAsset, AriaAccount
from response.auth import hash_password, require_auth, CurrentUser
from api.routes._shared import validate_asset_id, enforce_asset_scope
from core.elasticsearch import search_alerts, count_alerts

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])


# ═══════════════════════════════════════════════════════════════════════════════
# Admin authorization helper
# ═══════════════════════════════════════════════════════════════════════════════

def _validate_admin_secret(header: str | None) -> None:
    from config import get_settings
    settings = get_settings()
    secret = settings.aria_admin_secret
    bad_defaults = {"", "changeme", "default", "admin"}
    if not secret or secret.lower() in bad_defaults:
        raise HTTPException(
            status_code=403,
            detail="Admin access is disabled because aria_admin_secret is not configured or uses a default value.",
        )
    if not header:
        raise HTTPException(status_code=403, detail="X-ARIA-Admin-Secret header is required.")
    if header != secret:
        raise HTTPException(status_code=403, detail="Invalid admin secret.")


# ═══════════════════════════════════════════════════════════════════════════════
# Pydantic schemas
# ═══════════════════════════════════════════════════════════════════════════════

class SourceConfig(BaseModel):
    index_pattern: Optional[str] = None
    host_name: Optional[str] = None
    agent_name: Optional[str] = None
    agent_id: Optional[str] = None


class AnsibleConfig(BaseModel):
    ansible_host: Optional[str] = None
    ansible_user: Optional[str] = None
    ansible_port: Optional[int] = 22
    auth_type: Optional[str] = "private_key"  # password | private_key | local
    ssh_key_ref: Optional[str] = None
    password_secret_ref: Optional[str] = None
    become_method: Optional[str] = "sudo"
    become_password_secret_ref: Optional[str] = None
    remediation_enabled: Optional[bool] = None


class MonitoredAssetCreate(BaseModel):
    asset_id: str = Field(..., min_length=1, max_length=100)
    name: str = Field(..., min_length=1, max_length=255)
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    environment: Optional[str] = None
    description: Optional[str] = None
    enabled: bool = True
    wazuh: Optional[SourceConfig] = None
    falco: Optional[SourceConfig] = None
    telegraf: Optional[SourceConfig] = None
    filebeat: Optional[SourceConfig] = None
    suricata: Optional[SourceConfig] = None
    ansible: Optional[AnsibleConfig] = None
    # Nested JSON alternatives — sent by frontend when flat fields are not used
    source_config_json: Optional[dict] = None
    ansible_config_json: Optional[dict] = None
    remediation_enabled: bool = False


class MonitoredAssetUpdate(BaseModel):
    name: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    environment: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    wazuh: Optional[SourceConfig] = None
    falco: Optional[SourceConfig] = None
    telegraf: Optional[SourceConfig] = None
    filebeat: Optional[SourceConfig] = None
    suricata: Optional[SourceConfig] = None
    ansible: Optional[AnsibleConfig] = None
    # Nested JSON alternatives — sent by frontend when flat fields are not used
    source_config_json: Optional[dict] = None
    ansible_config_json: Optional[dict] = None
    remediation_enabled: Optional[bool] = None


class MonitoredAssetResponse(BaseModel):
    id: str
    asset_id: str
    name: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    environment: Optional[str] = None
    description: Optional[str] = None
    enabled: bool
    source_config_json: Optional[dict] = None
    ansible_config_json: Optional[dict] = None
    remediation_enabled: bool
    validation_status: str
    last_validated_at: Optional[str] = None
    last_seen_at: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @field_validator("last_validated_at", "last_seen_at", "created_at", "updated_at", mode="before")
    @classmethod
    def _dt_to_iso(cls, v):
        if v is None:
            return None
        if hasattr(v, "isoformat"):
            return v.isoformat()
        return str(v)

    class Config:
        from_attributes = True


class SourceCheckRequest(BaseModel):
    source: str  # wazuh | falco | telegraf | filebeat | suricata
    index_pattern: Optional[str] = None
    host_name: Optional[str] = None
    agent_name: Optional[str] = None
    agent_id: Optional[str] = None


class SourceCheckResponse(BaseModel):
    source: str
    status: str  # ok | missing | warning | error
    count: int = 0
    last_seen: Optional[str] = None
    sample_fields: Optional[dict] = None
    message: str


class AssetListResponse(BaseModel):
    assets: list[MonitoredAssetResponse]
    total: int


class AssetWithAccountResponse(MonitoredAssetResponse):
    has_aria_account: bool = False
    aria_account_username: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _source_configs_to_json(payload: MonitoredAssetCreate | MonitoredAssetUpdate) -> dict:
    """Build source_config_json from typed payload fields."""
    result = {}
    for source in ("wazuh", "falco", "telegraf", "filebeat", "suricata"):
        cfg = getattr(payload, source, None)
        if cfg:
            result[source] = cfg.model_dump(exclude_none=True)
    return result


def _json_to_source_configs(source_json: dict) -> dict:
    """Convert stored JSON back to typed SourceConfig objects for response."""
    result = {}
    for source, data in (source_json or {}).items():
        result[source] = SourceConfig(**data)
    return result


def _sanitize_ansible_for_response(ansible_json: dict) -> dict:
    """Return safe Ansible config — never expose raw secrets."""
    if not ansible_json:
        return {}
    safe = dict(ansible_json)
    # Replace any secret values with configured flags
    for key in ("password_secret_ref", "become_password_secret_ref"):
        if key in safe and safe[key]:
            safe[key] = {"configured": True, "value": None}
    return safe


def _build_host_filter_query(source: str, host_name: str | None, agent_name: str | None, agent_id: str | None) -> dict:
    """Build ES query clause for host identity filtering.

    Uses `match` queries (not `term`) because identity fields are typically
    mapped as `text` and go through analysis. `match` ensures case-insensitive
    token matching. `term` on analyzed text fields would fail silently.
    """
    should_clauses = []

    if source == "wazuh":
        if agent_name:
            should_clauses.append({"match": {"agent.name": agent_name}})
        if agent_id:
            should_clauses.append({"match": {"agent.id": agent_id}})
        if host_name:
            should_clauses.append({"match": {"host.name": host_name}})
            should_clauses.append({"match": {"manager.name": host_name}})
    elif source == "falco":
        if host_name:
            should_clauses.append({"match": {"hostname": host_name}})
            should_clauses.append({"match": {"host.name": host_name}})
            should_clauses.append({"match": {"output_fields.hostname": host_name}})
            should_clauses.append({"match": {"output_fields.evt_hostname": host_name}})
            should_clauses.append({"match": {"output_fields.host": host_name}})
            should_clauses.append({"match": {"output_fields.monitored_asset": host_name}})
    elif source == "telegraf":
        if host_name:
            should_clauses.append({"match": {"tag.host": host_name}})
            should_clauses.append({"match": {"tags.host": host_name}})
            should_clauses.append({"match": {"host": host_name}})
            should_clauses.append({"match": {"host.name": host_name}})
    elif source in ("filebeat", "suricata"):
        if host_name:
            should_clauses.append({"match": {"host.name": host_name}})
            should_clauses.append({"match": {"agent.name": host_name}})
            should_clauses.append({"match": {"agent.hostname": host_name}})
            should_clauses.append({"match": {"monitored_asset": host_name}})
    else:
        if host_name:
            should_clauses.append({"match": {"host.name": host_name}})
            should_clauses.append({"match": {"hostname": host_name}})
            should_clauses.append({"match": {"agent.name": host_name}})

    if not should_clauses:
        return {"match_all": {}}

    return {"bool": {"should": should_clauses, "minimum_should_match": 1}}


async def _check_source_in_es(
    source: str,
    index_pattern: str | None,
    host_name: str | None,
    agent_name: str | None,
    agent_id: str | None,
) -> SourceCheckResponse:
    """Query Elasticsearch to verify a source has data for the given identity."""
    from config import get_settings
    settings = get_settings()

    # Resolve default index pattern if not provided
    if not index_pattern:
        defaults = {
            "wazuh": settings.wazuh_index_pattern,
            "falco": settings.falco_index_pattern,
            "telegraf": settings.telegraf_index_pattern,
            "filebeat": settings.filebeat_index_pattern,
            "suricata": settings.suricata_index_pattern,
        }
        index_pattern = defaults.get(source, "*")

    host_filter = _build_host_filter_query(source, host_name, agent_name, agent_id)

    # For Suricata inside Filebeat, add dataset filter
    query = {"bool": {"filter": [host_filter]}}
    if source == "suricata":
        query["bool"]["filter"].append({
            "bool": {
                "should": [
                    {"term": {"event.dataset": "suricata.eve"}},
                    {"term": {"event.module": "suricata"}},
                    {"term": {"fileset.name": "eve"}},
                ],
                "minimum_should_match": 1,
            }
        })

    try:
        count = await count_alerts(index_pattern=index_pattern, query=query)
        if count > 0:
            latest = await search_alerts(
                index_pattern=index_pattern,
                query=query,
                size=1,
                sort=[{"@timestamp": {"order": "desc"}}],
            )
            hits = latest.get("hits", {}).get("hits", [])
            last_seen = None
            sample_fields = {}
            if hits:
                src = hits[0].get("_source", {})
                ts = src.get("@timestamp")
                if ts:
                    last_seen = str(ts)
                # Extract a few identity fields as sample
                sample_fields = {
                    k: src.get(k)
                    for k in ("host.name", "agent.name", "agent.id", "hostname", "tag.host")
                    if src.get(k) is not None
                }
            return SourceCheckResponse(
                source=source,
                status="ok",
                count=count,
                last_seen=last_seen,
                sample_fields=sample_fields,
                message=f"Data found ({count} docs)",
            )
        else:
            return SourceCheckResponse(
                source=source,
                status="missing",
                count=0,
                message="No data found for the given identity in the last indexed documents.",
            )
    except Exception as e:
        logger.warning("asset_source_check_failed", source=source, error=str(e))
        return SourceCheckResponse(
            source=source,
            status="error",
            count=0,
            message=f"Elasticsearch query failed: {str(e)}",
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("", response_model=AssetListResponse)
async def list_assets(
    include_disabled: bool = Query(False),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
    session: AsyncSession = Depends(get_session),
):
    """List monitored assets. Defaults to enabled only."""
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)
    stmt = select(MonitoredAsset)
    if asset_id:
        stmt = stmt.where(MonitoredAsset.asset_id == asset_id)
    if not include_disabled:
        stmt = stmt.where(MonitoredAsset.enabled == True)
    stmt = stmt.order_by(MonitoredAsset.name)
    result = await session.execute(stmt)
    assets = result.scalars().all()

    # Enrich with account info
    account_usernames = set()
    if assets:
        acc_result = await session.execute(
            select(AriaAccount.username).where(AriaAccount.asset_id.in_([a.asset_id for a in assets]))
        )
        account_usernames = {row[0] for row in acc_result.all()}

    enriched = []
    for a in assets:
        data = MonitoredAssetResponse.model_validate(a).model_dump()
        data["has_aria_account"] = a.ip_address in account_usernames if a.ip_address else False
        data["aria_account_username"] = a.ip_address if a.ip_address in account_usernames else None
        enriched.append(AssetWithAccountResponse(**data))

    return AssetListResponse(assets=enriched, total=len(assets))


@router.post("", response_model=MonitoredAssetResponse, status_code=201)
async def create_asset(
    payload: MonitoredAssetCreate,
    session: AsyncSession = Depends(get_session),
    x_aria_admin_secret: Optional[str] = Header(None, alias="X-ARIA-Admin-Secret"),
):
    """Create a new monitored asset manually. Admin-secret protected."""
    _validate_admin_secret(x_aria_admin_secret)

    # Check duplicate asset_id
    existing = await session.execute(
        select(MonitoredAsset).where(MonitoredAsset.asset_id == payload.asset_id)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="asset_id already exists.")

    # Prefer nested JSON if provided (frontend pattern), else fall back to flat typed fields
    if payload.source_config_json is not None:
        source_json = dict(payload.source_config_json)
    else:
        source_json = _source_configs_to_json(payload)

    if payload.ansible_config_json is not None:
        ansible_json = dict(payload.ansible_config_json)
    else:
        ansible_json = payload.ansible.model_dump(exclude_none=True) if payload.ansible else {}

    # If enabled=True, require at least one source to be configured
    has_source = any(
        cfg.get("index_pattern") or cfg.get("host_name")
        for cfg in source_json.values()
    )
    if payload.enabled and not has_source:
        raise HTTPException(
            status_code=400,
            detail="At least one source must be configured before enabling this asset.",
        )

    validation_status = "pending"
    if payload.enabled:
        validation_status = "ok" if has_source else "missing"

    asset = MonitoredAsset(
        asset_id=payload.asset_id,
        name=payload.name,
        hostname=payload.hostname,
        ip_address=payload.ip_address,
        environment=payload.environment,
        description=payload.description,
        enabled=payload.enabled,
        source_config_json=source_json,
        ansible_config_json=ansible_json,
        remediation_enabled=payload.remediation_enabled and bool(ansible_json.get("ansible_host")),
        validation_status=validation_status,
    )
    session.add(asset)
    await session.commit()
    await session.refresh(asset)

    # Auto-create default server_user account if asset has an IP
    if asset.ip_address:
        existing_account = await session.execute(
            select(AriaAccount).where(AriaAccount.username == asset.ip_address)
        )
        if not existing_account.scalar_one_or_none():
            account = AriaAccount(
                username=asset.ip_address,
                email=None,
                password_hash=hash_password(f"ARIA-{asset.ip_address}"),
                role="server_user",
                asset_id=asset.asset_id,
                is_active=True,
                is_banned=False,
            )
            session.add(account)
            await session.commit()
            logger.info("asset_account_auto_created", username=asset.ip_address, asset_id=asset.asset_id)

    logger.info("asset_created", asset_id=asset.asset_id, name=asset.name)
    return MonitoredAssetResponse.model_validate(asset)


@router.get("/{asset_id}", response_model=AssetWithAccountResponse)
async def get_asset(
    asset_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Get a single monitored asset safely (no secrets exposed)."""
    result = await session.execute(
        select(MonitoredAsset).where(MonitoredAsset.asset_id == asset_id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")

    acc_result = await session.execute(
        select(AriaAccount.username).where(AriaAccount.asset_id == asset_id)
    )
    account_username = acc_result.scalar_one_or_none()

    data = MonitoredAssetResponse.model_validate(asset).model_dump()
    data["has_aria_account"] = bool(account_username)
    data["aria_account_username"] = account_username
    return AssetWithAccountResponse(**data)


@router.patch("/{asset_id}", response_model=MonitoredAssetResponse)
async def update_asset(
    asset_id: str,
    payload: MonitoredAssetUpdate,
    session: AsyncSession = Depends(get_session),
    x_aria_admin_secret: Optional[str] = Header(None, alias="X-ARIA-Admin-Secret"),
):
    """Update a monitored asset. Admin-secret protected."""
    _validate_admin_secret(x_aria_admin_secret)

    result = await session.execute(
        select(MonitoredAsset).where(MonitoredAsset.asset_id == asset_id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")

    updates = {}
    for field in ("name", "hostname", "ip_address", "environment", "description", "enabled"):
        val = getattr(payload, field, None)
        if val is not None:
            updates[field] = val

    # Source configs — prefer nested JSON if provided, else fall back to flat fields
    if payload.source_config_json is not None:
        updates["source_config_json"] = dict(payload.source_config_json)
    elif payload.wazuh is not None or payload.falco is not None or payload.telegraf is not None or payload.filebeat is not None or payload.suricata is not None:
        current = dict(asset.source_config_json or {})
        for source in ("wazuh", "falco", "telegraf", "filebeat", "suricata"):
            cfg = getattr(payload, source, None)
            if cfg is not None:
                if cfg.model_dump(exclude_none=True):
                    current[source] = cfg.model_dump(exclude_none=True)
                else:
                    current.pop(source, None)
        updates["source_config_json"] = current

    # Ansible config — prefer nested JSON if provided, else fall back to flat field
    if payload.ansible_config_json is not None:
        ansible_json = dict(payload.ansible_config_json)
        updates["ansible_config_json"] = ansible_json
        # Force remediation_enabled off if ansible host is missing
        if not ansible_json.get("ansible_host"):
            updates["remediation_enabled"] = False
    elif payload.ansible is not None:
        ansible_json = payload.ansible.model_dump(exclude_none=True)
        updates["ansible_config_json"] = ansible_json
        # Force remediation_enabled off if ansible host is missing
        if not ansible_json.get("ansible_host"):
            updates["remediation_enabled"] = False

    if payload.remediation_enabled is not None:
        ansible = updates.get("ansible_config_json") or asset.ansible_config_json or {}
        if payload.remediation_enabled and not ansible.get("ansible_host"):
            raise HTTPException(
                status_code=400,
                detail="Cannot enable remediation without ansible_host configured.",
            )
        updates["remediation_enabled"] = payload.remediation_enabled

    if updates:
        updates["updated_at"] = datetime.now(timezone.utc)
        await session.execute(
            update(MonitoredAsset)
            .where(MonitoredAsset.asset_id == asset_id)
            .values(**updates)
        )
        await session.commit()
        await session.refresh(asset)
        logger.info("asset_updated", asset_id=asset_id, fields=list(updates.keys()))

    return MonitoredAssetResponse.model_validate(asset)


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(
    asset_id: str,
    session: AsyncSession = Depends(get_session),
    x_aria_admin_secret: Optional[str] = Header(None, alias="X-ARIA-Admin-Secret"),
):
    """Delete a monitored asset. Admin-secret protected."""
    _validate_admin_secret(x_aria_admin_secret)

    result = await session.execute(
        select(MonitoredAsset).where(MonitoredAsset.asset_id == asset_id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")

    await session.delete(asset)
    await session.commit()
    logger.info("asset_deleted", asset_id=asset_id)
    return None


@router.post("/check-source", response_model=SourceCheckResponse)
async def check_source(
    payload: SourceCheckRequest,
    x_aria_admin_secret: Optional[str] = Header(None, alias="X-ARIA-Admin-Secret"),
):
    """Check one data source in Elasticsearch before saving a server."""
    _validate_admin_secret(x_aria_admin_secret)

    return await _check_source_in_es(
        source=payload.source,
        index_pattern=payload.index_pattern,
        host_name=payload.host_name,
        agent_name=payload.agent_name,
        agent_id=payload.agent_id,
    )


@router.post("/{asset_id}/validate")
async def validate_asset(
    asset_id: str,
    session: AsyncSession = Depends(get_session),
    x_aria_admin_secret: Optional[str] = Header(None, alias="X-ARIA-Admin-Secret"),
):
    """Validate all configured sources for an asset against Elasticsearch."""
    _validate_admin_secret(x_aria_admin_secret)

    result = await session.execute(
        select(MonitoredAsset).where(MonitoredAsset.asset_id == asset_id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")

    source_json = asset.source_config_json or {}
    checks = []
    any_ok = False
    any_error = False

    for source, cfg in source_json.items():
        if not isinstance(cfg, dict):
            continue
        check = await _check_source_in_es(
            source=source,
            index_pattern=cfg.get("index_pattern"),
            host_name=cfg.get("host_name"),
            agent_name=cfg.get("agent_name"),
            agent_id=cfg.get("agent_id"),
        )
        checks.append(check.model_dump())
        if check.status == "ok":
            any_ok = True
        elif check.status == "error":
            any_error = True

    validation_status = "ok" if any_ok else ("error" if any_error else "missing")
    asset.validation_status = validation_status
    asset.last_validated_at = datetime.now(timezone.utc)
    await session.commit()

    return {"asset_id": asset_id, "validation_status": validation_status, "checks": checks}


@router.get("/{asset_id}/ansible")
async def get_asset_ansible(
    asset_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Return safe Ansible config/readiness state (no secrets)."""
    result = await session.execute(
        select(MonitoredAsset).where(MonitoredAsset.asset_id == asset_id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")

    ansible = asset.ansible_config_json or {}
    safe = _sanitize_ansible_for_response(ansible)

    # Resolve secret configured flags, respecting auth_type
    # When per-asset refs are missing, fall back to global settings
    from config import get_settings
    global_settings = get_settings()

    auth_type = ansible.get("auth_type", "private_key")
    password_configured = False
    become_password_configured = False
    ssh_key_configured = False
    uses_global_fallback = False

    # SSH key: per-asset ref first, then global settings
    if auth_type in ("private_key", "local"):
        key_ref = ansible.get("ssh_key_ref")
        if key_ref:
            ssh_key_configured = os.path.exists(key_ref)
        elif global_settings.ansible_ssh_key:
            ssh_key_configured = os.path.exists(global_settings.ansible_ssh_key)
            uses_global_fallback = True

    # SSH password: per-asset ref first, then global settings
    if auth_type == "password":
        secret_ref = ansible.get("password_secret_ref")
        if secret_ref:
            password_configured = bool(os.environ.get(secret_ref))
        elif global_settings.ansible_ssh_password:
            password_configured = True
            uses_global_fallback = True

    # Become password: per-asset ref first, then global settings
    become_secret_ref = ansible.get("become_password_secret_ref")
    if become_secret_ref:
        become_password_configured = bool(os.environ.get(become_secret_ref))
    elif global_settings.ansible_become_password:
        become_password_configured = True
        uses_global_fallback = True

    readiness = {
        "ansible_host_configured": bool(ansible.get("ansible_host")),
        "ansible_user_configured": bool(ansible.get("ansible_user")),
        "auth_type": auth_type,
        "ssh_key_configured": ssh_key_configured,
        "password_configured": password_configured,
        "become_password_configured": become_password_configured,
        "remediation_enabled": asset.remediation_enabled and asset.enabled,
        "asset_enabled": asset.enabled,
        "uses_global_fallback": uses_global_fallback,
    }

    return {"asset_id": asset_id, "ansible": safe, "readiness": readiness}


@router.patch("/{asset_id}/ansible")
async def update_asset_ansible(
    asset_id: str,
    payload: AnsibleConfig,
    session: AsyncSession = Depends(get_session),
    x_aria_admin_secret: Optional[str] = Header(None, alias="X-ARIA-Admin-Secret"),
):
    """Update Ansible metadata for an asset. Admin-secret protected. No raw secrets."""
    _validate_admin_secret(x_aria_admin_secret)

    result = await session.execute(
        select(MonitoredAsset).where(MonitoredAsset.asset_id == asset_id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")

    ansible_json = payload.model_dump(exclude_none=True)
    updates = {
        "ansible_config_json": ansible_json,
        "updated_at": datetime.now(timezone.utc),
    }
    # Force remediation off if ansible_host missing
    if not ansible_json.get("ansible_host"):
        updates["remediation_enabled"] = False
    elif payload.remediation_enabled is not None:
        # Only update remediation_enabled when explicitly provided in payload
        updates["remediation_enabled"] = payload.remediation_enabled
    # else: preserve existing remediation_enabled — do not touch it

    await session.execute(
        update(MonitoredAsset)
        .where(MonitoredAsset.asset_id == asset_id)
        .values(**updates)
    )
    await session.commit()
    await session.refresh(asset)
    logger.info("asset_ansible_updated", asset_id=asset_id)
    return {"asset_id": asset_id, "ansible": _sanitize_ansible_for_response(asset.ansible_config_json)}


@router.post("/{asset_id}/ansible/test-connection")
async def test_asset_connection(
    asset_id: str,
    payload: Optional[AnsibleConfig] = None,
    session: AsyncSession = Depends(get_session),
    x_aria_admin_secret: Optional[str] = Header(None, alias="X-ARIA-Admin-Secret"),
):
    """Harmless connection test: whoami/hostname/uptime. No remediation. Admin-secret protected.
    
    If a payload is provided, merges it with the stored asset config for testing
    current form values without saving.
    """
    _validate_admin_secret(x_aria_admin_secret)

    result = await session.execute(
        select(MonitoredAsset).where(MonitoredAsset.asset_id == asset_id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")

    if not asset.enabled:
        raise HTTPException(status_code=400, detail="Asset is disabled.")

    stored = asset.ansible_config_json or {}
    # Merge payload with stored config for testing (payload overrides stored)
    if payload:
        test_config = payload.model_dump(exclude_unset=True)
        ansible = {**stored, **test_config}
    else:
        ansible = dict(stored)

    target = ansible.get("ansible_host")
    user = ansible.get("ansible_user")
    port = ansible.get("ansible_port", 22)

    if not target or not user:
        raise HTTPException(status_code=400, detail="SSH host or user is missing.")

    from config import get_settings
    global_settings = get_settings()

    # Build a harmless ad-hoc Ansible command
    import tempfile
    import subprocess
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        inv_path = Path(tmpdir) / "inventory.ini"
        warnings = []
        uses_global_fallback = False

        # Build host variables as a single inventory line (INI format)
        host_vars = f"ansible_user={user} ansible_port={port}"

        auth_type = ansible.get("auth_type", "private_key")
        if auth_type == "private_key":
            key_ref = ansible.get("ssh_key_ref")
            if key_ref:
                if not os.path.exists(key_ref):
                    return {"status": "error", "message": f"SSH key file not found at {key_ref}", "output": "", "error": f"File does not exist: {key_ref}"}
                host_vars += f" ansible_ssh_private_key_file={key_ref}"
            elif global_settings.ansible_ssh_key and os.path.exists(global_settings.ansible_ssh_key):
                host_vars += f" ansible_ssh_private_key_file={global_settings.ansible_ssh_key}"
                uses_global_fallback = True
                warnings.append("Using global SSH key (ansible_ssh_key) because asset has no ssh_key_ref.")
            else:
                return {
                    "status": "error",
                    "message": "SSH key path is required for private-key auth. Enter a key path or switch to password auth.",
                    "output": "",
                    "error": "No ssh_key_ref configured for this asset and no global ansible_ssh_key is set.",
                }
        elif auth_type == "password":
            secret_ref = ansible.get("password_secret_ref")
            password = None
            if secret_ref:
                password = os.environ.get(secret_ref)
                if not password:
                    return {"status": "error", "message": f"Password environment variable {secret_ref} is not set.", "output": "", "error": f"Environment variable '{secret_ref}' is not defined in the ARIA backend process. Add it to .env and restart."}
            elif global_settings.ansible_ssh_password:
                password = global_settings.ansible_ssh_password
                uses_global_fallback = True
                warnings.append("Using global SSH password (ansible_ssh_password) because asset has no password_secret_ref.")
            else:
                return {
                    "status": "error",
                    "message": "Password env var reference is required for password auth.",
                    "output": "",
                    "error": "No password_secret_ref configured for this asset and no global ansible_ssh_password is set.",
                }
            if password:
                host_vars += f" ansible_ssh_pass={password}"
        elif auth_type == "local":
            return {"status": "ok", "message": "Local connection mode — no remote test needed."}

        become_method = ansible.get("become_method", "none")
        if become_method in ("sudo", "su"):
            become_secret_ref = ansible.get("become_password_secret_ref")
            bpw = None
            if become_secret_ref:
                bpw = os.environ.get(become_secret_ref)
                if not bpw:
                    warnings.append(f"Become password env var {become_secret_ref} is not set. Sudo may fail.")
            elif global_settings.ansible_become_password:
                bpw = global_settings.ansible_become_password
                uses_global_fallback = True
                warnings.append("Using global become password (ansible_become_password) because asset has no become_password_secret_ref.")
            else:
                warnings.append("Sudo password not configured. Become may fail.")
            if bpw:
                host_vars += f" ansible_become_pass={bpw}"

        inventory_content = f"[target]\n{target} {host_vars}\n"
        inv_path.write_text(inventory_content, encoding="utf-8")
        inv_path.chmod(0o600)

        cmd = [
            "ansible", "target", "-i", str(inv_path),
            "-m", "shell", "-a", "whoami && hostname && uptime",
            "--timeout", "30",
        ]
        if become_method in ("sudo", "su"):
            cmd.extend(["--become", "--become-method", become_method])

        try:
            env = os.environ.copy()
            env["ANSIBLE_HOST_KEY_CHECKING"] = "False"
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=35, env=env)
            message = "Connection successful."
            if warnings:
                message += " Warnings: " + " ".join(warnings)
            if uses_global_fallback:
                message += " (Using global legacy credentials as fallback.)"
            if proc.returncode == 0:
                return {"status": "ok", "message": message, "output": proc.stdout.strip(), "uses_global_fallback": uses_global_fallback}
            else:
                return {"status": "error", "message": "Connection failed." + (" Warnings: " + " ".join(warnings) if warnings else ""), "output": proc.stdout.strip(), "error": proc.stderr.strip(), "uses_global_fallback": uses_global_fallback}
        except FileNotFoundError:
            return {"status": "error", "message": "ansible command not found. Is Ansible installed?"}
        except subprocess.TimeoutExpired:
            return {"status": "error", "message": "Connection test timed out after 30 seconds."}
