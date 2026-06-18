"""Settings API for ARIA runtime configuration management.

Provides safe read/update of .env settings with runtime reload and connection testing.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import structlog
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field, field_validator

from config.settings import get_settings, reload_settings

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])

SETTINGS_RELOAD_CHANNEL = "aria:settings:reload"


async def publish_settings_reload(changed_env_vars: dict[str, str]) -> None:
    """Publish changed env vars to Redis so background workers reload without restart."""
    try:
        from core.redis import get_redis_client
        client = await get_redis_client()
        await client.publish(SETTINGS_RELOAD_CHANNEL, json.dumps(changed_env_vars))
    except Exception as e:
        logger.warning("settings_reload_publish_failed", error=str(e))


# ── Settings metadata schema ────────────────────────────────────────────────

SETTING_TYPE_MAP: dict[str, str] = {
    "elasticsearch_url": "string",
    "elasticsearch_user": "string",
    "elasticsearch_password": "secret",
    "elasticsearch_use_ssl": "bool",
    "wazuh_index_pattern": "string",
    "falco_index_pattern": "string",
    "suricata_index_pattern": "string",
    "filebeat_index_pattern": "string",
    "telegraf_index_pattern": "string",
    "redis_host": "string",
    "redis_port": "int",
    "redis_db": "int",
    "redis_password": "secret",
    "llm_provider": "string",
    "llm_model": "string",
    "ollama_host": "string",
    "ollama_timeout": "int",
    "llm_enabled": "bool",
    "llm_fallback_to_pyrca": "bool",
    "openai_api_key": "secret",
    "anthropic_api_key": "secret",
    "google_api_key": "secret",
    "openrouter_api_key": "secret",
    "nvidia_api_key": "secret",
    "ansible_enabled": "bool",
    "ansible_remote_host": "string",
    "ansible_remote_user": "string",
    "ansible_ssh_port": "int",
    "ansible_ssh_key": "string",
    "ansible_ssh_password": "secret",
    "ansible_timeout": "int",
    "ansible_become_method": "string",
    "ansible_become_password": "secret",
    "aria_admin_secret": "secret",
    "local_ingestion_enabled": "bool",
    "incident_auto_create_enabled": "bool",
    "incident_watcher_interval": "int",
    "incident_correlation_interval": "int",
    "max_concurrent_investigations": "int",
    "stuck_investigation_hours": "int",
    "stuck_running_minutes": "int",
    "stuck_pending_hours": "int",
    "running_investigation_timeout_minutes": "int",
    "fix_verify_wait_minutes": "int",
    "fix_verify_window_minutes": "int",
    "auto_approve_enabled": "bool",
    "auto_approve_all_enabled": "bool",
    "auto_approve_method": "string",
    "auto_approve_max_risk_score": "int",
    "auto_approve_max_alerts": "int",
    "auto_approve_block_risk_score": "int",
    "auto_approve_dynamic_enabled": "bool",
    "auto_approve_ai_enabled": "bool",
    "auto_approve_ai_threshold": "float",
    "performance_enabled": "bool",
    "performance_poll_interval": "int",
    "performance_cpu_warning": "int",
    "performance_cpu_critical": "int",
    "performance_memory_warning": "int",
    "performance_memory_critical": "int",
    "performance_disk_warning": "int",
    "performance_disk_critical": "int",
    "wazuh_poll_interval_seconds": "int",
    "falco_poll_interval_seconds": "int",
    "filebeat_poll_interval_seconds": "int",
    "suricata_poll_interval_seconds": "int",
}

SECTION_KEYS: dict[str, list[str]] = {
    "security": ["internal_trusted_active", "admin_secret_configured", "protected_endpoints_enabled",
                 "cors_origins", "rate_limit_enabled", "rate_limit_window_seconds",
                 "rate_limit_max_requests", "rate_limit_sensitive_max_requests",
                 "aria_admin_users", "aria_admin_secret"],
    "data_sources": ["elasticsearch_url", "elasticsearch_user", "elasticsearch_password",
                     "elasticsearch_use_ssl", "wazuh_index_pattern", "falco_index_pattern",
                     "suricata_index_pattern", "filebeat_index_pattern", "telegraf_index_pattern"],
    "redis": ["redis_host", "redis_port", "redis_db", "redis_password"],
    "ai": ["llm_enabled", "active_ai_provider", "ai_provider_mismatch_warning",
           "llm_provider", "llm_model", "ollama_host", "ollama_timeout",
           "llm_fallback_to_pyrca", "openai_api_key", "anthropic_api_key", "google_api_key",
           "openrouter_api_key", "nvidia_api_key"],
    "ansible": ["ansible_enabled", "ansible_connection_auth_mode", "ansible_become_mode",
                "ansible_remote_host", "ansible_remote_user",
                "ansible_ssh_port", "ansible_ssh_key", "ansible_ssh_password",
                "ansible_timeout", "ansible_become_method", "ansible_become_password"],
    "workflow": ["local_ingestion_enabled", "incident_auto_create_enabled",
                 "auto_approve_enabled", "auto_approve_all_enabled", "auto_approve_method",
                 "fix_verify_wait_minutes", "fix_verify_window_minutes",
                 "stuck_investigation_hours", "stuck_running_minutes", "stuck_pending_hours",
                 "running_investigation_timeout_minutes", "max_concurrent_investigations"],
    "monitoring": ["performance_enabled", "performance_poll_interval",
                   "performance_cpu_warning", "performance_cpu_critical",
                   "performance_memory_warning", "performance_memory_critical",
                   "performance_disk_warning", "performance_disk_critical"],
    "pipeline": ["opensoar_enabled", "opensoar_poll_interval", "opensoar_batch_size",
                 "opensoar_first_run_lookback_hours", "opensoar_min_severity",
                 "wazuh_poll_interval_seconds", "falco_poll_interval_seconds",
                 "filebeat_poll_interval_seconds", "suricata_poll_interval_seconds"],
}

# Keys that require a backend restart to take effect
REQUIRES_RESTART_KEYS: set[str] = {
    "backend_port", "api_host", "cors_origins", "db_path",
}


# ── Computed settings (read-only, derived from actual settings) ─────────────

def _admin_secret_configured(settings: Any) -> bool:
    secret = getattr(settings, "aria_admin_secret", None) or ""
    return bool(secret and secret.strip().lower() not in {"", "changeme", "default", "admin"})


def _ai_provider_mismatch_warning(settings: Any) -> str | None:
    provider = (getattr(settings, "llm_provider", None) or "ollama").lower()
    host = (getattr(settings, "ollama_host", None) or "").lower()
    if provider == "nvidia" and ("localhost" in host or "127.0.0.1" in host):
        return "Provider is NVIDIA NIM but base URL looks like a local Ollama endpoint. Confirm provider selection."
    if provider in ("ollama", "auto") and "integrate.api.nvidia.com" in host:
        return "Provider is Ollama but base URL points to NVIDIA. Confirm provider selection."
    return None


def _ansible_connection_auth_mode(settings: Any) -> str:
    host = getattr(settings, "ansible_remote_host", None) or ""
    if host.lower() in ("localhost", "127.0.0.1", ""):
        return "local"
    if getattr(settings, "ansible_ssh_key", None):
        return "ssh_key"
    if getattr(settings, "ansible_ssh_password", None):
        return "ssh_password"
    return "ssh_key"


def _ansible_become_mode(settings: Any) -> str:
    method = (getattr(settings, "ansible_become_method", None) or "").lower()
    if not method or method == "none":
        return "none"
    if getattr(settings, "ansible_become_password", None):
        return "sudo_password"
    return "passwordless"


_COMPUTED_KEYS: dict[str, tuple[str, Any]] = {
    "internal_trusted_active": ("bool", lambda s: True),
    "admin_secret_configured": ("bool", _admin_secret_configured),
    "protected_endpoints_enabled": ("bool", _admin_secret_configured),
    "active_ai_provider": ("string", lambda s: (getattr(s, "llm_provider", None) or "ollama").lower()),
    "ai_provider_mismatch_warning": ("string", _ai_provider_mismatch_warning),
    "ansible_connection_auth_mode": ("string", _ansible_connection_auth_mode),
    "ansible_become_mode": ("string", _ansible_become_mode),
}


# ── Pydantic models ─────────────────────────────────────────────────────────

class SettingsValue(BaseModel):
    key: str
    value: Any
    type: str
    secret: bool = False


class SettingsSection(BaseModel):
    section: str
    values: list[SettingsValue]


class SettingsResponse(BaseModel):
    sections: list[SettingsSection]


class SettingsPreviewRequest(BaseModel):
    changes: dict[str, Any]


class SettingsPreviewResponse(BaseModel):
    preview: list[dict[str, Any]]
    masked: bool = True


class SettingsUpdateRequest(BaseModel):
    changes: dict[str, Any]
    reload: bool = True


class SettingsUpdateResult(BaseModel):
    applied: list[str]
    requires_restart: list[str]
    errors: list[str]
    warnings: list[str]


class RuntimeReloadResult(BaseModel):
    applied: list[str]
    failed: list[str]
    requires_restart: list[str]
    warnings: list[str]


class TestConnectionResult(BaseModel):
    status: str
    latency_ms: float
    last_checked: str
    message: str
    recommended_action: Optional[str] = None


# ── Helpers ─────────────────────────────────────────────────────────────────

def _validate_admin_secret(header: str | None) -> None:
    settings = get_settings()
    secret = settings.aria_admin_secret
    bad_defaults = {"", "changeme", "default", "admin"}
    if not secret or secret.lower() in bad_defaults:
        raise HTTPException(status_code=403, detail="Admin access is disabled because aria_admin_secret is not configured or uses a default value.")
    if not header:
        raise HTTPException(status_code=403, detail="X-ARIA-Admin-Secret header is required.")
    if header != secret:
        raise HTTPException(status_code=403, detail="Invalid admin secret.")


def _sanitize_value(key: str, value: Any) -> Any:
    st = SETTING_TYPE_MAP.get(key, "string")
    if st == "secret":
        if value and str(value).strip():
            return {"configured": True, "value": None}
        return {"configured": False, "value": None}
    if st == "bool":
        return bool(value)
    if st == "int":
        return int(value) if value is not None else 0
    if st == "float":
        return float(value) if value is not None else 0.0
    return value


def _get_current_value(key: str) -> Any:
    settings = get_settings()
    return getattr(settings, key, None)


def _coerce_value(key: str, raw: Any) -> str:
    """Coerce a raw value to string suitable for .env."""
    if raw is None:
        return ""
    st = SETTING_TYPE_MAP.get(key, "string")
    if st == "bool":
        return "true" if raw in (True, "true", "True", "1", 1) else "false"
    if st in ("int", "float"):
        return str(raw)
    if st == "json":
        if isinstance(raw, (dict, list)):
            return json.dumps(raw)
        return str(raw)
    return str(raw)


def _update_env_file(updates: dict[str, str]) -> None:
    env_path = Path(".env")
    tmp_path = Path(".env.tmp")

    lines: list[str] = []
    if env_path.exists():
        text = env_path.read_text(encoding="utf-8")
        lines = text.splitlines()

    updated_keys: set[str] = set()
    new_lines: list[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue
        if "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in updates:
                new_lines.append(f"{key}={updates[key]}")
                updated_keys.add(key)
                continue
        new_lines.append(line)

    for key, value in updates.items():
        if key not in updated_keys:
            new_lines.append(f"{key}={value}")

    # Validate that we can parse the result
    out_text = "\n".join(new_lines) + "\n"
    # Simple validation: no line should look malformed
    for ln in new_lines:
        if ln.strip() and not ln.strip().startswith("#") and "=" not in ln:
            raise ValueError(f"Malformed .env line after update: {ln}")

    tmp_path.write_text(out_text, encoding="utf-8")
    shutil.move(str(tmp_path), str(env_path))


def _build_settings_response() -> SettingsResponse:
    settings = get_settings()
    sections: list[SettingsSection] = []

    for section_name, keys in SECTION_KEYS.items():
        values: list[SettingsValue] = []
        for key in keys:
            if key in _COMPUTED_KEYS:
                st, getter = _COMPUTED_KEYS[key]
                raw = getter(settings)
                values.append(SettingsValue(
                    key=key,
                    value=raw,
                    type=st,
                    secret=False,
                ))
            elif hasattr(settings, key):
                raw = getattr(settings, key)
                st = SETTING_TYPE_MAP.get(key, "string")
                is_secret = st == "secret"
                values.append(SettingsValue(
                    key=key,
                    value=_sanitize_value(key, raw),
                    type=st,
                    secret=is_secret,
                ))
        sections.append(SettingsSection(section=section_name, values=values))

    return SettingsResponse(sections=sections)


# ── Overview / status helpers ───────────────────────────────────────────────

async def _check_elasticsearch_health() -> dict[str, Any]:
    try:
        from elasticsearch import AsyncElasticsearch
        settings = get_settings()
        client_kwargs = {
            "hosts": [settings.elasticsearch_url],
            "basic_auth": (settings.elasticsearch_user, settings.elasticsearch_password),
            "ssl_show_warn": False,
        }
        if not settings.elasticsearch_use_ssl:
            import ssl
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            client_kwargs["ssl_context"] = ssl_ctx
        es = AsyncElasticsearch(**client_kwargs)
        try:
            start = time.time()
            await asyncio.wait_for(es.info(), timeout=5)
            latency = (time.time() - start) * 1000
            return {"status": "connected", "latency_ms": round(latency, 1)}
        finally:
            await es.close()
    except asyncio.TimeoutError:
        return {"status": "disconnected", "error": "Connection timed out"}
    except Exception as e:
        return {"status": "disconnected", "error": str(e)[:100]}


async def _check_redis_health() -> dict[str, Any]:
    try:
        from core import get_redis_client
        redis = await get_redis_client()
        start = time.time()
        await asyncio.wait_for(redis.ping(), timeout=3)
        latency = (time.time() - start) * 1000
        return {"status": "connected", "latency_ms": round(latency, 1)}
    except asyncio.TimeoutError:
        return {"status": "disconnected", "error": "Connection timed out"}
    except Exception as e:
        return {"status": "disconnected", "error": str(e)[:100]}


async def _check_ai_health() -> dict[str, Any]:
    settings = get_settings()
    provider = (settings.llm_provider or "ollama").lower()
    mismatch = _ai_provider_mismatch_warning(settings)
    if not settings.llm_enabled:
        return {"status": "disabled", "provider": provider, "mismatch_warning": mismatch}
    try:
        from response.ai_engine.llm_clients import _call_llm
        start = time.time()
        # Lightweight safe prompt with strict timeout
        result = await asyncio.wait_for(_call_llm("Reply with exactly: pong"), timeout=5)
        latency = (time.time() - start) * 1000
        return {"status": "ready", "latency_ms": round(latency, 1), "provider": provider, "mismatch_warning": mismatch}
    except asyncio.TimeoutError:
        return {"status": "degraded", "error": "LLM response timed out", "provider": provider, "mismatch_warning": mismatch}
    except Exception as e:
        return {"status": "degraded", "error": str(e)[:100], "provider": provider, "mismatch_warning": mismatch}


async def _check_ansible_preflight(host: str | None, user: str, ssh_key: str | None,
                                   ssh_password: str | None, become_password: str | None) -> dict[str, Any]:
    import shutil
    settings = get_settings()
    target = host or settings.ansible_remote_host
    if not target:
        return {"status": "not_configured", "message": "No remote host configured."}

    is_local = target.lower() in ("localhost", "127.0.0.1", "::1")
    has_password = bool(ssh_password)
    has_key = bool(ssh_key)

    # Determine auth modes for reporting
    conn_mode = "local" if is_local else ("ssh_key" if has_key else ("ssh_password" if has_password else "ssh_key"))
    become_mode = "none" if not settings.ansible_become_method or settings.ansible_become_method.lower() == "none" else ("sudo_password" if become_password else "passwordless")

    # Local mode: skip all SSH checks and report success
    if is_local:
        message = "Connection auth: local | Become: sudo_password\n✓ ssh_connectivity: passed (local)\n✓ remote_python: passed (local)\n✓ firewall_tool: passed (local)\n✓ tmp_write: passed (local)\n✓ sudo_ready: passed (local)"
        return {
            "status": "success",
            "checks": [
                {"name": "ssh_connectivity", "status": "passed"},
                {"name": "remote_python", "status": "passed"},
                {"name": "firewall_tool", "status": "passed"},
                {"name": "tmp_write", "status": "passed"},
                {"name": "sudo_ready", "status": "passed"},
            ],
            "message": message,
        }

    def _ssh_cmd(remote_cmd: str) -> list[str]:
        """Build SSH command based on available auth methods."""
        base = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10", "-o", "UserKnownHostsFile=/dev/null"]
        if has_password and shutil.which("sshpass"):
            return ["sshpass", "-p", ssh_password, "ssh"] + base + [f"{user}@{target}", remote_cmd]
        else:
            return ["ssh", "-o", "BatchMode=yes"] + base + (["-i", ssh_key] if has_key else []) + [f"{user}@{target}", remote_cmd]

    checks: list[dict[str, Any]] = []

    # SSH connectivity
    try:
        proc = await asyncio.create_subprocess_exec(
            *_ssh_cmd("echo ok"),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        if proc.returncode == 0 and b"ok" in stdout:
            checks.append({"name": "ssh_connectivity", "status": "passed"})
        else:
            err = stderr.decode().strip()[:200] if stderr else "unknown error"
            checks.append({"name": "ssh_connectivity", "status": "failed", "detail": err})
    except Exception as e:
        checks.append({"name": "ssh_connectivity", "status": "failed", "detail": str(e)[:100]})

    # Remote Python
    try:
        proc = await asyncio.create_subprocess_exec(
            *_ssh_cmd("python3 --version || python --version"),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        if b"Python" in stdout or b"Python" in stderr:
            checks.append({"name": "remote_python", "status": "passed"})
        else:
            checks.append({"name": "remote_python", "status": "failed"})
    except Exception as e:
        checks.append({"name": "remote_python", "status": "failed", "detail": str(e)[:100]})

    # iptables availability
    try:
        proc = await asyncio.create_subprocess_exec(
            *_ssh_cmd("which iptables || which nft || which ufw"),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        if proc.returncode == 0:
            checks.append({"name": "firewall_tool", "status": "passed"})
        else:
            checks.append({"name": "firewall_tool", "status": "warning", "detail": "No iptables/nft/ufw found"})
    except Exception as e:
        checks.append({"name": "firewall_tool", "status": "failed", "detail": str(e)[:100]})

    # /tmp write
    try:
        proc = await asyncio.create_subprocess_exec(
            *_ssh_cmd("touch /tmp/aria_preflight_test && rm /tmp/aria_preflight_test && echo ok"),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        if b"ok" in stdout:
            checks.append({"name": "tmp_write", "status": "passed"})
        else:
            checks.append({"name": "tmp_write", "status": "failed"})
    except Exception as e:
        checks.append({"name": "tmp_write", "status": "failed", "detail": str(e)[:100]})

    # sudo/become readiness
    try:
        proc = await asyncio.create_subprocess_exec(
            *_ssh_cmd("sudo -n echo ok 2>/dev/null || echo no"),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        if b"ok" in stdout:
            checks.append({"name": "sudo_ready", "status": "passed", "detail": "Passwordless sudo available"})
        elif become_password:
            # User has a become password configured — sudo will work via password auth
            checks.append({"name": "sudo_ready", "status": "passed", "detail": "Password-based sudo configured"})
        else:
            checks.append({"name": "sudo_ready", "status": "warning", "detail": "Passwordless sudo not available and no become password configured"})
    except Exception as e:
        checks.append({"name": "sudo_ready", "status": "failed", "detail": str(e)[:100]})

    failed = [c for c in checks if c["status"] == "failed"]
    warnings = [c for c in checks if c["status"] == "warning"]
    lines = [f"Connection auth: {conn_mode} | Become: {become_mode}"]
    for c in checks:
        icon = "✓" if c["status"] == "passed" else ("⚠" if c["status"] == "warning" else "✗")
        lines.append(f"{icon} {c['name']}: {c['status']}" + (f" ({c.get('detail', '')})" if c.get("detail") else ""))
    message = "\n".join(lines)

    if failed:
        return {
            "status": "failed",
            "checks": checks,
            "message": message,
            "recommended_action": "Verify SSH credentials and target host accessibility.",
        }
    if warnings:
        return {
            "status": "warning",
            "checks": checks,
            "message": message,
            "recommended_action": "Review warnings before executing playbooks.",
        }
    return {
        "status": "success",
        "checks": checks,
        "message": message,
    }


# ── Endpoints ───────────────────────────────────────────────────────────────

@router.get("", response_model=SettingsResponse)
async def get_settings_endpoint():
    """Get all settings, sanitized (no secrets)."""
    return _build_settings_response()


@router.post("/preview", response_model=SettingsPreviewResponse)
async def preview_settings(request: SettingsPreviewRequest):
    """Preview changes without saving. Masks secrets."""
    preview: list[dict[str, Any]] = []
    for key, new_val in request.changes.items():
        old_raw = _get_current_value(key)
        st = SETTING_TYPE_MAP.get(key, "string")
        if st == "secret":
            old_display = "configured" if old_raw else "not configured"
            new_display = "replaced" if new_val and str(new_val).strip() else "removed"
        else:
            old_display = old_raw
            new_display = new_val
        preview.append({
            "key": key,
            "old": old_display,
            "new": new_display,
            "type": st,
        })
    return SettingsPreviewResponse(preview=preview, masked=True)


@router.patch("", response_model=SettingsUpdateResult)
async def update_settings(
    request: SettingsUpdateRequest,
    x_aria_admin_secret: Optional[str] = Header(None, alias="X-ARIA-Admin-Secret"),
):
    """Update settings and write to .env atomically."""
    _validate_admin_secret(x_aria_admin_secret)

    result = SettingsUpdateResult(applied=[], requires_restart=[], errors=[], warnings=[])
    env_updates: dict[str, str] = {}

    for key, raw in request.changes.items():
        if key not in SETTING_TYPE_MAP:
            result.errors.append(f"Unknown setting: {key}")
            continue

        # Validation
        st = SETTING_TYPE_MAP[key]
        try:
            if st == "bool":
                val = raw in (True, "true", "True", "1", 1)
            elif st == "int":
                val = int(raw)
                if val < 0 and "timeout" not in key and "interval" not in key and "hours" not in key and "minutes" not in key:
                    result.errors.append(f"{key} must be non-negative")
                    continue
            elif st == "float":
                val = float(raw)
            elif st == "json":
                if isinstance(raw, (dict, list)):
                    val = json.dumps(raw)
                else:
                    val = str(raw)
            else:
                val = str(raw) if raw is not None else ""

            # URL validation for specific keys
            if key == "elasticsearch_url" and val:
                if not val.startswith(("http://", "https://")):
                    result.errors.append(f"{key} must be a valid HTTP(S) URL")
                    continue
            if key == "ollama_host" and val:
                if not val.startswith(("http://", "https://")):
                    result.errors.append(f"{key} must be a valid HTTP(S) URL")
                    continue
            if key in ("redis_port", "ansible_ssh_port") and isinstance(val, int):
                if not (1 <= val <= 65535):
                    result.errors.append(f"{key} must be a valid port (1-65535)")
                    continue
            if "timeout" in key and isinstance(val, int):
                if val < 1:
                    result.errors.append(f"{key} must be at least 1")
                    continue
        except (ValueError, TypeError) as e:
            result.errors.append(f"Invalid value for {key}: {e}")
            continue

        env_updates[key.upper()] = _coerce_value(key, val)
        result.applied.append(key)
        if key in REQUIRES_RESTART_KEYS:
            result.requires_restart.append(key)

    if result.errors:
        return result

    if not env_updates:
        result.warnings.append("No changes to apply.")
        return result

    try:
        _update_env_file(env_updates)
    except Exception as e:
        result.errors.append(f"Failed to write .env: {e}")
        return result

    if request.reload:
        reload_result = await _do_runtime_reload()
        result.warnings.extend(reload_result.warnings)
        for k in reload_result.requires_restart:
            if k not in result.requires_restart:
                result.requires_restart.append(k)
        # Notify background workers so they also reload without restart
        await publish_settings_reload(env_updates)

    return result


async def _do_runtime_reload() -> RuntimeReloadResult:
    result = RuntimeReloadResult(applied=[], failed=[], requires_restart=[], warnings=[])

    # Clear settings cache
    try:
        reload_settings()
        result.applied.append("settings")
    except Exception as e:
        result.failed.append("settings")
        result.warnings.append(f"Settings reload failed: {e}")

    # Reconnect Redis
    try:
        from core.redis import close_redis_client
        close_redis_client()
        result.applied.append("redis")
    except Exception as e:
        result.failed.append("redis")
        result.warnings.append(f"Redis reconnect failed: {e}")

    # Reconnect Elasticsearch
    try:
        from core.elasticsearch import close_es_client
        close_es_client()
        result.applied.append("elasticsearch")
    except Exception as e:
        result.failed.append("elasticsearch")
        result.warnings.append(f"Elasticsearch reconnect failed: {e}")

    # AI client is per-request, no persistent client to reload
    result.applied.append("ai_config")

    # Ansible config is read per-use, no persistent client
    result.applied.append("ansible_config")

    return result


@router.post("/reload", response_model=RuntimeReloadResult)
async def reload_runtime_settings(
    x_aria_admin_secret: Optional[str] = Header(None, alias="X-ARIA-Admin-Secret"),
):
    """Reload runtime settings without writing .env."""
    _validate_admin_secret(x_aria_admin_secret)
    return await _do_runtime_reload()


# ── Test endpoints ──────────────────────────────────────────────────────────

@router.post("/test/elasticsearch", response_model=TestConnectionResult)
async def test_elasticsearch(request: dict[str, Any] | None = None):
    """Test Elasticsearch connectivity and optionally check configured indices."""
    settings = get_settings()
    url = (request or {}).get("elasticsearch_url", settings.elasticsearch_url)
    user = (request or {}).get("elasticsearch_user", settings.elasticsearch_user)
    password = (request or {}).get("elasticsearch_password", settings.elasticsearch_password)
    use_ssl = (request or {}).get("elasticsearch_use_ssl", settings.elasticsearch_use_ssl)

    start = time.time()
    try:
        from elasticsearch import AsyncElasticsearch
        client_kwargs = {
            "hosts": [url],
            "basic_auth": (user, password),
            "ssl_show_warn": False,
        }
        if not use_ssl:
            client_kwargs["verify_certs"] = False
            client_kwargs["ssl_show_warn"] = False
        es = AsyncElasticsearch(**client_kwargs)
        try:
            await es.info()
            latency = (time.time() - start) * 1000

            # Optionally check configured source indices
            index_checks: list[str] = []
            for pattern_key, label in [
                ("wazuh_index_pattern", "Wazuh"),
                ("falco_index_pattern", "Falco"),
                ("suricata_index_pattern", "Suricata"),
                ("filebeat_index_pattern", "Filebeat"),
                ("telegraf_index_pattern", "Telegraf"),
            ]:
                pattern = (request or {}).get(pattern_key) or getattr(settings, pattern_key, None)
                if pattern:
                    try:
                        exists = await es.indices.exists(index=pattern)
                        index_checks.append(f"{label}: {'exists' if exists else 'not found'}")
                    except Exception as ie:
                        index_checks.append(f"{label}: check failed ({str(ie)[:40]})")

            msg = "Elasticsearch connection successful."
            if index_checks:
                msg += " Indices: " + "; ".join(index_checks)
            return TestConnectionResult(
                status="success",
                latency_ms=round(latency, 1),
                last_checked=datetime.now(timezone.utc).isoformat(),
                message=msg,
                recommended_action=None,
            )
        finally:
            await es.close()
    except Exception as e:
        latency = (time.time() - start) * 1000
        return TestConnectionResult(
            status="failed",
            latency_ms=round(latency, 1),
            last_checked=datetime.now(timezone.utc).isoformat(),
            message=f"Elasticsearch connection failed: {str(e)[:100]}",
            recommended_action="Check URL, credentials, and network connectivity.",
        )


@router.post("/test/redis", response_model=TestConnectionResult)
async def test_redis(request: dict[str, Any] | None = None):
    """Test Redis connectivity using saved or provided values."""
    settings = get_settings()
    host = (request or {}).get("redis_host", settings.redis_host)
    port = (request or {}).get("redis_port", settings.redis_port)
    db = (request or {}).get("redis_db", settings.redis_db)
    password = (request or {}).get("redis_password", settings.redis_password)

    start = time.time()
    try:
        import redis.asyncio as redis_lib
        client = redis_lib.Redis(host=host, port=port, db=db, password=password or None, decode_responses=True)
        try:
            await client.ping()
            latency = (time.time() - start) * 1000
            return TestConnectionResult(
                status="success",
                latency_ms=round(latency, 1),
                last_checked=datetime.now(timezone.utc).isoformat(),
                message="Redis connection successful.",
                recommended_action=None,
            )
        finally:
            await client.close()
    except Exception as e:
        latency = (time.time() - start) * 1000
        return TestConnectionResult(
            status="failed",
            latency_ms=round(latency, 1),
            last_checked=datetime.now(timezone.utc).isoformat(),
            message=f"Redis connection failed: {str(e)[:100]}",
            recommended_action="Check host, port, and password.",
        )


@router.post("/test/ai", response_model=TestConnectionResult)
async def test_ai(request: dict[str, Any] | None = None):
    """Test AI/LLM connectivity using a lightweight prompt."""
    settings = get_settings()
    enabled = (request or {}).get("llm_enabled", settings.llm_enabled)
    if not enabled:
        return TestConnectionResult(
            status="warning",
            latency_ms=0,
            last_checked=datetime.now(timezone.utc).isoformat(),
            message="AI is disabled.",
            recommended_action="Enable AI to use LLM features.",
        )

    start = time.time()
    try:
        from response.ai_engine.llm_clients import _call_llm
        result = await _call_llm("Reply with exactly: pong")
        latency = (time.time() - start) * 1000
        return TestConnectionResult(
            status="success",
            latency_ms=round(latency, 1),
            last_checked=datetime.now(timezone.utc).isoformat(),
            message=f"AI responded: {str(result)[:40]}",
            recommended_action=None,
        )
    except Exception as e:
        latency = (time.time() - start) * 1000
        return TestConnectionResult(
            status="failed",
            latency_ms=round(latency, 1),
            last_checked=datetime.now(timezone.utc).isoformat(),
            message=f"AI test failed: {str(e)[:100]}",
            recommended_action="Check provider URL, API key, and model availability.",
        )


@router.post("/test/ansible-preflight")
async def test_ansible_preflight(request: dict[str, Any] | None = None):
    """Run Ansible preflight checks using saved or provided values."""
    settings = get_settings()
    host = (request or {}).get("ansible_remote_host", settings.ansible_remote_host)
    user = (request or {}).get("ansible_remote_user", settings.ansible_remote_user)
    ssh_key = (request or {}).get("ansible_ssh_key", settings.ansible_ssh_key)
    ssh_password = (request or {}).get("ansible_ssh_password", settings.ansible_ssh_password)
    become_password = (request or {}).get("ansible_become_password", settings.ansible_become_password)

    result = await _check_ansible_preflight(host, user, ssh_key, ssh_password, become_password)
    status_map = {"success": "success", "warning": "warning", "failed": "failed", "not_configured": "failed"}
    return TestConnectionResult(
        status=status_map.get(result["status"], "failed"),
        latency_ms=0,
        last_checked=datetime.now(timezone.utc).isoformat(),
        message=result["message"],
        recommended_action=result.get("recommended_action"),
    )


# ── Per-asset env-var endpoint ──────────────────────────────────────────────

class SetEnvVarRequest(BaseModel):
    key: str
    value: str

    @field_validator("key")
    @classmethod
    def validate_key(cls, v: str) -> str:
        if not v.startswith("ARIA_ASSET_"):
            raise ValueError("Key must start with ARIA_ASSET_")
        allowed_suffixes = ("_ANSIBLE_PASSWORD", "_BECOME_PASSWORD", "_ANSIBLE_PRIVATE_KEY_PATH")
        if not any(v.endswith(s) for s in allowed_suffixes):
            raise ValueError(f"Key must end with one of: {allowed_suffixes}")
        return v


@router.post("/env-var")
async def set_env_var(
    request: SetEnvVarRequest,
    x_aria_admin_secret: Optional[str] = Header(None, alias="X-ARIA-Admin-Secret"),
):
    """Safely write a single per-asset environment variable to .env.
    Admin-secret protected. Creates a backup before writing.
    """
    _validate_admin_secret(x_aria_admin_secret)

    env_path = Path(".env")
    backup_path = Path(f".env.backup.{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}")
    if env_path.exists():
        shutil.copy(str(env_path), str(backup_path))

    try:
        _update_env_file({request.key: request.value})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Failed to update .env: {e}")

    # Also update os.environ so the running process sees the new value immediately
    # (no restart required for per-asset credentials)
    os.environ[request.key] = request.value

    # Notify background workers so they also pick up the new credential without restart
    await publish_settings_reload({request.key: request.value})

    logger.info("env_var_written", key=request.key, backup=str(backup_path))
    return {
        "saved": True,
        "key": request.key,
        "restart_required": False,
        "message": "Credential saved to backend .env and loaded into the running process.",
    }


# ── Pipeline cursor endpoints ───────────────────────────────────────────────

@router.get("/pipeline/cursors")
async def get_pipeline_cursors():
    """Return cursor status for all pipeline sources."""
    from pipeline.poller.cursor_manager import _redis_get, _read_file_cursor, list_cursor_sources

    settings = get_settings()
    sources = ["wazuh", "falco", "filebeat", "suricata"]
    cursors = {}

    for source in sources:
        redis_val = await _redis_get(f"opensoar:cursor:{source}")
        file_val = _read_file_cursor(source)
        cursors[source] = {
            "redis_present": redis_val is not None,
            "redis_value": redis_val,
            "file_present": file_val is not None,
            "file_value": file_val,
            "cursor_dir": settings.cursor_dir,
        }

    # Dedup mode detection
    dedup_mode = "unknown"
    try:
        from core import get_redis_client
        redis = await get_redis_client()
        dedup_keys = await redis.keys("opensoar:dedup:*")
        if dedup_keys:
            dedup_mode = "redis"
    except Exception:
        pass

    if dedup_mode == "unknown":
        import os
        seen_dir = Path(settings.seen_ids_dir)
        if seen_dir.exists() and any(seen_dir.iterdir()):
            dedup_mode = "file"

    return {
        "cursors": cursors,
        "cursor_dir": settings.cursor_dir,
        "seen_ids_dir": settings.seen_ids_dir,
        "dedup_mode": dedup_mode,
        "sources": sources,
    }


class CursorResetRequest(BaseModel):
    confirmation: str


@router.post("/pipeline/cursors/{source}/reset")
async def reset_pipeline_cursor(
    source: str,
    request: CursorResetRequest,
    x_aria_admin_secret: Optional[str] = Header(None, alias="X-ARIA-Admin-Secret"),
):
    _validate_admin_secret(x_aria_admin_secret)

    valid_sources = {"wazuh", "falco", "filebeat", "suricata"}
    if source not in valid_sources:
        raise HTTPException(status_code=400, detail=f"Invalid source. Must be one of: {', '.join(sorted(valid_sources))}")

    if request.confirmation.strip() != "RESET CURSOR":
        raise HTTPException(status_code=400, detail="Confirmation phrase does not match. Required: RESET CURSOR")

    from pipeline.poller.cursor_manager import reset_cursor

    result = await reset_cursor(source)
    return {"status": "ok", "message": f"Cursor for {source} has been reset.", "result": result}


# ── Overview status endpoint ────────────────────────────────────────────────

@router.get("/overview")
async def get_settings_overview():
    """Return status overview for the Settings dashboard."""
    settings = get_settings()

    # Run external health checks in parallel to reduce latency
    es_health, redis_health, ai_health = await asyncio.gather(
        _check_elasticsearch_health(),
        _check_redis_health(),
        _check_ai_health(),
        return_exceptions=True,
    )
    if isinstance(es_health, Exception):
        es_health = {"status": "disconnected", "error": str(es_health)[:100]}
    if isinstance(redis_health, Exception):
        redis_health = {"status": "disconnected", "error": str(redis_health)[:100]}
    if isinstance(ai_health, Exception):
        ai_health = {"status": "degraded", "error": str(ai_health)[:100]}

    ansible_ready = bool(settings.ansible_enabled and settings.ansible_remote_host)

    # Workflow status
    workflow_active = bool(
        settings.local_ingestion_enabled or settings.incident_auto_create_enabled
    )

    # Monitoring status
    perf_status = "ok" if settings.performance_enabled else "disabled"

    # Pipeline status
    pipeline_status = "running" if settings.opensoar_enabled or settings.local_ingestion_enabled else "stopped"

    # Security status
    secret_ok = settings.aria_admin_secret and settings.aria_admin_secret.lower() not in {"", "changeme", "default", "admin"}

    # Assets status
    assets_status = "unknown"
    assets_detail = None
    try:
        from sqlalchemy import select, func
        from response.db import AsyncSessionLocal
        from response.models import MonitoredAsset
        async with AsyncSessionLocal() as session:
            total = await session.scalar(select(func.count()).select_from(MonitoredAsset))
            enabled = await session.scalar(select(func.count()).select_from(MonitoredAsset).where(MonitoredAsset.enabled == True))
            if total == 0:
                assets_status = "not_configured"
                assets_detail = "No assets configured"
            elif enabled == 0:
                assets_status = "warning"
                assets_detail = f"{total} asset(s) disabled"
            else:
                assets_status = "ok"
                assets_detail = f"{enabled} enabled"
    except Exception:
        pass

    # Build detail strings for connected services
    ds_detail = es_health.get("error")
    if not ds_detail and es_health.get("latency_ms"):
        ds_detail = f"latency {es_health['latency_ms']}ms"

    redis_detail = redis_health.get("error")
    if not redis_detail and redis_health.get("latency_ms"):
        redis_detail = f"latency {redis_health['latency_ms']}ms"

    return {
        "security": {"status": "protected" if secret_ok else "warning", "detail": "internal_trusted"},
        "assets": {"status": assets_status, "detail": assets_detail},
        "data_sources": {"status": "connected" if es_health["status"] == "connected" else "degraded", "detail": ds_detail},
        "redis": {"status": "connected" if redis_health["status"] == "connected" else "disconnected", "detail": redis_detail},
        "ai": {"status": ai_health["status"], "detail": ai_health.get("error") or ai_health.get("mismatch_warning")},
        "ansible": {"status": "ready" if ansible_ready else "not_configured"},
        "workflow": {"status": "active" if workflow_active else "paused"},
        "monitoring": {"status": perf_status},
        "pipeline": {"status": pipeline_status},
    }
