import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Set

import structlog
from config import get_settings
from pipeline.sender import client

logger = structlog.get_logger()
PATTERN_TRACKING_FILE = Path(get_settings().pattern_tracking_file)
_PATTERN_TRACKING: dict[str, dict] = {}

# Track unique IPs per threat intel rule for context
_THREAT_INTEL_IPS: dict[str, Set[str]] = {}


def _load_pattern_tracking() -> dict:
    """Load pattern tracking from disk."""
    global _PATTERN_TRACKING
    if not _PATTERN_TRACKING and PATTERN_TRACKING_FILE.exists():
        try:
            _PATTERN_TRACKING = json.loads(PATTERN_TRACKING_FILE.read_text())
        except Exception:
            _PATTERN_TRACKING = {}
    return _PATTERN_TRACKING


def _cleanup_old_patterns(max_age_hours: int = 24) -> int:
    """Remove pattern entries older than max_age_hours to prevent indefinite growth."""
    global _PATTERN_TRACKING
    if not _PATTERN_TRACKING:
        return 0

    now = datetime.now(timezone.utc)
    cleaned_count = 0
    keys_to_remove = []

    for key, data in _PATTERN_TRACKING.items():
        last_seen = data.get("last_seen")
        if last_seen:
            try:
                last_seen_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                age_hours = (now - last_seen_dt).total_seconds() / 3600
                if age_hours > max_age_hours:
                    keys_to_remove.append(key)
            except Exception:
                pass

    for key in keys_to_remove:
        del _PATTERN_TRACKING[key]
        cleaned_count += 1

    if cleaned_count > 0:
        _save_pattern_tracking()
        logger.info("pattern_tracking_cleaned", count=cleaned_count, remaining=len(_PATTERN_TRACKING))

    return cleaned_count


def _save_pattern_tracking() -> None:
    """Persist pattern tracking to disk."""
    try:
        PATTERN_TRACKING_FILE.parent.mkdir(parents=True, exist_ok=True)
        PATTERN_TRACKING_FILE.write_text(json.dumps(_PATTERN_TRACKING))
    except Exception:
        pass


def _get_pattern_key(source: str, source_ip: str, rule_name: str) -> str:
    """Generate a pattern key for grouping repeated alerts."""
    return f"{source}|{source_ip or 'none'}|{rule_name}"


async def _handle_repeated_alert(alert_id: str, payload: dict, pattern_info: dict) -> None:
    """Update an existing alert with occurrence count instead of creating a new one."""
    try:
        settings = get_settings()
        occurrence_count = pattern_info.get("occurrence_count", 1) + 1
        first_seen = pattern_info.get("first_seen", datetime.now(timezone.utc).isoformat())

        current_tags = payload.get("tags", []) or []
        current_tags = [t for t in current_tags if not t.startswith("occurrences-")]
        current_tags.append(f"occurrences-{occurrence_count}")

        logger.debug(
            "updating_alert_with_occurrences",
            alert_id=alert_id,
            occurrence_count=occurrence_count,
            tags=current_tags,
        )

        if settings.upstream_enabled:
            result = await client.update_alert(alert_id, {
                "tags": current_tags,
            })
            logger.info(
                "alert_grouped_repeated_upstream",
                alert_id=alert_id,
                occurrence_count=occurrence_count,
                update_result=result.get("tags", []) if isinstance(result, dict) else "unknown",
            )
        else:
            # Update local alert metadata instead
            try:
                from response.db import AsyncSessionLocal
                from response.models import Alert
                from sqlalchemy import update
                async with AsyncSessionLocal() as session:
                    await session.execute(
                        update(Alert).where(Alert.id == alert_id).values(
                            tags=current_tags,
                            alert_metadata={
                                **(payload.get("metadata") or {}),
                                "occurrence_count": occurrence_count,
                                "first_seen": first_seen,
                                "last_seen": datetime.now(timezone.utc).isoformat(),
                            }
                        )
                    )
                    await session.commit()
            except Exception as local_err:
                logger.warning("local_occurrence_update_failed", alert_id=alert_id, error=str(local_err))

            logger.info(
                "alert_grouped_repeated_local",
                alert_id=alert_id,
                occurrence_count=occurrence_count,
            )
    except Exception as e:
        logger.warning("update_repeated_alert_failed", alert_id=alert_id, error=str(e))
