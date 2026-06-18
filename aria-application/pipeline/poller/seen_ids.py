import json
from pathlib import Path
from typing import Set

import structlog
from config import get_settings

logger = structlog.get_logger()
SEEN_IDS_DIR = Path(get_settings().seen_ids_dir)
_SEEN_IDS_CACHE: dict[str, Set[str]] = {}
MAX_SEEN_IDS_PER_SOURCE = 50000


def _load_seen_ids(source: str) -> Set[str]:
    """Load seen ES document IDs from disk cache."""
    if source in _SEEN_IDS_CACHE:
        return _SEEN_IDS_CACHE[source]
    path = SEEN_IDS_DIR / f"{source}.json"
    try:
        if path.exists():
            data = json.loads(path.read_text())
            _SEEN_IDS_CACHE[source] = set(data)
            return _SEEN_IDS_CACHE[source]
    except Exception:
        pass
    _SEEN_IDS_CACHE[source] = set()
    return _SEEN_IDS_CACHE[source]


def _save_seen_ids(source: str) -> None:
    """Persist seen IDs to disk."""
    try:
        SEEN_IDS_DIR.mkdir(parents=True, exist_ok=True)
        seen = _SEEN_IDS_CACHE.get(source, set())
        if len(seen) > MAX_SEEN_IDS_PER_SOURCE:
            trimmed = list(seen)[-MAX_SEEN_IDS_PER_SOURCE:]
            _SEEN_IDS_CACHE[source] = set(trimmed)
            seen = _SEEN_IDS_CACHE[source]
        (SEEN_IDS_DIR / f"{source}.json").write_text(json.dumps(list(seen)))
    except Exception:
        pass


def _is_ever_seen(source: str, es_id: str) -> bool:
    """Check if we've ever forwarded this ES document ID."""
    seen = _load_seen_ids(source)
    if es_id in seen:
        return True
    seen.add(es_id)
    return False
