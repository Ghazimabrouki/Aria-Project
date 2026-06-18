"""
Whitelist API.
Manage IPs, subnets, and domains that should never be blocked.
"""

import asyncio
from fastapi import APIRouter, HTTPException, Query
from typing import Optional, List

from core.whitelist import (
    get_whitelist_entries,
    add_whitelist_entry,
    remove_whitelist_entry,
    is_whitelisted,
    _retroactively_mark_alerts,
)

router = APIRouter(prefix="/api/v1/whitelist", tags=["whitelist"])


@router.get("")
async def list_whitelist(
    type: Optional[str] = Query(None, description="Filter by type: ip | subnet | domain"),
    label: Optional[str] = Query(None, description="Filter by label: internal | trusted | admin"),
):
    """List all whitelist entries."""
    entries = await get_whitelist_entries(type_filter=type, label_filter=label)
    return {"entries": entries, "total": len(entries)}


@router.post("")
async def create_whitelist_entry(body: dict):
    """Add a new whitelist entry."""
    entry_type = body.get("type")
    value = body.get("value")
    label = body.get("label", "trusted")
    description = body.get("description")

    if not entry_type or not value:
        raise HTTPException(status_code=400, detail="type and value are required")
    if entry_type not in ("ip", "subnet", "domain"):
        raise HTTPException(status_code=400, detail="type must be ip, subnet, or domain")

    try:
        entry = await add_whitelist_entry(entry_type, value, label, description)
        # Retroactively mark matching alerts in the background
        if entry_type in ("ip", "subnet"):
            asyncio.create_task(_retroactively_mark_alerts(value))
        return {"success": True, "entry": entry}
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.delete("/{entry_id}")
async def delete_whitelist_entry(entry_id: str):
    """Remove a whitelist entry."""
    removed = await remove_whitelist_entry(entry_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Entry not found")
    return {"success": True, "id": entry_id}


@router.get("/check")
async def check_whitelist(value: str):
    """Check if a value is whitelisted."""
    result = await is_whitelisted(value)
    return {"value": value, "whitelisted": result}


@router.post("/check-batch")
async def check_whitelist_batch(body: dict):
    """Check multiple values at once."""
    values = body.get("values", [])
    if not isinstance(values, list):
        raise HTTPException(status_code=400, detail="values must be a list")
    results = {}
    for value in values:
        if isinstance(value, str):
            results[value] = await is_whitelisted(value)
    return {"results": results}
