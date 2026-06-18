"""AI Assistant API route - Contextual, state-aware, and action-capable."""

import asyncio
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

router = APIRouter(prefix="/api/v1/assistant", tags=["assistant"])

_MAX_QUESTION_LENGTH = 2000
_ALLOWED_SOURCES = {
    "alerts",
    "incidents",
    "investigations",
    "archives",
    "performance",
    "pipeline",
    "ips",
}


class QueryRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=_MAX_QUESTION_LENGTH)
    conversation_id: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    sources: Optional[List[str]] = None
    asset_id: Optional[str] = None  # Selected monitored server for scoping context

    @field_validator("question")
    @classmethod
    def _strip_question(cls, v: str) -> str:
        return v.strip()

    @field_validator("sources")
    @classmethod
    def _validate_sources(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if not v:
            return v
        filtered = [s.lower().strip() for s in v if s]
        invalid = [s for s in filtered if s not in _ALLOWED_SOURCES]
        if invalid:
            raise ValueError(f"Invalid sources: {invalid}. Allowed: {_ALLOWED_SOURCES}")
        return filtered


class ActionRequest(BaseModel):
    action_type: str = Field(..., min_length=1)
    params: Dict[str, Any] = Field(default_factory=dict)
    decided_by: str = Field(default="assistant_user", min_length=1, max_length=100)


class CreateConversationRequest(BaseModel):
    title: Optional[str] = Field(default=None, max_length=200)
    focus_entity_type: Optional[str] = Field(default=None, max_length=50)
    focus_entity_id: Optional[str] = Field(default=None, max_length=36)


@router.post("/query")
async def query_assistant(
    body: QueryRequest,
    request: Request,
) -> Dict[str, Any]:
    """
    Ask the AI assistant a question within an optional conversation thread.
    The assistant retains context, fetches deep entity data, and suggests actions.
    """
    from response.assistant import answer_question, add_message, create_conversation

    conversation_id = body.conversation_id
    focus_entity = None

    # Ensure conversation exists if provided; otherwise create one on first message
    if conversation_id:
        from response.assistant import get_conversation
        conv = await get_conversation(conversation_id)
        if conv and conv.focus_entity_type and conv.focus_entity_id:
            focus_entity = {"type": conv.focus_entity_type, "id": conv.focus_entity_id}
    else:
        conv = await create_conversation(title=body.question[:60])
        conversation_id = conv.id

    # Store user message
    await add_message(conversation_id, "user", body.question)

    # Validate and inject asset_id into context if provided
    context = body.context or {}
    if body.asset_id:
        from api.routes._shared import validate_asset_id
        validated = await validate_asset_id(body.asset_id)
        if validated:
            context["asset_id"] = validated

    # Generate answer with a hard timeout to prevent hanging
    try:
        result = await asyncio.wait_for(
            answer_question(
                body.question,
                conversation_id=conversation_id,
                focus_entity=focus_entity,
                client_ip=request.client.host if request.client else None,
                context=context,
            ),
            timeout=120.0,
        )
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Assistant timed out while generating an answer.")

    # Store assistant message
    await add_message(
        conversation_id,
        "assistant",
        result["answer"],
        actions=result.get("actions"),
        sources=result.get("sources"),
    )

    return {
        "answer": result["answer"],
        "conversation_id": conversation_id,
        "sources": result.get("sources", []),
        "record_count": result.get("record_count", 0),
        "statistics": result.get("statistics", {}),
        "actions": result.get("actions", []),
    }


@router.post("/actions")
async def execute_assistant_action(
    body: ActionRequest,
    request: Request,
) -> Dict[str, Any]:
    """
    Execute an action suggested by the assistant.
    Supported actions: approve_investigation, decline_investigation, execute_investigation, archive_investigation, trigger_watcher.
    """
    from response.assistant import execute_action

    result = await execute_action(
        body.action_type,
        body.params,
        client_ip=request.client.host if request.client else None,
    )
    return result


@router.get("/conversations")
async def list_conversations(limit: int = 50) -> Dict[str, Any]:
    """List recent assistant conversations."""
    from response.assistant import list_conversations as _list

    convs = await _list(limit=limit)
    return {
        "conversations": [
            {
                "id": c.id,
                "title": c.title,
                "focus_entity_type": c.focus_entity_type,
                "focus_entity_id": c.focus_entity_id,
                "created_at": c.created_at.isoformat() if c.created_at else "",
                "updated_at": c.updated_at.isoformat() if c.updated_at else "",
                "message_count": len(c.messages) if hasattr(c, "messages") else 0,
            }
            for c in convs
        ]
    }


@router.post("/conversations")
async def create_conversation(body: CreateConversationRequest) -> Dict[str, Any]:
    """Create a new assistant conversation."""
    from response.assistant import create_conversation as _create

    conv = await _create(title=body.title or "New Conversation")
    if body.focus_entity_type:
        conv.focus_entity_type = body.focus_entity_type
    if body.focus_entity_id:
        conv.focus_entity_id = body.focus_entity_id
    # Update focus fields
    if body.focus_entity_type or body.focus_entity_id:
        from response.db import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            await session.merge(conv)
            await session.commit()

    return {
        "id": conv.id,
        "title": conv.title,
        "focus_entity_type": conv.focus_entity_type,
        "focus_entity_id": conv.focus_entity_id,
        "created_at": conv.created_at.isoformat() if conv.created_at else "",
    }


@router.get("/conversations/{conversation_id}")
async def get_conversation(conversation_id: str) -> Dict[str, Any]:
    """Get a conversation with all messages."""
    from response.assistant import get_conversation as _get

    conv = await _get(conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    return {
        "id": conv.id,
        "title": conv.title,
        "focus_entity_type": conv.focus_entity_type,
        "focus_entity_id": conv.focus_entity_id,
        "created_at": conv.created_at.isoformat() if conv.created_at else "",
        "updated_at": conv.updated_at.isoformat() if conv.updated_at else "",
        "messages": [
            {
                "id": m.id,
                "role": m.role,
                "content": m.content,
                "actions": m.actions_json and __import__("json").loads(m.actions_json),
                "sources": m.sources_json and __import__("json").loads(m.sources_json),
                "created_at": m.created_at.isoformat() if m.created_at else "",
            }
            for m in conv.messages
        ],
    }


@router.delete("/conversations/{conversation_id}")
async def delete_conversation(conversation_id: str) -> Dict[str, Any]:
    """Delete a conversation."""
    from response.assistant import delete_conversation as _delete

    ok = await _delete(conversation_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {"status": "deleted", "conversation_id": conversation_id}


@router.get("/context")
async def get_assistant_context() -> Dict[str, Any]:
    """Get information about what data the AI can access and what actions it can perform."""
    return {
        "available_sources": [
            {
                "name": "OpenSOAR Alerts",
                "description": "Live security alerts from Wazuh, Suricata, Falco",
                "endpoint": "/api/v1/alerts",
            },
            {
                "name": "OpenSOAR Incidents",
                "description": "Active incidents from OpenSOAR",
                "endpoint": "/api/v1/incidents",
            },
            {
                "name": "Local Investigations",
                "description": "AI investigations in progress with full timeline, playbook, and outcomes",
                "endpoint": "/api/v1/investigations",
            },
            {
                "name": "Archives",
                "description": "Completed and archived investigations",
                "endpoint": "/api/v1/archives",
            },
            {
                "name": "Performance Metrics",
                "description": "CPU, memory, disk from monitored hosts",
                "endpoint": "/api/v1/metrics",
            },
            {
                "name": "Pipeline Status",
                "description": "Alert forwarding status",
                "endpoint": "/api/v1/pipeline/status",
            },
            {
                "name": "IPS Events",
                "description": "Network attack events",
                "endpoint": "/api/v1/ips",
            },
        ],
        "supported_actions": [
            {
                "type": "approve_investigation",
                "label": "Approve Playbook",
                "description": "Approve an AI-generated playbook and trigger Ansible execution",
                "requires_confirmation": True,
            },
            {
                "type": "decline_investigation",
                "label": "Decline Playbook",
                "description": "Decline an AI-generated playbook and archive the investigation",
                "requires_confirmation": True,
            },
            {
                "type": "execute_investigation",
                "label": "Execute Playbook",
                "description": "Execute a playbook directly (bypass approval)",
                "requires_confirmation": True,
            },
            {
                "type": "archive_investigation",
                "label": "Archive Investigation",
                "description": "Manually archive an investigation",
                "requires_confirmation": True,
            },
            {
                "type": "trigger_watcher",
                "label": "Trigger Watcher",
                "description": "Manually trigger the incident watcher to poll for new incidents",
                "requires_confirmation": False,
            },
        ],
        "query_tips": [
            "Ask about specific hosts: 'How is web-01 performing?'",
            "Ask about IPs: 'What alerts from 1.2.3.4'",
            "Ask about severity: 'Show critical alerts'",
            "Ask about status: 'How many investigations pending?'",
            "Follow-up contextually: 'Tell me more about that investigation'",
            "Ask for actions: 'Approve the playbook for investigation X'",
        ],
    }


@router.get("/sources")
async def get_source_statistics() -> Dict[str, Any]:
    """Get statistics about available data sources."""
    import structlog
    from response.db import AsyncSessionLocal
    from response.models import Investigation, Archive
    from sqlalchemy import select, func

    stats: Dict[str, Any] = {"sources": {}, "connection_status": {}}

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(func.count(Investigation.id)).where(Investigation.status != "archived")
            )
            stats["sources"]["active_investigations"] = result.scalar() or 0

            result = await session.execute(select(func.count(Archive.id)))
            stats["sources"]["archives"] = result.scalar() or 0
    except Exception as e:
        logger = structlog.get_logger()
        logger.error("assistant_source_stats_error", error=str(e))

    stats["connection_status"]["opensoar"] = "connect to check"
    stats["connection_status"]["performance"] = "connect to check"

    return stats


@router.get("/health")
async def assistant_health() -> Dict[str, Any]:
    """Health check for assistant."""
    from config import get_settings

    settings = get_settings()

    return {
        "status": "healthy" if settings.llm_enabled else "llm_disabled",
        "llm_enabled": settings.llm_enabled,
        "model": settings.llm_model if settings.llm_enabled else None,
        "sources": "all_configured",
        "contextual_memory": True,
        "action_support": True,
    }
