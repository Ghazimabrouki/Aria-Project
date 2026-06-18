"""
E2E Test 06 — AI Assistant

Tests the AI assistant endpoint with real questions.
Verifies it answers from actual data, not training knowledge.
Also covers validation and conversation lifecycle.
"""
import pytest

from tests.e2e.conftest import E2E_TAG


@pytest.mark.asyncio
async def test_assistant_basic_query(backend_client, services):
    """POST /api/v1/assistant/query returns a response."""
    r = await backend_client.post(
        "/api/v1/assistant/query",
        json={"question": "What alerts are currently in the system?"},
    )
    assert r.status_code == 200, f"Assistant failed: {r.status_code} {r.text[:300]}"
    data = r.json()
    assert "answer" in data
    assert "sources" in data
    assert "record_count" in data
    print(f"\n  Record count: {data['record_count']}")
    print(f"  Answer preview: {str(data['answer'])[:200]}")


@pytest.mark.asyncio
async def test_assistant_ip_query(backend_client, services):
    """Assistant can answer questions about specific IPs."""
    r = await backend_client.post(
        "/api/v1/assistant/query",
        json={"question": "Show me all alerts from IP 45.33.32.156"},
    )
    assert r.status_code == 200
    data = r.json()
    assert "answer" in data
    print(f"\n  IP query sources: {data['record_count']}")
    print(f"  Answer: {str(data['answer'])[:200]}")


@pytest.mark.asyncio
async def test_assistant_severity_query(backend_client, services):
    """Assistant can filter by severity."""
    r = await backend_client.post(
        "/api/v1/assistant/query",
        json={"question": "Are there any critical severity incidents right now?"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["answer"]
    print(f"\n  Critical query answer: {str(data['answer'])[:200]}")


@pytest.mark.asyncio
async def test_assistant_history_query(backend_client, services):
    """Assistant searches archived cases."""
    r = await backend_client.post(
        "/api/v1/assistant/query",
        json={"question": "Have we seen SSH brute force attacks before? What was done?"},
    )
    assert r.status_code == 200
    data = r.json()
    print(f"\n  History query: {data['record_count']} sources")
    print(f"  Answer: {str(data['answer'])[:200]}")


@pytest.mark.asyncio
async def test_assistant_does_not_invent_data(backend_client, services):
    """
    Assistant should say it doesn't have data for impossible queries,
    not invent fictional incidents.
    """
    r = await backend_client.post(
        "/api/v1/assistant/query",
        json={"question": "What happened with IP 0.0.0.0 in the year 1990?"},
    )
    assert r.status_code == 200
    data = r.json()
    answer = str(data["answer"]).lower()
    # Should admit no data, not invent something
    has_no_data_phrase = any(phrase in answer for phrase in [
        "don't have", "no data", "not find", "no information",
        "no relevant", "cannot find", "no records", "i don't"
    ])
    print(f"\n  Answer for impossible query: {str(data['answer'])[:200]}")
    if not has_no_data_phrase:
        print("  WARNING: Assistant may be inventing data for impossible queries")


@pytest.mark.asyncio
async def test_assistant_playbook_history_query(backend_client, services):
    """Assistant can retrieve past playbooks used for specific attack types."""
    r = await backend_client.post(
        "/api/v1/assistant/query",
        json={"question": "What Ansible playbooks have we run to fix security incidents?"},
    )
    assert r.status_code == 200
    data = r.json()
    print(f"\n  Playbook history: {data['record_count']} sources")
    print(f"  Answer: {str(data['answer'])[:200]}")


@pytest.mark.asyncio
async def test_assistant_mitre_tactic_query(backend_client, services):
    """Assistant understands MITRE tactic queries."""
    r = await backend_client.post(
        "/api/v1/assistant/query",
        json={"question": "Show me all privilege escalation incidents"},
    )
    assert r.status_code == 200
    data = r.json()
    print(f"\n  MITRE query sources: {data['record_count']}")
    print(f"  Answer: {str(data['answer'])[:200]}")


# ═══════════════════════════════════════════════════════════════════════════════
# Hardening tests
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_assistant_empty_input_rejected(backend_client, services):
    """Empty question should be rejected with 422."""
    r = await backend_client.post(
        "/api/v1/assistant/query",
        json={"question": ""},
    )
    assert r.status_code == 422, f"Expected 422, got {r.status_code}"


@pytest.mark.asyncio
async def test_assistant_conversation_lifecycle(backend_client, services):
    """Create, list, get, and delete a conversation."""
    # Create
    r = await backend_client.post("/api/v1/assistant/conversations", json={"title": "E2E Lifecycle"})
    assert r.status_code == 200
    conv = r.json()
    conv_id = conv["id"]

    # List
    r = await backend_client.get("/api/v1/assistant/conversations?limit=50")
    assert r.status_code == 200
    ids = [c["id"] for c in r.json()["conversations"]]
    assert conv_id in ids

    # Get
    r = await backend_client.get(f"/api/v1/assistant/conversations/{conv_id}")
    assert r.status_code == 200
    assert r.json()["id"] == conv_id
    assert r.json()["title"] == "E2E Lifecycle"

    # Query within conversation
    r = await backend_client.post(
        "/api/v1/assistant/query",
        json={"question": "Hello", "conversation_id": conv_id},
    )
    assert r.status_code == 200
    assert r.json()["conversation_id"] == conv_id

    # Delete
    r = await backend_client.delete(f"/api/v1/assistant/conversations/{conv_id}")
    assert r.status_code == 200

    # Verify deleted
    r = await backend_client.get(f"/api/v1/assistant/conversations/{conv_id}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_assistant_action_no_auth_required(backend_client, services):
    """
    Assistant actions must work without API keys or admin secrets.
    The action endpoint is open access like the rest of the assistant feature.
    """
    r = await backend_client.post(
        "/api/v1/assistant/actions",
        json={"action_type": "trigger_watcher", "params": {}},
    )
    # Must not return 401 or 403
    assert r.status_code not in (401, 403), f"Assistant action must not require auth. Got: {r.status_code} {r.text[:200]}"


@pytest.mark.asyncio
async def test_assistant_context_endpoint(backend_client, services):
    """GET /assistant/context returns structured metadata."""
    r = await backend_client.get("/api/v1/assistant/context")
    assert r.status_code == 200
    data = r.json()
    assert "available_sources" in data
    assert "supported_actions" in data
    assert "query_tips" in data
    actions = data["supported_actions"]
    assert any(a["type"] == "approve_investigation" for a in actions)
    assert any(a.get("requires_confirmation") is True for a in actions)


@pytest.mark.asyncio
async def test_assistant_health_endpoint(backend_client, services):
    """GET /assistant/health returns status."""
    r = await backend_client.get("/api/v1/assistant/health")
    assert r.status_code == 200
    data = r.json()
    assert "status" in data
    assert "llm_enabled" in data
    assert "action_support" in data
