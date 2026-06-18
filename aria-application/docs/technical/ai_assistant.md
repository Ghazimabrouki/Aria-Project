# AI Assistant — Technical Documentation

## 1. Feature name
Contextual AI Assistant

## 2. Purpose
Provide a conversational interface for operators to query SOC data, receive contextual answers with cited sources, and execute approved actions (approve/decline/execute/archive investigations, trigger watcher).

## 3. Input
- Natural language question (1–2000 characters).
- Optional `conversation_id` for threaded history.
- Optional `focus_entity` (investigation/incident/alert ID).
- Optional `sources` filter (alerts, incidents, investigations, archives, performance, pipeline, ips).

## 4. Processing steps
1. **Input validation** — Pydantic validates length, strips whitespace, rejects empty input.
2. **Sanitization** — Normalizes newlines, truncates to 2000 chars.
3. **Prompt-injection detection** — Scans for known injection patterns; adds a security warning to the LLM prompt if detected.
4. **Keyword extraction** — Parse question for entity IDs, IP addresses, hostnames, severity keywords.
5. **Deep entity fetch** — Query SQLite + Redis + ES for investigations, incidents, alerts, archives, performance metrics, IPS events, pipeline status.
6. **Prioritize** — Rank records by relevance (exact ID match > IP match > time proximity).
7. **Build prompt** — Safe system config (no URLs/ports/credentials) + fetched context + conversation history + user question.
8. **LLM or fallback** — Call multi-provider LLM (`llm_clients.py`) or `_generate_fallback_answer()` (rule-based markdown). Protected by a 120-second route timeout.
9. **Action suggestions** — `answer_question()` returns `actions` array (e.g. `approve_investigation`).
10. **Persist** — Store user message + assistant response in `AssistantConversation` / `AssistantMessage`.

## 5. Output
```json
{
  "answer": "...",
  "sources": [...],
  "record_count": 12,
  "statistics": {...},
  "actions": [...]
}
```

## 6. Main files
| File | Role |
|------|------|
| `response/assistant.py` | Core logic: `answer_question()`, `execute_action()`, input sanitization, prompt injection guardrails |
| `api/routes/assistant.py` | REST API: query, actions, context, sources, conversations. Open access — no API keys or admin secrets required. |
| `response/models.py` | `AssistantConversation`, `AssistantMessage` |
| `frontend/app/(dashboard)/assistant/page.tsx` | Next.js chat UI with abort, retry, confirmation modal, source citations |
| `frontend/lib/api.ts` | Typed API client with abort signal support |
| `tests/test_assistant.py` | Unit tests for sanitization, CRUD, actions, prompt safety |
| `tests/e2e/test_06_ai_assistant.py` | E2E tests for live backend |

## 7. API endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/assistant/query` | Q&A + conversation creation |
| POST | `/assistant/actions` | Execute suggested action |
| GET | `/assistant/conversations` | List conversations |
| POST | `/assistant/conversations` | Create conversation |
| GET | `/assistant/conversations/{id}` | Get conversation + messages |
| DELETE | `/assistant/conversations/{id}` | Delete conversation |
| GET | `/assistant/context` | Available data sources + supported actions |
| GET | `/assistant/sources` | Data-source statistics |
| GET | `/assistant/health` | Assistant health check |

## 8. Database tables
- `AssistantConversation` — `title`, `focus_entity_type`, `focus_entity_id`, `created_at`, `updated_at`
- `AssistantMessage` — `conversation_id`, `role` (user/assistant/action), `content`, `actions_json`, `sources_json`

## 9. Security features
- **Input validation**: Pydantic models enforce max lengths and source allowlists.
- **Prompt injection guardrails**: Regex-based detection adds a security warning to the LLM prompt.
- **Config redaction**: URLs, ports, and credentials are never injected into the LLM prompt.
- **Rate limiting**: `/assistant/actions` is included in the sensitive-path rate limiter.
- **Audit logging**: Destructive actions (approve/decline/execute/archive) write to `investigation_audit_events`.
- **Action whitelist**: Only `approve_investigation`, `decline_investigation`, `execute_investigation`, `archive_investigation`, `trigger_watcher` are allowed.
- **Timeout**: The query route has a 120-second hard timeout to prevent hanging requests.
- **No auth barriers**: The `/assistant` feature does **not** require API keys or admin secrets. Endpoints are open access so the frontend chat works without additional credentials.

## 10. Frontend features
- **Confirmation modal**: Destructive actions (approve, decline, execute, archive) show a professional AlertDialog with action name, target ID, and risk warning before execution.
- **Abort in-flight queries** with a **Stop** button.
- **Retry** failed messages.
- **Source citation** count displayed under assistant answers.
- **Input character counter** (max 2000).
- **Request deduplication** (prevents double-submit).
- **Proper error states**:
  - 401 → "You must be signed in."
  - 403 → "You do not have permission to perform this action."
  - Other → "Action failed. Please retry."
- **Distinct error styling** — error messages get `bg-destructive/10` border.

## 11. Known limitations
- No streaming (SSE/WebSocket) — responses are returned as complete JSON.
- No dedicated feedback/thumbs-up table for assistant answers.
- Action execution is open access. A real authentication/authorization layer should be added before exposing assistant actions in untrusted networks.
