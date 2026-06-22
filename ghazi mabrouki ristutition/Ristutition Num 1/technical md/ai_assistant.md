# AI Assistant — Technical Documentation

## 1. Feature name
Contextual AI Assistant

## 2. Purpose
Provide a conversational interface for operators to query SOC data, receive contextual answers with cited sources, and execute approved actions (approve/decline/execute/archive investigations, trigger watcher).

## 3. Input
- Natural language question.
- Optional `conversation_id` for threaded history.
- Optional `focus_entity` (investigation/incident/alert ID).

## 4. Processing steps
1. **Keyword extraction** — Parse question for entity IDs, IP addresses, hostnames, severity keywords.
2. **Deep entity fetch** — Query SQLite + Redis + ES for investigations, incidents, alerts, archives, performance metrics, IPS events, pipeline status.
3. **Prioritize** — Rank records by relevance (exact ID match > IP match > time proximity).
4. **Build prompt** — System config + fetched context + conversation history + user question.
5. **LLM or fallback** — Call multi-provider LLM (`llm_clients.py`) or `_generate_fallback_answer()` (rule-based markdown).
6. **Action suggestions** — `answer_question()` returns `actions` array (e.g. `approve_investigation`).
7. **Persist** — Store user message + assistant response in `AssistantConversation` / `AssistantMessage`.

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
| `response/assistant.py` | Core logic: `answer_question()`, `execute_action()` |
| `api/routes/assistant.py` | REST API: query, actions, context, sources |
| `response/models.py` | `AssistantConversation`, `AssistantMessage` |

## 7. API endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/assistant/query` | Q&A + conversation creation |
| POST | `/assistant/actions` | Execute suggested action |
| GET | `/assistant/context` | Available data sources + supported actions |
| GET | `/assistant/sources` | Data-source statistics |

## 8. Database tables
- `AssistantConversation` — `title`, `created_at`, `updated_at`
- `AssistantMessage` — `conversation_id`, `role` (user/assistant/action), `content`, `actions_json`, `sources_json`

## 9. Background jobs
None dedicated; operates on-demand via API.

## 10. Frontend page
- **Route**: `/assistant`
- **File**: `frontend/app/(dashboard)/assistant/page.tsx` *(not returned in source exploration)*
- **Status**: Verify existence in repository. No `frontend/components/assistant/` directory.

## 11. Example
Operator asks *"Why is web-01 CPU high?"* → assistant fetches performance metrics for `web-01`, finds critical CPU alert + running investigation → answers with summary and sources → suggests action `[{type: "execute_investigation", label: "Run Playbook Now", params: {investigation_id: "inv-123"}}]`.

## 12. Known limitations
- Frontend page source not delivered; verify existence in repo.
- No concrete DB examples for `actions_json` / `sources_json` serialization.
- Action execution bypasses the normal approval UI; intended for low-risk or pre-approved actions only.
