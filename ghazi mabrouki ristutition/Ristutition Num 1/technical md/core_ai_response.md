# Core SOC Workflow — AI Response

## 1. Feature name
AI Response Engine

## 2. Purpose
Generate investigation summaries, risk assessments, narrative explanations, and Ansible remediation playbooks using LLMs; handle multi-provider routing, circuit breaker, fallback generation, and structured response parsing.

## 3. Input
- Investigation context from `context_builder.py` (timeline, IOCs, MITRE, behavioral, risk score).
- LLM provider config (`LLM_PROVIDER`, `LLM_MODEL`, API keys).

## 4. Processing steps
1. **Circuit breaker** — Check if LLM service is healthy; skip if open.
2. **Build prompt** (`prompt_builder.py`) — Massive context-aware prompt with strict output format headers (`SUMMARY:`, `NARRATIVE:`, `RISK_ASSESSMENT:`, `PLAYBOOK:`).
3. **Call LLM** (`llm_clients.py`) — Route to Ollama (local retry), Google Gemini, OpenRouter, or NVIDIA NIM; adaptive timeout.
4. **Parse** (`main.py` `_parse_ai_response()`) — Regex section extraction + YAML fenced code block parsing.
5. **Store** — Write `summary`, `narrative`, `risk_assessment`, `playbook_yaml` to `Investigation`.
6. **Auto-approve check** — `should_auto_approve()` runs 4-layer evaluation.
7. **Approval notification** — WebSocket broadcast or Slack/SMTP if pending human decision.

## 5. Output
- `Investigation.playbook_yaml`, `summary`, `narrative`, `risk_score`.
- `PlaybookApproval` row (if auto-approve declines).
- WebSocket `investigations` broadcast.

## 6. Main files
| File | Role |
|------|------|
| `response/ai_engine/main.py` | Orchestration, parsing, storage |
| `response/ai_engine/prompt_builder.py` | Context → LLM prompt |
| `response/ai_engine/llm_clients.py` | Multi-provider clients |
| `response/auto_approve.py` | 4-layer approval |
| `response/confidence_tracker.py` | Adaptive threshold learning |
| `response/decision_logger.py` | Audit trail |

## 7. API endpoints
See Investigations API (`/investigations/*`).

## 8. Database tables
- `Investigation`
- `PlaybookApproval`
- `PlaybookRun`
- `FixVerification`

## 9. Background jobs
- **AI Engine Runner** — spawned per-investigation by Watcher
- **Auto-Approval Evaluator**
- **Daily confidence threshold recalculation** (implied by tracker)

## 10. Frontend page
- **Route**: `/investigations`
- **Features**: AI-generated summary, narrative, playbook YAML preview, risk badge.

## 11. Example
Context with risk 78 → prompt built → Gemini returns structured text → parsed into sections → playbook YAML extracted (restart service + block IP) → auto-approve guardrail blocks because risk > 70 → human approval required → operator clicks Approve → `PlaybookApproval` updated.

## 12. Known limitations
- LLM output parsing relies on regex; malformed responses fallback to rule-based generation.
- Ollama local timeouts can stall investigations; circuit breaker prevents cascade but adds latency.
- No concrete example of a fully parsed AI response exists in repository fixtures.
