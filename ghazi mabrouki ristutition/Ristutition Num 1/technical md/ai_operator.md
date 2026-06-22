# AI Operator — Technical Documentation

## 1. Feature name
AI Operator (NL-to-Ansible)

## 2. Purpose
Translate natural language operational requests into Ansible playbooks, execute them against target hosts with human approval, and return structured analysis.

## 3. Input
- Natural language prompt (e.g. *"check disk usage on web-01"*).
- `target_hosts` list.
- Session + conversation history for follow-ups.

## 4. Processing steps
1. **Reason** — `_reason_about_request()` extracts intent, confidence, and required tools.
2. **Match template** — Intent-matched pre-built templates (`ram_usage`, `disk_usage`, `cpu_processes`, `open_ports`, `ssh_failures`, `service_status`, `firewall_rules`, `docker_containers`, `file_read`, `package_check`).
3. **Generate** — If no template matches, call LLM to generate YAML playbook + execution summary.
4. **Persist pending** — Store `OperatorRun` + `OperatorMessage` with `playbook_yaml`, `status="pending"`.
5. **Auto-execute low-risk** — Read-only commands (facts, checks) may auto-run if confidence is high.
6. **Approval gate** — Mutating commands require human approval via `POST /runs/{run_id}/approve`.
7. **Execute** — `_execute_and_analyze()`: SSH pre-check (`sshpass` or key) → `ansible-playbook` subprocess → structured output parsing → LLM analysis or `_build_simple_analysis()`.
8. **Follow-up** — Conversation history allows file-reference regex extraction for multi-turn tasks.

## 5. Output
- `OperatorRun` record with `status`, `result_json`, `execution_summary`.
- Human-readable markdown analysis.

## 6. Main files
| File | Role |
|------|------|
| `api/routes/operator.py` | Full API (~2,374 lines): sessions, messages, approval, status |
| `response/ansible_exec.py` | Shared Ansible execution engine |
| `response/models.py` | `OperatorRun`, `OperatorSession`, `OperatorMessage` |
| `config/ansible_inventory` | Target host inventory |

## 7. API endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/operator/sessions` | Create session |
| POST | `/operator/sessions/{session_id}/message` | Send NL request |
| GET | `/operator/sessions/{session_id}` | Get session + history |
| POST | `/operator/runs/{run_id}/approve` | Approve pending run |
| GET | `/operator/runs/{run_id}/status` | Poll run status |
| GET | `/operator/runs/{run_id}` | Full run details |

## 8. Database tables
- `OperatorSession` — `title`, `created_at`, `updated_at`
- `OperatorRun` — `session_id`, `status` (pending/running/completed/failed), `playbook_yaml`, `execution_summary`, `result_json`
- `OperatorMessage` — `session_id`, `role` (user/assistant), `content`, `run_id`

## 9. Background jobs
None dedicated; execution is API-triggered.

## 10. Frontend page
- **Route**: `/operator`
- **File**: `frontend/app/(dashboard)/operator/page.tsx` *(not returned in source exploration)*
- **Status**: Verify existence in repository.

## 11. Example
Operator sends *"show me disk usage on db-01"* → intent=`disk_usage` → template matched → playbook YAML generated (`ansible.builtin.command: df -h`) → low-risk → auto-executed → SSH OK → Ansible runs → output parsed → LLM analysis: *"/ is 82% full, /var/log is 45% full"* → stored in `OperatorMessage`.

## 12. Known limitations
- Frontend page source not delivered.
- No concrete DB examples for `result_json` or `playbook_yaml` content.
- `api/routes/monitoring.py` was scoped under Operator/Performance but not delivered.
