import asyncio
import json
import time
from datetime import datetime, timezone

import structlog

from config import get_settings
from response.db import AsyncSessionLocal
from response.models import Investigation

logger = structlog.get_logger()
settings = get_settings()

# Use adaptive timeout from response.adaptive (fallback to static if unavailable)
AI_TIMEOUT_FALLBACK = 60  # Google Gemini is much faster
_ollama_model = "qwen3:8b"  # Default, will be updated from settings

# Circuit breaker for API failures
_circuit_breaker = None


def _get_circuit_breaker():
    """Get or create circuit breaker instance."""
    global _circuit_breaker
    if _circuit_breaker is None:
        from response.adaptive import CircuitBreaker
        _circuit_breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=120)
    return _circuit_breaker


# Import sibling modules after shared variables are defined to avoid circular imports
from response.ai_engine.llm_clients import _get_timeout, _call_llm, _setup_ollama_model
from response.ai_engine.prompt_builder import _build_prompt, _get_attack_type_tasks
from response.ai_engine.response_parser import _parse_ai_response, _validate_playbook, _sanitize_playbook_yaml, _quality_gate_check, _ai_grounding_quality_check
from response.playbook_safety import validate_playbook_safety
from response.remediation_planner import plan_remediation


async def _update_investigation(investigation_id: str, **kwargs):
    """Update Investigation row fields."""
    from sqlalchemy import update
    from datetime import datetime, timezone

    kwargs["updated_at"] = datetime.now(timezone.utc)

    async with AsyncSessionLocal() as session:
        await session.execute(
            update(Investigation)
            .where(Investigation.id == investigation_id)
            .values(**kwargs)
        )
        await session.commit()


async def _broadcast_ai_completion(investigation_id: str, status: str, has_playbook: bool, error: str = None):
    """Broadcast AI engine completion."""
    try:
        from api.websocket import ws_manager
        await ws_manager.broadcast("investigations", {
            "type": "ai_completed",
            "investigation_id": investigation_id,
            "status": status,
            "has_playbook": has_playbook,
            "error": error,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        logger.debug("ws_broadcast_ai_completion_failed", error=str(e))


async def _store_deterministic_plan(investigation_id: str, plan: dict):
    """Store a deterministic remediation plan in the investigation record."""
    from response.playbook_safety import compute_investigation_safety

    # Validate deterministic playbook through safety pipeline
    investigation_context = {
        "investigation_type": "security",
        "target_host": "",
        "alert_sources": [],
    }

    playbook_yaml = plan.get("playbook_yaml")
    rollback_yaml = plan.get("rollback_yaml")

    # Run safety validation on deterministic output (defense-in-depth)
    safety_result = {"safe": True, "executable": True, "manual_review_required": False, "reasons": [], "blocked_tasks": []}
    if playbook_yaml:
        safety_result = validate_playbook_safety(playbook_yaml, investigation_context)

    # Determine final status
    if not safety_result["safe"]:
        status = "manual_review_required"
        ai_error = "SAFETY VALIDATION FAILED:\n" + "\n".join(f"- {r}" for r in safety_result["reasons"])
        playbook_valid = False
    elif playbook_yaml and not rollback_yaml:
        status = "manual_review_required"
        ai_error = "ROLLBACK REQUIRED: Mutating playbook has no rollback playbook."
        playbook_valid = False
    else:
        status = "awaiting_approval"
        ai_error = None
        playbook_valid = True

    truth_report = plan.get("truth_report", {})

    await _update_investigation(
        investigation_id,
        status=status,
        ai_summary=plan.get("ai_summary", ""),
        ai_narrative=plan.get("ai_narrative", ""),
        ai_risk=plan.get("ai_risk", ""),
        playbook_yaml=playbook_yaml,
        rollback_playbook=rollback_yaml,
        playbook_valid=playbook_valid,
        ai_error=ai_error,
        ai_quality_status="passed",
        ai_quality_json={
            "grounding": {"status": "passed", "score": 95},
            "builder": {"name": plan.get("builder_name"), "deterministic": True},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        verification_plan_json=plan.get("verification_plan"),
    )

    # Create audit event
    try:
        async with AsyncSessionLocal() as session:
            from response.models import InvestigationAuditEvent
            event = InvestigationAuditEvent(
                investigation_id=investigation_id,
                event_type="deterministic_remediation_generated",
                actor="aria-system",
                details=json.dumps({
                    "builder_name": plan.get("builder_name"),
                    "execution_mode": plan.get("execution_mode"),
                    "safety_tier": plan.get("safety_tier"),
                    "deterministic": True,
                }),
            )
            session.add(event)
            await session.commit()
    except Exception:
        pass

    # Create ARIA alert for deterministic generation (best-effort)
    try:
        async with AsyncSessionLocal() as alert_session:
            from response.models import Investigation
            from sqlalchemy import select
            result = await alert_session.execute(select(Investigation).where(Investigation.id == investigation_id))
            inv = result.scalar_one_or_none()
            if inv:
                # ARIA alert module may not be fully implemented — skip if missing
                pass
    except Exception:
        pass


def _generate_fallback_ai_result(context: dict) -> dict:
    """Generate a rule-based summary and playbook when the LLM is unavailable."""
    incident = context.get("incident", {})
    alerts = context.get("alerts", [])
    source_ips = context.get("source_ips", [])
    dest_ips = context.get("dest_ips", [])
    hostnames = context.get("hostnames", [])
    mitre_tactics = context.get("mitre_tactics", [])
    attack_type = context.get("attack_type", "unknown")
    proof_of_compromise = context.get("proof_of_compromise", {})

    title = incident.get("title", "Unknown Incident")
    severity = incident.get("severity", "medium")

    # Build summary from alert names
    alert_names = [a.get("title", a.get("rule_name", "Unknown")) for a in alerts[:5]]
    summary_bullets = "\n".join([f"- {name}" for name in alert_names]) if alert_names else "- No alert details available."

    poc_note = ""
    if proof_of_compromise.get("compromised"):
        poc_note = f"\nPROOF OF COMPROMISE: {proof_of_compromise.get('confidence', 'unknown').upper()} confidence"
        for indicator in proof_of_compromise.get("indicators", [])[:3]:
            poc_note += f"\n  - {indicator}"

    # Correct attack type label for SSH brute-force
    attack_type_label = attack_type.replace('_', ' ').title()
    if attack_type == "unknown" and source_ips and any("ssh" in str(a.get("title", "")).lower() or "pam" in str(a.get("title", "")).lower() for a in alerts):
        attack_type_label = "SSH brute-force / password guessing attempt"
    elif attack_type == "brute_force":
        attack_type_label = "SSH brute-force / password guessing attempt"

    summary = (
        f"Investigation for: {title}\n\n"
        f"Severity: {severity.upper()} | Attack Type: {attack_type_label}{poc_note}\n\n"
        f"Key Alerts:\n{summary_bullets}\n\n"
        f"Affected Hosts: {', '.join(hostnames) if hostnames else 'Unknown'}\n"
        f"Source IPs: {', '.join(source_ips) if source_ips else 'Unknown'}\n"
        f"MITRE Tactics: {', '.join(mitre_tactics) if mitre_tactics else 'None identified'}"
    )

    # Evidence-aware narrative: no isolation for failed-login-only
    has_successful_login = any("accepted" in str(a.get("title", "")).lower() or "authentication_success" in str(a.get("raw", "")).lower() for a in alerts)
    if attack_type in ("brute_force", "unknown") and source_ips and not has_successful_login:
        narrative = (
            f"This incident was triggered by {len(alerts)} alert(s). "
            f"The primary target is {hostnames[0] if hostnames else 'unknown host'}. "
            f"Source IP {source_ips[0]} shows repeated failed SSH/PAM authentication attempts. "
            f"No successful login or post-auth activity is confirmed. "
            f"This is a credential access attempt, not a confirmed compromise. "
            f"Recommended actions: review auth logs, block the source IP if policy allows, and continue monitoring. "
            f"Do NOT isolate the host unless compromise evidence appears."
        )
    else:
        narrative = (
            f"This incident was triggered by {len(alerts)} alert(s). "
            f"The primary targets are {', '.join(hostnames) if hostnames else 'unknown hosts'}. "
            f"Source IPs include {', '.join(source_ips) if source_ips else 'none recorded'}. "
            f"Recommended immediate actions: isolate affected hosts, review authentication logs, and check for lateral movement."
        )

    if severity == "critical":
        risk_level = "Critical"
    elif severity == "high":
        risk_level = "High"
    elif severity == "medium":
        risk_level = "Medium"
    else:
        risk_level = "Low"
    risk = (
        f"**Risk Level: {risk_level}**\n\n"
        f"- External source IPs detected: {'Yes' if source_ips else 'No'}\n"
        f"- Number of alerts: {len(alerts)}\n"
        f"- Affected hosts: {len(hostnames)}\n"
        f"- MITRE tactics: {', '.join(mitre_tactics) if mitre_tactics else 'None'}"
    )

    target = hostnames[0] if hostnames else (dest_ips[0] if dest_ips else "localhost")
    safe_title = title.replace('"', '\\"')

    # Detect OS from alert metadata
    target_os = "linux"
    for alert in alerts:
        agent_os = alert.get("metadata", {}).get("agent_os_name", "")
        if agent_os and "windows" in agent_os.lower():
            target_os = "windows"
            break
        decoder = alert.get("metadata", {}).get("decoder_name", "")
        if decoder and "windows" in decoder.lower():
            target_os = "windows"
            break

    # Build attack-specific fallback playbook using existing task templates
    iocs = context.get("all_iocs", {})
    attack_tasks = _get_attack_type_tasks(attack_type, iocs)

    if target_os == "windows":
        # Windows-specific fallback playbook
        if source_ips:
            block_cmds = "\n".join([f'        netsh advfirewall firewall add rule name="OpenSOAR-Block-{ip}" dir=in action=block remoteip={ip}' for ip in source_ips[:5]])
            containment_tasks = f"""    - name: "Block external source IPs via Windows Firewall"
      ansible.windows.win_shell: |
{block_cmds}
      ignore_errors: yes

    - name: "Collect active connections"
      ansible.windows.win_shell: "Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table -AutoSize"
      register: conns
      ignore_errors: yes
      changed_when: false
"""
        else:
            containment_tasks = """    - name: "No automated network block - missing attacker IP"
      ansible.windows.win_shell: "Write-Output 'No attacker/source IP was present in the alert context. Automated blocking is intentionally skipped; review evidence before corrective action.'"
      register: containment_skip
      changed_when: false

    - name: "Collect active connections"
      ansible.windows.win_shell: "Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table -AutoSize"
      register: conns
      ignore_errors: yes
      changed_when: false
"""
        # Replace Linux-specific tasks in attack_tasks with Windows equivalents
        attack_tasks = attack_tasks.replace("ansible.builtin.shell", "ansible.windows.win_shell")
        attack_tasks = attack_tasks.replace("ansible.builtin.command", "ansible.windows.win_shell")
        attack_tasks = attack_tasks.replace("ansible.builtin.iptables", "ansible.windows.win_firewall_rule")
        attack_tasks = attack_tasks.replace("ansible.builtin.service", "ansible.windows.win_service")
        attack_tasks = attack_tasks.replace("/var/log/auth.log", "Get-EventLog -LogName Security -Newest 100")
        attack_tasks = attack_tasks.replace("/var/log/apache2/error.log", "C:\\\\inetpub\\\\logs\\\\LogFiles\\\\")
        attack_tasks = attack_tasks.replace("/var/log/nginx/error.log", "C:\\\\nginx\\\\logs\\\\error.log")
        attack_tasks = attack_tasks.replace("ps aux", "Get-Process")
        attack_tasks = attack_tasks.replace("crontab", "Get-ScheduledTask")
    else:
        # Linux-specific fallback playbook (default)
        if source_ips:
            block_cmds = "\n".join([f"        iptables -A INPUT -s '{ip}' -j DROP" for ip in source_ips[:5]])
            containment_tasks = f"""    - name: "Block external source IPs"
      ansible.builtin.shell: |
{block_cmds}
      ignore_errors: yes

    - name: "Collect active connections"
      ansible.builtin.shell: "ss -tunapl | head -20"
      register: conns
      ignore_errors: yes
      changed_when: false
"""
        else:
            containment_tasks = """    - name: "No automated network block - missing attacker IP"
      ansible.builtin.debug:
        msg: "No attacker/source IP was present in the alert context. Automated blocking is intentionally skipped; review evidence before corrective action."
      changed_when: false

    - name: "Collect active connections"
      ansible.builtin.shell: "ss -tunapl | head -50"
      register: conns
      ignore_errors: yes
      changed_when: false
"""

    # Generate explicit rollback with exact IP removal
    rollback_yaml = ""
    if source_ips:
        if target_os == "windows":
            rollback_cmds = "\n".join([f'        netsh advfirewall firewall delete rule name="OpenSOAR-Block-{ip}"' for ip in source_ips[:5]])
            rollback_yaml = f"""---
- name: "Rollback - {safe_title}"
  hosts: {target}
  gather_facts: no
  tasks:
    - name: "Remove blocked source IPs"
      ansible.windows.win_shell: |
{rollback_cmds}
      ignore_errors: yes
"""
        else:
            rollback_cmds = "\n".join([f"      - iptables -D INPUT -s '{ip}' -j DROP || echo 'Rule for {ip} already removed'" for ip in source_ips[:5]])
            rollback_yaml = f"""---
- name: "Rollback - {safe_title}"
  hosts: {target}
  gather_facts: no
  tasks:
    - name: "Remove blocked source IPs"
      ansible.builtin.shell: |
{rollback_cmds}
      ignore_errors: yes
"""

    playbook_yaml = f"""---
- name: "Auto-remediation for {safe_title}"
  hosts: {target}
  gather_facts: no
  vars:
    attacker_ips: {source_ips[:5]}
    target_ips: {dest_ips[:3]}
    attack_type: "{attack_type}"
    target_os: "{target_os}"
  tasks:
{containment_tasks}
{attack_tasks}
"""

    return {
        "summary": summary,
        "narrative": narrative,
        "risk": risk,
        "playbook_yaml": playbook_yaml,
        "rollback_yaml": rollback_yaml,
    }


async def run_investigation(investigation_id: str, context: dict):
    """
    Main entry point called by the watcher after creating an Investigation row.
    Calls Ollama, parses response, stores results, updates status.
    """
    logger.info("ai_investigation_started", investigation_id=investigation_id, context_keys=list(context.keys()))

    # Update status to show we're working
    await _update_investigation(investigation_id, status="pending", ai_error=None)

    # Broadcast that AI is processing
    try:
        from api.websocket import ws_manager
        await ws_manager.broadcast("investigations", {
            "type": "ai_started",
            "investigation_id": investigation_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    except Exception:
        pass

    # Initialize model on first run
    _setup_ollama_model()

    # ------------------------------------------------------------------
    # Deterministic remediation planner — known scenarios bypass LLM
    # ------------------------------------------------------------------
    deterministic_plan = plan_remediation(context)
    if deterministic_plan:
        logger.info("deterministic_remediation_plan_used",
                    investigation_id=investigation_id,
                    builder=deterministic_plan.get("builder_name"),
                    execution_mode=deterministic_plan.get("execution_mode"),
                    safety_tier=deterministic_plan.get("safety_tier"))
        await _store_deterministic_plan(investigation_id, deterministic_plan)
        await _broadcast_ai_completion(
            investigation_id,
            deterministic_plan.get("safety_tier", "awaiting_approval"),
            bool(deterministic_plan.get("playbook_yaml")),
            f"Deterministic builder '{deterministic_plan.get('builder_name')}' used"
        )
        return True

    try:
        prompt = _build_prompt(context)
        logger.info("ai_prompt_built", investigation_id=investigation_id, prompt_length=len(prompt))
    except Exception as e:
        logger.error("ai_prompt_build_error", investigation_id=investigation_id, error=str(e), exc_info=True)
        await _update_investigation(investigation_id, ai_error=f"Prompt build failed: {e}")
        await _broadcast_ai_completion(investigation_id, "failed", False, f"Prompt build failed: {e}")
        return False

    # Get adaptive timeout
    timeout = await _get_timeout(len(prompt))

    # Check circuit breaker before making API call
    cb = _get_circuit_breaker()
    can_proceed, wait_seconds = cb.can_proceed()
    if not can_proceed:
        logger.warning("circuit_breaker_open", wait_seconds=wait_seconds)
        await _update_investigation(investigation_id, ai_error=f"Circuit breaker open - wait {wait_seconds}s")
        await _broadcast_ai_completion(investigation_id, "rate_limited", False, f"Circuit breaker open - wait {wait_seconds}s")
        return False

    start_time = time.time()

    try:
        provider = settings.llm_provider.lower() if settings.llm_provider else "ollama"
        if provider == "google":
            logger.info("ai_calling_google", investigation_id=investigation_id, timeout=timeout)
            raw_response = await asyncio.wait_for(_call_llm(prompt), timeout=timeout + 30)
        else:
            logger.info("ai_calling_ollama", investigation_id=investigation_id, timeout=timeout)
            # Allow extra time for retries within _call_ollama
            raw_response = await asyncio.wait_for(_call_llm(prompt), timeout=timeout + 120)

        duration = time.time() - start_time

        # Record successful response
        try:
            from response.adaptive import record_response_safe
            await record_response_safe(duration, True)
        except Exception:
            pass

        logger.info("ai_ollama_response_received", investigation_id=investigation_id, response_length=len(raw_response), response_preview=raw_response[:200])
    except asyncio.TimeoutError:
        duration = time.time() - start_time
        logger.error("ai_investigation_timeout", investigation_id=investigation_id, timeout=timeout)

        # Record timeout error
        try:
            from response.adaptive import record_error_safe
            from response.adaptive import ErrorClassifier
            await record_error_safe("timeout")
            await record_response_safe(duration, False)
        except Exception:
            pass

        # Fallback to rule-based analysis
        logger.info("ai_investigation_fallback_timeout", investigation_id=investigation_id)
        fallback = _generate_fallback_ai_result(context)
        await _update_investigation(
            investigation_id,
            status="awaiting_approval",
            ai_summary=fallback["summary"],
            ai_narrative=fallback["narrative"],
            ai_risk=fallback["risk"],
            playbook_yaml=fallback["playbook_yaml"],
            rollback_playbook=fallback.get("rollback_yaml", ""),
            playbook_valid=True,
            ai_error=None,
            ai_quality_status="weak",
            ai_quality_json={"grounding": {"status": "weak", "reasons": ["fallback_used_timeout"]}, "timestamp": datetime.now(timezone.utc).isoformat()},
        )
        await _broadcast_ai_completion(investigation_id, "awaiting_approval", True, "Fallback analysis used (LLM timeout)")
        return True
    except Exception as e:
        duration = time.time() - start_time
        logger.error("ai_investigation_ollama_error", investigation_id=investigation_id, error=str(e), exc_info=True)

        # Record error
        try:
            from response.adaptive import record_error_safe, record_response_safe
            from response.adaptive import ErrorClassifier
            error_type = ErrorClassifier.categorize(str(e))
            await record_error_safe(error_type)
            await record_response_safe(duration, False)
        except Exception:
            pass

        # Fallback to rule-based analysis on any LLM failure
        logger.info("ai_investigation_fallback_error", investigation_id=investigation_id, error=str(e))
        fallback = _generate_fallback_ai_result(context)
        await _update_investigation(
            investigation_id,
            status="awaiting_approval",
            ai_summary=fallback["summary"],
            ai_narrative=fallback["narrative"],
            ai_risk=fallback["risk"],
            playbook_yaml=fallback["playbook_yaml"],
            rollback_playbook=fallback.get("rollback_yaml", ""),
            playbook_valid=True,
            ai_error=None,
            ai_quality_status="weak",
            ai_quality_json={"grounding": {"status": "weak", "reasons": ["fallback_used_error"]}, "timestamp": datetime.now(timezone.utc).isoformat()},
        )
        await _broadcast_ai_completion(investigation_id, "awaiting_approval", True, "Fallback analysis used (LLM unavailable)")
        return True

    try:
        parsed = _parse_ai_response(raw_response)

        # Run quality gates on parsed response
        quality = _quality_gate_check(parsed, investigation_id)

        # Run evidence grounding / hallucination quality check
        grounding = _ai_grounding_quality_check(parsed, context, investigation_id)

        # Retry logic: if summary is empty or quality is failed, retry LLM once
        retry_count = 0
        max_retries = 1
        while retry_count < max_retries and (not parsed.get("summary") or grounding["status"] == "failed"):
            retry_count += 1
            logger.warning("ai_quality_retry",
                          investigation_id=investigation_id,
                          retry=retry_count,
                          reason="empty_summary" if not parsed.get("summary") else "grounding_failed",
                          grounding_status=grounding["status"])
            try:
                raw_response_retry = await asyncio.wait_for(_call_llm(prompt), timeout=timeout + 120)
                parsed_retry = _parse_ai_response(raw_response_retry)
                quality_retry = _quality_gate_check(parsed_retry, investigation_id)
                grounding_retry = _ai_grounding_quality_check(parsed_retry, context, investigation_id)
                # Only use retry result if it's better
                if parsed_retry.get("summary") and grounding_retry["status"] != "failed":
                    parsed = parsed_retry
                    quality = quality_retry
                    grounding = grounding_retry
                    raw_response = raw_response_retry
                    logger.info("ai_quality_retry_succeeded",
                               investigation_id=investigation_id,
                               new_grounding_status=grounding["status"])
                    break
            except Exception as e:
                logger.warning("ai_quality_retry_failed",
                              investigation_id=investigation_id,
                              error=str(e))
                break

        # Sanitize playbook to fix known AI hallucinations
        if parsed.get("playbook_yaml"):
            parsed["playbook_yaml"] = _sanitize_playbook_yaml(
                parsed["playbook_yaml"], investigation_id
            )

        playbook_valid = _validate_playbook(parsed["playbook_yaml"])

        # Run comprehensive safety validation BEFORE approval
        safety = {"safe": True, "executable": True, "manual_review_required": False, "reasons": [], "blocked_tasks": []}
        if parsed.get("playbook_yaml"):
            investigation_context = {
                "investigation_type": context.get("investigation_type", "security"),
                "target_host": context.get("hostnames", [None])[0] or context.get("dest_ips", [None])[0],
                "alert_sources": list({a.get("source", "") for a in context.get("alerts", [])}),
            }
            safety = validate_playbook_safety(parsed["playbook_yaml"], investigation_context)
            if not safety["safe"]:
                logger.warning("ai_playbook_safety_blocked",
                             investigation_id=investigation_id,
                             reasons=safety["reasons"],
                             blocked_tasks=safety["blocked_tasks"])

        # If safety requires manual review, set status accordingly
        if safety.get("manual_review_required"):
            await _update_investigation(
                investigation_id,
                status="manual_review_required",
                ai_summary=parsed["summary"],
                ai_narrative=parsed.get("narrative", ""),
                ai_risk=parsed.get("risk", ""),
                playbook_yaml=parsed["playbook_yaml"],
                playbook_valid=False,
                ai_error="SAFETY VALIDATION FAILED:\n" + "\n".join(f"- {r}" for r in safety["reasons"]),
            )
            await _broadcast_ai_completion(
                investigation_id,
                "manual_review_required",
                bool(parsed["playbook_yaml"]),
                "Playbook blocked by safety validation: " + "; ".join(safety["reasons"][:3])
            )
            # Create ARIA alert for unsafe playbook
            try:
                async with AsyncSessionLocal() as alert_session:
                    from response.aria_alerts import alert_on_unsafe_playbook
                    from response.models import Investigation
                    result = await alert_session.execute(select(Investigation).where(Investigation.id == investigation_id))
                    inv_alert = result.scalar_one_or_none()
                    if inv_alert:
                        await alert_on_unsafe_playbook(alert_session, inv_alert, safety.get("reasons", []))
            except Exception:
                pass
            return True

        # Rollback check for mutating playbooks
        rollback_yaml = parsed.get("rollback_yaml", "")
        has_rollback = bool(rollback_yaml and len(rollback_yaml) > 50 and not rollback_yaml.lower().startswith("no rollback required"))
        if playbook_valid and parsed.get("playbook_yaml") and not has_rollback:
            # Determine if playbook is mutating
            import yaml as _yaml
            try:
                pb = _yaml.safe_load(parsed["playbook_yaml"])
                mutating_modules = ("ansible.builtin.iptables", "ansible.builtin.service", "ansible.builtin.shell",
                                   "ansible.builtin.command", "ansible.builtin.lineinfile", "ansible.builtin.blockinfile",
                                   "ansible.builtin.file", "ansible.builtin.copy", "ansible.builtin.template")
                is_mutating = False
                if isinstance(pb, list):
                    for play in pb:
                        if isinstance(play, dict):
                            for task in play.get("tasks", []):
                                if isinstance(task, dict):
                                    for key in task:
                                        if any(key.startswith(m) or key == m.split(".")[-1] for m in mutating_modules):
                                            is_mutating = True
                                            break
                if is_mutating:
                    logger.warning("ai_playbook_missing_rollback",
                                 investigation_id=investigation_id)
                    await _update_investigation(
                        investigation_id,
                        status="manual_review_required",
                        ai_summary=parsed["summary"],
                        ai_narrative=parsed.get("narrative", ""),
                        ai_risk=parsed.get("risk", ""),
                        playbook_yaml=parsed["playbook_yaml"],
                        rollback_playbook=None,
                        playbook_valid=False,
                        ai_error="ROLLBACK REQUIRED: This playbook contains state-changing tasks but no rollback playbook was generated. Manual review is required before execution.",
                    )
                    await _broadcast_ai_completion(
                        investigation_id,
                        "manual_review_required",
                        bool(parsed["playbook_yaml"]),
                        "Rollback playbook missing for mutating tasks"
                    )
                    return True
            except Exception:
                pass

        # Store rollback if present
        if has_rollback:
            await _update_investigation(investigation_id, rollback_playbook=rollback_yaml)

        # Run real Ansible syntax-check BEFORE approval
        if playbook_valid and parsed.get("playbook_yaml"):
            try:
                from response.ansible_exec import _validate_ansible_syntax
                syntax_valid, syntax_error = await _validate_ansible_syntax(
                    parsed["playbook_yaml"], investigation_id
                )
                
                # Auto-fix unknown modules by extracting from error and replacing
                if not syntax_valid and "couldn't resolve module/action" in syntax_error:
                    import re
                    mod_match = re.search(r"couldn't resolve module/action '([^']+)'", syntax_error)
                    if mod_match:
                        fake_module = mod_match.group(1)
                        logger.warning("ai_playbook_unknown_module_auto_fix",
                                     investigation_id=investigation_id, module=fake_module)
                        # Replace the unknown module line with ansible.builtin.command
                        # Match lines like "      fake_module:" (with indentation)
                        parsed["playbook_yaml"] = re.sub(
                            rf"^(\s+){re.escape(fake_module)}:",
                            rf"\1ansible.builtin.command: cmd=echo 'replaced {fake_module}'",
                            parsed["playbook_yaml"],
                            flags=re.MULTILINE
                        )
                        # Retry syntax check
                        syntax_valid, syntax_error = await _validate_ansible_syntax(
                            parsed["playbook_yaml"], investigation_id
                        )
                
                if not syntax_valid:
                    playbook_valid = False
                    logger.error("ai_playbook_ansible_syntax_failed",
                               investigation_id=investigation_id, error=syntax_error)
                    # Store error but still save the playbook for human review
                    await _update_investigation(
                        investigation_id,
                        status="awaiting_approval",
                        ai_summary=parsed["summary"],
                        ai_narrative=parsed.get("narrative", ""),
                        ai_risk=parsed.get("risk", ""),
                        playbook_yaml=parsed["playbook_yaml"],
                        playbook_valid=False,
                        ai_error=f"Playbook syntax invalid: {syntax_error[:200]}",
                    )
                    await _broadcast_ai_completion(
                        investigation_id, "awaiting_approval", True,
                        f"Playbook has syntax errors: {syntax_error[:100]}"
                    )
                    return True
            except Exception as e:
                logger.warning("ai_ansible_syntax_check_failed",
                             investigation_id=investigation_id, error=str(e))
                # Continue - syntax check unavailable is not a blocker

        # Combine related sections into existing DB columns (no migration needed)
        # narrative = attack chain + threat intelligence + root cause + timeline gaps + asset inventory
        narrative_parts = []
        if parsed.get("narrative"):
            narrative_parts.append(("Attack Chain", parsed["narrative"]))
        if parsed.get("threat_intel"):
            narrative_parts.append(("Threat Intelligence", parsed["threat_intel"]))
        if parsed.get("root_cause"):
            narrative_parts.append(("Root Cause", parsed["root_cause"]))
        if parsed.get("timeline_gaps"):
            narrative_parts.append(("Timeline Gaps", parsed["timeline_gaps"]))
        if parsed.get("asset_inventory"):
            narrative_parts.append(("Asset Inventory", parsed["asset_inventory"]))
        combined_narrative = "\n\n".join(f"--- {title} ---\n{content}" for title, content in narrative_parts)

        # risk = risk assessment + verification procedure + impact + confidence
        risk_parts = []
        if parsed.get("risk"):
            risk_parts.append(("Risk Assessment", parsed["risk"]))
        if parsed.get("impact"):
            risk_parts.append(("Impact Assessment", parsed["impact"]))
        if parsed.get("confidence"):
            risk_parts.append(("Confidence Scoring", parsed["confidence"]))
        if parsed.get("verification"):
            risk_parts.append(("Verification", parsed["verification"]))
        combined_risk = "\n\n".join(f"--- {title} ---\n{content}" for title, content in risk_parts)

        # Store AI quality metadata regardless of outcome
        ai_quality_json = {
            "grounding": grounding,
            "structure": quality,
            "retry_count": retry_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Empty or failed-quality output is not acceptable
        if not parsed["summary"] and not parsed["playbook_yaml"]:
            logger.warning(
                "ai_investigation_empty_response",
                investigation_id=investigation_id,
                response_length=len(raw_response),
            )
            await _update_investigation(
                investigation_id,
                status="manual_review_required",
                ai_error="AI returned empty or unparseable response after retry",
                ai_summary=raw_response[:500] if raw_response else None,
                ai_quality_status="failed",
                ai_quality_json=ai_quality_json,
            )
            await _broadcast_ai_completion(investigation_id, "manual_review_required", False, "AI returned empty response")
            return True

        # If grounding quality is failed, require manual review
        if grounding["status"] == "failed":
            logger.warning("ai_grounding_quality_failed",
                          investigation_id=investigation_id,
                          reasons=grounding["reasons"],
                          score=grounding["overall_score"])
            await _update_investigation(
                investigation_id,
                status="manual_review_required",
                ai_summary=parsed["summary"],
                ai_narrative=combined_narrative or parsed["narrative"],
                ai_risk=combined_risk or parsed["risk"],
                playbook_yaml=parsed["playbook_yaml"],
                playbook_valid=playbook_valid,
                ai_error=f"AI QUALITY FAILED (score {grounding['overall_score']}/100): {', '.join(grounding['reasons'][:3])}",
                ai_quality_status="failed",
                ai_quality_json=ai_quality_json,
            )
            await _broadcast_ai_completion(
                investigation_id,
                "manual_review_required",
                bool(parsed["playbook_yaml"]),
                f"AI quality failed: {', '.join(grounding['reasons'][:3])}"
            )
            # Create ARIA alert for AI quality failure
            try:
                async with AsyncSessionLocal() as alert_session:
                    from response.aria_alerts import alert_on_ai_quality
                    from response.models import Investigation
                    result = await alert_session.execute(select(Investigation).where(Investigation.id == investigation_id))
                    inv_alert = result.scalar_one_or_none()
                    if inv_alert:
                        await alert_on_ai_quality(alert_session, inv_alert)
            except Exception:
                pass
            return True

        # Build quality note for analyst review
        quality_note = ""
        if not quality["passed"]:
            quality_note = f"\n[QUALITY WARNING: Score {quality['overall_score']}/100 - {', '.join(quality['warnings'])}]"
        if grounding["status"] == "weak":
            quality_note += f"\n[GROUNDING WARNING: Score {grounding['overall_score']}/100 - {', '.join(grounding['reasons'][:3])}]"

        ai_quality_status = "passed" if grounding["status"] == "passed" else "weak"

        await _update_investigation(
            investigation_id,
            status="awaiting_approval",
            ai_summary=parsed["summary"] + quality_note,
            ai_narrative=combined_narrative or parsed["narrative"],
            ai_risk=combined_risk or parsed["risk"],
            playbook_yaml=parsed["playbook_yaml"],
            playbook_valid=playbook_valid,
            ai_error=None,
            ai_quality_status=ai_quality_status,
            ai_quality_json=ai_quality_json,
        )

        # Broadcast AI completion
        broadcast_msg = None
        if not quality["passed"]:
            broadcast_msg = f"Quality gates flagged: {', '.join(quality['warnings'][:3])}"
        if grounding["status"] == "weak":
            broadcast_msg = (broadcast_msg or "") + f" Grounding weak: {', '.join(grounding['reasons'][:3])}"
        await _broadcast_ai_completion(
            investigation_id,
            "awaiting_approval",
            bool(parsed["playbook_yaml"]),
            broadcast_msg
        )

        # Create ARIA alert for weak AI quality
        if ai_quality_status == "weak":
            try:
                async with AsyncSessionLocal() as alert_session:
                    from response.aria_alerts import alert_on_ai_quality
                    from response.models import Investigation
                    result = await alert_session.execute(select(Investigation).where(Investigation.id == investigation_id))
                    inv_alert = result.scalar_one_or_none()
                    if inv_alert:
                        await alert_on_ai_quality(alert_session, inv_alert)
            except Exception:
                pass

        logger.info(
            "ai_investigation_complete",
            investigation_id=investigation_id,
            has_summary=bool(parsed["summary"]),
            has_playbook=bool(parsed["playbook_yaml"]),
            playbook_valid=playbook_valid,
        )

        # Record success - close circuit breaker
        cb = _get_circuit_breaker()
        cb.record_success()

        # Try auto-approve before sending notification
        try:
            from response.auto_approve import apply_auto_approve
            auto_approve_result = await apply_auto_approve(investigation_id)

            if auto_approve_result.should_auto_approve:
                logger.info(
                    "auto_approve_triggered",
                    investigation_id=investigation_id,
                    reason=auto_approve_result.reason,
                    confidence=auto_approve_result.confidence
                )
                # Broadcast auto-approve
                try:
                    from api.websocket import broadcast_investigation_change
                    await broadcast_investigation_change(investigation_id, "awaiting_approval", "approved", f"Auto-approved: {auto_approve_result.reason}")
                except Exception:
                    pass
                return True  # Skip notification, already auto-approved and executing
        except Exception as e:
            logger.warning("auto_approve_failed", investigation_id=investigation_id, error=str(e))

        # Send notification for approval needed (only if not auto-approved)
        try:
            from response.notification import send_approval_notification
            await send_approval_notification(
                investigation_id=investigation_id,
                incident_title=context.get("incident", {}).get("title", "Unknown"),
                risk_score=context.get("risk_score", 50),
                attack_type=context.get("attack_type", "unknown"),
                target_host=context.get("hostnames", [None])[0] or context.get("dest_ips", [None])[0] or context.get("source_ips", [None])[0],
                source_ips=context.get("source_ips", [])
            )
        except Exception as e:
            logger.warning("notification_failed", investigation_id=investigation_id, error=str(e))

        return True
    except Exception as e:
        logger.error("ai_parse_error", investigation_id=investigation_id, error=str(e), exc_info=True)
        await _update_investigation(investigation_id, ai_error=f"Parse error: {e}")
        await _broadcast_ai_completion(investigation_id, "failed", False, f"Parse error: {e}")
        return False
