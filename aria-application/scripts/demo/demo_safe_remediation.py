#!/usr/bin/env python3
"""
Controlled safe remediation real-execution demo.

Validates one end-to-end scenario on localhost:
  1. Insert demo alert + incident + investigation into DB
  2. Verify safety status = safe
  3. Approve investigation
  4. Trigger real ansible-playbook execution against localhost
  5. Verify iptables rule was added
  6. Run fix verifier
  7. Run rollback playbook manually
  8. Verify iptables rule was removed
  9. Record results

Target: localhost only. Uses TEST-NET IP 192.0.2.1 (RFC 5737).
"""
from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import select, update, delete
from response.db import AsyncSessionLocal
from response.models import Alert, AlertIncidentLink, Incident, Investigation, PlaybookApproval
from response.playbook_safety import compute_investigation_safety

# ── Controlled demo data ─────────────────────────────────────────────────────

DEMO_ALERT_ID = "demo-exec-alert-001"
DEMO_INCIDENT_ID = "demo-exec-incident-001"
DEMO_INV_ID = "demo-exec-inv-001"
TEST_IP = "192.0.2.1"

SAFE_PLAYBOOK = f"""\
---
- name: Block test IP {TEST_IP}
  hosts: target
  connection: local
  gather_facts: no
  tasks:
    - name: Block exact source IP {TEST_IP}
      ansible.builtin.iptables:
        chain: INPUT
        source: {TEST_IP}
        jump: DROP
        state: present
"""

SAFE_ROLLBACK = f"""\
---
- name: Remove block for {TEST_IP}
  hosts: target
  connection: local
  gather_facts: no
  tasks:
    - name: Remove exact iptables rule for {TEST_IP}
      ansible.builtin.iptables:
        chain: INPUT
        source: {TEST_IP}
        jump: DROP
        state: absent
"""

IPTABLES_CHECK_CMD = ["iptables", "-L", "INPUT", "-n", "--line-numbers"]


def _iptables_has_rule(ip: str) -> bool:
    result = subprocess.run(IPTABLES_CHECK_CMD, capture_output=True, text=True)
    return ip in result.stdout


def _iptables_remove_rule(ip: str) -> None:
    """Emergency cleanup: remove rule by IP if it exists."""
    result = subprocess.run(IPTABLES_CHECK_CMD, capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if ip in line:
            parts = line.split()
            if parts and parts[0].isdigit():
                subprocess.run(["iptables", "-D", "INPUT", parts[0]], capture_output=True)
                break


async def _insert_demo_data():
    async with AsyncSessionLocal() as session:
        session.add(Alert(
            id=DEMO_ALERT_ID,
            source="demo_execution",
            source_id="demo-001",
            title="Demo: Suspicious network activity",
            description=f"Controlled demo alert for safe remediation execution test. Source IP: {TEST_IP}",
            severity="high",
            source_ip=TEST_IP,
            hostname="demo-localhost",
            rule_name="demo_rule",
            tags=["controlled_demo", "execution_test"],
            created_at=datetime.now(timezone.utc),
        ))
        session.add(Incident(
            id=DEMO_INCIDENT_ID,
            title="Demo: Suspicious network activity",
            description=f"Controlled demo incident. Target IP: {TEST_IP}",
            severity="high",
            status="open",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        ))
        session.add(AlertIncidentLink(alert_id=DEMO_ALERT_ID, incident_id=DEMO_INCIDENT_ID))
        session.add(Investigation(
            id=DEMO_INV_ID,
            incident_id=DEMO_INCIDENT_ID,
            local_incident_id=DEMO_INCIDENT_ID,
            incident_title="Demo: Suspicious network activity",
            incident_severity="high",
            incident_status="open",
            status="awaiting_approval",
            source="manual",
            investigation_type="security",
            ai_summary=f"Demo analysis: suspicious activity from {TEST_IP}. Recommended: targeted iptables block.",
            ai_narrative="Controlled demo execution scenario.",
            ai_risk="medium",
            playbook_yaml=SAFE_PLAYBOOK,
            playbook_valid=True,
            target_host="localhost",
            target_user="root",
            source_ips=TEST_IP,
            rollback_playbook=SAFE_ROLLBACK,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        ))
        await session.commit()
    print("[1] Demo data inserted into DB")


async def _verify_safety():
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Investigation).where(Investigation.id == DEMO_INV_ID))
        inv = result.scalar_one()
        safety = compute_investigation_safety(inv)

    print(f"[2] Safety check:")
    print(f"    playbook_safety_status: {safety['playbook_safety_status']}")
    print(f"    rollback_safety_status: {safety['rollback_safety_status']}")
    print(f"    is_safe_to_display: {safety['is_safe_to_display']}")
    print(f"    has_remediation_action: {safety['has_remediation_action']}")
    print(f"    execution_mode: {safety['execution_mode']}")
    print(f"    is_executable: {safety['is_executable']}")
    print(f"    blocked_reasons: {safety['blocked_reasons']}")

    assert safety["playbook_safety_status"] == "safe", "Playbook not safe"
    assert safety["rollback_safety_status"] == "safe", "Rollback not safe"
    assert safety["is_executable"] is True, "Not executable"
    print("    ✓ All safety checks passed")
    return safety


async def _approve():
    from api.routes.investigations import approve_investigation, ApproveRequest
    from response.db import get_session

    gen = get_session()
    db_session = await gen.__anext__()
    try:
        result = await approve_investigation(DEMO_INV_ID, ApproveRequest(decided_by="demo_analyst"), session=db_session)
        print(f"[3] Approval result: {result}")
    finally:
        await gen.aclose()
    print("    ✓ Approval succeeded")


def _patch_settings_for_localhost():
    """Override ansible_remote_user so localhost SSH uses root instead of ghazi."""
    from config.settings import get_settings
    s = get_settings()
    s._original_ansible_remote_user = s.ansible_remote_user
    s.ansible_remote_user = ""
    print("    [settings] ansible_remote_user patched to '' for localhost execution")


def _restore_settings():
    from config.settings import get_settings
    s = get_settings()
    if hasattr(s, '_original_ansible_remote_user'):
        s.ansible_remote_user = s._original_ansible_remote_user
        print("    [settings] ansible_remote_user restored")


async def _poll_status(timeout: int = 60):
    print(f"[4] Polling execution status (timeout {timeout}s)...")
    start = time.time()
    while time.time() - start < timeout:
        await asyncio.sleep(2)
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(Investigation).where(Investigation.id == DEMO_INV_ID))
            inv = result.scalar_one()
            print(f"    status={inv.status}  (elapsed {int(time.time()-start)}s)")
            if inv.status in ("completed", "failed", "archived"):
                return inv.status
    return "timeout"


def _check_iptables(label: str) -> bool:
    has_rule = _iptables_has_rule(TEST_IP)
    print(f"[5] {label}: iptables rule for {TEST_IP} {'EXISTS' if has_rule else 'NOT FOUND'}")
    return has_rule


async def _run_verifier():
    from response.fix_verifier import verify_fix
    result = await verify_fix(DEMO_INV_ID)
    print(f"[6] Verifier result: {result}")
    return result


def _run_rollback():
    print(f"[7] Running rollback playbook...")
    # Write rollback to disk and execute directly with ansible-playbook
    playbook_path = Path(f"/tmp/demo_rollback_{DEMO_INV_ID}.yml")
    playbook_path.write_text(SAFE_ROLLBACK, encoding="utf-8")
    inventory_path = Path(f"/tmp/demo_inventory_{DEMO_INV_ID}.ini")
    inventory_path.write_text(
        "[target]\nlocalhost ansible_user=root ansible_ssh_common_args='-o StrictHostKeyChecking=no' ansible_ssh_port=22\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        ["ansible-playbook", "-i", str(inventory_path), str(playbook_path)],
        capture_output=True,
        text=True,
    )
    print(f"    exit_code={result.returncode}")
    if result.returncode != 0:
        print(f"    stderr: {result.stderr[:500]}")
    else:
        print("    ✓ Rollback completed successfully")
    return result.returncode == 0


async def _cleanup_db():
    async with AsyncSessionLocal() as session:
        from response.models import PlaybookRun, FixVerification, InvestigationAlert
        await session.execute(delete(FixVerification).where(FixVerification.investigation_id == DEMO_INV_ID))
        await session.execute(delete(PlaybookRun).where(PlaybookRun.investigation_id == DEMO_INV_ID))
        await session.execute(delete(PlaybookApproval).where(PlaybookApproval.investigation_id == DEMO_INV_ID))
        await session.execute(delete(InvestigationAlert).where(InvestigationAlert.investigation_id == DEMO_INV_ID))
        await session.execute(delete(Investigation).where(Investigation.id == DEMO_INV_ID))
        await session.execute(delete(Incident).where(Incident.id == DEMO_INCIDENT_ID))
        await session.execute(delete(AlertIncidentLink).where(AlertIncidentLink.alert_id == DEMO_ALERT_ID))
        await session.execute(delete(Alert).where(Alert.id == DEMO_ALERT_ID))
        await session.commit()
    print("[9] DB cleanup completed")


async def main():
    print("=" * 60)
    print("ARIA Controlled Safe Remediation — Real Execution Demo")
    print("=" * 60)
    print(f"Target: localhost")
    print(f"Test IP: {TEST_IP} (TEST-NET-1, RFC 5737)")
    print(f"Playbook: iptables block exact IP")
    print(f"Rollback: iptables remove exact IP")
    print("=" * 60)

    # Pre-flight cleanup
    _iptables_remove_rule(TEST_IP)
    assert not _iptables_has_rule(TEST_IP), "Pre-flight: rule should not exist"

    try:
        await _insert_demo_data()
        safety = await _verify_safety()
        _patch_settings_for_localhost()
        await _approve()
        final_status = await _poll_status(timeout=60)
        _restore_settings()

        print(f"[4] Final execution status: {final_status}")

        rule_exists_after_execution = _check_iptables("After execution")
        verifier_result = await _run_verifier()
        rollback_ok = _run_rollback()
        rule_exists_after_rollback = _check_iptables("After rollback")

        print("=" * 60)
        print("DEMO RESULTS")
        print("=" * 60)
        print(f"investigation_id:     {DEMO_INV_ID}")
        print(f"playbook_safe:        {safety['playbook_safety_status'] == 'safe'}")
        print(f"rollback_safe:        {safety['rollback_safety_status'] == 'safe'}")
        print(f"approval_ok:          True")
        print(f"execution_status:     {final_status}")
        print(f"rule_after_execution: {rule_exists_after_execution}")
        print(f"verifier_result:      {verifier_result}")
        print(f"rollback_ok:          {rollback_ok}")
        print(f"rule_after_rollback:  {rule_exists_after_rollback}")

        all_ok = (
            safety["playbook_safety_status"] == "safe"
            and safety["rollback_safety_status"] == "safe"
            and rule_exists_after_execution
            and rollback_ok
            and not rule_exists_after_rollback
        )
        if all_ok:
            print("\n✓ VERDICT: PASS — Safe controlled remediation validated end-to-end")
        else:
            print("\n✗ VERDICT: FAIL — See details above")

    finally:
        _iptables_remove_rule(TEST_IP)
        await _cleanup_db()
        print("[10] Emergency iptables cleanup done")


if __name__ == "__main__":
    asyncio.run(main())
