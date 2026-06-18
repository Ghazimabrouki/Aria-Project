#!/usr/bin/env python3
"""
Safe Runtime Remediation Demo Seeder

Creates a controlled demo runtime investigation with real corrective actions
that only touch /tmp/opensoar_runtime_demo/. No system files are modified.

Usage:
    python3 scripts/demo/seed_runtime_remediation_demo.py
    python3 scripts/demo/seed_runtime_remediation_demo.py --cleanup
"""

import argparse
import asyncio
import json
import os
import shutil
import sys
import uuid
from datetime import datetime, timezone

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from response.db import AsyncSessionLocal
from response.models import Investigation

DEMO_DIR = "/tmp/opensoar_runtime_demo"
DEMO_MARKER = os.path.join(DEMO_DIR, "suspicious_marker.txt")
DEMO_BACKUP = os.path.join(DEMO_DIR, "suspicious_marker.txt.bak")

DEMO_INCIDENT_TITLE = "DEMO: Safe Runtime Remediation Test"
DEMO_HOST = "localhost"


def _ensure_demo_fs():
    """Create safe demo filesystem artifacts."""
    os.makedirs(DEMO_DIR, exist_ok=True)
    with open(DEMO_MARKER, "w") as f:
        f.write("# This is a safe demo marker file for OpenSOAR runtime remediation testing.\n")
        f.write(f"# Created at: {datetime.now(timezone.utc).isoformat()}\n")
    # Pre-create backup so rollback can restore
    shutil.copy2(DEMO_MARKER, DEMO_BACKUP)
    print(f"[DEMO] Created marker file: {DEMO_MARKER}")


def _cleanup_demo_fs():
    """Remove all demo filesystem artifacts."""
    if os.path.exists(DEMO_DIR):
        shutil.rmtree(DEMO_DIR)
        print(f"[DEMO] Removed demo directory: {DEMO_DIR}")


def _build_demo_plan() -> dict:
    """Build a safe remediation plan that only affects demo files."""
    return {
        "decision": "high_risk_action_requires_approval",
        "decision_reason": (
            "Demo scenario: a suspicious marker file was detected in a temporary directory. "
            "Safe remediation is available — remove the marker and verify it is gone."
        ),
        "target_context": "host",
        "target_host": DEMO_HOST,
        "scope_reason": "Demo file in /tmp/opensoar_runtime_demo only. No system paths affected.",
        "actual_remediation_available": True,
        "approval_required": True,
        "corrective_actions": [
            {
                "type": "remove_file",
                "description": "Remove the suspicious demo marker file",
                "path": DEMO_MARKER,
            }
        ],
        "rollback_actions": [
            {
                "type": "file_restore",
                "description": "Restore the demo marker from backup",
                "path": DEMO_MARKER,
                "backup_path": DEMO_BACKUP,
            }
        ],
        "verification_checks": [
            "Confirm demo marker file no longer exists",
            "Confirm backup file remains in demo directory",
        ],
        "next_manual_steps": [
            "Review the demo playbook in the Remediation tab.",
            "Click Approve & Run to execute the safe remediation.",
            "Check the Verification tab to confirm the file was removed.",
        ],
    }


def _build_demo_playbook() -> str:
    """Build a safe Ansible playbook that only touches demo files.
    
    Designed for staged execution: tasks use phase-friendly naming so the
    playbook splitter classifies them into the correct phases, and the
    rollback task uses ansible.builtin.debug so it is harmless if executed.
    Backup is pre-created by the demo script so it is not needed here.
    """
    playbook = """---
- name: DEMO - Safe Runtime Remediation
  hosts: {host}
  gather_facts: no
  vars:
    demo_dir: "{demo_dir}"
    demo_marker: "{demo_marker}"
    demo_backup: "{demo_backup}"

  tasks:
    - name: PHASE 0 - Evidence Collection
      ansible.builtin.command: ls -la {{{{ demo_dir }}}}
      changed_when: false

    - name: PHASE 1 - Safety Check
      ansible.builtin.stat:
        path: "{{{{ demo_marker }}}}"
      register: marker_stat

    - name: PHASE 2 - Remediation - Remove suspicious marker
      ansible.builtin.file:
        path: "{{{{ demo_marker }}}}"
        state: absent

    - name: PHASE 3 - Verification - Confirm marker absent
      ansible.builtin.stat:
        path: "{{{{ demo_marker }}}}"
      register: post_stat

    - name: PHASE 3 - Verification - Assert marker is gone
      ansible.builtin.assert:
        that:
          - not post_stat.stat.exists
        fail_msg: "Verification FAILED: demo marker still exists."
        success_msg: "Verification PASSED: demo marker removed."
      when: not ansible_check_mode

    - name: PHASE 4 - Rollback - Restore marker from backup (demo only)
      ansible.builtin.debug:
        msg: "Rollback would restore {{{{ demo_marker }}}} from {{{{ demo_backup }}}}"
""".format(
        host=DEMO_HOST,
        demo_dir=DEMO_DIR,
        demo_marker=DEMO_MARKER,
        demo_backup=DEMO_BACKUP,
    )
    return playbook.strip()


def _build_demo_resource_context() -> dict:
    return {
        "hostname": DEMO_HOST,
        "runtime_category": "file_access",
        "rule_name": "DEMO_Suspicious_File_Access",
        "proc_name": "demo_app",
        "proc_pid": 12345,
        "fd_name": DEMO_MARKER,
        "fd_type": "file",
        "container_id": "host",
        "is_expected_admin_activity": False,
        "is_intervention_required": True,
    }


DIAGNOSTIC_PLAYBOOK_YAML = """---
- name: DEMO - Runtime Diagnostic
  hosts: localhost
  gather_facts: no
  tasks:
    - name: Check demo marker file
      ansible.builtin.stat:
        path: /tmp/opensoar_runtime_demo/suspicious_marker.txt
      register: marker

    - name: Report findings
      ansible.builtin.debug:
        msg: "Demo marker exists: {{ marker.stat.exists }}"
"""

def _build_demo_findings() -> dict:
    return {
        "detected_cause": f"Demo marker file detected at {DEMO_MARKER}",
        "expert_summary": "A suspicious marker file was created in the demo directory. This is a controlled test scenario.",
        "technical_explanation": "The demo script placed a marker file in /tmp/opensoar_runtime_demo to simulate a runtime security event.",
        "threat_assessment": "suspicious",
        "confidence": "high",
        "evidence": [
            {"source": "demo_script", "finding": f"Marker file exists: {DEMO_MARKER}"}
        ],
        "recommendations": [
            {"action": "Review the demo playbook before approval."},
            {"action": "Run the remediation and observe the verification result."},
        ],
    }


async def seed_demo():
    _ensure_demo_fs()

    plan = _build_demo_plan()
    playbook_yaml = _build_demo_playbook()
    resource_ctx = _build_demo_resource_context()
    findings = _build_demo_findings()

    evidence = {
        "remediation_plan": plan,
        "actual_remediation_available": True,
        "diagnostic_playbook_yaml": DIAGNOSTIC_PLAYBOOK_YAML,
    }

    demo_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    async with AsyncSessionLocal() as session:
        inv = Investigation(
            id=demo_id,
            incident_id=demo_id,
            incident_title=DEMO_INCIDENT_TITLE,
            incident_severity="medium",
            incident_status="open",
            status="awaiting_approval",
            investigation_type="runtime",
            source="falco",
            target_host=DEMO_HOST,
            target_user="root",
            target_os="linux",
            resource_type="file_access",
            resource_context_json=resource_ctx,
            findings_json=findings,
            evidence_json=evidence,
            playbook_yaml=playbook_yaml,
            playbook_valid=True,
            ai_summary="Demo: suspicious marker file detected in temporary directory. Safe remediation available.",
            diagnostic_output="Demo diagnostic output: file exists and is safe to remove.\n\nPLAY [DEMO - Runtime Diagnostic]\nTASK [Check demo marker file] ok: marker exists\nTASK [Report findings] msg: Demo marker exists: True\n",
            diagnostic_started_at=now,
            diagnostic_finished_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(inv)
        await session.commit()

    print(f"\n[DEMO] Created runtime investigation: {demo_id}")
    print(f"[DEMO] Status: awaiting_approval")
    print(f"[DEMO] Corrective actions: {len(plan['corrective_actions'])}")
    print(f"[DEMO] Rollback actions: {len(plan['rollback_actions'])}")
    print(f"\n[DEMO] Open in frontend:")
    print(f"        http://localhost:3000/runtime/investigations/{demo_id}")
    print(f"\n[DEMO] Next steps:")
    print(f"        1. Open the investigation detail page")
    print(f"        2. Go to the Remediation tab — see the playbook with Phase 4 rollback")
    print(f"        3. Click 'Approve & Run' to execute the safe remediation")
    print(f"        4. Check the Verification tab for the result")
    print(f"\n[DEMO] To clean up:")
    print(f"        python3 scripts/demo/seed_runtime_remediation_demo.py --cleanup")
    print(f"        (This removes the DB record and demo files)")


async def cleanup_demo():
    _cleanup_demo_fs()

    from sqlalchemy import delete, select as sa_select
    from response.models import InvestigationAlert, PlaybookApproval, PlaybookRun, FixVerification

    async with AsyncSessionLocal() as session:
        # Find demo investigations
        result = await session.execute(
            sa_select(Investigation).where(Investigation.incident_title == DEMO_INCIDENT_TITLE)
        )
        demos = result.scalars().all()

        for inv in demos:
            inv_id = inv.id
            # Clean up related records first
            await session.execute(delete(InvestigationAlert).where(InvestigationAlert.investigation_id == inv_id))
            await session.execute(delete(PlaybookApproval).where(PlaybookApproval.investigation_id == inv_id))
            await session.execute(delete(PlaybookRun).where(PlaybookRun.investigation_id == inv_id))
            await session.execute(delete(FixVerification).where(FixVerification.investigation_id == inv_id))
            await session.delete(inv)
            print(f"[DEMO] Removed demo investigation: {inv_id}")

        await session.commit()

    print("[DEMO] Cleanup complete.")


def main():
    parser = argparse.ArgumentParser(description="Seed or clean up a safe runtime remediation demo")
    parser.add_argument("--cleanup", action="store_true", help="Remove all demo data")
    args = parser.parse_args()

    if args.cleanup:
        asyncio.run(cleanup_demo())
    else:
        asyncio.run(seed_demo())


if __name__ == "__main__":
    main()
