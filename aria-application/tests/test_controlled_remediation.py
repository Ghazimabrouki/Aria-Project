"""
Controlled safe remediation end-to-end validation.

Creates 3 realistic demo scenarios with safe playbooks and precise rollbacks,
plus 3 negative safety tests for dangerous patterns that must be blocked.
"""
from __future__ import annotations

import json
import pytest
from datetime import datetime, timezone
from sqlalchemy import delete, select, update

from response.db import AsyncSessionLocal
from response.models import (
    Alert,
    AlertIncidentLink,
    Incident,
    Investigation,
    InvestigationAlert,
    PlaybookApproval,
    PlaybookRun,
    FixVerification,
)
from response.playbook_safety import (
    compute_investigation_safety,
    validate_playbook_safety,
    validate_rollback_safety,
)


@pytest.fixture(autouse=True)
async def _clean_controlled_remediation_rows():
    yield
    async with AsyncSessionLocal() as session:
        await session.execute(delete(FixVerification).where(FixVerification.investigation_id.like("controlled-demo-%")))
        await session.execute(delete(PlaybookRun).where(PlaybookRun.investigation_id.like("controlled-demo-%")))
        await session.execute(delete(PlaybookApproval).where(PlaybookApproval.investigation_id.like("controlled-demo-%")))
        await session.execute(delete(InvestigationAlert).where(InvestigationAlert.investigation_id.like("controlled-demo-%")))
        await session.execute(delete(Investigation).where(Investigation.id.like("controlled-demo-%")))
        await session.execute(delete(Incident).where(Incident.id.like("controlled-demo-%")))
        await session.execute(delete(AlertIncidentLink).where(AlertIncidentLink.alert_id.like("controlled-demo-%")))
        await session.execute(delete(Alert).where(Alert.id.like("controlled-demo-%")))
        await session.commit()


# ──────────────────────────────────────────────────────────────────────────────
#  Controlled safe playbooks
# ──────────────────────────────────────────────────────────────────────────────

SAFE_SURICATA_PLAYBOOK = """\
---
- name: Block suspicious Suricata source IP
  hosts: localhost
  become: yes
  tasks:
    - name: Block exact source IP 192.168.100.50
      ansible.builtin.iptables:
        chain: INPUT
        source: 192.168.100.50
        jump: DROP
        state: present
      become: yes
"""

SAFE_SURICATA_ROLLBACK = """\
---
- name: Remove block for 192.168.100.50
  hosts: localhost
  become: yes
  tasks:
    - name: Remove exact iptables rule for 192.168.100.50
      ansible.builtin.iptables:
        chain: INPUT
        source: 192.168.100.50
        jump: DROP
        state: absent
      become: yes
"""

SAFE_WAZUH_PLAYBOOK = """\
---
- name: Block SSH brute force source IP
  hosts: localhost
  become: yes
  tasks:
    - name: Block exact source IP 10.0.0.99 on SSH port
      ansible.builtin.iptables:
        chain: INPUT
        source: 10.0.0.99
        destination_port: 22
        protocol: tcp
        jump: DROP
        state: present
      become: yes
"""

SAFE_WAZUH_ROLLBACK = """\
---
- name: Remove SSH block for 10.0.0.99
  hosts: localhost
  become: yes
  tasks:
    - name: Remove exact iptables rule for 10.0.0.99
      ansible.builtin.iptables:
        chain: INPUT
        source: 10.0.0.99
        destination_port: 22
        protocol: tcp
        jump: DROP
        state: absent
      become: yes
"""

SAFE_FALCO_PLAYBOOK = """\
---
- name: Quarantine suspicious demo file
  hosts: localhost
  become: yes
  tasks:
    - name: Ensure quarantine directory exists
      ansible.builtin.file:
        path: /tmp/quarantine
        state: directory
        mode: "0750"
    - name: Copy suspicious file to quarantine
      ansible.builtin.copy:
        src: /tmp/demo_test_file
        dest: /tmp/quarantine/demo_test_file
        remote_src: yes
    - name: Remove original file
      ansible.builtin.file:
        path: /tmp/demo_test_file
        state: absent
"""

SAFE_FALCO_ROLLBACK = """\
---
- name: Restore file from quarantine
  hosts: localhost
  become: yes
  tasks:
    - name: Copy file back from quarantine
      ansible.builtin.copy:
        src: /tmp/quarantine/demo_test_file
        dest: /tmp/demo_test_file
        remote_src: yes
    - name: Remove quarantine copy
      ansible.builtin.file:
        path: /tmp/quarantine/demo_test_file
        state: absent
"""


async def _insert_scenario(alert_id, incident_id, inv_id, playbook, rollback, alert_source, alert_title, source_ip):
    """Insert a complete alert → incident → investigation chain."""
    async with AsyncSessionLocal() as session:
        session.add(Alert(
            id=alert_id,
            source=alert_source,
            source_id=f"{alert_source}-001",
            title=alert_title,
            description=f"Controlled demo alert: {alert_title}",
            severity="high",
            source_ip=source_ip,
            hostname="demo-host-01",
            rule_name="controlled_demo_rule",
            tags=["controlled_demo"],
            created_at=datetime.now(timezone.utc),
        ))
        session.add(Incident(
            id=incident_id,
            title=alert_title,
            description=f"Controlled demo incident: {alert_title}",
            severity="high",
            status="open",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        ))
        session.add(AlertIncidentLink(alert_id=alert_id, incident_id=incident_id))
        session.add(Investigation(
            id=inv_id,
            incident_id=incident_id,
            local_incident_id=incident_id,
            incident_title=alert_title,
            incident_severity="high",
            incident_status="open",
            status="awaiting_approval",
            source="auto",
            investigation_type="security",
            ai_summary=f"Controlled demo: {alert_title}. Recommended action: targeted remediation.",
            ai_narrative="Controlled demo scenario for safe remediation validation.",
            ai_risk="medium",
            playbook_yaml=playbook,
            playbook_valid=True,
            target_host="localhost",
            target_user="root",
            source_ips=source_ip,
            rollback_playbook=rollback,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        ))
        session.add(InvestigationAlert(
            id=f"{inv_id}-ia",
            investigation_id=inv_id,
            alert_id=alert_id,
            severity="high",
            source=alert_source,
            title=alert_title,
            alert_json=json.dumps({"source_ip": source_ip}),
        ))
        await session.commit()


# ──────────────────────────────────────────────────────────────────────────────
#  Positive scenarios
# ──────────────────────────────────────────────────────────────────────────────

class TestSuricataIpBlock:
    ids = {
        "alert": "controlled-demo-suricata-alert",
        "incident": "controlled-demo-suricata-incident",
        "inv": "controlled-demo-suricata-inv",
    }

    @pytest.fixture(autouse=True)
    async def setup(self):
        await _insert_scenario(
            self.ids["alert"], self.ids["incident"], self.ids["inv"],
            SAFE_SURICATA_PLAYBOOK, SAFE_SURICATA_ROLLBACK,
            "suricata", "Suricata: Suspicious network activity", "192.168.100.50",
        )

    def test_safety_computation(self):
        async def _check():
            async with AsyncSessionLocal() as session:
                result = await session.execute(select(Investigation).where(Investigation.id == self.ids["inv"]))
                inv = result.scalar_one()
                safety = compute_investigation_safety(inv)
                assert safety["playbook_safety_status"] == "safe"
                assert safety["rollback_safety_status"] == "safe"
                assert safety["is_safe_to_display"] is True
                assert safety["has_remediation_action"] is True
                assert safety["execution_mode"] == "remediation"
                assert safety["is_executable"] is True
                assert safety["blocked_reasons"] == []
        import asyncio
        asyncio.run(_check())

    def test_detail_endpoint_returns_correct_fields(self):
        async def _check():
            from api.routes.investigations import get_investigation
            from response.db import get_session
            gen = get_session()
            db_session = await gen.__anext__()
            try:
                detail = await get_investigation(self.ids["inv"], session=db_session)
                assert detail.playbook_safety_status == "safe"
                assert detail.rollback_safety_status == "safe"
                assert detail.is_safe_to_display is True
                assert detail.has_remediation_action is True
                assert detail.execution_mode == "remediation"
                assert detail.is_executable is True
                assert detail.blocked_reasons == []
            finally:
                await gen.aclose()
        import asyncio
        asyncio.run(_check())

    def test_approval_allowed(self, mock_request):
        async def _check():
            from api.routes.investigations import approve_investigation, ApproveRequest
            from response.db import get_session
            gen = get_session()
            db_session = await gen.__anext__()
            try:
                result = await approve_investigation(self.ids["inv"], ApproveRequest(decided_by="demo_analyst"), mock_request, session=db_session)
                assert "approved" in result["message"].lower()
            finally:
                await gen.aclose()
        import asyncio
        asyncio.run(_check())

    def test_execution_allowed_after_approval(self, mock_request):
        async def _check():
            from api.routes.investigations import execute_playbook_direct, ApproveRequest
            from response.db import get_session
            # Pre-approve
            async with AsyncSessionLocal() as session:
                await session.execute(
                    update(Investigation)
                    .where(Investigation.id == self.ids["inv"])
                    .values(status="approved")
                )
                session.add(PlaybookApproval(
                    investigation_id=self.ids["inv"],
                    decision="approved",
                    decided_by="demo_analyst",
                    decided_at=datetime.now(timezone.utc),
                ))
                await session.commit()

            gen = get_session()
            db_session = await gen.__anext__()
            try:
                result = await execute_playbook_direct(self.ids["inv"], ApproveRequest(decided_by="demo_analyst"), mock_request, session=db_session)
                assert result["status"] == "running"
            finally:
                await gen.aclose()
        import asyncio
        asyncio.run(_check())


class TestWazuhSshBlock:
    ids = {
        "alert": "controlled-demo-wazuh-alert",
        "incident": "controlled-demo-wazuh-incident",
        "inv": "controlled-demo-wazuh-inv",
    }

    @pytest.fixture(autouse=True)
    async def setup(self):
        await _insert_scenario(
            self.ids["alert"], self.ids["incident"], self.ids["inv"],
            SAFE_WAZUH_PLAYBOOK, SAFE_WAZUH_ROLLBACK,
            "wazuh", "Wazuh: SSH brute force attempt", "10.0.0.99",
        )

    def test_safety_computation(self):
        async def _check():
            async with AsyncSessionLocal() as session:
                result = await session.execute(select(Investigation).where(Investigation.id == self.ids["inv"]))
                inv = result.scalar_one()
                safety = compute_investigation_safety(inv)
                assert safety["playbook_safety_status"] == "safe"
                assert safety["rollback_safety_status"] == "safe"
                assert safety["is_safe_to_display"] is True
                assert safety["has_remediation_action"] is True
                assert safety["execution_mode"] == "remediation"
                assert safety["is_executable"] is True
                assert safety["blocked_reasons"] == []
        import asyncio
        asyncio.run(_check())

    def test_detail_endpoint(self):
        async def _check():
            from api.routes.investigations import get_investigation
            from response.db import get_session
            gen = get_session()
            db_session = await gen.__anext__()
            try:
                detail = await get_investigation(self.ids["inv"], session=db_session)
                assert detail.is_executable is True
                assert detail.has_remediation_action is True
                assert detail.execution_mode == "remediation"
            finally:
                await gen.aclose()
        import asyncio
        asyncio.run(_check())

    def test_execution_with_pre_approval(self, mock_request):
        async def _check():
            from api.routes.investigations import execute_playbook_direct, ApproveRequest
            from response.db import get_session
            async with AsyncSessionLocal() as session:
                await session.execute(
                    update(Investigation)
                    .where(Investigation.id == self.ids["inv"])
                    .values(status="approved")
                )
                session.add(PlaybookApproval(
                    investigation_id=self.ids["inv"],
                    decision="approved",
                    decided_by="demo_analyst",
                    decided_at=datetime.now(timezone.utc),
                ))
                await session.commit()
            gen = get_session()
            db_session = await gen.__anext__()
            try:
                result = await execute_playbook_direct(self.ids["inv"], ApproveRequest(decided_by="demo_analyst"), mock_request, session=db_session)
                assert result["status"] == "running"
            finally:
                await gen.aclose()
        import asyncio
        asyncio.run(_check())


class TestFalcoFileQuarantine:
    ids = {
        "alert": "controlled-demo-falco-alert",
        "incident": "controlled-demo-falco-incident",
        "inv": "controlled-demo-falco-inv",
    }

    @pytest.fixture(autouse=True)
    async def setup(self):
        await _insert_scenario(
            self.ids["alert"], self.ids["incident"], self.ids["inv"],
            SAFE_FALCO_PLAYBOOK, SAFE_FALCO_ROLLBACK,
            "falco", "Falco: Suspicious file modification", "10.0.0.5",
        )

    def test_safety_computation(self):
        async def _check():
            async with AsyncSessionLocal() as session:
                result = await session.execute(select(Investigation).where(Investigation.id == self.ids["inv"]))
                inv = result.scalar_one()
                safety = compute_investigation_safety(inv)
                assert safety["playbook_safety_status"] == "safe"
                assert safety["rollback_safety_status"] == "safe"
                assert safety["is_safe_to_display"] is True
                assert safety["has_remediation_action"] is True
                assert safety["execution_mode"] == "remediation"
                assert safety["is_executable"] is True
                assert safety["blocked_reasons"] == []
        import asyncio
        asyncio.run(_check())

    def test_detail_endpoint(self):
        async def _check():
            from api.routes.investigations import get_investigation
            from response.db import get_session
            gen = get_session()
            db_session = await gen.__anext__()
            try:
                detail = await get_investigation(self.ids["inv"], session=db_session)
                assert detail.is_executable is True
                assert detail.has_remediation_action is True
                assert detail.execution_mode == "remediation"
            finally:
                await gen.aclose()
        import asyncio
        asyncio.run(_check())

    def test_execution_with_pre_approval(self, mock_request):
        async def _check():
            from api.routes.investigations import execute_playbook_direct, ApproveRequest
            from response.db import get_session
            async with AsyncSessionLocal() as session:
                await session.execute(
                    update(Investigation)
                    .where(Investigation.id == self.ids["inv"])
                    .values(status="approved")
                )
                session.add(PlaybookApproval(
                    investigation_id=self.ids["inv"],
                    decision="approved",
                    decided_by="demo_analyst",
                    decided_at=datetime.now(timezone.utc),
                ))
                await session.commit()
            gen = get_session()
            db_session = await gen.__anext__()
            try:
                result = await execute_playbook_direct(self.ids["inv"], ApproveRequest(decided_by="demo_analyst"), mock_request, session=db_session)
                assert result["status"] == "running"
            finally:
                await gen.aclose()
        import asyncio
        asyncio.run(_check())


# ──────────────────────────────────────────────────────────────────────────────
#  Negative safety tests
# ──────────────────────────────────────────────────────────────────────────────

class TestNegativeSafetyCases:
    """Verify dangerous patterns are blocked by safety validation."""

    def test_nuclear_rollback_blocked(self):
        playbook = """\
---
- name: Block IP
  hosts: localhost
  tasks:
    - name: Block attacker
      ansible.builtin.iptables:
        chain: INPUT
        source: 1.2.3.4
        jump: DROP
        state: present
"""
        rollback = """\
---
- name: Nuclear rollback
  hosts: localhost
  tasks:
    - name: Flush all rules
      ansible.builtin.shell: iptables -F && iptables -X
"""
        pb_safety = validate_playbook_safety(playbook)
        rb_safety = validate_rollback_safety(rollback)
        assert pb_safety["safe"] is True
        assert rb_safety["safe"] is False
        assert any("nuclear" in r.lower() for r in rb_safety["reasons"])

    def test_sudoers_edit_blocked(self):
        playbook = """\
---
- name: Update sudoers
  hosts: localhost
  tasks:
    - name: Add attacker to sudoers
      ansible.builtin.lineinfile:
        path: /etc/sudoers
        line: "attacker ALL=(ALL) NOPASSWD:ALL"
        state: present
"""
        result = validate_playbook_safety(playbook)
        assert result["safe"] is False
        assert any("sudoers" in r.lower() for r in result["reasons"])

    def test_rm_rf_blocked(self):
        playbook = """\
---
- name: Clean up
  hosts: localhost
  tasks:
    - name: Remove suspicious files
      ansible.builtin.shell: rm -rf /tmp/suspicious
"""
        result = validate_playbook_safety(playbook)
        assert result["safe"] is False
        assert any("rm -rf" in r.lower() for r in result["reasons"])

    def test_empty_jinja_firewall_source_blocked(self):
        playbook = """\
---
- name: Block attacker
  hosts: localhost
  tasks:
    - name: Block with empty source
      ansible.builtin.shell: iptables -A INPUT -s {{ attacker_ip }} -j DROP
"""
        result = validate_playbook_safety(playbook)
        assert result["safe"] is False
        assert any("empty" in r.lower() or "jinja" in r.lower() for r in result["reasons"])

    def test_broad_chmod_blocked(self):
        playbook = """\
---
- name: Fix permissions
  hosts: localhost
  tasks:
    - name: chmod everything
      ansible.builtin.shell: chmod -R 777 /etc
"""
        result = validate_playbook_safety(playbook)
        assert result["safe"] is False
        assert any("chmod" in r.lower() for r in result["reasons"])

    def test_systemctl_stop_ssh_blocked(self):
        playbook = """\
---
- name: Stop SSH
  hosts: localhost
  tasks:
    - name: Stop sshd
      ansible.builtin.service:
        name: sshd
        state: stopped
"""
        result = validate_playbook_safety(playbook)
        assert result["safe"] is False
        assert any("ssh" in r.lower() for r in result["reasons"])
