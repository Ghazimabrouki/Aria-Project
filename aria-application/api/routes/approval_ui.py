"""
Simple Approval UI - Serve HTML page for approving/declining investigations.
"""
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi import Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
from pydantic import BaseModel

from response.db import get_session
from response.models import Investigation, PlaybookRun, FixVerification

router = APIRouter(prefix="", tags=["approval"])


class ApproveRequest(BaseModel):
    decided_by: str = "analyst"


class DeclineRequest(BaseModel):
    decided_by: str = "analyst"
    reason: Optional[str] = None


@router.get("/approve/{investigation_id}")
async def show_approve_page(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """
    Show approval page for an investigation.
    Displays AI summary, playbook, risk assessment with Approve/Decline buttons.
    """
    # Fetch investigation
    result = await session.execute(
        select(Investigation).where(Investigation.id == investigation_id)
    )
    inv = result.scalar_one_or_none()
    
    if not inv:
        return HTMLResponse(f"<h1>Investigation not found: {investigation_id}</h1>", status_code=404)
    
    # Get playbook run if exists
    run_result = await session.execute(
        select(PlaybookRun).where(PlaybookRun.investigation_id == investigation_id)
    )
    run = run_result.scalar_one_or_none()
    
    # Get verification if exists
    ver_result = await session.execute(
        select(FixVerification).where(FixVerification.investigation_id == investigation_id)
    )
    verification = ver_result.scalar_one_or_none()
    
    # Format data
    severity_emoji = "🔴" if inv.incident_severity == "high" else "🟡" if inv.incident_severity == "medium" else "🟢"
    status_color = "green" if inv.status == "completed" else "orange" if inv.status == "awaiting_approval" else "red" if inv.status in ("failed", "declined") else "blue"
    
    # Playbook preview (first 30 lines)
    playbook_display = inv.playbook_yaml[:2000] if inv.playbook_yaml else "No playbook generated"
    
    # AI summary
    ai_summary = inv.ai_summary or "No summary available"
    ai_narrative = inv.ai_narrative or "No narrative available"
    ai_risk = inv.ai_risk or "No risk assessment"
    
    # Run results
    run_status = f"{run.status} (exit code: {run.exit_code})" if run else "Not executed yet"
    run_output = run.output[:1000] if run and run.output else "No output"
    
    # Verification results
    ver_status = verification.status if verification else "Not verified"
    ver_details = verification.detail[:500] if verification and verification.detail else "No details"
    
    buttons_html = ""
    if inv.status in ('awaiting_approval', 'pending'):
        buttons_html = f'''
        <div class="buttons">
            <button class="btn btn-approve" onclick="approve()">✅ Approve & Execute</button>
            <button class="btn btn-decline" onclick="decline()">❌ Decline</button>
        </div>
        '''
    else:
        buttons_html = '<div class="section"><h3>ℹ️ This investigation has already been processed (Status: ' + inv.status + ')</h3></div>'
    
    run_html = ""
    if run:
        run_html = f'''
        <div class="section">
            <h2>📊 Execution Results</h2>
            <p><strong>Status:</strong> {run_status}</p>
            <div class="playbook">{run_output}</div>
        </div>
        '''
    
    ver_html = ""
    if verification:
        ver_html = f'''
        <div class="section">
            <h2>✅ Verification Results</h2>
            <p><strong>Status:</strong> {ver_status}</p>
            <p>{ver_details}</p>
        </div>
        '''
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Investigation Approval</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               background: #1a1a2e; color: #eee; padding: 20px; margin: 0; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; 
                   background: #16213e; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
        .status {{ padding: 5px 15px; border-radius: 20px; background: {status_color}; font-weight: bold; }}
        .section {{ background: #16213e; padding: 20px; border-radius: 10px; margin-bottom: 15px; }}
        .section h2 {{ margin-top: 0; color: #00d9ff; border-bottom: 1px solid #333; padding-bottom: 10px; }}
        .playbook {{ background: #0f0f1a; padding: 15px; border-radius: 5px; 
                    font-family: monospace; white-space: pre-wrap; overflow-x: auto; 
                    max-height: 300px; overflow-y: auto; font-size: 12px; }}
        .buttons {{ display: flex; gap: 20px; margin-top: 20px; }}
        .btn {{ flex: 1; padding: 15px 30px; font-size: 18px; font-weight: bold; 
               border: none; border-radius: 8px; cursor: pointer; text-align: center; }}
        .btn-approve {{ background: #00c853; color: white; }}
        .btn-approve:hover {{ background: #00e676; }}
        .btn-decline {{ background: #d32f2f; color: white; }}
        .btn-decline:hover {{ background: #f44336; }}
        .meta {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 15px; }}
        .meta-item {{ background: #0f0f1a; padding: 10px; border-radius: 5px; }}
        .meta-label {{ color: #888; font-size: 12px; }}
        .meta-value {{ font-size: 14px; font-weight: bold; }}
        .risk {{ padding: 10px; border-radius: 5px; margin: 10px 0; }}
        .risk-high {{ background: #b71c1c; }}
        .risk-medium {{ background: #f57f17; }}
        .risk-low {{ background: #1b5e20; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>Investigation Review</h1>
                <p style="color: #888; margin: 5px 0;">ID: {investigation_id}</p>
            </div>
            <div class="status">{severity_emoji} {inv.incident_severity.upper()} | {inv.status}</div>
        </div>
        
        <div class="meta">
            <div class="meta-item">
                <div class="meta-label">Target Host</div>
                <div class="meta-value">{inv.target_host or 'Unknown'}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Source IPs</div>
                <div class="meta-value">{inv.source_ips[:50] if inv.source_ips else 'Unknown'}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">MITRE Tactics</div>
                <div class="meta-value">{inv.mitre_tactics[:50] if inv.mitre_tactics else 'None'}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🤖 AI Summary</h2>
            <p>{ai_summary}</p>
        </div>
        
        <div class="section">
            <h2>📖 Attack Narrative</h2>
            <p>{ai_narrative}</p>
        </div>
        
        <div class="section">
            <h2>⚠️ Risk Assessment</h2>
            <div class="risk {'risk-high' if 'HIGH' in ai_risk.upper() or 'CRITICAL' in ai_risk.upper() else 'risk-medium' if 'MEDIUM' in ai_risk.upper() else 'risk-low'}">
                {ai_risk}
            </div>
        </div>
        
        <div class="section">
            <h2>📋 Generated Playbook</h2>
            <div class="playbook">{playbook_display}</div>
        </div>
        
        {run_html}
        {ver_html}
        
        {buttons_html}
    </div>
    
    <script>
        async function approve() {{
            if (!confirm('Approve this playbook? It will be executed immediately.')) return;
            try {{
                const resp = await fetch('/api/v1/investigations/{investigation_id}/approve', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{decided_by: 'slack_ui'}})
                }});
                const data = await resp.json();
                if (resp.ok) {{
                    alert('✅ Approved! Playbook execution started.');
                    location.reload();
                }} else {{
                    alert('Error: ' + data.detail);
                }}
            }} catch (e) {{
                alert('Error: ' + e);
            }}
        }}
        
        async function decline() {{
            const reason = prompt('Reason for declining (optional):');
            try {{
                const resp = await fetch('/api/v1/investigations/{investigation_id}/decline', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{decided_by: 'slack_ui', reason: reason || 'Declined from Slack'}})
                }});
                const data = await resp.json();
                if (resp.ok) {{
                    alert('❌ Declined and archived.');
                    location.reload();
                }} else {{
                    alert('Error: ' + data.detail);
                }}
            }} catch (e) {{
                alert('Error: ' + e);
            }}
        }}
    </script>
</body>
</html>"""
    
    return HTMLResponse(html)