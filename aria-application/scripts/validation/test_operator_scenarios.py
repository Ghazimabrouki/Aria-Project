#!/usr/bin/env python3
"""
Operator scenario tests — sends a variety of requests to /operator
and polls until each run completes, printing structured results.
"""
import asyncio
import httpx
from datetime import datetime

BASE = "http://localhost:8001/api/v1"

SCENARIOS = [
    "check memory usage",
    "is nginx running",
    "check firewall status and block ip 5.5.5.5",
    "check cpu usage then list top 5 processes",
    "what ports are open",
    "check if sshd is active and show disk usage",
    "show me the contents of /etc/hosts",
    "check is the firewall is active or not then block this ip 1.2.3.4 then check is NetworkManager is working or not and then list for me the open ports in my system",
]


async def create_session(client: httpx.AsyncClient, title: str):
    r = await client.post(f"{BASE}/operator/sessions", json={"title": title, "target_hosts": ["ghazi"]})
    r.raise_for_status()
    return r.json()["session_id"]


async def send_and_poll(client: httpx.AsyncClient, session_id: str, prompt: str):
    # send message
    r = await client.post(
        f"{BASE}/operator/sessions/{session_id}/message",
        json={"prompt": prompt, "require_approval": True},
    )
    r.raise_for_status()
    data = r.json()
    run_id = data.get("run_id")
    status = data.get("status")

    if status == "pending_approval" and run_id:
        # auto-approve for testing
        await client.post(f"{BASE}/operator/runs/{run_id}/approve", json={"decided_by": "test"})

        # poll until done
        for _ in range(40):
            await asyncio.sleep(3)
            r = await client.get(f"{BASE}/operator/runs/{run_id}/status")
            status_data = r.json()
            if status_data.get("status") not in ("running", "pending"):
                return status_data
        return {"error": "timeout", "run_id": run_id}

    elif status == "completed":
        # local query
        r = await client.get(f"{BASE}/operator/sessions/{session_id}")
        sess = r.json()
        for m in reversed(sess.get("messages", [])):
            if m.get("role") == "assistant":
                return {
                    "status": "completed",
                    "intent": "local_query",
                    "result": m.get("result", {}),
                }
        return {"status": "completed", "result": {}}

    return {"status": status, "run_id": run_id}


def print_result(prompt: str, data: dict):
    print(f"\n{'='*60}")
    print(f"PROMPT: {prompt}")
    print(f"STATUS: {data.get('status', 'unknown')}")
    result = data.get("result", {})
    analysis = result.get("analysis", {}) if isinstance(result, dict) else {}
    if analysis:
        print(f"OUTCOME: {analysis.get('outcome', 'n/a')}")
        print(f"EXPLANATION:\n{analysis.get('explanation', 'N/A')}")
        recs = analysis.get("recommendations", [])
        if recs:
            print(f"RECOMMENDATIONS: {recs}")
    else:
        print(f"RESULT: {result}")
    print(f"{'='*60}\n")


async def main():
    async with httpx.AsyncClient(timeout=30) as client:
        for prompt in SCENARIOS:
            sid = await create_session(client, f"test_{datetime.now().isoformat()}")
            data = await send_and_poll(client, sid, prompt)
            print_result(prompt, data)


if __name__ == "__main__":
    asyncio.run(main())
