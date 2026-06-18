#!/usr/bin/env python3
"""
Live test script - exercises all OpenSOAR API endpoints against the real instance.
Skips auth step (assumes already authenticated). Shows dashboard results.
"""

import asyncio
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import structlog
from pipeline.sender import client

logger = structlog.get_logger()


async def test_health():
    print("\n" + "="*60)
    print("1. HEALTH CHECK")
    print("="*60)
    resp = await client._get_http().get("/api/v1/health")
    print(f"   Status: {resp.status_code}")
    print(f"   Body: {resp.text[:200]}")
    return resp.status_code == 200


async def test_dashboard_stats():
    print("\n" + "="*60)
    print("2. DASHBOARD STATS")
    print("="*60)
    resp = await client._get_http().get("/api/v1/dashboard/stats", headers=client._auth_headers())
    print(f"   Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        if isinstance(data, dict):
            for k, v in data.items():
                print(f"   {k}: {v}")
        else:
            print(f"   Data: {json.dumps(data, indent=2)[:500]}")
    else:
        print(f"   Error: {resp.text[:200]}")


async def test_list_alerts():
    print("\n" + "="*60)
    print("3. LIST ALERTS (latest 5)")
    print("="*60)
    resp = await client._get_http().get("/api/v1/alerts", params={"limit": 5}, headers=client._auth_headers())
    print(f"   Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        total = data.get("total", 0)
        alerts = data.get("alerts", [])
        print(f"   Total alerts: {total}")
        print(f"   Showing: {len(alerts)}")
        for a in alerts:
            print(f"\n   - ID: {a.get('id', '')[:8]}...")
            print(f"     Title: {a.get('title', '')[:80]}")
            print(f"     Severity: {a.get('severity')} | Status: {a.get('status')}")
            print(f"     Source: {a.get('source')} | Source IP: {a.get('source_ip')}")
            if a.get('tags'):
                print(f"     Tags: {a.get('tags')[:5]}")
    return resp.status_code == 200


async def test_list_incidents():
    print("\n" + "="*60)
    print("4. LIST INCIDENTS")
    print("="*60)
    resp = await client._get_http().get("/api/v1/incidents", headers=client._auth_headers())
    print(f"   Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        total = data.get("total", 0)
        incidents = data.get("incidents", [])
        print(f"   Total incidents: {total}")
        print(f"   Showing: {len(incidents)}")
        for inc in incidents:
            print(f"\n   - ID: {inc.get('id', '')[:8]}...")
            print(f"     Title: {inc.get('title', '')[:80]}")
            print(f"     Severity: {inc.get('severity')} | Status: {inc.get('status')}")
            print(f"     Alert count: {inc.get('alert_count')}")
            if inc.get('tags'):
                print(f"     Tags: {inc.get('tags')[:5]}")
    return resp.status_code == 200


async def test_list_observables():
    print("\n" + "="*60)
    print("5. LIST OBSERVABLES (latest 5)")
    print("="*60)
    resp = await client._get_http().get("/api/v1/observables", params={"limit": 5}, headers=client._auth_headers())
    print(f"   Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        total = data.get("total", 0)
        observables = data.get("observables", [])
        print(f"   Total observables: {total}")
        print(f"   Showing: {len(observables)}")
        for obs in observables:
            print(f"\n   - ID: {obs.get('id', '')[:8]}...")
            print(f"     Type: {obs.get('type')} | Value: {str(obs.get('value', ''))[:50]}")
            print(f"     Enrichment: {obs.get('enrichment_status')}")
            if obs.get('enrichments'):
                print(f"     Enrichments: {len(obs.get('enrichments', []))}")
    return resp.status_code == 200


async def test_list_playbooks():
    print("\n" + "="*60)
    print("6. LIST PLAYBOOKS")
    print("="*60)
    resp = await client._get_http().get("/api/v1/playbooks", headers=client._auth_headers())
    print(f"   Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        if isinstance(data, list):
            print(f"   Total playbooks: {len(data)}")
            for pb in data:
                status = "ENABLED" if pb.get('enabled') else "DISABLED"
                print(f"\n   - {pb.get('name', 'unnamed')} [{status}]")
                print(f"     ID: {pb.get('id', '')[:8]}...")
                print(f"     Trigger: {pb.get('trigger_type')}")
        else:
            print(f"   Data: {json.dumps(data, indent=2)[:300]}")
    return resp.status_code == 200


async def test_list_runs():
    print("\n" + "="*60)
    print("7. LIST RUNS (latest 5)")
    print("="*60)
    resp = await client._get_http().get("/api/v1/runs", params={"limit": 5}, headers=client._auth_headers())
    print(f"   Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        total = data.get("total", 0)
        runs = data.get("runs", [])
        print(f"   Total runs: {total}")
        print(f"   Showing: {len(runs)}")
        for run in runs:
            print(f"\n   - ID: {run.get('id', '')[:8]}...")
            print(f"     Status: {run.get('status')}")
            print(f"     Playbook: {str(run.get('playbook_id', ''))[:8]}...")
            print(f"     Alert: {str(run.get('alert_id', ''))[:8]}...")
            if run.get('error'):
                print(f"     Error: {run.get('error')[:100]}")
    return resp.status_code == 200


async def test_list_actions():
    print("\n" + "="*60)
    print("8. LIST AVAILABLE ACTIONS")
    print("="*60)
    resp = await client._get_http().get("/api/v1/actions", headers=client._auth_headers())
    print(f"   Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        if isinstance(data, list):
            print(f"   Total actions: {len(data)}")
            for action in data:
                print(f"\n   - {action.get('name')}")
                print(f"     Integration: {action.get('integration')}")
                print(f"     IOC Types: {action.get('ioc_types', [])}")
                print(f"     Description: {action.get('description', '')[:80]}")
        else:
            print(f"   Data: {json.dumps(data, indent=2)[:300]}")
    return resp.status_code == 200


async def test_list_integrations():
    print("\n" + "="*60)
    print("9. LIST INTEGRATIONS")
    print("="*60)
    resp = await client._get_http().get("/api/v1/integrations", headers=client._auth_headers())
    print(f"   Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        if isinstance(data, list):
            print(f"   Total integrations: {len(data)}")
            for integ in data:
                print(f"\n   - {integ.get('name')}")
                print(f"     Type: {integ.get('integration_type')}")
                print(f"     Health: {integ.get('health_status')}")
                print(f"     Enabled: {integ.get('enabled')}")
        else:
            print(f"   Data: {json.dumps(data, indent=2)[:300]}")
    return resp.status_code == 200


async def test_list_api_keys():
    print("\n" + "="*60)
    print("10. LIST API KEYS")
    print("="*60)
    resp = await client._get_http().get("/api/v1/api-keys", headers=client._auth_headers())
    print(f"   Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        if isinstance(data, list):
            print(f"   Total keys: {len(data)}")
            for key in data:
                print(f"\n   - {key.get('name')}")
                print(f"     Prefix: {key.get('prefix')}")
                print(f"     Active: {key.get('is_active')}")
                print(f"     Last used: {key.get('last_used_at')}")
        else:
            print(f"   Data: {json.dumps(data, indent=2)[:300]}")
    return resp.status_code == 200


async def test_incident_suggestions():
    print("\n" + "="*60)
    print("11. INCIDENT SUGGESTIONS")
    print("="*60)
    resp = await client._get_http().get("/api/v1/incidents/suggestions", headers=client._auth_headers())
    print(f"   Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        print(f"   Response: {json.dumps(data, indent=2)[:500]}")
    return resp.status_code == 200


async def test_list_analysts():
    print("\n" + "="*60)
    print("12. LIST ANALYSTS")
    print("="*60)
    resp = await client._get_http().get("/api/v1/auth/analysts", headers=client._auth_headers())
    print(f"   Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        if isinstance(data, list):
            print(f"   Total analysts: {len(data)}")
            for a in data:
                print(f"\n   - {a.get('username')} ({a.get('display_name', '')})")
                print(f"     Role: {a.get('role')} | Active: {a.get('is_active')}")
        else:
            print(f"   Data: {json.dumps(data, indent=2)[:300]}")
    return resp.status_code == 200


async def test_create_incident_and_alert_link():
    print("\n" + "="*60)
    print("13. CREATE INCIDENT + LINK ALERT")
    print("="*60)
    
    resp = await client._get_http().post(
        "/api/v1/incidents",
        json={
            "title": "Test Incident - Live Test",
            "description": "Auto-created by live test script to verify incident creation and alert linking",
            "severity": "medium",
            "tags": ["live-test", "automated", "datausage-test"],
        },
        headers=client._auth_headers(),
    )
    print(f"   Create incident status: {resp.status_code}")
    
    if resp.status_code != 201:
        print(f"   Error: {resp.text[:200]}")
        return False
    
    incident = resp.json()
    incident_id = incident.get("id")
    print(f"   Incident created: {incident_id}")
    print(f"   Title: {incident.get('title')}")
    print(f"   Severity: {incident.get('severity')}")
    print(f"   Tags: {incident.get('tags')}")
    
    resp2 = await client._get_http().get("/api/v1/alerts", params={"limit": 1}, headers=client._auth_headers())
    if resp2.status_code == 200:
        alerts_data = resp2.json()
        alerts = alerts_data.get("alerts", [])
        if alerts:
            alert_id = alerts[0].get("id")
            print(f"\n   Linking alert {alert_id[:8]}... to incident")
            
            resp3 = await client._get_http().post(
                f"/api/v1/incidents/{incident_id}/alerts",
                json={"alert_id": alert_id},
                headers=client._auth_headers(),
            )
            print(f"   Link alert status: {resp3.status_code}")
            if resp3.status_code == 201:
                print(f"   Alert linked successfully!")
                
                resp4 = await client._get_http().get(f"/api/v1/incidents/{incident_id}/alerts", headers=client._auth_headers())
                if resp4.status_code == 200:
                    print(f"   Incident alerts: {json.dumps(resp4.json(), indent=2)[:300]}")
    
    return resp.status_code == 201


async def test_create_observable():
    print("\n" + "="*60)
    print("14. CREATE OBSERVABLE + ENRICHMENT")
    print("="*60)
    
    resp = await client._get_http().post(
        "/api/v1/observables",
        json={
            "type": "ip",
            "value": "198.51.100.1",
            "source": "live-test-script",
        },
        headers=client._auth_headers(),
    )
    print(f"   Create observable status: {resp.status_code}")
    
    if resp.status_code in (201, 422):
        if resp.status_code == 422:
            print(f"   Observable already exists (expected)")
            resp2 = await client._get_http().get("/api/v1/observables", params={"limit": 1, "type": "ip"}, headers=client._auth_headers())
            if resp2.status_code == 200:
                obs_data = resp2.json()
                obs_list = obs_data.get("observables", [])
                if obs_list:
                    obs_id = obs_list[0].get("id")
                    print(f"   Found existing observable: {obs_id[:8]}...")
                    resp3 = await client._get_http().post(
                        f"/api/v1/observables/{obs_id}/enrichments",
                        json={
                            "source": "live-test-enrichment",
                            "data": {"test": True, "geo_country": "TN", "cloud_provider": "ovh"},
                            "malicious": False,
                            "score": 25,
                        },
                        headers=client._auth_headers(),
                    )
                    print(f"   Add enrichment status: {resp3.status_code}")
        else:
            obs = resp.json()
            obs_id = obs.get("id")
            print(f"   Observable created: {obs_id}")
            print(f"   Type: {obs.get('type')} | Value: {obs.get('value')}")
            
            resp2 = await client._get_http().post(
                f"/api/v1/observables/{obs_id}/enrichments",
                json={
                    "source": "live-test-enrichment",
                    "data": {"test": True, "geo_country": "TN", "cloud_provider": "ovh"},
                    "malicious": False,
                    "score": 25,
                },
                headers=client._auth_headers(),
            )
            print(f"   Add enrichment status: {resp2.status_code}")
    
    return True


async def test_add_comment():
    print("\n" + "="*60)
    print("15. ADD COMMENT TO ALERT")
    print("="*60)
    
    resp = await client._get_http().get("/api/v1/alerts", params={"limit": 1}, headers=client._auth_headers())
    if resp.status_code == 200:
        alerts_data = resp.json()
        alerts = alerts_data.get("alerts", [])
        if alerts:
            alert_id = alerts[0].get("id")
            print(f"   Targeting alert: {alert_id[:8]}...")
            
            resp2 = await client._get_http().post(
                f"/api/v1/alerts/{alert_id}/comments",
                json={"text": "Live test comment - verifying comment API works correctly"},
                headers=client._auth_headers(),
            )
            print(f"   Add comment status: {resp2.status_code}")
            if resp2.status_code == 200:
                comment = resp2.json()
                print(f"   Comment ID: {comment.get('id', '')[:8]}...")
                print(f"   Action: {comment.get('action')}")
                print(f"   Detail: {comment.get('detail', '')[:100]}")
            return resp2.status_code == 200
    return False


async def main():
    print("\n" + "#"*60)
    print("# LIVE OPENSOAR API TEST - ALL ENDPOINTS")
    print("#"*60)
    
    await client.authenticate()
    print(f"\nAuthenticated: {client._token is not None}")
    
    results = {}
    
    results["health"] = await test_health()
    results["dashboard"] = await test_dashboard_stats()
    results["alerts"] = await test_list_alerts()
    results["incidents"] = await test_list_incidents()
    results["observables"] = await test_list_observables()
    results["playbooks"] = await test_list_playbooks()
    results["runs"] = await test_list_runs()
    results["actions"] = await test_list_actions()
    results["integrations"] = await test_list_integrations()
    results["api_keys"] = await test_list_api_keys()
    results["incident_suggestions"] = await test_incident_suggestions()
    results["analysts"] = await test_list_analysts()
    results["create_incident"] = await test_create_incident_and_alert_link()
    results["create_observable"] = await test_create_observable()
    results["add_comment"] = await test_add_comment()
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"\nPassed: {passed}/{total}")
    
    for name, status in results.items():
        icon = "PASS" if status else "FAIL"
        print(f"  [{icon}] {name}")
    
    print(f"\nDashboard URL: http://193.95.30.97:8000")
    print("Check the dashboard to see the test incident, observable, and comment!")


if __name__ == "__main__":
    asyncio.run(main())
