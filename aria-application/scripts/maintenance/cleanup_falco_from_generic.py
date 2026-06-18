#!/usr/bin/env python3
"""
One-time cleanup script: report (and optionally hide) Falco records
from generic /alerts, /incidents, and /investigations endpoints.

Dry-run by default. Use --apply to execute changes.

Changes made:
- Alerts with source="falco" are NOT deleted; they are kept for runtime traceability.
  The generic /alerts API now filters them out by default.
- Investigations with investigation_type="runtime" are NOT deleted.
  The generic /investigations API now filters them out.
- Incidents linked to runtime investigations or containing Falco alerts
  are NOT deleted. The /incidents API now filters them out.

This script only REPORTS what the APIs will hide. No DB mutations are needed
for the filtering to take effect, because all filtering is done at the API layer.
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/home/dash/Desktop/opensoar backend 6 mai/opensoar backend")

from sqlalchemy import select, func
from response.db import AsyncSessionLocal
from response.models import Alert, Incident, Investigation, AlertIncidentLink


async def report_counts():
    async with AsyncSessionLocal() as session:
        # 1. Falco alerts in local DB
        falco_alert_count = await session.execute(
            select(func.count(Alert.id)).where(Alert.source == "falco")
        )
        falco_alerts = falco_alert_count.scalar() or 0

        # 2. Runtime investigations
        runtime_inv_count = await session.execute(
            select(func.count(Investigation.id)).where(
                Investigation.investigation_type == "runtime"
            )
        )
        runtime_invs = runtime_inv_count.scalar() or 0

        # 3. Incidents linked to runtime investigations
        runtime_linked_incident_count = await session.execute(
            select(func.count(Incident.id))
            .join(
                Investigation,
                Investigation.local_incident_id == Incident.id,
            )
            .where(Investigation.investigation_type == "runtime")
        )
        runtime_linked_incidents = runtime_linked_incident_count.scalar() or 0

        # 4. Incidents containing any Falco alert
        falco_incident_count = await session.execute(
            select(func.count(Incident.id))
            .join(AlertIncidentLink, AlertIncidentLink.incident_id == Incident.id)
            .join(Alert, Alert.id == AlertIncidentLink.alert_id)
            .where(Alert.source == "falco")
        )
        falco_incidents = falco_incident_count.scalar() or 0

        # 5. Total alerts, incidents, investigations
        total_alerts = (await session.execute(select(func.count(Alert.id)))).scalar() or 0
        total_incidents = (await session.execute(select(func.count(Incident.id)))).scalar() or 0
        total_invs = (await session.execute(select(func.count(Investigation.id)))).scalar() or 0

        print("=" * 60)
        print("FALCO CLEANUP REPORT (dry-run)")
        print("=" * 60)
        print(f"\nTotal alerts in DB:           {total_alerts}")
        print(f"Falco alerts:                 {falco_alerts}")
        print(f"  → Will be hidden from /alerts:  {falco_alerts}")
        print(f"  → Still accessible by ID:       {falco_alerts} (for runtime detail)")

        print(f"\nTotal investigations in DB:   {total_invs}")
        print(f"Runtime investigations:       {runtime_invs}")
        print(f"  → Will be hidden from /investigations: {runtime_invs}")
        print(f"  → Still accessible via /runtime/investigations: {runtime_invs}")

        print(f"\nTotal incidents in DB:        {total_incidents}")
        print(f"Incidents linked to runtime:  {runtime_linked_incidents}")
        print(f"Incidents with Falco alerts:  {falco_incidents}")
        print(f"  → Will be hidden from /incidents: {runtime_linked_incidents + falco_incidents}")

        print(f"\nVisible after filtering:")
        print(f"  /alerts:          ~{total_alerts - falco_alerts}")
        print(f"  /investigations:  ~{total_invs - runtime_invs}")
        print(f"  /incidents:       ~{total_incidents - runtime_linked_incidents - falco_incidents}")
        print("=" * 60)

        return {
            "falco_alerts": falco_alerts,
            "runtime_investigations": runtime_invs,
            "runtime_linked_incidents": runtime_linked_incidents,
            "falco_incidents": falco_incidents,
        }


def main():
    parser = argparse.ArgumentParser(description="Report Falco records in generic tables")
    parser.add_argument("--apply", action="store_true", help="No-op; filtering is API-side")
    args = parser.parse_args()

    counts = asyncio.run(report_counts())

    if args.apply:
        print("\nNote: No DB mutations needed. Filtering is implemented at the API layer.")
        print("The --apply flag is a no-op. Run the validation tests to confirm.")

    # Exit 0 if report completed successfully
    sys.exit(0)


if __name__ == "__main__":
    main()
