# Backup and Decommission Limitations

This document states only what current source proves. Anything not proven is marked accordingly.

## What is confirmed

### SQLite backup behavior

The ARIA worker runs a daily SQLite backup loop at 03:00 local time. It copies `investigations.db` to `data/backups/` and keeps only the most recent seven files. *Confirmed from current source.*

### Existing backup/restore scripts

- `aria-application/scripts/maintenance/backup_db.sh` backs up the SQLite database, playbooks, cursors, seen IDs, artifacts, and evidence. Default retention is 30 days.
- `aria-application/scripts/maintenance/restore_db.sh` restores from a backup archive.

*Confirmed from current source.*

### Redis persistence volume

The Compose file defines a named volume `redis-data` and runs Redis with `--appendonly yes`. Redis state is persisted to AOF inside that volume. *Confirmed from current source.*

## What is not confirmed or incomplete

### Elasticsearch snapshots

There is no confirmed Elasticsearch snapshot repository, snapshot policy, or index lifecycle management in the current repository. *Not confirmed from repository.*

### Off-host backup

There is no confirmed off-host, encrypted, or immutable backup of ARIA data, Elasticsearch indices, Wazuh/Kibana configuration, or host certificates. *Not confirmed from repository.*

### Full disaster recovery

A complete disaster-recovery runbook — covering Brain VM rebuild, certificate restoration, Wazuh re-enrollment, monitored VM re-onboarding, and Elasticsearch index recovery — is not present or proven. *Not confirmed from repository.*

### RPO/RTO and restore drills

No recovery point objective, recovery time objective, or documented restore-drill procedure exists in the repository. *Not confirmed from repository.*

### Compose volume backup

A documented procedure for backing up and restoring the `redis-data` Compose volume is not present. *Not confirmed from repository.*

## Decommission limitations

### ARIA asset delete

Deleting an asset via the ARIA API (`DELETE /api/v1/assets/{asset_id}`) removes only the SQLite registry record. It does **not** automatically:

- stop or uninstall agents on the monitored VM;
- revoke Wazuh enrollment;
- revoke SSH keys or access;
- delete Elasticsearch indices or documents;
- rotate credentials.

*Confirmed from current source.*

### Missing decommission script

The monitored-VM bootstrap scripts reference `delete_set_up.sh --all`, but that file is absent from the repository. A full monitored-VM teardown runbook is not available. *Not confirmed from repository.*

## Manual decisions required

Before decommissioning a monitored server or retiring the Brain VM, decide and execute manually:

- Data retention period for alerts, incidents, and evidence.
- Agent removal and service disablement on monitored VMs.
- Wazuh agent deletion and enrollment cleanup.
- SSH key rotation and removal from Brain VM and Ansible inventories.
- Credential rotation (Elasticsearch, Wazuh, admin secrets, Ansible become passwords).
- Elasticsearch index deletion or archival.
- Redis volume and SQLite backup disposition.
- Certificate and key destruction.

## Summary

| Area | Status |
|---|---|
| SQLite daily backup | Confirmed from current source |
| SQLite maintenance scripts | Confirmed from current source |
| Redis AOF persistence | Confirmed from current source |
| Elasticsearch snapshots | Not confirmed from repository |
| Off-host encrypted backup | Not confirmed from repository |
| Full disaster recovery | Not confirmed from repository |
| RPO/RTO / restore drills | Not confirmed from repository |
| Compose volume backup runbook | Not confirmed from repository |
| Asset delete removes agents/SSH/credentials | Not confirmed from repository |
| Complete monitored-VM decommission script | Not confirmed from repository |
