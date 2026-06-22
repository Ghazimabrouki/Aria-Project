# Monitored VM Onboarding

This document describes the current boundary for onboarding a monitored server into ARIA. It is separate from Brain VM installation and must be performed after the Brain VM is healthy.

## What runs on a monitored VM

A monitored server runs selected telemetry producers only. *Confirmed from current source.*

| Component | Role |
|---|---|
| Wazuh Agent | Host IDS events to central Wazuh Manager. |
| Filebeat | Ship logs/alerts to Elasticsearch. |
| Suricata | Network IDS; EVE output consumed by Filebeat. |
| Falco + Falcosidekick | Runtime security events to Elasticsearch. |
| Telegraf | Host metrics to Elasticsearch. |

## What does **not** run on a monitored VM

The following ARIA and central components stay on the Brain VM only. *Confirmed from current source.*

- ARIA API
- ARIA worker
- Redis
- SQLite
- Kibana
- Elasticsearch
- Wazuh Manager

## Required connectivity and telemetry direction

| Direction | Port | Purpose |
|---|---|---|
| Monitored VM → Brain VM | 1514/tcp+udp | Wazuh agent events. |
| Monitored VM → Brain VM | 1515/tcp | Wazuh enrollment. |
| Monitored VM → Brain VM | 9200/tcp HTTPS | Filebeat/Falcosidekick/Telegraf → Elasticsearch. |
| Brain VM → Monitored VM | 22/tcp | SSH for Ansible remediation (only after remediation is explicitly enabled). |
| Admin → Brain VM | 5601/tcp HTTPS | Kibana access. |
| Admin → Brain VM | 3001/tcp HTTP | ARIA dashboard. |

*Confirmed from current source.*

## Current bootstrap locations and canonical ambiguity

Several copies of the monitored-VM bootstrap script exist. *Confirmed from current source.*

```text
aria-application/scripts/vm-onboarding/bootstrap_monitored_vm.sh
aria-tools-setup/Script that i should inject in VMs to monitor them/bootstrap_monitored_vm.sh
ansible-vm-setup/bootstrap_monitored_vm.sh
```

The first two are byte-identical in the current tree. The `ansible-vm-setup/` copy is newer and supports an `--environment` flag; the Ansible playbook uses that colocated copy.

**A canonical monitored-VM bootstrap script is not formally declared yet.** Review the copies and choose one before execution. Do not mix flags or assumptions between variants.

## Direct bootstrap path

Based only on source-supported behavior:

1. Log in to the monitored VM as root.
2. Copy a reviewed `bootstrap_monitored_vm.sh` to the server.
3. Run it with flags for the components you want:

   ```bash
   bash bootstrap_monitored_vm.sh --all \
     --vm-name <MONITORED_VM_NAME> \
     --ip <MONITORED_VM_IP> \
     --es-ip <BRAIN_VM_IP> \
     --es-user <ELASTICSEARCH_USERNAME> \
     --wazuh-manager <BRAIN_VM_IP> \
     --wazuh-group default
   ```

4. The script reads the Elasticsearch password from the `ARIA_ES_PASSWORD` environment variable. Set it securely; do not pass it on the command line.
5. The script prints a JSON payload ready for `POST /api/v1/assets` with `remediation_enabled=false`.

*Confirmed from current source.*

## Ansible wrapper path

`ansible-vm-setup/playbook.yml` copies its colocated bootstrap script to each monitored VM and runs it. *Confirmed from current source.*

**Security warning:** The current Ansible material contains plaintext credentials in `inventory.ini` and `playbook.yml`. Sanitize and rotate all credentials before production use. Do not commit live inventory or passwords. *Confirmed from current source.*

Example workflow after sanitization:

1. Replace `ansible-vm-setup/inventory.ini` with a vault-encrypted or runtime-injected inventory.
2. Replace hard-coded passwords in `playbook.yml` with encrypted variables or secret references.
3. Run the playbook from the Brain VM or a dedicated control host.

## ARIA asset registration and validation

The bootstrap scripts do **not** automatically register the asset in ARIA. After bootstrap succeeds:

1. Take the JSON payload printed by the script.
2. POST it to:

   ```text
   http://<BRAIN_VM_IP>:8001/api/v1/assets
   ```

   with the admin secret header required by `api/routes/assets.py`. *Confirmed from current source.*

3. Verify the asset appears in the ARIA dashboard.
4. Verify telemetry indices in Elasticsearch:

   ```bash
   curl -k -u <ELASTICSEARCH_USERNAME> \
     "https://<BRAIN_VM_IP>:9200/_cat/indices?v"
   ```

   (requires credentials; do not show them).

## Initial safe state: `remediation_enabled=false`

Both bootstrap payloads and the backend model default to `remediation_enabled=false`. *Confirmed from current source.*

Keep remediation disabled until:

- Ansible and SSH are configured for the asset;
- SSH connectivity and host-key policy are tested;
- Playbook scope and approval workflow are reviewed;
- Backups and rollback procedures are in place.

Only then update the asset to `remediation_enabled=true` deliberately.

## Safe validation checks

### On the monitored VM

```bash
systemctl is-active wazuh-agent
systemctl is-active filebeat
systemctl is-active suricata
systemctl is-active falco-modern-bpf || systemctl is-active falco-bpf || systemctl is-active falco-kmod
systemctl is-active falcosidekick
systemctl is-active telegraf
```

### On the Brain VM

```bash
# Wazuh agent list (requires Wazuh auth)
/var/ossec/bin/agent_control -l

# Elasticsearch indices (requires ES credentials)
curl -k -u <ELASTICSEARCH_USERNAME> \
  "https://<BRAIN_VM_IP>:9200/_cat/indices/<MONITORED_VM_NAME>-*?v"

# ARIA asset list (requires admin secret)
curl -sS http://127.0.0.1:8001/api/v1/assets \
  -H 'X-ARIA-Admin-Secret: <ADMIN_SECRET>'
```

## Decommission limitation

Deleting an ARIA asset removes only the SQLite registry record. It does **not** automatically:

- remove Wazuh Agent, Filebeat, Suricata, Falco, Falcosidekick, or Telegraf from the monitored VM;
- revoke Wazuh enrollment;
- revoke SSH keys or access;
- delete Elasticsearch indices or documents;
- rotate credentials.

Manual cleanup is required. *Confirmed from current source.*

## Wazuh identity validation

Bootstrap variants set `host_name` / `agent_name` differently (some use `VM_NAME`, others use `VM_ENVIRONMENT`). After onboarding, verify the Wazuh agent ID and name in the Wazuh Manager output match the intended `<MONITORED_VM_NAME>`. Reconcile bootstrap variants before scaling onboarding. *Confirmed from current source.*
