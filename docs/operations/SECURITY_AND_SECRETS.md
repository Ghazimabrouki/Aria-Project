# Security and Secrets

This document defines the current security boundaries and safe-handling rules for ARIA. It documents limitations; it does not claim ARIA is production-hardened as-is.

## Never commit

Do not commit any of the following to this repository:

- `.env` files or environment backups.
- Passwords, tokens, API keys, or private keys.
- Live Ansible inventories with credentials.
- Generated runtime data, evidence, or archives.
- Database backups, SQLite files, or Redis dumps.
- TLS private keys or certificate stores.

*Confirmed from current source.*

## `.env` handling

- `.env` is required for deployment but must be created and managed outside version control.
- `scripts/install_brain_vm.sh` checks that a readable `.env` exists beside the canonical Compose file, but it does **not** read, source, print, copy, or modify `.env`.
- Never print `.env` contents in logs, terminal output, screenshots, or documentation.
- `.env.example` exists as a starting point but is incomplete relative to the current `config/settings.py`; reconcile both files when preparing a real environment. *Confirmed from current source.*

## Existing Ansible and historical content

The current repository contains plaintext credentials and disabled security checks that require sanitization before production use. *Confirmed from current source.*

- `ansible-vm-setup/inventory.ini` contains a plaintext password.
- `ansible-vm-setup/playbook.yml` contains a plaintext Elasticsearch password and a hard-coded IP.
- `aria-application/config/ansible_inventory` disables SSH host-key checking.
- `.env.backup.*` files are tracked in the nested Git history and may contain historical secrets.
- `aria-application/response/auth.py` contains a hard-coded JWT signing secret.
- `aria-tools-setup/tools/siem_setup.sh` contains a hard-coded Kibana saved-object encryption key.

Before production use:

- Rotate all passwords, keys, and tokens.
- Remove or vault-encrypt inventories and playbooks.
- Enable SSH host-key verification.
- Replace hard-coded secrets with environment-driven or secret-manager-backed values.
- Review and clean Git history if secrets were ever committed.

## TLS verification

Current scripts and configurations often disable TLS verification (`curl -k`, `elasticsearch.ssl.verificationMode: none`, `insecure_skip_verify=true`, `TLS_MODE=insecure`). This is acceptable only for lab or initial setup; production requires a proper PKI or trusted CA chain. *Confirmed from current source.*

## SSH host-key verification

SSH host-key checking is disabled in current Ansible configuration (`host_key_checking = False`, `StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null`). Re-enable it and maintain known-hosts files before using Ansible in production. *Confirmed from current source.*

## Authorization coverage

Authentication and authorization enforcement is inconsistent across routes. Some detail, action, WebSocket, approval, and monitoring routes lack uniform auth/asset-scope checks. A production review is required. *Confirmed from current source.*

## Exposed ports

The current Compose binds host ports for Redis (`6380`), API (`8001`), and frontend (`3001`). In production:

- Bind Redis to loopback or an internal network only.
- Place the API and frontend behind an authenticated TLS reverse proxy.
- Restrict native service ports (9200, 5601, 1514/1515, 55000) to trusted networks.

*Operational limitation.*

## Mutable image tags

The current Compose uses mutable `latest` tags. Pin to immutable digests or versioned tags for reproducible deployments. *Confirmed from current source.*

## Secrets management

ARIA does **not** currently ship with an integrated secret manager, complete TLS stack, SSO, or enterprise RBAC. Production deployment requires separate provisioning for these controls. *Not confirmed from repository.*

## Safe operational practices

- Run central setup scripts only on the intended Brain VM.
- Review scripts before execution; they can purge packages and change firewall/SSH settings.
- Store backups and evidence on encrypted, access-controlled storage.
- Audit who can access the Brain VM, the `.env` file, and the ARIA data directory.
- Treat the Brain VM as a single high-value target; compromise of this host gives access to telemetry, workflow state, and remediation capability.
