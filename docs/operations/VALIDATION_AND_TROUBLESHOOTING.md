# Validation and Troubleshooting

This guide contains safe, source-backed operational checks. It does not include destructive commands, remediation actions, or service restarts.

When a check requires credentials, the command is shown with placeholders only. Never log or display real passwords, tokens, or keys.

## Elasticsearch

```bash
systemctl is-active elasticsearch
journalctl -u elasticsearch --no-pager -n 200
```

Cluster health (requires credentials):

```bash
curl -k -u <ELASTICSEARCH_USERNAME> https://127.0.0.1:9200/_cluster/health
```

Expected indices include `wazuh-alerts-*`, `filebeat-*`, `falco-*`, `telegraf-*`, `system-auth-*`, `system-syslog-*`. *Confirmed from current source.*

## Kibana

```bash
systemctl is-active kibana
journalctl -u kibana --no-pager -n 200
```

Reachability (HTTPS, port 5601):

```bash
curl -k https://127.0.0.1:5601/api/status
```

## Wazuh Manager

```bash
systemctl is-active wazuh-manager
journalctl -u wazuh-manager --no-pager -n 200
```

Agent list (requires Wazuh auth):

```bash
/var/ossec/bin/agent_control -l
```

## Filebeat

```bash
systemctl is-active filebeat
journalctl -u filebeat --no-pager -n 200
```

List enabled modules:

```bash
filebeat modules list
```

## Suricata

```bash
systemctl is-active suricata
journalctl -u suricata --no-pager -n 200
```

Check EVE log exists:

```bash
ls -l /var/log/suricata/eve.json
```

## Falco and Falcosidekick

Falco may use one of several service names. Check all:

```bash
systemctl is-active falco-modern-bpf || echo "modern-bpf not active"
systemctl is-active falco-bpf || echo "bpf not active"
systemctl is-active falco-kmod || echo "kmod not active"
systemctl is-active falcosidekick
journalctl -u falcosidekick --no-pager -n 200
```

*Confirmed from current source.*

## Telegraf

```bash
systemctl is-active telegraf
journalctl -u telegraf --no-pager -n 200
telegraf --config /etc/telegraf/telegraf.conf --test
```

## Redis

```bash
docker compose -f aria-application/docker-compose.yml exec -T redis redis-cli ping
```

Expected response: `PONG`.

## ARIA API

```bash
curl http://127.0.0.1:8001/health
curl http://127.0.0.1:8001/api/v1/health
curl http://127.0.0.1:8001/docs
```

Logs:

```bash
docker compose -f aria-application/docker-compose.yml logs --tail=200 api
```

## ARIA worker

The worker has no exposed port. Validate it through logs and container state:

```bash
docker compose -f aria-application/docker-compose.yml ps worker
docker compose -f aria-application/docker-compose.yml logs --tail=200 worker
```

Healthy signs: recurring poll cycles, no uncaught exceptions, heartbeat entries.

## ARIA frontend

```bash
curl -I http://127.0.0.1:3001
```

Logs:

```bash
docker compose -f aria-application/docker-compose.yml logs --tail=200 frontend
```

## Compose-wide status

```bash
docker compose -f aria-application/docker-compose.yml ps
docker compose -f aria-application/docker-compose.yml ps --services --status running
```

Expected running services: `redis`, `api`, `worker`, `frontend`. *Confirmed from current source.*

## Monitored VM sources

On a monitored VM:

```bash
systemctl is-active wazuh-agent
systemctl is-active filebeat
systemctl is-active suricata
systemctl is-active falco-modern-bpf || systemctl is-active falco-bpf || systemctl is-active falco-kmod
systemctl is-active falcosidekick
systemctl is-active telegraf
```

Check bootstrap log:

```bash
tail -n 200 /var/log/aria-monitored-vm-setup.log
```

## Onboarding validation

After registering an asset:

1. Confirm the asset exists in ARIA (requires admin secret):

   ```bash
   curl -sS http://127.0.0.1:8001/api/v1/assets \
     -H 'X-ARIA-Admin-Secret: <ADMIN_SECRET>'
   ```

2. Confirm indices appear in Elasticsearch (requires credentials):

   ```bash
   curl -k -u <ELASTICSEARCH_USERNAME> \
     "https://127.0.0.1:9200/_cat/indices/<MONITORED_VM_NAME>-*?v"
   ```

3. Confirm `remediation_enabled` is `false` until Ansible/SSH is intentionally validated.

## Common failures and log locations

| Symptom | Likely cause | Log/check |
|---|---|---|
| Elasticsearch not active | RAM, TLS/cert mismatch, prior install conflict | `journalctl -u elasticsearch`, `/var/log/elasticsearch/` |
| Kibana not active | ES unreachable, TLS/cert issue | `journalctl -u kibana` |
| Wazuh agent not connecting | Wrong manager IP, firewall, enrollment closed | `/var/ossec/logs/ossec.log`, `agent_control -l` |
| Filebeat no indices | Wrong ES credentials/TLS, module not enabled | `journalctl -u filebeat`, `filebeat test output` |
| Suricata no EVE | Wrong interface, no traffic | `/var/log/suricata/`, `systemctl status suricata` |
| Falco events missing | Driver not loaded, sidekick misconfigured | `journalctl -u falco-*`, `journalctl -u falcosidekick` |
| Telegraf no metrics | ES output credentials/TLS | `journalctl -u telegraf`, `telegraf --test` |
| API unhealthy | `.env` missing, Redis down, DB path issue | `docker compose logs api` |
| Worker not processing | ES unreachable, `.env` misconfiguration | `docker compose logs worker` |
| Frontend blank | API unreachable, CORS mismatch | `docker compose logs frontend`, browser dev tools |
| Redis connection refused | Container not ready, host port conflict | `docker compose logs redis`, `redis-cli -p 6380 ping` |

## Commands that require credentials

The following checks need real credentials but must never expose them in command history or logs:

- Elasticsearch cluster health and index queries.
- Kibana API with authentication.
- Wazuh manager API (`/security/user/authenticate`).
- ARIA admin-secret protected routes.

Use environment variables or secure credential files with restrictive permissions; avoid typing secrets on the command line.
