#!/bin/bash

# Detection Rules Setup Script
# Creates Kibana detection rules for SOC monitoring
# Author: Ghazi Mabrouki

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

log() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}$*${NC}"; }
warn() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}$*${NC}"; }
err() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${RED}ERROR: $*${NC}" >&2; }

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    err "Run as root: sudo bash $0"
    exit 1
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "Missing command: $1"; exit 1; }
}

extract_es_credentials() {
  if [[ ! -f /etc/filebeat/filebeat.yml ]]; then
    err "Filebeat config not found. Install SIEM first."
    exit 1
  fi

  ES_HOST="${ARIA_ES_URL:-}"
  ES_USER="${ARIA_ES_USERNAME:-}"
  ES_PASS="${ARIA_ELASTIC_PASSWORD:-}"

  if [[ -z "$ES_HOST" || -z "$ES_USER" || -z "$ES_PASS" ]]; then
    eval "$(python3 - /etc/filebeat/filebeat.yml <<'PY'
import re, shlex, sys
p = sys.argv[1]
lines = open(p, 'r', encoding='utf-8', errors='ignore').read().splitlines()

def find_block(key):
    for i, line in enumerate(lines):
        if re.match(r'^\s*%s\s*:\s*$' % re.escape(key), line):
            base = len(line) - len(line.lstrip())
            out = []
            for l in lines[i+1:]:
                if not l.strip():
                    continue
                ind = len(l) - len(l.lstrip())
                if ind <= base:
                    break
                out.append(l)
            return out
    return []

def scalar(block, key):
    for l in block:
        m = re.match(r'^\s*%s\s*:\s*(.+?)\s*$' % re.escape(key), l)
        if m:
            return m.group(1).strip().strip('"').strip("'")
    return ''

def hosts(block):
    for l in block:
        m = re.match(r'^\s*hosts\s*:\s*(.+?)\s*$', l)
        if m:
            rhs = m.group(1).strip()
            if rhs.startswith('['):
                rhs = rhs.strip('[]')
                parts = [x.strip().strip('"').strip("'") for x in rhs.split(',') if x.strip()]
                return parts[0] if parts else ''
            return rhs.strip('"').strip("'")
    return ''
block = find_block('output.elasticsearch')
print('PARSED_ES_HOST=' + shlex.quote(hosts(block)))
print('PARSED_ES_USER=' + shlex.quote(scalar(block, 'username')))
print('PARSED_ES_PASS=' + shlex.quote(scalar(block, 'password')))
PY
)"
    ES_HOST="${ES_HOST:-$PARSED_ES_HOST}"
    ES_USER="${ES_USER:-$PARSED_ES_USER}"
    ES_PASS="${ES_PASS:-$PARSED_ES_PASS}"
  fi

  if [[ -z "$ES_HOST" ]]; then
    ES_HOST="127.0.0.1:9200"
  fi

  if [[ "$ES_HOST" != http* ]]; then
    ES_HOST="https://${ES_HOST}"
  fi

  if [[ -z "$ES_USER" ]]; then
    ES_USER="elastic"
  fi

  if [[ -z "$ES_PASS" ]]; then
    err "Could not extract Elasticsearch password from filebeat.yml"
    exit 1
  fi

  ES_URL="$ES_HOST"
  log "Elasticsearch: $ES_URL"
  log "User: $ES_USER"
}

detect_kibana() {
  local_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  local candidates=("https://${local_ip}:5601" "https://127.0.0.1:5601" "https://localhost:5601")

  for candidate in "${candidates[@]}"; do
    for _ in {1..10}; do
      if curl -sk -u "${ES_USER}:${ES_PASS}" "${candidate}/api/status" 2>/dev/null | grep -q '"version"'; then
        KIBANA_URL="$candidate"
        log "Kibana detected: $KIBANA_URL"
        return 0
      fi
      sleep 2
    done
  done

  err "Kibana not reachable. Install Kibana first."
  exit 1
}

curl_es() {
  curl -sk -u "${ES_USER}:${ES_PASS}" "$@"
}

curl_kibana() {
  curl -sk -u "${ES_USER}:${ES_PASS}" -H 'kbn-xsrf: true' "$@"
}

check_detection_rules_exist() {
  local rule_name="$1"
  response=$(curl_kibana "${KIBANA_URL}/api/detection_engine/rules?prepackaged=true" 2>/dev/null || echo "[]")
  if echo "$response" | grep -q "$rule_name"; then
    return 0
  fi
  return 1
}

create_detection_rule() {
  local name="$1"
  local description="$2"
  local query="$3"
  local risk_score="$4"
  local interval="$5"
  local rule_id="$6"
  local severity="low"

  if [[ "$risk_score" -ge 80 ]]; then
    severity="high"
  elif [[ "$risk_score" -ge 60 ]]; then
    severity="medium"
  fi

  log "Creating detection rule: $name"

  local payload=$(cat <<EOF
{
  "name": "$name",
  "description": "$description",
  "risk_score": $risk_score,
  "severity": "$severity",
  "rule_id": "$rule_id",
  "type": "query",
  "query": "$query",
  "interval": "$interval",
  "enabled": true,
  "tags": ["SOC", "Security"],
  "threat": [],
  "references": [],
  "false_positives": [],
  "license": "Elastic License"
}
EOF
)

  response=$(curl_kibana -X POST "${KIBANA_URL}/api/detection_engine/rules" \
    -H "Content-Type: application/json" \
    -d "$payload" 2>/dev/null || true)

  if echo "$response" | grep -qi "error"; then
    warn "Rule '$name' may already exist or creation failed"
  else
    log "Rule '$name' created successfully"
  fi
}

create_index_pattern() {
  local index_pattern="$1"
  local title="$2"

  log "Creating index pattern: $title"

  local payload=$(cat <<EOF
{
  "attributes": {
    "title": "$title",
    "timeFieldName": "@timestamp"
  }
}
EOF
)

  response=$(curl_kibana -X POST "${KIBANA_URL}/api/saved_objects/index-pattern/${index_pattern}" \
    -H "Content-Type: application/json" \
    -d "$payload" 2>/dev/null || true)
}

enable_siem() {
  log "Checking Elastic Security API..."

  local status
  status=$(curl_kibana -o /dev/null -w '%{http_code}' "${KIBANA_URL}/api/detection_engine/rules/_find?page=1&per_page=1" 2>/dev/null || true)
  if [[ "$status" == "200" ]]; then
    log "Elastic Security detection API is reachable"
  else
    warn "Elastic Security detection API returned HTTP ${status:-unknown}; continuing because rule creation may still initialize it."
  fi
}

create_ssh_bruteforce_rule() {
  create_detection_rule \
    "SSH Brute Force Detection" \
    "Detects multiple failed SSH authentication attempts from the same source IP" \
    "event.category:authentication AND event.outcome:failure AND process.name:sshd" \
    "70" \
    "5m" \
    "ssh-bruteforce-detection"
}

create_successful_login_rule() {
  create_detection_rule \
    "Successful Login Detection" \
    "Detects successful authentication events" \
    "event.category:authentication AND event.outcome:success" \
    "50" \
    "5m" \
    "successful-login-detection"
}

create_privilege_escalation_rule() {
  create_detection_rule \
    "Privilege Escalation Detection" \
    "Detects sudo privilege escalation attempts" \
    "event.action:sudo_exec OR message:session opened" \
    "80" \
    "5m" \
    "privilege-escalation-detection"
}

create_suspicious_user_creation_rule() {
  create_detection_rule \
    "Suspicious User Creation Detection" \
    "Detects creation of new user accounts" \
    "event.action:user_created OR (process.name:useradd AND host.os.family:debian)" \
    "70" \
    "5m" \
    "suspicious-user-creation-detection"
}

create_credential_access_rule() {
  create_detection_rule \
    "Credential Access Detection" \
    "Detects access to sensitive credential files" \
    "file.path:/etc/shadow OR file.path:/etc/passwd" \
    "80" \
    "5m" \
    "credential-access-detection"
}

create_persistence_login_rule() {
  create_detection_rule \
    "Persistence Login Detection" \
    "Detects login from suspicious/known backdoor accounts" \
    "user.name:backdoor AND event.category:authentication AND event.outcome:success" \
    "80" \
    "5m" \
    "persistence-login-detection"
}

verify_rules() {
  log "Verifying detection rules..."
  sleep 5

  local response count
  response=$(curl_kibana "${KIBANA_URL}/api/detection_engine/rules/_find?page=1&per_page=100&sort_field=created_at&sort_order=desc" 2>/dev/null || true)
  count=$(RESPONSE="$response" python3 - <<'PY'
import json, os
raw = os.environ.get("RESPONSE", "").strip()
try:
    obj = json.loads(raw) if raw else {}
except Exception:
    print("0")
    raise SystemExit
if isinstance(obj, dict):
    if isinstance(obj.get("total"), int):
        print(obj["total"])
    elif isinstance(obj.get("data"), list):
        print(len(obj["data"]))
    else:
        print("0")
else:
    print("0")
PY
)

  if [[ "$count" =~ ^[0-9]+$ && "$count" -gt 0 ]]; then
    log "Detection rules verified: $count rules active"
  else
    warn "Rules were submitted, but verification did not return a rule count. Check Kibana manually."
    warn "Verification response: ${response:-<empty>}"
  fi

  return 0
}

main() {
  require_root
  need_cmd curl
  need_cmd python3

  log "============================================"
  log "Detection Rules Setup"
  log "============================================"

  extract_es_credentials
  detect_kibana
  enable_siem

  log "Creating detection rules..."

  create_ssh_bruteforce_rule
  create_successful_login_rule
  create_privilege_escalation_rule
  create_suspicious_user_creation_rule
  create_credential_access_rule
  create_persistence_login_rule

  verify_rules

  log "============================================"
  log "Detection Rules Setup Complete!"
  log "============================================"
  echo ""
  log "View rules in Kibana: ${KIBANA_URL}/app/security/detections"
  echo ""
}

main "$@"