#!/bin/bash
#
# ARIA Brain VM installer wrapper.
#
# Sequence:
#   Existing central tools setup runner
#   -> validate central native services
#   -> validate ARIA .env exists
#   -> deploy ARIA (Docker Compose OR code-based start.sh)
#   -> validate ARIA services, Redis, frontend, and API health
#
# Deployment mode:
#   - Docker Compose (default): requires aria-application/docker-compose.yml
#   - Code-based: set ARIA_CODE_DIR to a directory containing .env and start.sh
#
# This script must only be run on the intended Brain VM. It performs no cloud
# provisioning, no monitored-VM onboarding, no Ansible execution, no asset
# registration, and no secret generation.

set -Eeuo pipefail

REQUIRED_CONFIRMATION="I_UNDERSTAND_THIS_CONFIGURES_THE_BRAIN_VM"

# -----------------------------------------------------------------------------
# Error handling
# -----------------------------------------------------------------------------

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

print_diagnostics() {
  echo
  echo "Diagnostic commands (run only on the Brain VM):"
  echo "  systemctl status elasticsearch kibana filebeat suricata wazuh-manager falcosidekick telegraf fail2ban"
  echo "  systemctl status falco-modern-bpf falco-bpf falco-kmod || true"
  echo "  journalctl -u elasticsearch -u kibana -u wazuh-manager --no-pager -n 200"
  if [[ "$DEPLOY_MODE" == "code" ]]; then
    echo "  tail -n 200 /var/log/aria/api.log"
    echo "  tail -n 200 /var/log/aria/main.log"
  else
    echo "  docker compose -f <compose-file> ps"
    echo "  docker compose -f <compose-file> logs --tail=200 api worker redis frontend"
  fi
  echo
  echo "Do not print .env contents, credentials, or bootstrap data."
}

cleanup_on_error() {
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    echo
    echo "Brain VM installer failed with exit code $rc."
    print_diagnostics
  fi
}
trap cleanup_on_error EXIT

# -----------------------------------------------------------------------------
# Resolve repository layout
# -----------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PRIMARY_TOOLS_RUNNER="${REPO_ROOT}/aria-tools-setup/tools/setup_script_telegraf.sh"
PRIMARY_COMPOSE_FILE="${REPO_ROOT}/aria-application/docker-compose.yml"
FALLBACK_TOOLS_RUNNER="${REPO_ROOT}/Aria_Tools_SetUp/tools/setup_script_telegraf.sh"
FALLBACK_COMPOSE_FILE="${REPO_ROOT}/Front_end + back_end/docker-compose.yml"

TOOLS_RUNNER=""
COMPOSE_FILE=""

if [[ -f "$PRIMARY_TOOLS_RUNNER" && -f "$PRIMARY_COMPOSE_FILE" ]]; then
  TOOLS_RUNNER="$PRIMARY_TOOLS_RUNNER"
  COMPOSE_FILE="$PRIMARY_COMPOSE_FILE"
fi

if [[ -f "$FALLBACK_TOOLS_RUNNER" && -f "$FALLBACK_COMPOSE_FILE" ]]; then
  if [[ -z "$TOOLS_RUNNER" ]]; then
    TOOLS_RUNNER="$FALLBACK_TOOLS_RUNNER"
    COMPOSE_FILE="$FALLBACK_COMPOSE_FILE"
  else
    # Both layouts exist: the relevant files must be identical.
    if ! cmp -s "$PRIMARY_TOOLS_RUNNER" "$FALLBACK_TOOLS_RUNNER"; then
      fail "Both primary and fallback tool runners exist and differ:\n  ${PRIMARY_TOOLS_RUNNER}\n  ${FALLBACK_TOOLS_RUNNER}"
    fi
    if ! cmp -s "$PRIMARY_COMPOSE_FILE" "$FALLBACK_COMPOSE_FILE"; then
      fail "Both primary and fallback Compose files exist and differ:\n  ${PRIMARY_COMPOSE_FILE}\n  ${FALLBACK_COMPOSE_FILE}"
    fi
  fi
fi

if [[ -z "$TOOLS_RUNNER" ]]; then
  fail "Could not find a valid Brain VM setup runner.\n" \
       "Tried:\n  ${PRIMARY_TOOLS_RUNNER}\n  ${FALLBACK_TOOLS_RUNNER}"
fi

# Resolve ARIA deployment target: Docker Compose (default) or code-based start.sh
ARIA_CODE_DIR="${ARIA_CODE_DIR:-}"
CODE_START_SCRIPT=""
if [[ -n "$ARIA_CODE_DIR" ]]; then
  ARIA_CODE_DIR="$(cd "$ARIA_CODE_DIR" && pwd)"
  if [[ -f "${ARIA_CODE_DIR}/.env" && -f "${ARIA_CODE_DIR}/start.sh" ]]; then
    CODE_START_SCRIPT="${ARIA_CODE_DIR}/start.sh"
  else
    fail "ARIA_CODE_DIR is set but missing .env or start.sh: ${ARIA_CODE_DIR}"
  fi
fi

COMPOSE_DIR=""
if [[ -n "$COMPOSE_FILE" ]]; then
  COMPOSE_DIR="$(dirname "$COMPOSE_FILE")"
fi

DEPLOY_MODE=""
if [[ -n "$CODE_START_SCRIPT" && -n "$COMPOSE_DIR" ]]; then
  # Both available: prefer code-based when ARIA_CODE_DIR is explicitly provided.
  DEPLOY_MODE="code"
elif [[ -n "$CODE_START_SCRIPT" ]]; then
  DEPLOY_MODE="code"
elif [[ -n "$COMPOSE_DIR" ]]; then
  DEPLOY_MODE="compose"
else
  fail "No ARIA deployment target found. Set ARIA_CODE_DIR for code-based deployment or ensure a docker-compose.yml exists."
fi

# -----------------------------------------------------------------------------
# Validate execution environment
# -----------------------------------------------------------------------------

if [[ "$(uname -s)" != "Linux" ]]; then
  fail "This installer supports Linux only."
fi

if [[ "$(id -u)" -ne 0 ]]; then
  fail "This installer must run as root."
fi

if [[ ! -d /run/systemd/system ]]; then
  fail "systemd does not appear to be running."
fi

for cmd in bash id hostname systemctl curl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    fail "Required command not found: $cmd"
  fi
done

if [[ "$DEPLOY_MODE" == "compose" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    fail "Docker is required for compose deployment mode."
  fi
  if ! docker compose version >/dev/null 2>&1; then
    fail "Docker Compose plugin not found. Ensure 'docker compose' works."
  fi
fi

# -----------------------------------------------------------------------------
# Display host information for operator confirmation
# -----------------------------------------------------------------------------

HOSTNAME="$(hostname -s 2>/dev/null || hostname)"
PRIMARY_ADDRESS="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"

if [[ -z "$PRIMARY_ADDRESS" ]]; then
  PRIMARY_ADDRESS="$(ip route get 1 2>/dev/null | awk '/src/ {print $7; exit}' || true)"
fi

echo "ARIA Brain VM installer"
echo "  Hostname: ${HOSTNAME}"
echo "  Detected primary address: ${PRIMARY_ADDRESS:-<unknown>}"
echo "  Tools runner: ${TOOLS_RUNNER}"
echo "  Deployment mode: ${DEPLOY_MODE}"
if [[ "$DEPLOY_MODE" == "code" ]]; then
  echo "  Code-based dir: ${ARIA_CODE_DIR}"
  echo "  Start script:   ${CODE_START_SCRIPT}"
else
  echo "  Compose file:   ${COMPOSE_FILE}"
fi
echo

# -----------------------------------------------------------------------------
# Reject partial-installation flags
# -----------------------------------------------------------------------------

PARTIAL_FLAGS=(
  INSTALL_SIEM
  INSTALL_SURICATA
  INSTALL_WAZUH
  INSTALL_FALCO
  INSTALL_TELEGRAF
  INSTALL_DETECTION_RULES
  INSTALL_HARDENING
)

for flag in "${PARTIAL_FLAGS[@]}"; do
  value="${!flag:-1}"
  if [[ "$value" != "1" ]]; then
    fail "Partial installation is not supported by this wrapper.\n" \
         "Unset or set ${flag}=1. Current value: ${value}"
  fi
done

# -----------------------------------------------------------------------------
# Require explicit destructive confirmation
# -----------------------------------------------------------------------------

echo "This installer will:"
echo "  1. Run the existing central tools setup runner (may install, purge, reconfigure, start, stop, or harden services)."
echo "  2. Validate central native services."
if [[ "$DEPLOY_MODE" == "code" ]]; then
  echo "  3. Require a readable .env file in ${ARIA_CODE_DIR}."
  echo "  4. Run the code-based start script: ${CODE_START_SCRIPT}."
  echo "  5. Validate ARIA processes, Redis, API health, and frontend response."
else
  echo "  3. Require a readable .env file beside ${COMPOSE_FILE}."
  echo "  4. Run 'docker compose pull' and 'docker compose up -d' in ${COMPOSE_DIR}."
  echo "  5. Validate ARIA containers, Redis, API health, and frontend response."
fi
echo
echo "Type the following phrase exactly to continue:"
echo "  ${REQUIRED_CONFIRMATION}"
read -r -p "Confirmation: " user_confirmation

if [[ "$user_confirmation" != "$REQUIRED_CONFIRMATION" ]]; then
  fail "Confirmation phrase did not match. Aborting."
fi

# -----------------------------------------------------------------------------
# Run the existing central tools runner
# -----------------------------------------------------------------------------

echo "Running central tools setup runner: ${TOOLS_RUNNER}"
if ! bash "$TOOLS_RUNNER"; then
  fail "Central tools setup runner failed."
fi

# -----------------------------------------------------------------------------
# Validate native services
# -----------------------------------------------------------------------------

echo "Validating central native services..."

REQUIRED_SERVICES=(
  elasticsearch
  kibana
  filebeat
  suricata
  wazuh-manager
  falcosidekick
  telegraf
  fail2ban
)

for svc in "${REQUIRED_SERVICES[@]}"; do
  if ! systemctl is-active --quiet "$svc"; then
    fail "Required service is not active: $svc"
  fi
  echo "  OK: $svc"
done

FALCO_UNITS=(falco-modern-bpf falco-bpf falco-kmod)
FALCO_ACTIVE_COUNT=0
for unit in "${FALCO_UNITS[@]}"; do
  if systemctl is-active --quiet "$unit"; then
    ((FALCO_ACTIVE_COUNT++)) || true
    echo "  OK: $unit"
  fi
done

if [[ "$FALCO_ACTIVE_COUNT" -ne 1 ]]; then
  fail "Expected exactly one active Falco unit (${FALCO_UNITS[*]}); found ${FALCO_ACTIVE_COUNT}."
fi

# -----------------------------------------------------------------------------
# Validate ARIA .env exists
# -----------------------------------------------------------------------------

if [[ "$DEPLOY_MODE" == "code" ]]; then
  ENV_FILE="${ARIA_CODE_DIR}/.env"
else
  ENV_FILE="${COMPOSE_DIR}/.env"
fi
if [[ ! -r "$ENV_FILE" ]]; then
  fail "ARIA .env file is missing or not readable: ${ENV_FILE}"
fi
echo "ARIA .env file exists: ${ENV_FILE}"
echo "  (The installer does not read, source, print, copy, or modify .env.)"

# -----------------------------------------------------------------------------
# Deploy ARIA
# -----------------------------------------------------------------------------

if [[ "$DEPLOY_MODE" == "code" ]]; then
  echo "Starting code-based ARIA from ${ARIA_CODE_DIR}..."
  (
    cd "$ARIA_CODE_DIR"
    bash "$CODE_START_SCRIPT"
  )

  echo "Validating ARIA processes..."

  if ! pgrep -f "uvicorn.*8001" >/dev/null 2>&1; then
    fail "ARIA API (uvicorn on port 8001) is not running."
  fi
  echo "  OK: ARIA API process found"

  if ! pgrep -f "python3 main.py" >/dev/null 2>&1; then
    fail "ARIA background services (main.py) are not running."
  fi
  echo "  OK: ARIA background services found"

  if command -v redis-cli >/dev/null 2>&1; then
    REDIS_PING="$(redis-cli ping 2>/dev/null || true)"
    if [[ "$REDIS_PING" != "PONG" ]]; then
      fail "Redis did not respond to PING: ${REDIS_PING}"
    fi
    echo "  OK: redis ping -> PONG"
  else
    if ! systemctl is-active --quiet redis-server 2>/dev/null && ! systemctl is-active --quiet redis 2>/dev/null; then
      fail "Redis service is not active."
    fi
    echo "  OK: redis service active"
  fi
else
  echo "Deploying ARIA Compose stack from ${COMPOSE_DIR}..."
  (
    cd "$COMPOSE_DIR"
    docker compose pull
    docker compose up -d
  )

  echo "Validating ARIA Compose containers..."
  (
    cd "$COMPOSE_DIR"

    docker compose ps

    RUNNING_SERVICES="$(docker compose ps --services --status running | sort)"
    if [[ -z "$RUNNING_SERVICES" ]]; then
      fail "No Compose services are running."
    fi

    REQUIRED_COMPOSE_SERVICES=(redis api worker frontend)
    for svc in "${REQUIRED_COMPOSE_SERVICES[@]}"; do
      if ! echo "$RUNNING_SERVICES" | grep -qx "$svc"; then
        fail "Required Compose service is not running: $svc"
      fi
      echo "  OK: $svc"
    done

    REDIS_PING="$(docker compose exec -T redis redis-cli ping)"
    if [[ "$REDIS_PING" != "PONG" ]]; then
      fail "Redis did not respond to PING: ${REDIS_PING}"
    fi
    echo "  OK: redis ping -> PONG"
  )
fi

# -----------------------------------------------------------------------------
# Validate API health
# -----------------------------------------------------------------------------

echo "Waiting for API health..."
API_HEALTH_URL="http://127.0.0.1:8001/health"
API_READY=false
for attempt in {1..30}; do
  if curl -fsS "$API_HEALTH_URL" >/dev/null 2>&1; then
    API_READY=true
    break
  fi
  echo "  API not ready yet (attempt ${attempt}/30)..."
  sleep 2
done

if [[ "$API_READY" != "true" ]]; then
  fail "API health endpoint did not become ready: ${API_HEALTH_URL}"
fi
echo "  OK: API health"

# -----------------------------------------------------------------------------
# Validate frontend response
# -----------------------------------------------------------------------------

echo "Checking frontend response..."
FRONTEND_URL="http://127.0.0.1:3001"
FRONTEND_STATUS="$(curl -sS -o /dev/null -w '%{http_code}' "$FRONTEND_URL" || true)"
if [[ "$FRONTEND_STATUS" != "200" && "$FRONTEND_STATUS" != "307" ]]; then
  fail "Frontend did not respond as expected at ${FRONTEND_URL} (status: ${FRONTEND_STATUS:-none})."
fi
echo "  OK: frontend responded (status ${FRONTEND_STATUS})"

# -----------------------------------------------------------------------------
# Final safe information
# -----------------------------------------------------------------------------

echo
echo "ARIA Brain VM installation appears successful."
echo
echo "Access placeholders:"
echo "  Dashboard:  http://${PRIMARY_ADDRESS:-<BRAIN_VM_IP>}:3001"
echo "  API health: http://127.0.0.1:8001/health"
echo "  API docs:   http://127.0.0.1:8001/docs"
echo "  Kibana:     https://${PRIMARY_ADDRESS:-<BRAIN_VM_IP>}:5601  (depending on host/network/TLS configuration)"
echo
if [[ "$DEPLOY_MODE" == "code" ]]; then
  echo "Deployment type: code-based (bare processes)"
  echo "  Logs: /var/log/aria/api.log and /var/log/aria/main.log"
else
  echo "Deployment type: Docker Compose"
  echo "  Logs: docker compose logs"
fi
echo
echo "Next steps:"
echo "  1. Validate native services and ARIA using docs/operations/VALIDATION_AND_TROUBLESHOOTING.md."
echo "  2. Onboard monitored VMs separately using docs/deployment/MONITORED_VM_ONBOARDING.md."
echo "  3. Keep remediation disabled until Ansible/SSH is intentionally validated."
echo
