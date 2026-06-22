#!/bin/bash
#
# ARIA Brain VM installer wrapper.
#
# Sequence:
#   Existing central tools setup runner
#   -> validate central native services
#   -> validate ARIA .env exists
#   -> docker compose pull
#   -> docker compose up -d
#   -> validate ARIA containers, Redis, frontend, and API health
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
  echo "  docker compose -f <compose-file> ps"
  echo "  docker compose -f <compose-file> logs --tail=200 api worker redis frontend"
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
  fail "Could not find a valid Brain VM setup runner and Compose file pair.\n" \
       "Tried:\n  ${PRIMARY_TOOLS_RUNNER} + ${PRIMARY_COMPOSE_FILE}\n" \
       "  ${FALLBACK_TOOLS_RUNNER} + ${FALLBACK_COMPOSE_FILE}"
fi

COMPOSE_DIR="$(dirname "$COMPOSE_FILE")"

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

for cmd in bash id hostname systemctl curl docker; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    fail "Required command not found: $cmd"
  fi
done

if ! docker compose version >/dev/null 2>&1; then
  fail "Docker Compose plugin not found. Ensure 'docker compose' works."
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
echo "  Compose file: ${COMPOSE_FILE}"
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
echo "  3. Require a readable .env file beside ${COMPOSE_FILE}."
echo "  4. Run 'docker compose pull' and 'docker compose up -d' in ${COMPOSE_DIR}."
echo "  5. Validate ARIA containers, Redis, API health, and frontend response."
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

ENV_FILE="${COMPOSE_DIR}/.env"
if [[ ! -r "$ENV_FILE" ]]; then
  fail "ARIA .env file is missing or not readable: ${ENV_FILE}"
fi
echo "ARIA .env file exists: ${ENV_FILE}"
echo "  (The installer does not read, source, print, copy, or modify .env.)"

# -----------------------------------------------------------------------------
# Deploy ARIA Compose stack
# -----------------------------------------------------------------------------

echo "Deploying ARIA Compose stack from ${COMPOSE_DIR}..."
(
  cd "$COMPOSE_DIR"
  docker compose pull
  docker compose up -d
)

# -----------------------------------------------------------------------------
# Validate Compose containers
# -----------------------------------------------------------------------------

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
echo "Next steps:"
echo "  1. Validate native services and containers using docs/operations/VALIDATION_AND_TROUBLESHOOTING.md."
echo "  2. Onboard monitored VMs separately using docs/deployment/MONITORED_VM_ONBOARDING.md."
echo "  3. Keep remediation disabled until Ansible/SSH is intentionally validated."
echo
