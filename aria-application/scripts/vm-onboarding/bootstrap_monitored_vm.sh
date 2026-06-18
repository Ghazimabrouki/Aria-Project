#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARIA_TEST_MODE="${ARIA_TEST_MODE:-0}"
ARIA_TEST_ROOT="${ARIA_TEST_ROOT:-}"
LOG_FILE="/var/log/aria-monitored-vm-setup.log"
TS="$(date +%Y%m%d_%H%M%S)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

VM_NAME="${VM_NAME:-}"
VM_ENVIRONMENT="${VM_ENVIRONMENT:-}"
VM_IP="${VM_IP:-}"
ES_IP="${ES_IP:-}"
ES_URL="${ES_URL:-}"
ES_USER="${ES_USER:-elastic}"
ENV_ES_PASSWORD="${ES_PASS:-${ARIA_ES_PASSWORD:-}}"
ES_PASSWORD=""
ES_CA="${ARIA_ES_CA:-}"
TLS_MODE="${TLS_MODE:-insecure}"
APT_LOCK_TIMEOUT="${APT_LOCK_TIMEOUT:-600}"
APT_LOCK_POLL_INTERVAL="${APT_LOCK_POLL_INTERVAL:-10}"
WAZUH_MANAGER="${WAZUH_MANAGER:-}"
WAZUH_GROUP="${WAZUH_GROUP:-default}"
WAZUH_AGENT_VERSION="${WAZUH_AGENT_VERSION:-4.5.4-1}"
WAZUH_ALLOW_DOWNGRADE="${WAZUH_ALLOW_DOWNGRADE:-0}"
WAZUH_REINSTALL="${WAZUH_REINSTALL:-0}"
WAZUH_CHOICE="${WAZUH_CHOICE:-}"
MONITOR_IFACE="${SURICATA_INTERFACE:-}"
ASSUME_YES="${ASSUME_YES:-0}"
MONITORED_VM_CONFIRM="${MONITORED_VM_CONFIRM:-}"
CHANGE_HOSTNAME=""

COMPONENT_ARG_SEEN=0
INSTALL_WAZUH=1
INSTALL_FILEBEAT=1
INSTALL_SURICATA=1
INSTALL_FALCO=1
INSTALL_TELEGRAF=1

FALCO_SERVICE=""
CURRENT_COMPONENT=""
FILEBEAT_COMPLETED=0
WAZUH_COMPLETED=0
SURICATA_COMPLETED=0
FALCO_COMPLETED=0
TELEGRAF_COMPLETED=0
CENTRAL_CONFIRM_PHRASE="I_UNDERSTAND_THIS_IS_A_MONITORED_VM"

usage() {
  cat <<USAGE
Usage:
  sudo bash ${SCRIPT_NAME} [options]

Options:
  --vm-name NAME          Monitored VM name, lowercase [a-z0-9_-]+.
  --environment ENV      Environment tag (e.g. safe, prod, dmz). Default: safe
  --ip IP                VM IP address. Auto-detected if omitted.
  --es-ip IP             Central Elasticsearch IP or host.
  --es-url URL           Central Elasticsearch URL. Default: https://<es-ip>:9200
  --es-user USER         Elasticsearch username. Default: elastic
  --es-ca PATH           Optional Elasticsearch CA certificate path.
  --wazuh-manager HOST   Wazuh Manager IP or host. Default: --es-ip/ES URL host
  --wazuh-group GROUP    Wazuh Agent group. Default: default
  --wazuh-version VER    Wazuh Agent package version. Default: ${WAZUH_AGENT_VERSION}
  --allow-wazuh-downgrade
                         Allow downgrading an existing newer Wazuh Agent.
  --reinstall-wazuh      Reinstall Wazuh Agent even if it is already installed.
  --interface IFACE      Suricata capture interface. Default: default route interface
  --apt-lock-timeout SECONDS
                         Wait time for apt/dpkg locks. Default: ${APT_LOCK_TIMEOUT}
  --yes                  Non-interactive mode. Requires ARIA_ES_PASSWORD.

Component selection:
  --all                  Install all monitored-VM components. Default.
  --wazuh                Install only selected components; include Wazuh Agent.
  --filebeat             Install only selected components; include Filebeat.
  --suricata             Install only selected components; include Suricata.
  --falco                Install only selected components; include Falco/Falcosidekick.
  --telegraf             Install only selected components; include Telegraf.

Password handling:
  Interactive mode prompts silently for the Elasticsearch password.
  Non-interactive mode reads it only from ARIA_ES_PASSWORD.
USAGE
}

log() { echo -e "${BLUE}[$(date '+%F %T')]${NC} $*"; }
ok() { echo -e "${GREEN}[$(date '+%F %T')] OK:${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date '+%F %T')] WARN:${NC} $*"; }
fail() { echo -e "${RED}[$(date '+%F %T')] ERROR:${NC} $*" >&2; exit 1; }

is_test_mode() {
  [[ "${ARIA_TEST_MODE}" == "1" ]]
}

require_safe_test_root() {
  if ! is_test_mode; then
    return
  fi
  [[ -n "$ARIA_TEST_ROOT" ]] || fail "ARIA_TEST_ROOT is required when ARIA_TEST_MODE=1."
  [[ "$ARIA_TEST_ROOT" != "/" ]] || fail "ARIA_TEST_ROOT cannot be /."
  ARIA_TEST_ROOT="${ARIA_TEST_ROOT%/}"
  LOG_FILE="${ARIA_TEST_ROOT}/var/log/aria-monitored-vm-setup.log"
  mkdir -p "${ARIA_TEST_ROOT}/etc" "${ARIA_TEST_ROOT}/var/log" "${ARIA_TEST_ROOT}/tmp" \
    "${ARIA_TEST_ROOT}/usr/local/bin" "${ARIA_TEST_ROOT}/usr/share/keyrings"
}

sandbox_path() {
  local path="$1"
  if is_test_mode && [[ "$path" == /* ]]; then
    printf '%s%s' "$ARIA_TEST_ROOT" "$path"
  else
    printf '%s' "$path"
  fi
}

assert_mocked_command() {
  local cmd="$1"
  local resolved
  case "$cmd" in
    apt|apt-get|systemctl|dpkg|dpkg-query|curl|gpg|filebeat|telegraf|suricata|suricata-update|journalctl|hostnamectl|ip|ss|wget)
      resolved="$(command -v "$cmd" 2>/dev/null || true)"
      [[ "$resolved" == "${SCRIPT_DIR}/test/mock-bin/${cmd}" ]] \
        || fail "ARIA_TEST_MODE refused to run unmocked command: ${cmd} (${resolved:-not found})"
      ;;
  esac
}

apt_lock_paths() {
  printf '%s\n' \
    /var/lib/dpkg/lock-frontend \
    /var/lib/dpkg/lock \
    /var/cache/apt/archives/lock
}

apt_lock_is_held() {
  local lock="$1"
  local real_lock
  real_lock="$(sandbox_path "$lock")"
  [[ -e "$real_lock" ]] || return 1
  if is_test_mode; then
    return 0
  fi
  if command -v fuser >/dev/null 2>&1; then
    fuser "$real_lock" >/dev/null 2>&1
    return
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof "$real_lock" >/dev/null 2>&1
    return
  fi
  if command -v lslocks >/dev/null 2>&1; then
    lslocks -n -o PATH 2>/dev/null | grep -Fxq "$real_lock"
    return
  fi
  return 1
}

print_apt_lock_holder() {
  local lock="$1"
  local real_lock
  real_lock="$(sandbox_path "$lock")"
  if is_test_mode; then
    warn "Sandbox lock marker present: ${real_lock} (simulating unattended-upgrades)."
    return
  fi
  warn "Apt/dpkg lock is held: ${real_lock}"
  if command -v fuser >/dev/null 2>&1; then
    fuser -v "$real_lock" 2>&1 || true
  elif command -v lsof >/dev/null 2>&1; then
    lsof "$real_lock" 2>&1 || true
  elif command -v lslocks >/dev/null 2>&1; then
    lslocks 2>/dev/null | grep -F "$real_lock" || true
  else
    warn "No lock holder inspection command found (tried fuser, lsof, lslocks)."
  fi
}

apt_locks_held() {
  local lock
  for lock in $(apt_lock_paths); do
    if apt_lock_is_held "$lock"; then
      printf '%s\n' "$lock"
    fi
  done
}

wait_for_apt_locks() {
  local start now elapsed held lock
  start="$(date +%s)"
  while true; do
    held="$(apt_locks_held)"
    if [[ -z "$held" ]]; then
      return 0
    fi

    now="$(date +%s)"
    elapsed=$((now - start))
    if (( elapsed >= APT_LOCK_TIMEOUT )); then
      while IFS= read -r lock; do
        [[ -n "$lock" ]] && print_apt_lock_holder "$lock"
      done <<< "$held"
      fail "Apt is busy. Wait for unattended-upgrades to finish, then rerun the script."
    fi

    warn "Apt/dpkg is busy (${elapsed}s elapsed, timeout ${APT_LOCK_TIMEOUT}s). Waiting for unattended-upgrades or other apt/dpkg work to finish..."
    while IFS= read -r lock; do
      [[ -n "$lock" ]] && print_apt_lock_holder "$lock"
    done <<< "$held"
    sleep "$APT_LOCK_POLL_INTERVAL"
  done
}

run_cmd() {
  if is_test_mode; then
    assert_mocked_command "$1"
  fi
  case "$1" in
    apt|apt-get|dpkg) wait_for_apt_locks ;;
  esac
  "$@"
}

show_service_logs() {
  local service="$1"
  run_cmd systemctl status "$service" --no-pager -l || true
  run_cmd journalctl -u "$service" -n 120 --no-pager || true
  local ossec_log
  ossec_log="$(sandbox_path /var/ossec/logs/ossec.log)"
  if [[ "$service" == wazuh-agent* && -f "$ossec_log" ]]; then
    echo "Recent /var/ossec/logs/ossec.log:"
    tail -n 120 "$ossec_log" || true
  fi
}

ensure_service_active() {
  local service="$1"
  local label="${2:-$1}"
  if ! run_cmd systemctl is-active --quiet "$service"; then
    warn "${label} service check failed; showing recent logs."
    show_service_logs "$service"
    fail "${label} service is not active."
  fi
}

restart_service_checked() {
  local service="$1"
  local label="${2:-$1}"
  local restart_timeout="${3:-120}"
  if ! timeout "$restart_timeout" run_cmd systemctl restart "$service"; then
    warn "${label} restart failed or timed out after ${restart_timeout}s; showing recent logs."
    show_service_logs "$service"
    return 1
  fi
  if ! run_cmd systemctl is-active --quiet "$service"; then
    warn "${label} service check failed; showing recent logs."
    show_service_logs "$service"
    return 1
  fi
  return 0
}

on_error() {
  local line="$1"
  local code="$2"
  if [[ "$CURRENT_COMPONENT" == "wazuh" && "$FILEBEAT_COMPLETED" -eq 1 && "$WAZUH_COMPLETED" -eq 0 ]]; then
    warn "Partial setup completed: Filebeat configured, Wazuh failed."
    echo "Cleanup command:"
    echo "  sudo bash delete_set_up.sh --all"
    echo "Filebeat backup restore hint:"
    echo "  ls /etc/filebeat/filebeat.yml.aria-bak-*"
  fi
  fail "Setup failed at line ${line} with exit code ${code}. See ${LOG_FILE}."
}
trap 'on_error "$LINENO" "$?"' ERR

setup_logging() {
  install -d -m 0755 "$(dirname "$LOG_FILE")"
  touch "$LOG_FILE"
  chmod 600 "$LOG_FILE"
  exec > >(tee -a "$LOG_FILE") 2>&1
}

require_root() {
  is_test_mode && return
  [[ "$(id -u)" -eq 0 ]] || fail "Run as root: sudo bash ${SCRIPT_NAME}"
}

mark_component_mode() {
  if [[ "$COMPONENT_ARG_SEEN" -eq 0 ]]; then
    COMPONENT_ARG_SEEN=1
    INSTALL_WAZUH=0
    INSTALL_FILEBEAT=0
    INSTALL_SURICATA=0
    INSTALL_FALCO=0
    INSTALL_TELEGRAF=0
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --vm-name) VM_NAME="${2:-}"; shift 2 ;;
      --environment) VM_ENVIRONMENT="${2:-}"; shift 2 ;;
      --ip) VM_IP="${2:-}"; shift 2 ;;
      --es-ip) ES_IP="${2:-}"; shift 2 ;;
      --es-url) ES_URL="${2:-}"; shift 2 ;;
      --es-user) ES_USER="${2:-}"; shift 2 ;;
      --es-ca) ES_CA="${2:-}"; shift 2 ;;
      --wazuh-manager) WAZUH_MANAGER="${2:-}"; shift 2 ;;
      --wazuh-group) WAZUH_GROUP="${2:-}"; shift 2 ;;
      --wazuh-version) WAZUH_AGENT_VERSION="${2:-}"; shift 2 ;;
      --allow-wazuh-downgrade) WAZUH_ALLOW_DOWNGRADE=1; shift ;;
      --reinstall-wazuh) WAZUH_REINSTALL=1; shift ;;
      --wazuh-choice) WAZUH_CHOICE="${2:-}"; shift 2 ;;
      --interface) MONITOR_IFACE="${2:-}"; shift 2 ;;
      --apt-lock-timeout) APT_LOCK_TIMEOUT="${2:-}"; shift 2 ;;
      --yes|-y) ASSUME_YES=1; shift ;;
      --all)
        COMPONENT_ARG_SEEN=0
        INSTALL_WAZUH=1
        INSTALL_FILEBEAT=1
        INSTALL_SURICATA=1
        INSTALL_FALCO=1
        INSTALL_TELEGRAF=1
        shift
        ;;
      --wazuh) mark_component_mode; INSTALL_WAZUH=1; shift ;;
      --filebeat) mark_component_mode; INSTALL_FILEBEAT=1; shift ;;
      --suricata) mark_component_mode; INSTALL_SURICATA=1; shift ;;
      --falco) mark_component_mode; INSTALL_FALCO=1; shift ;;
      --telegraf) mark_component_mode; INSTALL_TELEGRAF=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) fail "Unknown option: $1" ;;
    esac
  done
}

central_component_detected() {
  local detected=0
  if is_test_mode; then
    [[ "${MOCK_CENTRAL_SERVER:-0}" == "1" ]] && return 0
    return 1
  fi

  case "$(hostname -s 2>/dev/null || hostname 2>/dev/null || true)" in
    Dash-Linux|dash-linux) detected=1 ;;
  esac

  if [[ "$PWD" == *"opensoar backend"* || "$SCRIPT_DIR" == *"opensoar backend"* ]]; then
    detected=1
  fi
  if [[ -f "${SCRIPT_DIR}/../../api/app.py" || -d "${SCRIPT_DIR}/../../frontend" ]]; then
    detected=1
  fi

  if command -v systemctl >/dev/null 2>&1; then
    for service in elasticsearch kibana wazuh-manager; do
      if systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "${service}.service"; then
        detected=1
      fi
      if systemctl is-active --quiet "$service" 2>/dev/null; then
        detected=1
      fi
    done
  fi
  [[ "$detected" -eq 1 ]]
}

confirm_monitored_vm_target() {
  local answer
  if ! central_component_detected; then
    return
  fi

  warn "This script is for monitored VMs only, not the ARIA/ES/Wazuh Manager server."
  warn "Central ARIA/SOC indicators were detected on this host."
  if [[ "$MONITORED_VM_CONFIRM" == "$CENTRAL_CONFIRM_PHRASE" ]]; then
    warn "Override phrase supplied; continuing because operator confirmed this is a monitored VM."
    return
  fi
  if [[ "$ASSUME_YES" -eq 1 ]]; then
    fail "Central server indicators detected. Set MONITORED_VM_CONFIRM=${CENTRAL_CONFIRM_PHRASE} only if this is truly a monitored VM."
  fi
  read -r -p "Type EXACTLY '${CENTRAL_CONFIRM_PHRASE}' to continue: " answer
  [[ "$answer" == "$CENTRAL_CONFIRM_PHRASE" ]] || fail "Aborted to protect the ARIA/ES/Wazuh Manager server."
}

apply_install_components_env() {
  local components="${INSTALL_COMPONENTS:-}"
  local component
  local -a _components=()
  [[ -n "$components" ]] || return 0
  INSTALL_WAZUH=0
  INSTALL_FILEBEAT=0
  INSTALL_SURICATA=0
  INSTALL_FALCO=0
  INSTALL_TELEGRAF=0
  COMPONENT_ARG_SEEN=1
  components="${components// /}"
  IFS=',' read -r -a _components <<< "$components"
  for component in "${_components[@]}"; do
    case "$component" in
      all)
        INSTALL_WAZUH=1
        INSTALL_FILEBEAT=1
        INSTALL_SURICATA=1
        INSTALL_FALCO=1
        INSTALL_TELEGRAF=1
        ;;
      wazuh) INSTALL_WAZUH=1 ;;
      filebeat) INSTALL_FILEBEAT=1 ;;
      suricata) INSTALL_SURICATA=1 ;;
      falco) INSTALL_FALCO=1 ;;
      telegraf) INSTALL_TELEGRAF=1 ;;
      "") ;;
      *) fail "Unknown INSTALL_COMPONENTS value: ${component}" ;;
    esac
  done
}

prompt() {
  local label="$1"
  local default="$2"
  local value
  if [[ "$ASSUME_YES" -eq 1 ]]; then
    printf '%s' "$default"
    return
  fi
  read -r -p "${label} [${default}]: " value
  printf '%s' "${value:-$default}"
}

prompt_required() {
  local label="$1"
  local current="$2"
  local value="$current"
  if [[ "$ASSUME_YES" -eq 1 ]]; then
    [[ -n "$value" ]] || fail "${label} is required in --yes mode."
    printf '%s' "$value"
    return
  fi
  if [[ -n "$current" ]]; then
    read -r -p "${label} [${current}]: " value
    printf '%s' "${value:-$current}"
    return
  fi
  while [[ -z "$value" ]]; do
    read -r -p "${label}: " value
  done
  printf '%s' "$value"
}

prompt_secret() {
  if [[ "$ASSUME_YES" -eq 1 ]]; then
    ES_PASSWORD="$ENV_ES_PASSWORD"
    [[ -n "$ES_PASSWORD" ]] || fail "ARIA_ES_PASSWORD must be set in --yes mode."
    return
  fi
  read -r -s -p "Elasticsearch password: " ES_PASSWORD
  echo
  [[ -n "$ES_PASSWORD" ]] || fail "Elasticsearch password cannot be empty."
}

validate_vm_name() {
  [[ "$VM_NAME" =~ ^[a-z0-9_-]+$ ]] || fail "VM name must match lowercase [a-z0-9_-]+. Got: ${VM_NAME}"
}

default_interface() {
  run_cmd ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
}

url_host() {
  local url="$1"
  url="${url#http://}"
  url="${url#https://}"
  url="${url%%/*}"
  url="${url%%:*}"
  printf '%s' "$url"
}

collect_config() {
  local current_host
  current_host="$(hostname -s 2>/dev/null || hostname || true)"
  current_host="${current_host,,}"
  current_host="${current_host//[^a-z0-9_-]/-}"

  VM_NAME="$(prompt_required "Monitored VM name" "${VM_NAME:-$current_host}")"
  validate_vm_name

  VM_ENVIRONMENT="$(prompt "Environment tag (e.g. safe, prod, dmz)" "${VM_ENVIRONMENT:-safe}")"

  if [[ -z "$VM_IP" ]]; then
    VM_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  VM_IP="$(prompt_required "VM IP address" "${VM_IP:-}")"

  if [[ -z "$ES_URL" ]]; then
    ES_IP="$(prompt_required "Elasticsearch IP or host" "$ES_IP")"
    ES_URL="https://${ES_IP}:9200"
  fi
  ES_URL="${ES_URL%/}"

  if [[ -z "$ES_IP" ]]; then
    ES_IP="$(url_host "$ES_URL")"
  fi

  ES_USER="$(prompt "Elasticsearch username" "${ES_USER:-elastic}")"
  prompt_secret

  if [[ "$TLS_MODE" == "insecure" ]]; then
    ES_CA=""
  fi

  if [[ -n "$ES_CA" && ! -f "$ES_CA" ]]; then
    fail "Elasticsearch CA path does not exist: ${ES_CA}"
  fi
  if [[ "$TLS_MODE" == "ca" && -z "$ES_CA" ]]; then
    fail "TLS_MODE=ca requires ARIA_ES_CA or --es-ca."
  fi

  WAZUH_MANAGER="$(prompt "Wazuh Manager IP or host" "${WAZUH_MANAGER:-$ES_IP}")"
  WAZUH_GROUP="$(prompt "Wazuh Agent group" "${WAZUH_GROUP:-default}")"
  MONITOR_IFACE="$(prompt "Suricata capture interface" "${MONITOR_IFACE:-$(default_interface)}")"
  [[ -n "$MONITOR_IFACE" ]] || fail "Could not determine network interface. Use --interface."

  if [[ "$ASSUME_YES" -eq 1 ]]; then
    CHANGE_HOSTNAME="n"
  else
    read -r -p "Change system hostname to ${VM_NAME}? [y/N]: " CHANGE_HOSTNAME
    CHANGE_HOSTNAME="${CHANGE_HOSTNAME:-n}"
  fi
}

curl_es() {
  local path="$1"
  local ca_args=()
  local auth="${ES_USER}:${ES_PASSWORD}"
  if [[ -n "$ES_CA" ]]; then
    ca_args=(--cacert "$ES_CA")
  else
    ca_args=(-k)
  fi
  if is_test_mode; then
    auth="${ES_USER}:<redacted>"
  fi
  ARIA_CURL_USER="$ES_USER" ARIA_CURL_PASSWORD="$ES_PASSWORD" \
    run_cmd curl -sS "${ca_args[@]}" -u "$auth" --connect-timeout 5 --max-time 20 "${ES_URL}${path}"
}

test_elasticsearch() {
  log "Testing Elasticsearch connectivity at ${ES_URL} as ${ES_USER}..."
  if ! curl_es "/" >"$(sandbox_path /tmp/aria-monitored-vm-es-test.json)"; then
    fail "Elasticsearch connectivity failed for ${ES_URL}. Check URL, credentials, TLS, and network."
  fi
  ok "Elasticsearch is reachable."
}

backup_file() {
  local path="$1"
  local real_path
  real_path="$(sandbox_path "$path")"
  if [[ -e "$real_path" && ! -L "$real_path" ]]; then
    cp -a "$real_path" "${real_path}.aria-bak-${TS}"
    ok "Backed up ${real_path} to ${real_path}.aria-bak-${TS}"
  fi
}

write_root_file() {
  local path="$1"
  local mode="$2"
  local owner="$3"
  local real_path
  real_path="$(sandbox_path "$path")"
  install -d -m 0755 "$(dirname "$real_path")"
  backup_file "$path"
  cat > "$real_path"
  if ! is_test_mode; then
    chown "$owner" "$real_path" || true
  fi
  chmod "$mode" "$real_path"
}

fix_apt_sources() {
  local sources_list ubuntu_sources
  sources_list="$(sandbox_path /etc/apt/sources.list)"
  ubuntu_sources="$(sandbox_path /etc/apt/sources.list.d/ubuntu.sources)"
  if [[ -f "$sources_list" ]]; then
    # Comment out known broken mirrors and archived backports
    sed -i 's|^deb http://mirror\.mesrscloud\.rnu\.tn/.*|# &|' "$sources_list" 2>/dev/null || true
    sed -i 's|^deb-src http://mirror\.mesrscloud\.rnu\.tn/.*|# &|' "$sources_list" 2>/dev/null || true
    sed -i 's|^deb http://deb\.debian\.org/debian .*-backports main|# &|' "$sources_list" 2>/dev/null || true
    sed -i 's|^deb-src http://deb\.debian\.org/debian .*-backports main|# &|' "$sources_list" 2>/dev/null || true
  fi
  # Ubuntu 24.04+: if both sources.list and ubuntu.sources exist, the default
  # Ubuntu repos are duplicated. Comment out the legacy sources.list entries
  # to silence "configured multiple times" warnings and speed up apt.
  if [[ -f "$sources_list" && -f "$ubuntu_sources" ]]; then
    sed -i 's|^\s*deb http://archive\.ubuntu\.com/ubuntu|# &|' "$sources_list" 2>/dev/null || true
    sed -i 's|^\s*deb-src http://archive\.ubuntu\.com/ubuntu|# &|' "$sources_list" 2>/dev/null || true
    sed -i 's|^\s*deb http://security\.ubuntu\.com/ubuntu|# &|' "$sources_list" 2>/dev/null || true
    sed -i 's|^\s*deb-src http://security\.ubuntu\.com/ubuntu|# &|' "$sources_list" 2>/dev/null || true
  fi
}

install_base_dependencies() {
  log "Installing base package dependencies..."
  export DEBIAN_FRONTEND=noninteractive
  fix_apt_sources
  run_cmd apt-get update -y
  run_cmd apt-get install -y apt-transport-https ca-certificates curl gpg gnupg lsb-release wget tar
  ok "Base dependencies are installed."
}

maybe_change_hostname() {
  if [[ "${CHANGE_HOSTNAME,,}" =~ ^y(es)?$ ]]; then
    log "Changing hostname to ${VM_NAME}..."
    run_cmd hostnamectl set-hostname "$VM_NAME"
    ok "Hostname set to ${VM_NAME}."
  fi
}

add_elastic_repo() {
  local keyring source_list tmp_key tmp_gpg
  keyring="$(sandbox_path /usr/share/keyrings/elasticsearch-keyring.gpg)"
  source_list="$(sandbox_path /etc/apt/sources.list.d/elastic-7.x.list)"
  tmp_key="$(sandbox_path /tmp/elasticsearch-keyring.key)"
  tmp_gpg="$(sandbox_path /tmp/elasticsearch-keyring.gpg)"
  install -d -m 0755 "$(dirname "$keyring")" "$(dirname "$source_list")"
  if [[ ! -f "$keyring" ]]; then
    rm -f "$tmp_key" "$tmp_gpg"
    run_cmd curl -fsSL -o "$tmp_key" https://artifacts.elastic.co/GPG-KEY-elasticsearch
    run_cmd gpg --dearmor -o "$tmp_gpg" "$tmp_key"
    install -m 0644 "$tmp_gpg" "$keyring"
    chmod 0644 "$keyring"
  fi
  cat > "$source_list" <<'EOF'
deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main
EOF
  run_cmd apt-get update -y
}

installed_package_version() {
  local package="$1"
  run_cmd dpkg-query -W -f='${Version}' "$package" 2>/dev/null || true
}

write_wazuh_install_record() {
  if is_test_mode; then
    write_root_file /var/log/wazuh-agent-install.env 0600 root:root <<EOF
WAZUH_MANAGER=${WAZUH_MANAGER}
WAZUH_AGENT_GROUP=${WAZUH_GROUP}
WAZUH_AGENT_NAME=${VM_NAME}
WAZUH_AGENT_VERSION=${WAZUH_AGENT_VERSION}
EOF
  fi
}

escape_sed_replacement() {
  printf '%s' "$1" | sed 's/[\/&]/\\&/g'
}

configure_existing_wazuh_agent() {
  local ossec_conf manager_escaped
  ossec_conf="$(sandbox_path /var/ossec/etc/ossec.conf)"
  log "Configuring existing Wazuh Agent for manager ${WAZUH_MANAGER}, group ${WAZUH_GROUP}, agent name ${VM_NAME}."
  if [[ -f "$ossec_conf" ]]; then
    backup_file /var/ossec/etc/ossec.conf
    manager_escaped="$(escape_sed_replacement "$WAZUH_MANAGER")"
    if grep -q '<address>.*</address>' "$ossec_conf"; then
      sed -i "0,/<address>.*<\\/address>/s//<address>${manager_escaped}<\\/address>/" "$ossec_conf"
      ok "Updated Wazuh manager address in ${ossec_conf}."
    else
      warn "Could not find <address> in ${ossec_conf}; leaving manager configuration unchanged."
    fi
  else
    warn "Wazuh config not found at ${ossec_conf}; cannot update manager address automatically."
  fi
  warn "Wazuh agent name/group may require manager-side enrollment or re-enrollment."
  warn "If the central manager does not show this host as ${VM_NAME}, re-enroll it from the Wazuh Manager using your site's enrollment procedure."
}

wazuh_existing_choice() {
  local installed_version="$1"
  local choice
  echo >&2
  warn "Existing Wazuh Agent detected: ${installed_version}" >&2
  echo "1. Keep existing version and only configure manager/name/group [default]" >&2
  echo "2. Reinstall target version ${WAZUH_AGENT_VERSION}" >&2
  echo "3. Skip Wazuh agent" >&2
  echo "4. Abort" >&2

  if [[ "$ASSUME_YES" -eq 1 ]]; then
    printf '%s' "${WAZUH_CHOICE:-keep}"
    return
  fi
  read -r -p "Choose Wazuh action [1]: " choice
  case "${choice:-1}" in
    1|keep) printf 'keep' ;;
    2|reinstall) printf 'reinstall' ;;
    3|skip) printf 'skip' ;;
    4|abort) printf 'abort' ;;
    *) fail "Invalid Wazuh action: ${choice}" ;;
  esac
}

install_wazuh_package() {
  local deb package_url
  deb="$(sandbox_path "/tmp/wazuh-agent_${WAZUH_AGENT_VERSION}_amd64.deb")"
  package_url="https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_AGENT_VERSION}_amd64.deb"
  run_cmd curl -fsSL -o "$deb" "$package_url"
  if ! WAZUH_MANAGER="$WAZUH_MANAGER" \
    WAZUH_AGENT_GROUP="$WAZUH_GROUP" \
    WAZUH_AGENT_NAME="$VM_NAME" \
    DEBIAN_FRONTEND=noninteractive \
    run_cmd dpkg --force-confdef --force-confold -i "$deb"; then
    show_service_logs wazuh-agent
    fail "Wazuh Agent package install failed."
  fi
  if [[ ! -f "$(sandbox_path /etc/systemd/system/wazuh-agent.service)" && ! -f "$(sandbox_path /lib/systemd/system/wazuh-agent.service)" && ! -f "$(sandbox_path /usr/lib/systemd/system/wazuh-agent.service)" ]]; then
    warn "Wazuh Agent service file was not found after package install; systemd may use a packaged unit outside the sandbox or package install may be incomplete."
  fi
}

fail_wazuh_partial() {
  warn "Partial setup completed: Filebeat configured, Wazuh failed."
  echo "Cleanup command:"
  echo "  sudo bash delete_set_up.sh --all"
  echo "Filebeat backup restore hint:"
  echo "  ls /etc/filebeat/filebeat.yml.aria-bak-*"
  fail "$1"
}

install_wazuh_agent() {
  log "Installing Wazuh Agent ${WAZUH_AGENT_VERSION} for monitored VM ${VM_NAME}..."
  local installed_version choice
  installed_version="$(installed_package_version wazuh-agent)"
  write_wazuh_install_record

  if [[ -n "$installed_version" ]]; then
    choice="$(wazuh_existing_choice "$installed_version")"
    case "$choice" in
      keep)
        log "Keeping existing Wazuh Agent ${installed_version}; no package reinstall or downgrade will run."
        configure_existing_wazuh_agent
        ;;
      reinstall)
        if [[ "$installed_version" != "$WAZUH_AGENT_VERSION" ]] \
          && run_cmd dpkg --compare-versions "$installed_version" gt "$WAZUH_AGENT_VERSION" \
          && [[ "$WAZUH_ALLOW_DOWNGRADE" != "1" ]]; then
          warn "Existing Wazuh Agent ${installed_version} is newer than target ${WAZUH_AGENT_VERSION}; skipping downgrade."
          warn "Use --allow-wazuh-downgrade --reinstall-wazuh only if you intentionally want to replace it."
          configure_existing_wazuh_agent
        else
          install_wazuh_package
        fi
        ;;
      skip)
        warn "Skipping Wazuh Agent configuration by operator choice."
        WAZUH_COMPLETED=1
        return 0
        ;;
      abort) fail "Aborted by operator before changing Wazuh Agent." ;;
    esac
  else
    install_wazuh_package
  fi
  run_cmd systemctl daemon-reload
  run_cmd systemctl enable wazuh-agent
  if ! restart_service_checked wazuh-agent "wazuh-agent"; then
    fail_wazuh_partial "Wazuh Agent service failed."
  fi
  WAZUH_COMPLETED=1
  ok "Wazuh Agent is installed and running."
}

write_filebeat_config() {
  local cert_block
  local syslog_path messages_path authlog_path secure_path
  if [[ -n "$ES_CA" ]]; then
    cert_block="  ssl.certificate_authorities: [\"${ES_CA}\"]"
  else
    cert_block="  ssl.verification_mode: none"
  fi
  syslog_path="$(sandbox_path /var/log/syslog)"
  messages_path="$(sandbox_path /var/log/messages)"
  authlog_path="$(sandbox_path /var/log/auth.log)"
  secure_path="$(sandbox_path /var/log/secure)"

  # Build paths list dynamically — only include files that exist on this distro
  local paths_yaml=""
  for p in "$syslog_path" "$messages_path" "$authlog_path" "$secure_path"; do
    if [[ -f "$p" ]]; then
      paths_yaml+="      - ${p}\n"
    fi
  done
  # Fallback for systems where classic logfiles are missing (e.g. Ubuntu 24.04)
  if [[ -z "$paths_yaml" ]]; then
    paths_yaml="      - /var/log/syslog\n      - /var/log/auth.log\n"
  fi

  local owner="root:root"
  getent group filebeat >/dev/null 2>&1 && owner="root:filebeat"

  write_root_file /etc/filebeat/filebeat.yml 0640 "$owner" <<EOF
# Generated by ${SCRIPT_NAME} on ${TS}
filebeat.inputs:
  - type: filestream
    id: aria-${VM_NAME}-system-logs
    enabled: true
    paths:
$(printf '%b' "$paths_yaml")
    fields_under_root: true
    fields:
      monitored_asset: "${VM_NAME}"
      event.dataset: "system.syslog"

filebeat.config.modules:
  path: \${path.config}/modules.d/*.yml
  reload.enabled: false

setup.ilm.enabled: false
setup.template.enabled: true
setup.template.name: "filebeat-${VM_NAME}"
setup.template.pattern: "filebeat-${VM_NAME}-*"
setup.template.overwrite: true

output.elasticsearch:
  hosts: ["${ES_URL}"]
  username: "${ES_USER}"
  password: "${ES_PASSWORD}"
  index: "filebeat-${VM_NAME}-%{+yyyy.MM.dd}"
${cert_block}

processors:
  - add_host_metadata:
      netinfo.enabled: true
  - add_fields:
      target: ""
      fields:
        monitored_asset: "${VM_NAME}"
        host.name: "${VM_NAME}"
        aria.asset.name: "${VM_NAME}"
        aria.asset.role: "target"

logging.metrics.enabled: false
EOF
}

install_filebeat() {
  log "Installing Filebeat 7.17.13..."
  add_elastic_repo
  export DEBIAN_FRONTEND=noninteractive
  run_cmd apt-get install -y filebeat=7.17.13
  write_filebeat_config
  if ! run_cmd filebeat test config -c "$(sandbox_path /etc/filebeat/filebeat.yml)"; then
    warn "Filebeat config test failed; showing recent logs."
    show_service_logs filebeat
    fail "Filebeat config validation failed."
  fi
  run_cmd systemctl daemon-reload
  run_cmd systemctl enable filebeat
  restart_service_checked filebeat "filebeat"
  ok "Filebeat is installed and running."
}

configure_suricata_module() {
  if is_test_mode; then
    assert_mocked_command filebeat
  fi
  if ! command -v filebeat >/dev/null 2>&1; then
    warn "Filebeat is not installed; skipping Suricata Filebeat module."
    return
  fi
  local eve_path
  eve_path="$(sandbox_path /var/log/suricata/eve.json)"
  run_cmd filebeat modules enable suricata >/dev/null
  write_root_file /etc/filebeat/modules.d/suricata.yml 0644 root:root <<EOF
# Generated by monitored-Vms.sh
- module: suricata
  eve:
    enabled: true
    var.paths: ["${eve_path}"]
EOF
  restart_service_checked filebeat "filebeat"
  ok "Filebeat Suricata module is enabled."
}

install_suricata() {
  log "Installing and configuring Suricata on interface ${MONITOR_IFACE}..."
  local default_file eve_dir eve_file
  default_file="$(sandbox_path /etc/default/suricata)"
  eve_dir="$(sandbox_path /var/log/suricata)"
  eve_file="$(sandbox_path /var/log/suricata/eve.json)"
  export DEBIAN_FRONTEND=noninteractive
  run_cmd apt-get install -y suricata suricata-update || run_cmd apt-get install -y suricata
  backup_file /etc/default/suricata
  install -d -m 0755 "$(dirname "$default_file")"
  if [[ -f "$default_file" ]]; then
    if grep -q '^IFACE=' "$default_file"; then
      sed -i "s/^IFACE=.*/IFACE=${MONITOR_IFACE}/" "$default_file"
    else
      printf '\nIFACE=%s\n' "$MONITOR_IFACE" >> "$default_file"
    fi
  else
    printf 'IFACE=%s\n' "$MONITOR_IFACE" > "$default_file"
  fi
  # Also update interface in suricata.yaml (not just /etc/default/suricata)
  local suricata_yaml
  suricata_yaml="$(sandbox_path /etc/suricata/suricata.yaml)"
  if [[ -f "$suricata_yaml" ]]; then
    backup_file /etc/suricata/suricata.yaml
    sed -i "s/af-packet:\\s*$/af-packet:/" "$suricata_yaml" 2>/dev/null || true
    sed -i "0,/interface:.*eth0/s/interface:.*eth0/interface: ${MONITOR_IFACE}/" "$suricata_yaml" 2>/dev/null || true
    sed -i "s/interface: \"eth0\"/interface: \"${MONITOR_IFACE}\"/g" "$suricata_yaml" 2>/dev/null || true
  fi

  install -d -m 0755 "$eve_dir"
  touch "$eve_file"
  chmod 0644 "$eve_file"
  if command -v suricata-update >/dev/null 2>&1; then
    timeout 120 run_cmd suricata-update || warn "suricata-update failed or timed out; continuing with packaged/default rules."
  fi
  run_cmd systemctl daemon-reload
  run_cmd systemctl enable suricata
  restart_service_checked suricata "suricata"
  configure_suricata_module
  ok "Suricata is installed and running."
}

install_falco_package() {
  log "Installing Falco official package with modern eBPF..."
  local keyring source_list tmp_key tmp_gpg
  keyring="$(sandbox_path /usr/share/keyrings/falco-archive-keyring.gpg)"
  source_list="$(sandbox_path /etc/apt/sources.list.d/falcosecurity.list)"
  tmp_key="$(sandbox_path /tmp/falco-archive-keyring.key)"
  tmp_gpg="$(sandbox_path /tmp/falco-archive-keyring.gpg)"
  install -d -m 0755 "$(dirname "$keyring")" "$(dirname "$source_list")"
  rm -f "$tmp_key" "$tmp_gpg"
  run_cmd curl -fsSL -o "$tmp_key" https://falco.org/repo/falcosecurity-packages.asc
  run_cmd gpg --dearmor -o "$tmp_gpg" "$tmp_key"
  install -m 0644 "$tmp_gpg" "$keyring"
  chmod 0644 "$keyring"
  cat > "$source_list" <<'EOF'
deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main
EOF
  run_cmd apt-get update -y
  DEBIAN_FRONTEND=noninteractive FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf \
    run_cmd apt-get install -y falco

  # Force daemon-reload so systemd picks up the newly installed unit file
  # (needrestart may have deferred this on Debian/Ubuntu)
  run_cmd systemctl daemon-reload || true

  if run_cmd systemctl list-unit-files --no-legend | awk '{print $1}' | grep -qx 'falco-modern-bpf.service'; then
    FALCO_SERVICE="falco-modern-bpf.service"
  elif run_cmd systemctl list-unit-files --no-legend | awk '{print $1}' | grep -qx 'falco-bpf.service'; then
    FALCO_SERVICE="falco-bpf.service"
  elif run_cmd systemctl list-unit-files --no-legend | awk '{print $1}' | grep -qx 'falco-kmod.service'; then
    FALCO_SERVICE="falco-kmod.service"
  elif run_cmd systemctl list-unit-files --no-legend | awk '{print $1}' | grep -qx 'falco.service'; then
    FALCO_SERVICE="falco.service"
  else
    fail "No real Falco systemd service found."
  fi
}

configure_falco() {
  install -d -m 0755 "$(sandbox_path "/etc/systemd/system/${FALCO_SERVICE}.d")"
  write_root_file "/etc/systemd/system/${FALCO_SERVICE}.d/10-aria-hostname.conf" 0644 root:root <<EOF
[Service]
Environment=FALCO_HOSTNAME=${VM_NAME}
EOF

  install -d -m 0755 "$(sandbox_path /etc/falco/config.d)"
  write_root_file /etc/falco/config.d/10-aria-output.yaml 0644 root:root <<'EOF'
json_output: true
json_include_output_property: true
json_include_message_property: true
json_include_tags_property: true

http_output:
  enabled: true
  url: "http://127.0.0.1:2801/"

stdout_output:
  enabled: true

syslog_output:
  enabled: false

file_output:
  enabled: false
EOF
  run_cmd systemctl daemon-reload
}

install_falcosidekick() {
  log "Installing Falcosidekick..."
  local arch fsk_arch fsk_version archive
  arch="$(run_cmd dpkg --print-architecture)"
  case "$arch" in
    amd64) fsk_arch="amd64" ;;
    arm64) fsk_arch="arm64" ;;
    *) fail "Unsupported architecture for Falcosidekick: ${arch}" ;;
  esac
  fsk_version="$(run_cmd curl -fsSL https://api.github.com/repos/falcosecurity/falcosidekick/releases/latest | grep -Po '"tag_name":\s*"\K[^"]+' | sed 's/^v//' || true)"
  fsk_version="${fsk_version:-2.33.0}"
  archive="$(sandbox_path "/tmp/falcosidekick_${fsk_version}_linux_${fsk_arch}.tar.gz")"
  run_cmd curl -fsSL -o "$archive" "https://github.com/falcosecurity/falcosidekick/releases/download/${fsk_version}/falcosidekick_${fsk_version}_linux_${fsk_arch}.tar.gz"
  if is_test_mode; then
    printf '#!/usr/bin/env bash\nexit 0\n' > "$(sandbox_path /usr/local/bin/falcosidekick)"
  else
    tar -C /usr/local/bin -xzf "$archive"
    useradd --system --no-create-home --shell /usr/sbin/nologin falcosidekick 2>/dev/null || true
  fi
  chmod 0755 "$(sandbox_path /usr/local/bin/falcosidekick)"
  if is_test_mode; then
    install -d -m 0750 "$(sandbox_path /etc/falcosidekick)"
  else
    install -d -m 0750 -o root -g falcosidekick /etc/falcosidekick
  fi
}

configure_falcosidekick() {
  write_root_file /etc/falcosidekick/falcosidekick.env 0600 root:root <<EOF
ELASTICSEARCH_HOSTPORT=${ES_URL}
ELASTICSEARCH_INDEX=falco-${VM_NAME}
ELASTICSEARCH_SUFFIX=daily
ELASTICSEARCH_USERNAME=${ES_USER}
ELASTICSEARCH_PASSWORD=${ES_PASSWORD}
ELASTICSEARCH_CHECKCERT=false
ELASTICSEARCH_MINIMUMPRIORITY=notice
ELASTICSEARCH_ENABLECOMPRESSION=true
ELASTICSEARCH_BATCHING_ENABLED=true
ELASTICSEARCH_BATCHING_FLUSHINTERVAL=1s
ELASTICSEARCH_FLATTENFIELDS=true
EOF
  write_root_file /etc/falcosidekick/config.yaml 0640 root:falcosidekick <<EOF
listenport: 2801
debug: false

customfields:
  deployment: "soc"
  role: "target"
  host: "${VM_NAME}"
  monitored_asset: "${VM_NAME}"
  aria_asset_name: "${VM_NAME}"
EOF
  local env_file bin_path config_file
  env_file="$(sandbox_path /etc/falcosidekick/falcosidekick.env)"
  bin_path="$(sandbox_path /usr/local/bin/falcosidekick)"
  config_file="$(sandbox_path /etc/falcosidekick/config.yaml)"
  write_root_file /etc/systemd/system/falcosidekick.service 0644 root:root <<EOF
[Unit]
Description=Falcosidekick - Falco alert forwarder
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${env_file}
User=falcosidekick
Group=falcosidekick
ExecStart=${bin_path} -c ${config_file}
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
}

install_falco_stack() {
  install_falco_package
  configure_falco
  install_falcosidekick
  configure_falcosidekick
  run_cmd systemctl daemon-reload
  run_cmd systemctl enable falcosidekick
  restart_service_checked falcosidekick "falcosidekick"
  run_cmd systemctl enable "$FALCO_SERVICE"
  restart_service_checked "$FALCO_SERVICE" "$FALCO_SERVICE"
  sleep 3
  ok "Falco and Falcosidekick are installed and running."
}

add_influx_repo() {
  local keyring source_list tmp_key tmp_gpg
  keyring="$(sandbox_path /etc/apt/keyrings/influxdata-archive.gpg)"
  source_list="$(sandbox_path /etc/apt/sources.list.d/influxdata.list)"
  tmp_key="$(sandbox_path /tmp/influxdata-archive.key)"
  tmp_gpg="$(sandbox_path /tmp/influxdata-archive.gpg)"
  install -d -m 0755 "$(dirname "$keyring")" "$(dirname "$source_list")"
  run_cmd curl --silent --location -o "$tmp_key" https://repos.influxdata.com/influxdata-archive.key
  run_cmd gpg --show-keys --with-fingerprint --with-colons "$tmp_key" 2>&1 \
    | grep -q '^fpr:\+24C975CBA61A024EE1B631787C3D57159FC2F927:$' \
    || fail "InfluxData GPG fingerprint verification failed."
  rm -f "$tmp_gpg"
  run_cmd gpg --dearmor -o "$tmp_gpg" "$tmp_key"
  install -m 0644 "$tmp_gpg" "$keyring"
  chmod 0644 "$keyring"
  cat > "$source_list" <<'EOF'
deb [signed-by=/etc/apt/keyrings/influxdata-archive.gpg] https://repos.influxdata.com/debian stable main
EOF
  run_cmd apt-get update -y
}

install_telegraf() {
  log "Installing Telegraf from InfluxData repository..."
  add_influx_repo
  export DEBIAN_FRONTEND=noninteractive
  run_cmd apt-get install -y telegraf

  # Prepare TLS cert directory with correct ownership for telegraf user
  install -d -m 750 -o root -g telegraf "$(sandbox_path /etc/telegraf/certs)"

  local tls_block=""
  if [[ -n "$ES_CA" ]]; then
    install -m 640 -o root -g telegraf "$ES_CA" "$(sandbox_path /etc/telegraf/certs/elasticsearch-ca.crt)"
    tls_block="  tls_ca = \"/etc/telegraf/certs/elasticsearch-ca.crt\"
  insecure_skip_verify = false"
  elif [[ "$ES_URL" == https://* ]]; then
    tls_block="  insecure_skip_verify = true"
  fi

  write_root_file /etc/telegraf/telegraf.conf 0640 root:telegraf <<EOF
# Generated by ${SCRIPT_NAME} on ${TS}
[agent]
  interval = "10s"
  round_interval = true
  metric_batch_size = 1000
  metric_buffer_limit = 10000
  flush_interval = "10s"
  flush_jitter = "1s"
  precision = ""
  hostname = "${VM_NAME}"
  omit_hostname = false

[global_tags]
  deployment = "soc"
  role = "target"
  host = "${VM_NAME}"
  monitored_asset = "${VM_NAME}"

[[outputs.elasticsearch]]
  urls = ["${ES_URL}"]
  timeout = "5s"
  enable_sniffer = false
  health_check_interval = "10s"
  username = "${ES_USER}"
  password = "${ES_PASSWORD}"
  index_name = "telegraf-${VM_NAME}-%Y.%m.%d"
  manage_template = true
  template_name = "telegraf-${VM_NAME}"
  overwrite_template = false
${tls_block}

[[inputs.cpu]]
  percpu = true
  totalcpu = true
  collect_cpu_time = false
  report_active = true
[[inputs.mem]]
[[inputs.swap]]
[[inputs.disk]]
  ignore_fs = ["tmpfs", "devtmpfs", "devfs", "overlay", "squashfs"]
[[inputs.diskio]]
[[inputs.kernel]]
[[inputs.processes]]
[[inputs.system]]
[[inputs.net]]
[[inputs.netstat]]
[[inputs.linux_sysctl_fs]]
[[inputs.internal]]
[[inputs.procstat]]
  pattern = ".*"
  pid_tag = true
  pid_finder = "native"
EOF

  # Disk-directory usage monitoring script
  write_root_file /usr/local/bin/telegraf_disk_dirs.sh 0755 root:root <<'EOF'
#!/usr/bin/env bash
# Emit disk usage per mount point in Influx line protocol
for mp in $(findmnt -n -o TARGET -t ext4,xfs,btrfs,vfat 2>/dev/null | sort -u); do
  read -r size used avail pct <<< "$(df -B1 "$mp" | awk 'NR==2{print $2,$3,$4,$5}')"
  mp_tag="${mp// /_}"
  mp_tag="${mp_tag//,/_}"
  echo "disk_dir,host=${HOSTNAME:-unknown},mount=${mp_tag} size=${size}u,used=${used}u,avail=${avail}u,used_percent=${pct//%/} $(date +%s)000000000"
done
EOF

  # Drop-in config for disk directory monitoring
  install -d -m 755 "$(sandbox_path /etc/telegraf/telegraf.d)"
  write_root_file /etc/telegraf/telegraf.d/disk_dir.conf 0640 root:telegraf <<'EOF'
[[inputs.exec]]
  commands = ["/usr/local/bin/telegraf_disk_dirs.sh"]
  timeout = "20s"
  data_format = "influx"
  interval = "60s"
  name_override = "disk_dir"
EOF

  run_cmd systemctl daemon-reload
  run_cmd systemctl enable telegraf
  restart_service_checked telegraf "telegraf"
  ok "Telegraf is installed and running."
}

retry_es_check() {
  local label="$1"
  local path="$2"
  local pattern="$3"
  local found=0
  log "Checking Elasticsearch visibility for ${label}..."
  for _ in {1..12}; do
    if curl_es "$path" 2>/dev/null | grep -Eiq "$pattern"; then
      found=1
      break
    fi
    sleep 10
  done
  if [[ "$found" -eq 1 ]]; then
    ok "${label} is visible in Elasticsearch."
  else
    warn "${label} is not visible in Elasticsearch yet. This may be ingestion delay."
  fi
}

verify_services() {
  [[ "$INSTALL_WAZUH" -eq 1 ]] && ensure_service_active wazuh-agent "wazuh-agent"
  [[ "$INSTALL_FILEBEAT" -eq 1 || "$INSTALL_SURICATA" -eq 1 ]] && ensure_service_active filebeat "filebeat"
  [[ "$INSTALL_SURICATA" -eq 1 ]] && ensure_service_active suricata "suricata"
  [[ "$INSTALL_FALCO" -eq 1 ]] && ensure_service_active falcosidekick "falcosidekick"
  if [[ "$INSTALL_FALCO" -eq 1 ]]; then
    if [[ -z "$FALCO_SERVICE" ]]; then
      if run_cmd systemctl list-unit-files --no-legend | awk '{print $1}' | grep -qx 'falco-modern-bpf.service'; then
        FALCO_SERVICE="falco-modern-bpf.service"
      elif run_cmd systemctl list-unit-files --no-legend | awk '{print $1}' | grep -qx 'falco-bpf.service'; then
        FALCO_SERVICE="falco-bpf.service"
      elif run_cmd systemctl list-unit-files --no-legend | awk '{print $1}' | grep -qx 'falco-kmod.service'; then
        FALCO_SERVICE="falco-kmod.service"
      elif run_cmd systemctl list-unit-files --no-legend | awk '{print $1}' | grep -qx 'falco.service'; then
        FALCO_SERVICE="falco.service"
      fi
    fi
    [[ -n "$FALCO_SERVICE" ]] && ensure_service_active "$FALCO_SERVICE" "$FALCO_SERVICE"
  fi
  [[ "$INSTALL_TELEGRAF" -eq 1 ]] && ensure_service_active telegraf "telegraf"
  ok "Selected services passed local service checks."
}

verify_elasticsearch_visibility() {
  retry_es_check "Elasticsearch root" "/" '"cluster_name"|tagline'
  [[ "$INSTALL_WAZUH" -eq 1 ]] && retry_es_check "Wazuh agent ${VM_NAME}" "/wazuh-alerts-*/_search?q=agent.name:${VM_NAME}&size=1" "\"${VM_NAME}\""
  [[ "$INSTALL_FILEBEAT" -eq 1 ]] && retry_es_check "Filebeat host documents" "/filebeat-${VM_NAME}-*/_search?q=host.name:${VM_NAME}%20OR%20monitored_asset:${VM_NAME}&size=1" "\"${VM_NAME}\""
  [[ "$INSTALL_SURICATA" -eq 1 ]] && retry_es_check "Suricata eve events" "/filebeat-${VM_NAME}-*/_search?q=event.dataset:suricata.eve&size=1" "suricata\\.eve"
  [[ "$INSTALL_FALCO" -eq 1 ]] && retry_es_check "Falco index falco-${VM_NAME}-*" "/_cat/indices/falco-${VM_NAME}-*?h=index" "falco-${VM_NAME}-"
  [[ "$INSTALL_TELEGRAF" -eq 1 ]] && retry_es_check "Telegraf index telegraf-${VM_NAME}-*" "/_cat/indices/telegraf-${VM_NAME}-*?h=index" "telegraf-${VM_NAME}-"
  return 0
}

verify_falco_pipeline() {
  [[ "$INSTALL_FALCO" -eq 1 ]] || return 0
  log "Verifying Falco → Falcosidekick → Elasticsearch pipeline..."

  local test_time
  test_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Send a test alert to Falcosidekick
  if ! curl -s -X POST http://127.0.0.1:2801/ \
      -H "Content-Type: application/json" \
      -d "{\"output\":\"ARIA bootstrap verification alert\",\"priority\":\"Notice\",\"rule\":\"ARIA_Bootstrap_Verify\",\"time\":\"${test_time}\",\"output_fields\":{\"hostname\":\"${VM_NAME}\"}}" >/dev/null 2>&1; then
    warn "Could not POST test alert to Falcosidekick (http://127.0.0.1:2801). Falco events may not reach Elasticsearch."
    return 1
  fi

  # Wait for Falcosidekick batching + ES indexing
  local found=0
  local es_auth="${ES_USER}:${ES_PASSWORD}"
  local ca_args=()
  if [[ -n "$ES_CA" ]]; then
    ca_args=(--cacert "$ES_CA")
  else
    ca_args=(-k)
  fi

  for _ in {1..12}; do
    if curl -sS "${ca_args[@]}" -u "$es_auth" --connect-timeout 5 --max-time 10 \
        "${ES_URL}/falco-${VM_NAME}-*/_search?size=1&q=rule:ARIA_Bootstrap_Verify&sort=@timestamp:desc" 2>/dev/null \
        | grep -q "ARIA_Bootstrap_Verify"; then
      found=1
      break
    fi
    sleep 2
  done

  if [[ "$found" -eq 1 ]]; then
    ok "Falco pipeline verified: test alert reached Elasticsearch (falco-${VM_NAME}-*)."
  else
    warn "Falco test alert not found in Elasticsearch after ~24s."
    warn "Falco may be running but not generating alerts (quiet system), or Falcosidekick → ES is delayed."
    warn "To confirm: trigger a real event (e.g. 'cat /etc/shadow') and check 'curl ${ES_URL}/falco-${VM_NAME}-*/_search'"
  fi
}

get_wazuh_agent_id() {
  local agent_id=""
  # Try local client.keys first
  local client_keys
  client_keys="$(sandbox_path /var/ossec/etc/client.keys)"
  if [[ -f "$client_keys" ]]; then
    agent_id="$(awk -F: '{print $1}' "$client_keys" | head -n1 | tr -d ' ')"
  fi
  # If empty, try querying the Wazuh manager REST API (if reachable)
  if [[ -z "$agent_id" && -n "$WAZUH_MANAGER" ]]; then
    agent_id="$(curl -sS -k -u "${ES_USER}:${ES_PASSWORD}" "https://${WAZUH_MANAGER}:55000/agents?name=${VM_NAME}&pretty=false" 2>/dev/null | grep -oP '"id"\s*:\s*"\K[^"]+' | head -n1 || true)"
  fi
  printf '%s' "$agent_id"
}

show_summary() {
  local wazuh_agent_id=""
  if [[ "$INSTALL_WAZUH" -eq 1 ]]; then
    wazuh_agent_id="$(get_wazuh_agent_id)"
  fi

  cat <<EOF

╔══════════════════════════════════════════════════════════════════════════════╗
║                     ARIA — ADD / EDIT SERVER FORM VALUES                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

Edit Server
-----------
Asset ID:       ${VM_NAME}
Environment:    ${VM_ENVIRONMENT}
Hostname:       ${VM_NAME}
IP Address:     ${VM_IP}

Source Configuration
--------------------
EOF

  if [[ "$INSTALL_WAZUH" -eq 1 ]]; then
    cat <<EOF
wazuh
  [✓] Enabled
  Index Pattern:        wazuh-alerts-*
  Host Name:            ${VM_ENVIRONMENT}
  Agent Name:           ${VM_ENVIRONMENT}
  Agent ID:             ${wazuh_agent_id:-<check Wazuh manager after enrollment>}
EOF
  fi

  if [[ "$INSTALL_FALCO" -eq 1 ]]; then
    cat <<EOF
falco
  [✓] Enabled
  Index Pattern:        falco-${VM_NAME}-*
  Host Name:            ${VM_NAME}
EOF
  fi

  if [[ "$INSTALL_TELEGRAF" -eq 1 ]]; then
    cat <<EOF
telegraf
  [✓] Enabled
  Index Pattern:        telegraf-${VM_NAME}-*
  Host Name:            ${VM_NAME}
EOF
  fi

  if [[ "$INSTALL_FILEBEAT" -eq 1 ]]; then
    cat <<EOF
filebeat
  [✓] Enabled
  Index Pattern:        filebeat-${VM_NAME}-*
  Host Name:            ${VM_NAME}
EOF
  fi

  if [[ "$INSTALL_SURICATA" -eq 1 ]]; then
    cat <<EOF
suricata
  [✓] Enabled
  Index Pattern:        filebeat-${VM_NAME}-*
  Host Name:            ${VM_NAME}
EOF
  fi

  cat <<EOF

════════════════════════════════════════════════════════════════════════════════

JSON payload for ARIA API (POST /api/v1/assets):
EOF

  # Build the JSON payload dynamically
  local json_payload
  json_payload="{"
  json_payload+='"asset_id":"'"${VM_NAME}"'","name":"'"${VM_NAME}"'","hostname":"'"${VM_NAME}"'","ip_address":"'"${VM_IP}"'","environment":"'"${VM_ENVIRONMENT}"'","enabled":true,"remediation_enabled":false,"source_config_json":{'

  local sources=()
  [[ "$INSTALL_WAZUH" -eq 1 ]] && sources+=( '"wazuh":{"index_pattern":"wazuh-alerts-*","host_name":"'"${VM_ENVIRONMENT}"'","agent_name":"'"${VM_ENVIRONMENT}"'","agent_id":"'"${wazuh_agent_id}"'"}' )
  [[ "$INSTALL_FALCO" -eq 1 ]] && sources+=( '"falco":{"index_pattern":"falco-'"${VM_NAME}"'-*","host_name":"'"${VM_NAME}"'"}' )
  [[ "$INSTALL_TELEGRAF" -eq 1 ]] && sources+=( '"telegraf":{"index_pattern":"telegraf-'"${VM_NAME}"'-*","host_name":"'"${VM_NAME}"'"}' )
  [[ "$INSTALL_FILEBEAT" -eq 1 ]] && sources+=( '"filebeat":{"index_pattern":"filebeat-'"${VM_NAME}"'-*","host_name":"'"${VM_NAME}"'"}' )
  [[ "$INSTALL_SURICATA" -eq 1 ]] && sources+=( '"suricata":{"index_pattern":"filebeat-'"${VM_NAME}"'-*","host_name":"'"${VM_NAME}"'"}' )

  json_payload+=$(IFS=,; echo "${sources[*]}")
  json_payload+='},"ansible_config_json":null}'

  echo "$json_payload" | python3 -m json.tool 2>/dev/null || echo "$json_payload"

  cat <<EOF

════════════════════════════════════════════════════════════════════════════════

Ansible / Remediation Config (set later via /settings/ansible):
  ansible_host: ${VM_IP}
  ansible_user: root   (or your admin user)
  ansible_port: 22
  auth_type:    password or private_key

Troubleshooting:
  systemctl status wazuh-agent filebeat suricata falcosidekick telegraf --no-pager -l
  journalctl -u filebeat -n 100 --no-pager -l
  journalctl -u suricata -n 100 --no-pager -l
  journalctl -u falcosidekick -n 100 --no-pager -l
  journalctl -u telegraf -n 100 --no-pager -l
  curl -k -u '${ES_USER}:<password>' '${ES_URL}/_cat/indices/filebeat-${VM_NAME}-*,falco-${VM_NAME}-*,telegraf-${VM_NAME}-*?v'

Full setup log:
  ${LOG_FILE}
EOF
}

warn_high_load() {
  local load cpus
  load="$(cut -d' ' -f1 /proc/loadavg 2>/dev/null || echo 0)"
  cpus="$(nproc 2>/dev/null || echo 1)"
  if awk "BEGIN {exit !($load > $cpus * 3)}"; then
    warn "System load is very high ($load on $cpus CPUs)."
    warn "Service restarts may be slow or fail. Consider waiting for load to drop."
    if [[ "$ASSUME_YES" -eq 0 ]]; then
      local answer
      read -r -p "Continue anyway? [y/N]: " answer
      [[ "${answer,,}" =~ ^y(es)?$ ]] || fail "Aborted due to high system load."
    fi
  fi
}

main() {
  apply_install_components_env
  parse_args "$@"
  require_safe_test_root
  confirm_monitored_vm_target
  require_root
  setup_logging
  warn_high_load
  collect_config
  test_elasticsearch
  install_base_dependencies
  maybe_change_hostname

  if [[ "$INSTALL_FILEBEAT" -eq 1 ]]; then
    CURRENT_COMPONENT="filebeat"
    install_filebeat
    FILEBEAT_COMPLETED=1
  fi
  if [[ "$INSTALL_WAZUH" -eq 1 ]]; then
    CURRENT_COMPONENT="wazuh"
    install_wazuh_agent
    WAZUH_COMPLETED=1
  fi
  if [[ "$INSTALL_SURICATA" -eq 1 ]]; then
    CURRENT_COMPONENT="suricata"
    install_suricata
    SURICATA_COMPLETED=1
  fi
  if [[ "$INSTALL_FALCO" -eq 1 ]]; then
    CURRENT_COMPONENT="falco"
    install_falco_stack
    FALCO_COMPLETED=1
  fi
  if [[ "$INSTALL_TELEGRAF" -eq 1 ]]; then
    CURRENT_COMPONENT="telegraf"
    install_telegraf
    TELEGRAF_COMPLETED=1
  fi
  CURRENT_COMPONENT=""

  verify_services
  verify_elasticsearch_visibility
  verify_falco_pipeline
  show_summary
}

main "$@"
