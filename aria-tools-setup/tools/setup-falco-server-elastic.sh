#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${YELLOW}[$(date '+%F %T')] $*${NC}"; }
ok()   { echo -e "${GREEN}[$(date '+%F %T')] $*${NC}"; }
fail() { echo -e "${RED}[$(date '+%F %T')] ERROR: $*${NC}"; exit 1; }

require_root() {
  [ "${EUID}" -eq 0 ] || fail "Run as root: sudo bash setup-falco-server-elastic.sh"
}

prompt_elastic_config() {
  HOSTNAME_VALUE="$(hostname -f 2>/dev/null || hostname)"

  if [[ "${ARIA_NONINTERACTIVE:-0}" == "1" ]]; then
    local local_ip
    local_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    ES_URL="${ARIA_ES_URL:-https://${local_ip}:9200}"
    ES_URL="${ES_URL%/}"
    ES_USERNAME="${ARIA_ES_USERNAME:-elastic}"
    ES_PASSWORD="${ARIA_ELASTIC_PASSWORD:-}"
    ES_INDEX="${ARIA_FALCO_INDEX:-falco-events-server}"
    ENVIRONMENT_NAME="${ARIA_ENVIRONMENT_NAME:-server-lab}"
    ASSET_ROLE="${ARIA_ASSET_ROLE:-ubuntu-server}"
    [ -n "${ES_PASSWORD}" ] || fail "ARIA_ELASTIC_PASSWORD cannot be empty in noninteractive mode."
    ok "Using noninteractive Elasticsearch config: ${ES_URL} (${ES_USERNAME}), index ${ES_INDEX}-*"
    return 0
  fi

  echo
  echo "=== Elasticsearch/OpenSearch configuration ==="

  read -rp "Elasticsearch URL [https://127.0.0.1:9200]: " ES_URL
  ES_URL="${ES_URL:-https://127.0.0.1:9200}"
  ES_URL="${ES_URL%/}"

  read -rp "Elasticsearch username [elastic]: " ES_USERNAME
  ES_USERNAME="${ES_USERNAME:-elastic}"

  read -rsp "Elasticsearch password: " ES_PASSWORD
  echo

  read -rp "Falco index prefix [falco-events-server]: " ES_INDEX
  ES_INDEX="${ES_INDEX:-falco-events-server}"

  read -rp "Environment name [server-lab]: " ENVIRONMENT_NAME
  ENVIRONMENT_NAME="${ENVIRONMENT_NAME:-server-lab}"

  read -rp "Asset role [ubuntu-server]: " ASSET_ROLE
  ASSET_ROLE="${ASSET_ROLE:-ubuntu-server}"

  [ -n "${ES_PASSWORD}" ] || fail "Elasticsearch password cannot be empty."
}

test_elastic() {
  log "Testing Elasticsearch/OpenSearch connectivity..."

  curl -k -sS -u "${ES_USERNAME}:${ES_PASSWORD}" "${ES_URL}/" >/tmp/falco_elastic_test.json || {
    cat /tmp/falco_elastic_test.json 2>/dev/null || true
    fail "Cannot connect/authenticate to ${ES_URL}"
  }

  ok "Elasticsearch/OpenSearch is reachable."
}

install_dependencies() {
  log "Installing dependencies..."
  apt-get update -y
  apt-get install -y curl gpg wget tar ca-certificates
  ok "Dependencies installed."
}

remove_old_docker_falco() {
  log "Cleaning old Docker Compose Falco deployment if present..."

  mkdir -p /opt/falco-backup

  if [ -f /opt/falco/docker-compose.yml ]; then
    cp -a /opt/falco "/opt/falco-backup/falco-compose-$(date +%Y%m%d_%H%M%S)" || true

    if command -v docker >/dev/null 2>&1; then
      docker compose -f /opt/falco/docker-compose.yml down -v 2>/dev/null || \
      docker-compose -f /opt/falco/docker-compose.yml down -v 2>/dev/null || true
    fi

    mv /opt/falco "/opt/falco-old-$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
  fi

  if command -v docker >/dev/null 2>&1; then
    docker rm -f falco falcosidekick 2>/dev/null || true
  fi

  ok "Old Docker Falco cleanup completed."
}

install_falco() {
  log "Installing Falco official package with modern eBPF..."

  curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
    gpg --dearmor > /tmp/falco-archive-keyring.gpg

  install -m 0644 /tmp/falco-archive-keyring.gpg /usr/share/keyrings/falco-archive-keyring.gpg

  echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" \
    > /etc/apt/sources.list.d/falcosecurity.list

  apt-get update -y

  env DEBIAN_FRONTEND=noninteractive \
      FALCO_FRONTEND=noninteractive \
      FALCO_DRIVER_CHOICE=modern_ebpf \
      apt-get install -y falco

  # Important:
  # Do not use falco.service here because it can be an alias/symlink.
  # systemd refuses enabling alias unit names.
  if systemctl list-unit-files --no-legend | awk '{print $1}' | grep -qx 'falco-modern-bpf.service'; then
    FALCO_SERVICE="falco-modern-bpf.service"
  elif systemctl list-unit-files --no-legend | awk '{print $1}' | grep -qx 'falco-bpf.service'; then
    FALCO_SERVICE="falco-bpf.service"
  elif systemctl list-unit-files --no-legend | awk '{print $1}' | grep -qx 'falco-kmod.service'; then
    FALCO_SERVICE="falco-kmod.service"
  else
    fail "No real Falco systemd service found. Check: systemctl list-unit-files | grep falco"
  fi

  systemctl daemon-reload
  systemctl enable --now "${FALCO_SERVICE}"

  ok "Falco installed using ${FALCO_SERVICE}."
}


configure_falco_hostname() {
  log "Configuring Falco hostname..."

  mkdir -p "/etc/systemd/system/${FALCO_SERVICE}.d"

  cat > "/etc/systemd/system/${FALCO_SERVICE}.d/10-hostname.conf" <<EOF
[Service]
Environment=FALCO_HOSTNAME=${HOSTNAME_VALUE}
EOF

  systemctl daemon-reload

  ok "Falco hostname set to ${HOSTNAME_VALUE}."
}

configure_falco_output() {
  log "Configuring Falco JSON HTTP output..."

  mkdir -p /etc/falco/config.d

  # Clean old project-specific config name if it exists
  if [ -f /etc/falco/config.d/10-attijari-server-output.yaml ]; then
    mv /etc/falco/config.d/10-attijari-server-output.yaml \
      "/etc/falco/config.d/10-attijari-server-output.yaml.backup.$(date +%Y%m%d_%H%M%S)"
  fi

  cat > /etc/falco/config.d/10-server-output.yaml <<'EOF'
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

append_output:
  - match:
      source: syscall
    extra_fields:
      - evt.hostname
      - evt.time.iso8601
      - evt.type
      - evt.category
      - proc.name
      - proc.pid
      - proc.ppid
      - proc.pname
      - proc.cmdline
      - proc.pcmdline
      - proc.exepath
      - user.name
      - user.uid
      - fd.name
      - fd.type
      - fd.sip
      - fd.sport
      - fd.cip
      - fd.cport
      - container.id
      - container.name
      - k8s.pod.name
      - k8s.ns.name
EOF

  ok "Falco output configured."
}

configure_falco_rules() {
  log "Installing generic Linux server Falco rules..."

  mkdir -p /etc/falco/rules.d

  # Backup/remove old project-specific rule file if present
  if [ -f /etc/falco/rules.d/10-attijari-linux-server.rules.yaml ]; then
    mv /etc/falco/rules.d/10-attijari-linux-server.rules.yaml \
      "/etc/falco/rules.d/10-attijari-linux-server.rules.yaml.backup.$(date +%Y%m%d_%H%M%S)"
  fi

  if [ -f /etc/falco/rules.d/10-linux-server-security.rules.yaml ]; then
    cp /etc/falco/rules.d/10-linux-server-security.rules.yaml \
      "/etc/falco/rules.d/10-linux-server-security.rules.yaml.backup.$(date +%Y%m%d_%H%M%S)"
  fi

  cat > /etc/falco/rules.d/10-linux-server-security.rules.yaml <<'EOF'
- macro: server_spawned_process
  condition: (evt.type in (execve, execveat))

- macro: server_open_write
  condition: (evt.type in (open, openat, openat2, creat) and evt.is_open_write=true)

- macro: server_open_read
  condition: (evt.type in (open, openat, openat2) and evt.is_open_read=true)

- list: server_package_managers
  items: [apt, apt-get, dpkg, snap, unattended-upgr, yum, dnf]

- list: server_user_file_tools
  items: [cat, less, more, grep, egrep, fgrep, awk, sed, head, tail, vim, vi, nano, python, python3, perl, ruby, bash, sh, zsh, cp, scp, rsync, tar]

- rule: Critical Linux Service Control Command
  desc: Detect stop/restart/disable/mask operations against Linux services
  condition: >
    server_spawned_process
    and proc.name in (systemctl, service)
    and (
      proc.cmdline contains " stop "
      or proc.cmdline contains " restart "
      or proc.cmdline contains " disable "
      or proc.cmdline contains " mask "
      or proc.cmdline contains " kill "
    )
  output: >
    Critical service control command executed
    (host=%evt.hostname user=%user.name uid=%user.uid command=%proc.cmdline parent=%proc.pcmdline pid=%proc.pid ppid=%proc.ppid)
  priority: WARNING
  tags: [host, linux, systemd, service, change]

- rule: Systemd Unit File Modified
  desc: Detect modification of systemd service/unit files
  condition: >
    server_open_write
    and (
      fd.name startswith /etc/systemd/system
      or fd.name startswith /lib/systemd/system
      or fd.name startswith /usr/lib/systemd/system
    )
    and not proc.name in (server_package_managers)
  output: >
    Systemd unit file modified
    (host=%evt.hostname user=%user.name file=%fd.name command=%proc.cmdline parent=%proc.pcmdline pid=%proc.pid)
  priority: WARNING
  tags: [host, linux, systemd, persistence, service]

- rule: SSH Configuration Modified
  desc: Detect modification of SSH server configuration or authorized_keys
  condition: >
    server_open_write
    and (
      fd.name=/etc/ssh/sshd_config
      or fd.name startswith /etc/ssh/sshd_config.d
      or fd.name startswith /root/.ssh
      or fd.name contains "/.ssh/authorized_keys"
    )
    and not proc.name in (server_package_managers)
  output: >
    SSH configuration or authorized_keys modified
    (host=%evt.hostname user=%user.name file=%fd.name command=%proc.cmdline parent=%proc.pcmdline pid=%proc.pid)
  priority: WARNING
  tags: [host, linux, ssh, persistence, privilege]

- rule: Direct Shadow File Access By User Tool
  desc: Detect direct /etc/shadow reading by shell or user inspection tools
  condition: >
    server_open_read
    and fd.name=/etc/shadow
    and proc.name in (server_user_file_tools)
  output: >
    Direct sensitive shadow file access by user tool
    (host=%evt.hostname user=%user.name file=%fd.name command=%proc.cmdline parent=%proc.pcmdline pid=%proc.pid)
  priority: WARNING
  tags: [host, linux, credentials, privilege]

- rule: Package Manager Change Operation
  desc: Detect real package install/update/remove/upgrade operations
  condition: >
    server_spawned_process
    and proc.name in (apt, apt-get, dpkg, snap, yum, dnf)
    and user.name=root
    and (
      proc.cmdline contains " install"
      or proc.cmdline contains " remove"
      or proc.cmdline contains " purge"
      or proc.cmdline contains " upgrade"
      or proc.cmdline contains " dist-upgrade"
      or proc.cmdline contains " full-upgrade"
      or proc.cmdline contains " update"
      or proc.cmdline contains " autoremove"
      or proc.cmdline contains " refresh"
      or proc.cmdline contains " revert"
    )
    and not proc.cmdline contains "firmware-updater.firmware-notifier"
  output: >
    Package manager change operation executed
    (host=%evt.hostname user=%user.name command=%proc.cmdline parent=%proc.pcmdline pid=%proc.pid)
  priority: NOTICE
  tags: [host, linux, package, change]
EOF

  ok "Generic Linux server rules installed."
}

install_falcosidekick() {
  log "Installing Falcosidekick..."

  ARCH="$(dpkg --print-architecture)"
  case "${ARCH}" in
    amd64) FSK_ARCH="amd64" ;;
    arm64) FSK_ARCH="arm64" ;;
    *) fail "Unsupported architecture: ${ARCH}" ;;
  esac

  FSK_VERSION="$(curl -fsSL https://api.github.com/repos/falcosecurity/falcosidekick/releases/latest \
    | grep -Po '"tag_name":\s*"\K[^"]+' \
    | sed 's/^v//' || true)"

  FSK_VERSION="${FSK_VERSION:-2.33.0}"

  curl -L -o "/tmp/falcosidekick_${FSK_VERSION}_linux_${FSK_ARCH}.tar.gz" \
    "https://github.com/falcosecurity/falcosidekick/releases/download/${FSK_VERSION}/falcosidekick_${FSK_VERSION}_linux_${FSK_ARCH}.tar.gz"

  tar -C /usr/local/bin -xzf "/tmp/falcosidekick_${FSK_VERSION}_linux_${FSK_ARCH}.tar.gz"
  chmod 755 /usr/local/bin/falcosidekick

  useradd --system --no-create-home --shell /usr/sbin/nologin falcosidekick 2>/dev/null || true
  mkdir -p /etc/falcosidekick

  ok "Falcosidekick installed."
}

configure_falcosidekick() {
  log "Configuring Falcosidekick..."

  cat > /etc/falcosidekick/falcosidekick.env <<EOF
ELASTICSEARCH_HOSTPORT=${ES_URL}
ELASTICSEARCH_INDEX=${ES_INDEX}
ELASTICSEARCH_SUFFIX=daily
ELASTICSEARCH_USERNAME=${ES_USERNAME}
ELASTICSEARCH_PASSWORD=${ES_PASSWORD}
ELASTICSEARCH_CHECKCERT=false
ELASTICSEARCH_MINIMUMPRIORITY=notice
ELASTICSEARCH_ENABLECOMPRESSION=true
ELASTICSEARCH_BATCHING_ENABLED=true
ELASTICSEARCH_BATCHING_FLUSHINTERVAL=1s
ELASTICSEARCH_FLATTENFIELDS=true
EOF

  chown root:root /etc/falcosidekick/falcosidekick.env
  chmod 600 /etc/falcosidekick/falcosidekick.env

  cat > /etc/falcosidekick/config.yaml <<EOF
listenport: 2801
debug: false

customfields:
  environment: "${ENVIRONMENT_NAME}"
  source_type: "linux-server"
  asset_role: "${ASSET_ROLE}"
  monitored_host: "${HOSTNAME_VALUE}"
EOF

  chown root:falcosidekick /etc/falcosidekick/config.yaml
  chmod 640 /etc/falcosidekick/config.yaml

  cat > /etc/systemd/system/falcosidekick.service <<'EOF'
[Unit]
Description=Falcosidekick - Falco alert forwarder
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/falcosidekick/falcosidekick.env
User=falcosidekick
Group=falcosidekick
ExecStart=/usr/local/bin/falcosidekick -c /etc/falcosidekick/config.yaml
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

  systemctl daemon-reload
  systemctl enable --now falcosidekick

  ok "Falcosidekick configured."
}

configure_elastic_template() {
  log "Configuring Elasticsearch index template..."

  curl -k -sS -u "${ES_USERNAME}:${ES_PASSWORD}" \
    -X PUT "${ES_URL}/_template/${ES_INDEX}-template" \
    -H 'Content-Type: application/json' \
    -d "{
      \"index_patterns\": [\"${ES_INDEX}-*\"],
      \"settings\": {
        \"number_of_shards\": 1,
        \"number_of_replicas\": 0
      }
    }" >/dev/null || true

  curl -k -sS -u "${ES_USERNAME}:${ES_PASSWORD}" \
    -X PUT "${ES_URL}/${ES_INDEX}-*/_settings" \
    -H 'Content-Type: application/json' \
    -d '{"index":{"number_of_replicas":0}}' >/dev/null || true

  ok "Elasticsearch index template configured."
}

restart_services() {
  log "Restarting services..."

  systemctl restart falcosidekick
  sleep 2

  systemctl restart "${FALCO_SERVICE}"
  sleep 5

  systemctl is-active --quiet falcosidekick || fail "Falcosidekick is not active."
  systemctl is-active --quiet "${FALCO_SERVICE}" || fail "Falco is not active."

  ok "Falco and Falcosidekick are active."
}

generate_test_event() {
  log "Generating safe test event..."

  touch /etc/systemd/system/falco-installer-test.service
  rm -f /etc/systemd/system/falco-installer-test.service

  sleep 6

  ok "Test event generated."
}

verify_ingestion() {
  log "Verifying Elasticsearch ingestion..."

  curl -k -sS -u "${ES_USERNAME}:${ES_PASSWORD}" \
    "${ES_URL}/_cat/indices/${ES_INDEX}-*?v" || true

  INDEX_FOUND="false"

  for i in {1..12}; do
    if curl -k -sS -u "${ES_USERNAME}:${ES_PASSWORD}" \
      "${ES_URL}/_cat/indices/${ES_INDEX}-*?h=index" | grep -q "${ES_INDEX}-"; then
      INDEX_FOUND="true"
      break
    fi
    sleep 5
  done

  [ "${INDEX_FOUND}" = "true" ] || fail "No ${ES_INDEX}-* index found."

  ok "Elasticsearch ingestion verified."
}

show_summary() {
  echo
  ok "Falco server setup completed successfully."
  echo
  echo "Final architecture:"
  echo "  Falco (${FALCO_SERVICE})"
  echo "    -> http://127.0.0.1:2801"
  echo "    -> Falcosidekick"
  echo "    -> ${ES_URL}"
  echo "    -> ${ES_INDEX}-YYYY.MM.DD"
  echo
  echo "Commands:"
  echo "  systemctl status ${FALCO_SERVICE} --no-pager -l"
  echo "  systemctl status falcosidekick --no-pager -l"
  echo "  journalctl -u ${FALCO_SERVICE} -n 100 --no-pager -l"
  echo "  journalctl -u falcosidekick -n 100 --no-pager -l"
  echo
  echo "SOC index pattern:"
  echo "  ${ES_INDEX}-*"
}

main() {
  require_root
  prompt_elastic_config
  test_elastic
  install_dependencies
  remove_old_docker_falco
  install_falco
  configure_falco_hostname
  configure_falco_output
  configure_falco_rules
  install_falcosidekick
  configure_falcosidekick
  configure_elastic_template
  restart_services
  generate_test_event
  verify_ingestion
  show_summary
}

main "$@"
