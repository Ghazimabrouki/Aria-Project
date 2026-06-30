#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_DASHBOARD_TITLE="System Resources Metrics"
FILEBEAT_YML="/etc/filebeat/filebeat.yml"
TELEGRAF_YML="/etc/telegraf/telegraf.conf"
TELEGRAF_DIR="/etc/telegraf"
TELEGRAF_CONF_DIR="/etc/telegraf/telegraf.d"
TELEGRAF_LOCAL_DIR="${SCRIPT_DIR}/telegraf"
TELEGRAF_DISK_DIR_SCRIPT="/usr/local/bin/telegraf_disk_dirs.sh"
BOOTSTRAP_OUT="/root/telegraf-target-bootstrap.sh"

CLEAN=0
VERBOSE=0

log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
ok()   { log "OK: $*"; }
warn() { log "WARN: $*"; }
err()  { log "ERROR: $*" >&2; }

usage() {
  cat <<USAGE
Usage:
  sudo bash ${SCRIPT_NAME} [--clean] [--verbose]

Options:
  --clean     Remove telegraf and generated bootstrap only
  --verbose   Extra debug output
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clean) CLEAN=1; shift ;;
    --verbose) VERBOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) err "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

need_cmd() { command -v "$1" >/dev/null 2>&1 || { err "Missing command: $1"; exit 1; }; }

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    err "Run as root: sudo bash ${SCRIPT_NAME}"
    exit 1
  fi
}

parse_filebeat() {
  [[ -f "$FILEBEAT_YML" ]] || { err "Missing: $FILEBEAT_YML"; exit 1; }
  need_cmd python3

  python3 - "$FILEBEAT_YML" <<'PY'
import sys, re, shlex
p = sys.argv[1]
txt = open(p, 'r', encoding='utf-8', errors='ignore').read().splitlines()

def find_block(key):
    for i, line in enumerate(txt):
        if re.match(r'^\s*%s\s*:\s*$' % re.escape(key), line):
            base = len(line) - len(line.lstrip())
            block = []
            for j in range(i+1, len(txt)):
                l = txt[j]
                if not l.strip():
                    continue
                ind = len(l) - len(l.lstrip())
                if ind <= base:
                    break
                block.append(l)
            return block
    return []

def get_scalar(block, k):
    for l in block:
        m = re.match(r'^\s*%s\s*:\s*(.+)\s*$' % re.escape(k), l)
        if m:
            v = m.group(1).strip().strip('"').strip("'")
            return v
    return None

def get_hosts(block):
    for l in block:
        m = re.match(r'^\s*hosts\s*:\s*(.+)\s*$', l)
        if m:
            rhs = m.group(1).strip()
            if rhs.startswith('['):
                rhs = rhs.strip('[]')
                rhs = rhs.replace('"','').replace("'","")
                parts = [x.strip() for x in rhs.split(',') if x.strip()]
                return parts
            rhs = rhs.strip('"').strip("'")
            return [rhs]
    return []

out = find_block('output.elasticsearch')
if not out:
    out_top = find_block('output')
    if out_top:
        start = None
        for i,l in enumerate(out_top):
            if re.match(r'^\s*elasticsearch\s*:\s*$', l.strip()):
                start = i
                break
        if start is not None:
            base = len(out_top[start]) - len(out_top[start].lstrip())
            sub = []
            for j in range(start+1, len(out_top)):
                l2 = out_top[j]
                if not l2.strip():
                    continue
                ind = len(l2) - len(l2.lstrip())
                if ind <= base:
                    break
                sub.append(l2)
            out = sub

hosts = get_hosts(out)
user = get_scalar(out, 'username')
pwd  = get_scalar(out, 'password')

if not hosts:
    print('PARSE_ERROR=1')
    sys.exit(0)

print('PARSE_ERROR=0')
print('ES_HOSTS=' + shlex.quote(','.join(hosts)))
if user: print('ES_USER=' + shlex.quote(user))
if pwd:  print('ES_PASS=' + shlex.quote(pwd))
PY
}

load_config() {
  local parsed
  parsed="$(parse_filebeat)"
  [[ "$VERBOSE" -eq 1 ]] && echo "$parsed"

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    eval "$line"
  done <<<"$parsed"

  if [[ "${PARSE_ERROR:-1}" != "0" ]]; then
    err "Could not parse Elasticsearch connection from $FILEBEAT_YML"
    exit 1
  fi

  if [[ -n "${ARIA_ES_URL:-}" ]]; then
    ES_HOSTS="${ARIA_ES_URL#http://}"
    ES_HOSTS="${ES_HOSTS#https://}"
  fi
  if [[ -n "${ARIA_ES_USERNAME:-}" ]]; then
    ES_USER="$ARIA_ES_USERNAME"
  fi
  if [[ -n "${ARIA_ELASTIC_PASSWORD:-}" ]]; then
    ES_PASS="$ARIA_ELASTIC_PASSWORD"
  fi

  : "${ES_HOSTS:?missing ES hosts}"
  : "${ES_USER:?missing ES username}"
  : "${ES_PASS:?missing ES password}"

  ES_URL="https://$(echo "$ES_HOSTS" | cut -d',' -f1)"
  if [[ "$ES_URL" == https://https://* ]]; then ES_URL="${ES_URL#https://}"; fi
  if [[ "$(echo "$ES_HOSTS" | cut -d',' -f1)" == http://* || "$(echo "$ES_HOSTS" | cut -d',' -f1)" == https://* ]]; then
    ES_URL="$(echo "$ES_HOSTS" | cut -d',' -f1)"
  fi

  ES_SCHEME="https"
  [[ "$ES_URL" == http://* ]] && ES_SCHEME="http"

  ok "Elasticsearch URL: $ES_URL"
  ok "Elasticsearch user: $ES_USER"
}

detect_ca() {
  ES_CA=""
  for p in \
    /etc/elasticsearch/certs/ca/ca.crt \
    /etc/elasticsearch/certs/http_ca.crt \
    /usr/share/elasticsearch/config/certs/http_ca.crt \
    /etc/opensearch/certs/ca.pem \
    /etc/opensearch/certs/root-ca.pem
  do
    if [[ -f "$p" ]]; then ES_CA="$p"; break; fi
  done
  if [[ -n "$ES_CA" ]]; then
    ok "TLS CA detected: $ES_CA"
  else
    warn "No ES CA detected. Telegraf will use insecure_skip_verify=true."
  fi
}

curl_es() {
  local path="$1"
  local ca_opt=()
  if [[ -n "${ES_CA:-}" ]]; then
    ca_opt=(--cacert "$ES_CA")
  else
    ca_opt=(-k)
  fi
  curl -sS "${ca_opt[@]}" -u "${ES_USER}:${ES_PASS}" --connect-timeout 5 --max-time 20 "${ES_URL}${path}"
}

detect_es_version() {
  local v
  v="$(curl_es "/" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("version",{}).get("number",""))' 2>/dev/null || true)"
  if [[ -z "$v" ]]; then
    warn "CA-verified connection to ${ES_URL} failed (likely hostname/IP not in cert SAN)."
    warn "Retrying with TLS verification disabled to detect Elasticsearch version..."
    v="$(curl -sS -k -u "${ES_USER}:${ES_PASS}" --connect-timeout 5 --max-time 20 "${ES_URL}/" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("version",{}).get("number",""))' 2>/dev/null || true)"
    if [[ -n "$v" ]]; then
      ES_CA=""
      warn "Elasticsearch TLS certificate does not cover ${ES_URL}; Telegraf will use insecure_skip_verify=true."
    fi
  fi
  if [[ -z "$v" ]]; then
    err "Cannot detect Elasticsearch version. Check auth/TLS/network."
    exit 1
  fi
  ES_VERSION="$v"
  ES_MAJOR="${v%%.*}"
  ok "Detected Elasticsearch version: $ES_VERSION (major=$ES_MAJOR)"
  if [[ "$ES_MAJOR" != "7" ]]; then
    warn "Telegraf Elasticsearch output is documented for Elasticsearch up to v7.x. Current cluster major=$ES_MAJOR."
  fi
}

stop_container_if_exists() {
  local name="$1"
  if command -v docker >/dev/null 2>&1; then
    if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
      log "Stopping/removing container: $name"
      docker rm -f "$name" >/dev/null 2>&1 || true
    fi
  fi
}

compose_down_if_exists() {
  local dir="$1"
  if [[ -d "$dir" && -f "$dir/docker-compose.yml" ]]; then
    if command -v docker-compose >/dev/null 2>&1; then
      (cd "$dir" && docker-compose down) >/dev/null 2>&1 || true
    elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
      (cd "$dir" && docker compose down) >/dev/null 2>&1 || true
    fi
  fi
}

remove_old_metrics_stack() {
  log "Removing old metrics/observability stack (best effort)..."
  systemctl disable --now metricbeat >/dev/null 2>&1 || true
  apt-get -y purge metricbeat >/dev/null 2>&1 || true
  rm -rf /etc/metricbeat /var/lib/metricbeat >/dev/null 2>&1 || true

  compose_down_if_exists /opt/otel
  stop_container_if_exists otel-collector
  stop_container_if_exists otelcol
  stop_container_if_exists otel-collector-contrib
  rm -rf /opt/otel >/dev/null 2>&1 || true

  compose_down_if_exists /opt/soc-prometheus
  stop_container_if_exists soc-prometheus
  stop_container_if_exists soc-node-exporter
  stop_container_if_exists soc-promel
  rm -rf /opt/soc-prometheus >/dev/null 2>&1 || true

  ok "Previous Prometheus / OTel / Metricbeat components removed (if they existed)."
}

clean_telegraf_only() {
  log "CLEAN enabled: removing Telegraf only..."
  systemctl disable --now telegraf >/dev/null 2>&1 || true
  apt-get -y purge telegraf >/dev/null 2>&1 || true
  rm -rf /etc/telegraf /var/lib/telegraf >/dev/null 2>&1 || true
  rm -f /etc/apt/sources.list.d/influxdata.list /etc/apt/keyrings/influxdata-archive.gpg >/dev/null 2>&1 || true
  rm -f "$BOOTSTRAP_OUT" >/dev/null 2>&1 || true
  apt-get update -y >/dev/null 2>&1 || true
  ok "Telegraf removed."
  exit 0
}

install_telegraf() {
  log "Installing Telegraf from the official InfluxData repository..."
  export DEBIAN_FRONTEND=noninteractive

  mkdir -p /etc/apt/keyrings
  cd /tmp
  rm -f influxdata-archive.key
  curl --silent --location -O https://repos.influxdata.com/influxdata-archive.key
  gpg --show-keys --with-fingerprint --with-colons ./influxdata-archive.key 2>&1 \
    | grep -q '^fpr:\+24C975CBA61A024EE1B631787C3D57159FC2F927:$' \
    || { err "InfluxData GPG fingerprint verification failed."; exit 1; }
  cat influxdata-archive.key | gpg --dearmor | tee /etc/apt/keyrings/influxdata-archive.gpg >/dev/null
  echo 'deb [signed-by=/etc/apt/keyrings/influxdata-archive.gpg] https://repos.influxdata.com/debian stable main' \
    > /etc/apt/sources.list.d/influxdata.list
  rm -f influxdata-archive.key

  apt-get update -y
  apt-get install -y telegraf
  ok "Telegraf installed."
}

prepare_telegraf_ca() {
  if [[ "$ES_SCHEME" != "https" || -z "${ES_CA:-}" ]]; then
    return 0
  fi

  if ! getent group telegraf >/dev/null 2>&1; then
    warn "Telegraf group not found; leaving CA path unchanged: $ES_CA"
    return 0
  fi

  install -d -o root -g telegraf -m 750 "${TELEGRAF_DIR}/certs"
  install -o root -g telegraf -m 640 "$ES_CA" "${TELEGRAF_DIR}/certs/elasticsearch-ca.crt"
  ES_CA="${TELEGRAF_DIR}/certs/elasticsearch-ca.crt"
  ok "Telegraf-readable Elasticsearch CA installed: $ES_CA"
}

install_disk_dir_input() {
  mkdir -p "$TELEGRAF_CONF_DIR"

  cat > "$TELEGRAF_DISK_DIR_SCRIPT" <<'EOF_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

paths=(/var /home /tmp /opt)
for path in "${paths[@]}"; do
  [[ -d "$path" ]] || continue
  bytes="$(timeout 15s du -sb "$path" 2>/dev/null | awk '{print $1}' || true)"
  [[ -n "$bytes" ]] || bytes=0
  tag="$(printf '%s' "$path" | sed 's/ /\\ /g; s/,/\\,/g; s/=/\\=/g')"
  echo "disk_dir,path=${tag} bytes=${bytes}i"
done
EOF_SCRIPT
  chmod 755 "$TELEGRAF_DISK_DIR_SCRIPT"

  if [[ -f "${TELEGRAF_LOCAL_DIR}/telegraf.d/disk_dir.conf" ]]; then
    cp -f "${TELEGRAF_LOCAL_DIR}/telegraf.d/disk_dir.conf" "${TELEGRAF_CONF_DIR}/disk_dir.conf"
  else
    cat > "${TELEGRAF_CONF_DIR}/disk_dir.conf" <<'EOF_CONF'
[[inputs.exec]]
commands = ["/usr/local/bin/telegraf_disk_dirs.sh"]
timeout = "20s"
data_format = "influx"
interval = "60s"
name_override = "disk_dir"
EOF_CONF
  fi

  if getent group telegraf >/dev/null 2>&1; then
    chown -R root:telegraf "$TELEGRAF_CONF_DIR"
    chmod 750 "$TELEGRAF_CONF_DIR"
    chmod 640 "${TELEGRAF_CONF_DIR}/disk_dir.conf"
  else
    chmod 755 "$TELEGRAF_CONF_DIR"
    chmod 644 "${TELEGRAF_CONF_DIR}/disk_dir.conf"
  fi
  ok "Telegraf telegraf.d config installed: ${TELEGRAF_CONF_DIR}/disk_dir.conf"
}

test_telegraf_config() {
  local test_log="/tmp/telegraf-config-test.log"
  local config_args=(--config "$TELEGRAF_YML")
  if [[ -d "$TELEGRAF_CONF_DIR" ]]; then
    config_args+=(--config-directory "$TELEGRAF_CONF_DIR")
  fi

  if getent passwd telegraf >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
    if ! sudo -u telegraf /usr/bin/telegraf "${config_args[@]}" --test >"$test_log" 2>&1; then
      err "Telegraf config test failed. Output:"
      sed -n '1,160p' "$test_log" >&2 || true
      exit 1
    fi
  elif ! /usr/bin/telegraf "${config_args[@]}" --test >"$test_log" 2>&1; then
    err "Telegraf config test failed. Output:"
    sed -n '1,160p' "$test_log" >&2 || true
    exit 1
  fi

  ok "Telegraf config test passed."
}

write_telegraf_config() {
  [[ -f "$TELEGRAF_YML" && ! -f "${TELEGRAF_YML}.bak" ]] && cp -f "$TELEGRAF_YML" "${TELEGRAF_YML}.bak"

  local tls_block=""
  if [[ -n "${ES_CA:-}" && "$ES_SCHEME" == "https" ]]; then
    tls_block=$(cat <<EOF_TLS
  tls_ca = "${ES_CA}"
  insecure_skip_verify = false
EOF_TLS
)
  elif [[ "$ES_SCHEME" == "https" ]]; then
    tls_block=$(cat <<'EOF_TLS'
  insecure_skip_verify = true
EOF_TLS
)
  fi

  cat > "$TELEGRAF_YML" <<EOF_CONF
# Generated by ${SCRIPT_NAME}

[agent]
  interval = "10s"
  round_interval = true
  metric_batch_size = 1000
  metric_buffer_limit = 10000
  flush_interval = "10s"
  flush_jitter = "1s"
  precision = ""
  hostname = ""
  omit_hostname = false

[global_tags]
  deployment = "soc"
  role = "control-plane"

[[outputs.elasticsearch]]
  urls = ["${ES_URL}"]
  timeout = "5s"
  enable_sniffer = false
  health_check_interval = "10s"
  username = "${ES_USER}"
  password = "${ES_PASS}"
  index_name = "telegraf-%Y.%m.%d"
  manage_template = true
  template_name = "telegraf"
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
  pid_finder = "native"
EOF_CONF

  if getent group telegraf >/dev/null 2>&1; then
    chown root:telegraf "$TELEGRAF_YML"
    chmod 640 "$TELEGRAF_YML"
  else
    chmod 644 "$TELEGRAF_YML"
  fi
  ok "Telegraf configured: $TELEGRAF_YML"
}

start_telegraf() {
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now telegraf
  sleep 2
  if ! systemctl is-active --quiet telegraf; then
    err "telegraf service is not running."
    systemctl status telegraf --no-pager -l || true
    exit 1
  fi
  ok "telegraf is running."
}

verify_data() {
  log "Verifying data arrives in Elasticsearch (telegraf-* indices)..."
  local found=0
  for _ in {1..30}; do
    if curl_es "/_cat/indices/telegraf-*?h=index,docs.count" 2>/dev/null | awk '{print $2}' | grep -Eq '^[1-9]'; then
      found=1
      break
    fi
    sleep 2
  done

  if [[ $found -eq 1 ]]; then
    ok "Telegraf indices detected with docs ✅"
  else
    warn "No docs detected yet. Showing telegraf logs (tail 120):"
    journalctl -u telegraf --no-pager -n 120 || true
  fi

  log "Elasticsearch indices telegraf-* :"
  curl_es "/_cat/indices/telegraf-*?v" || true
}

write_target_bootstrap() {
  local target_tls_block=""
  if [[ "$ES_SCHEME" == "https" ]]; then
    target_tls_block=$(cat <<'EOF_TLS'
  insecure_skip_verify = true
EOF_TLS
)
  fi

  cat > "$BOOTSTRAP_OUT" <<EOF_BOOT
#!/usr/bin/env bash
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
mkdir -p /etc/apt/keyrings
cd /tmp
rm -f influxdata-archive.key
curl --silent --location -O https://repos.influxdata.com/influxdata-archive.key
gpg --show-keys --with-fingerprint --with-colons ./influxdata-archive.key 2>&1 \
  | grep -q '^fpr:\+24C975CBA61A024EE1B631787C3D57159FC2F927:$' \
  || { echo "InfluxData GPG fingerprint verification failed."; exit 1; }
cat influxdata-archive.key | gpg --dearmor | tee /etc/apt/keyrings/influxdata-archive.gpg >/dev/null
echo 'deb [signed-by=/etc/apt/keyrings/influxdata-archive.gpg] https://repos.influxdata.com/debian stable main' \
  > /etc/apt/sources.list.d/influxdata.list
rm -f influxdata-archive.key

apt-get update -y
apt-get install -y telegraf

cat > /etc/telegraf/telegraf.conf <<'EOF_CONF'
[agent]
  interval = "10s"
  round_interval = true
  metric_batch_size = 1000
  metric_buffer_limit = 10000
  flush_interval = "10s"
  flush_jitter = "1s"
  omit_hostname = false

[global_tags]
  deployment = "soc"
  role = "target"

[[outputs.elasticsearch]]
  urls = ["${ES_URL}"]
  timeout = "5s"
  enable_sniffer = false
  health_check_interval = "10s"
  username = "${ES_USER}"
  password = "${ES_PASS}"
  index_name = "telegraf-%Y.%m.%d"
  manage_template = true
  template_name = "telegraf"
  overwrite_template = false
${target_tls_block}

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
  pid_finder = "native"
EOF_CONF

if getent group telegraf >/dev/null 2>&1; then
  chown root:telegraf /etc/telegraf/telegraf.conf
  chmod 640 /etc/telegraf/telegraf.conf
else
  chmod 644 /etc/telegraf/telegraf.conf
fi

systemctl enable telegraf
systemctl restart telegraf
systemctl --no-pager --full status telegraf
EOF_BOOT

  chmod 700 "$BOOTSTRAP_OUT"
  ok "Target bootstrap generated: $BOOTSTRAP_OUT"
}

show_target_bootstrap() {
  echo
  echo "============================================================"
  echo "Target Telegraf bootstrap generated"
  echo "============================================================"
  echo "Saved locally at: $BOOTSTRAP_OUT"
  echo "This file contains Elasticsearch credentials. Transfer it securely to the target machine."
  if [[ "${ARIA_PRINT_BOOTSTRAP:-0}" == "1" ]]; then
    echo "============================================================"
    cat "$BOOTSTRAP_OUT"
  fi
  echo "============================================================"
}


find_dashboard_file() {
  local candidates=(
    "${SCRIPT_DIR}/System Resources Metrics.ndjson"
    "${SCRIPT_DIR}/System%20Resources%20Metrics.ndjson"
    "${PWD}/System Resources Metrics.ndjson"
    "${PWD}/System%20Resources%20Metrics.ndjson"
  )

  DASHBOARD_FILE=""
  for candidate in "${candidates[@]}"; do
    if [[ -f "$candidate" ]]; then
      DASHBOARD_FILE="$candidate"
      ok "Kibana dashboard bundle found: $DASHBOARD_FILE"
      return 0
    fi
  done

  warn "Kibana dashboard export not found. Skipping dashboard import."
  return 1
}

extract_saved_object_id() {
  local wanted_type="$1"
  local ndjson_file="$2"

  python3 - "$wanted_type" "$ndjson_file" <<'PY'
import json, sys
wanted_type = sys.argv[1]
path = sys.argv[2]
with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
    for raw in fh:
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except Exception:
            continue
        if obj.get("type") == wanted_type:
            print(obj.get("id", ""))
            break
PY
}

detect_kibana_url() {
  local local_ip=""
  local candidates=()

  local_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n "$local_ip" ]] && candidates+=("https://${local_ip}:5601")
  candidates+=("https://127.0.0.1:5601" "https://localhost:5601")

  for candidate in "${candidates[@]}"; do
    for _ in {1..30}; do
      local status_payload=""
      status_payload="$(curl -sk -u "${ES_USER}:${ES_PASS}" --connect-timeout 5 --max-time 15 "${candidate}/api/status" 2>/dev/null || true)"
      if [[ -n "$status_payload" ]] && grep -Eq '"version"|"overall"|"status"' <<<"$status_payload"; then
        KIBANA_URL="$candidate"
        ok "Kibana API detected: $KIBANA_URL"
        return 0
      fi
      sleep 2
    done
  done

  warn "Kibana API is not reachable yet. Skipping dashboard import."
  return 1
}

curl_kibana() {
  local method="$1"
  local path="$2"
  shift 2
  curl -sk -u "${ES_USER}:${ES_PASS}" -X "$method" \
    -H 'kbn-xsrf: true' \
    --connect-timeout 5 --max-time 90 \
    "$@" \
    "${KIBANA_URL}${path}"
}

set_kibana_default_route() {
  local dashboard_id="$1"
  local index_pattern_id="${2:-}"
  local default_route="/app/dashboards#/view/${dashboard_id}"
  local payload response kibana_version fallback_payload

  payload="$(python3 - "$default_route" "$index_pattern_id" <<'PY'
import json, sys
route = sys.argv[1]
index_id = sys.argv[2] if len(sys.argv) > 2 else ""
changes = {"defaultRoute": route}
if index_id:
    changes["defaultIndex"] = index_id
print(json.dumps({"changes": changes}))
PY
)"

  response="$(curl_kibana POST "/api/kibana/settings" -H 'Content-Type: application/json' -d "$payload" || true)"
  if grep -q '"settings"' <<<"$response"; then
    ok "Kibana default route configured: $default_route"
    [[ -n "$index_pattern_id" ]] && ok "Kibana default index pattern configured."
    return 0
  fi

  kibana_version="$(curl_kibana GET "/api/status" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("version", {}).get("number", ""))' 2>/dev/null || true)"
  if [[ -z "$kibana_version" ]]; then
    warn "Could not detect Kibana version for saved-objects fallback."
    warn "Kibana settings response: ${response:-<empty>}"
    return 1
  fi

  fallback_payload="$(python3 - "$default_route" "$index_pattern_id" <<'PY'
import json, sys
route = sys.argv[1]
index_id = sys.argv[2] if len(sys.argv) > 2 else ""
attrs = {"defaultRoute": route}
if index_id:
    attrs["defaultIndex"] = index_id
print(json.dumps({"attributes": attrs}))
PY
)"

  response="$(curl_kibana POST "/api/saved_objects/config/${kibana_version}" -H 'Content-Type: application/json' -d "$fallback_payload" || true)"
  if grep -Eq '"id"|"success"' <<<"$response"; then
    ok "Kibana config saved object created for version ${kibana_version}."
    return 0
  fi

  response="$(curl_kibana PUT "/api/saved_objects/config/${kibana_version}" -H 'Content-Type: application/json' -d "$fallback_payload" || true)"
  if grep -Eq '"id"|"attributes"' <<<"$response"; then
    ok "Kibana config saved object updated for version ${kibana_version}."
    return 0
  fi

  warn "Failed to set Kibana default route through both settings and saved-objects APIs."
  warn "Last Kibana response: ${response:-<empty>}"
  return 1
}

import_kibana_dashboard() {
  local import_response success dashboard_id index_pattern_id

  find_dashboard_file || return 0
  detect_kibana_url || return 0

  dashboard_id="$(extract_saved_object_id "dashboard" "$DASHBOARD_FILE")"
  index_pattern_id="$(extract_saved_object_id "index-pattern" "$DASHBOARD_FILE")"

  if [[ -z "$dashboard_id" ]]; then
    warn "No dashboard saved object found in ${DASHBOARD_FILE}. Skipping import."
    return 0
  fi

  log "Importing Kibana dashboard bundle..."
  import_response="$(curl_kibana POST "/api/saved_objects/_import?overwrite=true" -F "file=@${DASHBOARD_FILE};type=application/ndjson" || true)"

  success="$(IMPORT_RESPONSE="$import_response" python3 - <<'PY'
import json, os
raw = os.environ.get("IMPORT_RESPONSE", "").strip()
try:
    obj = json.loads(raw) if raw else {}
except Exception:
    print("0")
    raise SystemExit
print("1" if obj.get("success") is True else "0")
PY
)"

  if [[ "$success" != "1" ]]; then
    warn "Kibana import did not report success."
    warn "Kibana import response: ${import_response:-<empty>}"
    return 0
  fi

  ok "Kibana dashboard bundle imported successfully."
  set_kibana_default_route "$dashboard_id" "$index_pattern_id" || true
}

main() {
  require_root
  need_cmd curl
  need_cmd python3
  need_cmd apt-get
  need_cmd systemctl
  need_cmd gpg
  need_cmd timeout

  if [[ "$CLEAN" -eq 1 ]]; then
    clean_telegraf_only
  fi

  load_config
  detect_ca
  detect_es_version
  remove_old_metrics_stack
  install_telegraf
  prepare_telegraf_ca
  write_telegraf_config
  install_disk_dir_input
  test_telegraf_config
  start_telegraf
  verify_data
  import_kibana_dashboard
  write_target_bootstrap
  show_target_bootstrap

  ok "DONE. You can open Kibana and search for:"
  log "  Index pattern: telegraf-*"
  log "  Discover filter example: role:control-plane OR role:target"
  log "  Dashboard landing page: ${DEFAULT_DASHBOARD_TITLE}"
}

main
