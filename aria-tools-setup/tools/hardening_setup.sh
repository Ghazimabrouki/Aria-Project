#!/bin/bash

# Security Hardening Setup Script
# Installs Fail2Ban, configures UFW firewall, and applies SSH hardening
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

install_fail2ban() {
  log "=========================================="
  log "Installing Fail2Ban"
  log "=========================================="

  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y fail2ban

  log "Configuring Fail2Ban for SSH protection..."

  cat > /etc/fail2ban/jail.local <<'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

  systemctl enable fail2ban
  systemctl start fail2ban

  sleep 2

  if systemctl is-active --quiet fail2ban; then
    log "Fail2Ban is running"
    fail2ban-client status
  else
    warn "Fail2Ban may not have started correctly"
  fi
}

configure_ufw_firewall() {
  log "=========================================="
  log "Configuring UFW Firewall"
  log "=========================================="

  apt-get install -y ufw

  ufw default deny incoming
  ufw default allow outgoing

  local allowed_cidr="${ARIA_ALLOWED_CIDR:-any}"
  ufw allow ssh
  ufw allow 22/tcp

  # Note: 8001 (ARIA API) is best placed behind an authenticated TLS reverse
  # proxy in production. It is allowed here so the platform is reachable in a
  # lab/default deployment; restrict it with ARIA_ALLOWED_CIDR when possible.
  if [[ "$allowed_cidr" == "any" ]]; then
    ufw allow 5601/tcp comment "Kibana"
    ufw allow 9200/tcp comment "Elasticsearch ingest"
    ufw allow 1514/tcp comment "Wazuh agent events"
    ufw allow 1514/udp comment "Wazuh agent events"
    ufw allow 1515/tcp comment "Wazuh agent enrollment"
    ufw allow 55000/tcp comment "Wazuh API"
    ufw allow 3001/tcp comment "ARIA dashboard"
    ufw allow 8001/tcp comment "ARIA API"
    ufw allow 11434/tcp comment "Ollama local LLM"
  else
    ufw allow from "$allowed_cidr" to any port 5601 proto tcp comment "Kibana"
    ufw allow from "$allowed_cidr" to any port 9200 proto tcp comment "Elasticsearch ingest"
    ufw allow from "$allowed_cidr" to any port 1514 comment "Wazuh agent events"
    ufw allow from "$allowed_cidr" to any port 1515 proto tcp comment "Wazuh agent enrollment"
    ufw allow from "$allowed_cidr" to any port 55000 proto tcp comment "Wazuh API"
    ufw allow from "$allowed_cidr" to any port 3001 proto tcp comment "ARIA dashboard"
    ufw allow from "$allowed_cidr" to any port 8001 proto tcp comment "ARIA API"
    ufw allow from "$allowed_cidr" to any port 11434 proto tcp comment "Ollama local LLM"
  fi

  ufw --force enable
  ufw status verbose

  log "Firewall configured successfully"
}

apply_ssh_hardening() {
  log "=========================================="
  log "Applying SSH Hardening"
  log "=========================================="

  local sshd_config="/etc/ssh/sshd_config"

  cp "$sshd_config" "${sshd_config}.bak"
  log "Backed up sshd_config to ${sshd_config}.bak"

  sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$sshd_config"
  sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$sshd_config"
  sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' "$sshd_config"
  sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' "$sshd_config"
  sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' "$sshd_config"
  sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 2/' "$sshd_config"
  sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "$sshd_config"
  sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$sshd_config"

  if ! grep -q "^ChallengeResponseAuthentication no" "$sshd_config"; then
    echo "ChallengeResponseAuthentication no" >> "$sshd_config"
  fi
  if ! grep -q "^UsePAM yes" "$sshd_config"; then
    echo "UsePAM yes" >> "$sshd_config"
  fi

  if systemctl list-unit-files --no-legend | awk '{print $1}' | grep -qx 'sshd.service'; then
    systemctl restart sshd
  elif systemctl list-unit-files --no-legend | awk '{print $1}' | grep -qx 'ssh.service'; then
    systemctl restart ssh
  else
    warn "Could not find sshd.service or ssh.service; SSH config was updated but service was not restarted"
  fi

  log "SSH hardening applied"
  log "Changes made:"
  echo "  - Root login disabled"
  echo "  - Password authentication disabled"
  echo "  - Pubkey authentication enabled"
  echo "  - Max auth tries reduced to 3"
  echo "  - X11 forwarding disabled"
  echo "  - Client alive interval set to 5 minutes"
}

verify_hardening() {
  log "=========================================="
  log "Verifying Hardening"
  log "=========================================="

  echo ""
  echo "=== Fail2Ban Status ==="
  fail2ban-client status 2>/dev/null || warn "Fail2Ban not running"

  echo ""
  echo "=== UFW Status ==="
  ufw status 2>/dev/null || warn "UFW not configured"

  echo ""
  echo "=== SSH Config Verification ==="
  grep -E "^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|MaxAuthTries)" /etc/ssh/sshd_config | head -5

  echo ""
  log "Hardening verification complete"
}

show_summary() {
  log "=========================================="
  log "Security Hardening Complete!"
  log "=========================================="
  echo ""
  echo "Applied hardening measures:"
  echo "  1. Fail2Ban - Blocks IPs after 5 failed SSH attempts"
  echo "  2. UFW Firewall - SSH, Elastic/Wazuh/Kibana, and ARIA (3001/8001) allowed"
  echo "  3. SSH Hardening:"
  echo "     - Root login disabled"
  echo "     - Password authentication disabled"
  echo "     - Key-based authentication required"
  echo "     - Max auth tries limited to 3"
  echo ""
  echo "IMPORTANT: Ensure you have SSH key access before using this server!"
  echo "Backup config: /etc/ssh/sshd_config.bak"
  echo ""
  echo "To check Fail2Ban: fail2ban-client status"
  echo "To check UFW: ufw status"
  echo ""
}

main() {
  require_root

  log "=========================================="
  log "Security Hardening Setup"
  log "Author: Ghazi Mabrouki"
  log "=========================================="
  echo ""
  if [[ "${ARIA_ASSUME_YES:-0}" == "1" ]]; then
    confirm="y"
    warn "ARIA_ASSUME_YES=1: applying hardening without an interactive prompt. Ensure SSH key access is already working."
  else
    read -p "Continue with security hardening? (y/n): " confirm
  fi
  if [[ "$confirm" != "y" ]]; then
    log "Aborted"
    exit 0
  fi

  install_fail2ban
  configure_ufw_firewall
  apply_ssh_hardening
  verify_hardening
  show_summary
}

main "$@"