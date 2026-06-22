#!/bin/bash

# Automated SOC Components Setup Script
# Author: Ghazi Mabrouki

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARIA_ASSUME_YES="${ARIA_ASSUME_YES:-1}"
ARIA_NONINTERACTIVE="${ARIA_NONINTERACTIVE:-1}"
INSTALL_SIEM="${INSTALL_SIEM:-1}"
INSTALL_SURICATA="${INSTALL_SURICATA:-1}"
INSTALL_WAZUH="${INSTALL_WAZUH:-1}"
INSTALL_FALCO="${INSTALL_FALCO:-1}"
INSTALL_TELEGRAF="${INSTALL_TELEGRAF:-1}"
INSTALL_DETECTION_RULES="${INSTALL_DETECTION_RULES:-1}"
INSTALL_HARDENING="${INSTALL_HARDENING:-1}"

export ARIA_ASSUME_YES ARIA_NONINTERACTIVE

command_exists() {
  command -v "$1" >/dev/null 2>&1 || [[ -x "/usr/games/$1" ]]
}

check_root_privileges() {
  if [[ $(id -u) -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run with root privileges.${NC}"
    exit 1
  fi
}

check_prerequisites() {
  local prerequisites=("git" "curl" "figlet" "lolcat" "gpg" "unzip" "add-apt-repository" "ip")
  local missing_prerequisites=()

  for prerequisite in "${prerequisites[@]}"; do
    if ! command_exists "$prerequisite"; then
      missing_prerequisites+=("$prerequisite")
    fi
  done

  if [ ${#missing_prerequisites[@]} -eq 0 ]; then
    echo -e "${GREEN}All prerequisites are installed.${NC}"
  else
    echo -e "${RED}Prerequisites missing:${NC}"
    for prerequisite in "${missing_prerequisites[@]}"; do
      echo -e "  - $prerequisite"
    done
    echo -e "Installing missing prerequisites..."
    install_prerequisites
  fi
}

install_prerequisites() {
  local prerequisites=("lsb-release" "curl" "apt-transport-https" "zip" "unzip" "gnupg" "lolcat" "figlet" "software-properties-common" "iproute2")

  echo -e "${GREEN}Installing prerequisites...${NC}"
  apt-get update
  apt-get install -y "${prerequisites[@]}"
  ensure_lolcat_path
  echo -e "${GREEN}All prerequisites have been installed.${NC}"
}

ensure_lolcat_path() {
  if ! command -v lolcat >/dev/null 2>&1 && [[ -x /usr/games/lolcat ]]; then
    ln -sf /usr/games/lolcat /usr/local/bin/lolcat
  fi
}

check_and_install_lolcat() {
  ensure_lolcat_path
  if ! command_exists "lolcat"; then
    echo -e "${RED}lolcat is not installed. Installing lolcat...${NC}"
    if command_exists "sudo"; then
      sudo gem install lolcat
      echo -e "${GREEN}lolcat has been installed.${NC}"
    else
      echo -e "${RED}sudo is not available. Please install lolcat manually.${NC}"
    fi
  fi
}

check_and_install_docker() {
  if ! command_exists "docker"; then
    echo -e "${YELLOW}Docker is not installed. Installing Docker...${NC}"
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    systemctl enable docker
    systemctl start docker
    echo -e "${GREEN}Docker has been installed.${NC}"
    rm -f get-docker.sh
  else
    echo -e "${GREEN}Docker is already installed.${NC}"
  fi

  if ! command_exists "docker-compose"; then
    echo -e "${YELLOW}Docker Compose is not installed. Installing Docker Compose...${NC}"
    curl -L "https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    echo -e "${GREEN}Docker Compose has been installed.${NC}"
  else
    echo -e "${GREEN}Docker Compose is already installed.${NC}"
  fi
}

prompt_elastic_password_once() {
  if [[ -z "${ARIA_ELASTIC_PASSWORD:-}" ]]; then
    echo -e "${YELLOW}One password will be used for Elasticsearch, Kibana, Filebeat, Wazuh, Falco, and Telegraf.${NC}"
    while [[ -z "${ARIA_ELASTIC_PASSWORD:-}" ]]; do
      read -s -p "Enter the shared Elastic password: " ARIA_ELASTIC_PASSWORD
      echo
      if [[ -z "$ARIA_ELASTIC_PASSWORD" ]]; then
        echo -e "${RED}Password cannot be empty.${NC}"
      elif [[ ${#ARIA_ELASTIC_PASSWORD} -lt 6 ]]; then
        echo -e "${RED}Password must be at least 6 characters.${NC}"
        ARIA_ELASTIC_PASSWORD=""
      elif [[ ! "$ARIA_ELASTIC_PASSWORD" =~ ^[A-Za-z0-9._@%+=:,/-]+$ ]]; then
        echo -e "${RED}Use only letters, numbers, and . _ @ % + = : , / - for this shared setup password.${NC}"
        ARIA_ELASTIC_PASSWORD=""
      fi
    done
  fi

  local local_ip
  local_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  if [[ ${#ARIA_ELASTIC_PASSWORD} -lt 6 || ! "$ARIA_ELASTIC_PASSWORD" =~ ^[A-Za-z0-9._@%+=:,/-]+$ ]]; then
    echo -e "${RED}ARIA_ELASTIC_PASSWORD is not safe for generated config files. Use only letters, numbers, and . _ @ % + = : , / - with at least 6 characters.${NC}"
    exit 1
  fi

  export ARIA_ELASTIC_PASSWORD
  export ARIA_ES_USERNAME="${ARIA_ES_USERNAME:-elastic}"
  export ARIA_ES_URL="${ARIA_ES_URL:-https://${local_ip}:9200}"
}

welcome_message() {
  figlet "SOC Setup" | lolcat
  echo -e "${GREEN}Automated SOC Components Setup Script${NC}"
  echo -e "${GREEN}Author: Ghazi Mabrouki${NC}"
  echo ""
  echo -e "${GREEN}This script will help you set up a comprehensive security monitoring environment.${NC}"
  echo "It includes the following components:"
  echo "1. SIEM (Elasticsearch, Kibana, Filebeat)"
  echo "2. NIDS (Suricata)"
  echo "3. HIDS (Wazuh Manager)"
  echo "4. Runtime Security (Falco)"
  echo "5. Host Metrics (Telegraf)"
  echo "6. Detection Rules (Kibana security rules)"
  echo "7. Security Hardening (Fail2Ban, Firewall, SSH)"
  echo ""
  echo "The SIEM will be installed with Elasticsearch version 7.17.13 and Wazuh version 4.5, as they were compatible during the script creation."
  echo "Falco will run as a system service with Falcosidekick forwarding alerts to Elasticsearch."
  echo "Telegraf will run as a host service, ship host metrics to Elasticsearch, and generate the target-machine bootstrap to monitor remote systems."
  echo "Detection Rules create security detection rules in Kibana for monitoring suspicious activities."
  echo "Security Hardening applies Fail2Ban, UFW firewall, and SSH hardening measures."
  echo ""
  echo -e "${YELLOW}Automatic mode is enabled. Components run in order without repeated yes/password prompts.${NC}"
  echo -e "${YELLOW}Override with INSTALL_SIEM=0, INSTALL_FALCO=0, etc. if you need to skip a component.${NC}"
}

install_siem() {
  check_and_install_lolcat
  figlet "Starting SIEM Setup" | lolcat
  chmod +x "${SCRIPT_DIR}/siem_setup.sh"
  if ! "${SCRIPT_DIR}/siem_setup.sh"; then
    echo -e "${RED}SIEM setup failed.${NC}"
    exit 1
  fi
  figlet "SIEM Setup Completed" | lolcat
}

install_suricata() {
  check_and_install_lolcat
  figlet "Starting Suricata Setup" | lolcat
  chmod +x "${SCRIPT_DIR}/suricata_setup.sh"
  if ! "${SCRIPT_DIR}/suricata_setup.sh"; then
    echo -e "${RED}Suricata setup failed.${NC}"
    exit 1
  fi
  figlet "Suricata Setup Completed" | lolcat
}

install_wazuh() {
  check_and_install_lolcat
  figlet "Starting Wazuh Setup" | lolcat
  chmod +x "${SCRIPT_DIR}/wazuh_setup.sh"
  if ! "${SCRIPT_DIR}/wazuh_setup.sh"; then
    echo -e "${RED}Wazuh setup failed.${NC}"
    exit 1
  fi
  figlet "Wazuh Setup Completed" | lolcat
}

install_falco() {
  check_and_install_lolcat
  figlet "Starting Falco Setup" | lolcat
  chmod +x "${SCRIPT_DIR}/setup-falco-server-elastic.sh"
  if ! "${SCRIPT_DIR}/setup-falco-server-elastic.sh"; then
    echo -e "${RED}Falco setup failed.${NC}"
    exit 1
  fi
  figlet "Falco Setup Completed" | lolcat
}

install_telegraf() {
  check_and_install_lolcat
  figlet "Starting Telegraf Setup" | lolcat

  if [[ ! -f /etc/filebeat/filebeat.yml ]]; then
    echo -e "${YELLOW}Skipping Telegraf: /etc/filebeat/filebeat.yml not found.${NC}"
    echo -e "${YELLOW}Tip: Install SIEM/Filebeat first, then rerun Telegraf setup.${NC}"
    return 0
  fi

  chmod +x "${SCRIPT_DIR}/telegraf_setup.sh"
  if ! "${SCRIPT_DIR}/telegraf_setup.sh"; then
    echo -e "${RED}Telegraf setup failed.${NC}"
    exit 1
  fi
  figlet "Telegraf Setup Completed" | lolcat
}

install_detection_rules() {
  check_and_install_lolcat
  figlet "Detection Rules" | lolcat

  if [[ ! -f /etc/filebeat/filebeat.yml ]]; then
    echo -e "${YELLOW}Skipping Detection Rules: /etc/filebeat/filebeat.yml not found.${NC}"
    echo -e "${YELLOW}Tip: Install SIEM first, then rerun Detection Rules setup.${NC}"
    return 0
  fi

  chmod +x "${SCRIPT_DIR}/detection_rules_setup.sh"
  if ! "${SCRIPT_DIR}/detection_rules_setup.sh"; then
    echo -e "${RED}Detection Rules setup failed.${NC}"
    exit 1
  fi
  figlet "Detection Rules Completed" | lolcat
}

install_hardening() {
  check_and_install_lolcat
  figlet "Security Hardening" | lolcat

  chmod +x "${SCRIPT_DIR}/hardening_setup.sh"
  if ! "${SCRIPT_DIR}/hardening_setup.sh"; then
    echo -e "${RED}Hardening setup failed.${NC}"
    exit 1
  fi
  figlet "Hardening Completed" | lolcat
}

check_system_requirements() {
  total_ram=$(free -m | awk '/^Mem:/{print $2}')
  available_disk_space=$(df -h / | awk 'NR==2{print "Available Disk Space: " $4}')

  echo "Checking Requirements" | lolcat
  echo "Total RAM: ${total_ram} MB" | lolcat
  echo "${available_disk_space}" | lolcat

  if [ "$total_ram" -lt 4096 ]; then
    echo "Warning: Not Enough RAM." | lolcat
    echo -e "${YELLOW}Recommended: 8GB RAM for all components${NC}"
    if [[ "$ARIA_ASSUME_YES" != "1" ]]; then
      read -p "Do you want to continue with the installation? (y/n): " continue_choice
    else
      continue_choice="y"
    fi
    if [ "$continue_choice" != "y" ]; then
      figlet "Setup Aborted" | lolcat
      exit 1
    fi
  fi
}

show_target_telegraf_bootstrap() {
  local bootstrap_path="/root/telegraf-target-bootstrap.sh"
  if [[ -f "$bootstrap_path" ]]; then
    echo ""
    echo -e "${YELLOW}Target Telegraf bootstrap generated.${NC}"
    echo -e "${GREEN}Saved locally at: ${bootstrap_path}${NC}"
    echo -e "${YELLOW}This file contains Elasticsearch credentials. Transfer it securely to the target machine.${NC}"
    if [[ "${ARIA_PRINT_BOOTSTRAP:-0}" == "1" ]]; then
      echo "================================================================"
      cat "$bootstrap_path"
      echo "================================================================"
    fi
  fi
}

main() {
  check_root_privileges
  check_prerequisites
  ensure_lolcat_path
  check_and_install_lolcat
  welcome_message
  check_system_requirements
  prompt_elastic_password_once

  install_siem_choice="n"
  install_suricata_choice="n"
  install_wazuh_choice="n"
  install_falco_choice="n"
  install_telegraf_choice="n"
  install_detection_rules_choice="n"
  install_hardening_choice="n"

  if [ "$INSTALL_SIEM" == "1" ]; then
    install_siem_choice="y"
    install_siem
  fi

  if [ "$INSTALL_SURICATA" == "1" ]; then
    install_suricata_choice="y"
    install_suricata
  fi

  if [ "$INSTALL_WAZUH" == "1" ]; then
    install_wazuh_choice="y"
    install_wazuh
  fi

  if [ "$INSTALL_FALCO" == "1" ]; then
    install_falco_choice="y"
    install_falco
  fi

  if [ "$INSTALL_TELEGRAF" == "1" ]; then
    install_telegraf_choice="y"
    install_telegraf
  fi

  if [ "$INSTALL_DETECTION_RULES" == "1" ]; then
    install_detection_rules_choice="y"
    install_detection_rules
  fi

  if [ "$INSTALL_HARDENING" == "1" ]; then
    install_hardening_choice="y"
    install_hardening
  fi

  figlet "All done!" | lolcat
  echo -e "${GREEN}============================================${NC}"
  echo -e "${GREEN}SOC Setup Complete!${NC}"
  echo -e "${GREEN}Author: Ghazi Mabrouki${NC}"
  echo -e "${GREEN}============================================${NC}"
  echo ""
  echo -e "${YELLOW}Access your dashboards at:${NC}"
  echo -e "Kibana: https://$(hostname -I | cut -d' ' -f1):5601"
  echo ""
  echo -e "${YELLOW}Check service status:${NC}"
  echo "systemctl status elasticsearch kibana filebeat"
  [ "$install_suricata_choice" == "y" ] && echo "systemctl status suricata"
  [ "$install_wazuh_choice" == "y" ] && echo "systemctl status wazuh-manager"
  [ "$install_falco_choice" == "y" ] && echo "systemctl status falcosidekick --no-pager -l"
  [ "$install_telegraf_choice" == "y" ] && echo "systemctl status telegraf"

  [ "$install_telegraf_choice" == "y" ] && show_target_telegraf_bootstrap
}

main



