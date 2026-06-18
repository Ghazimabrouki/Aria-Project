#!/bin/bash

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Function to display welcome message
welcome_message() {
  echo -e "${YELLOW}#############################################${NC}"
  echo -e "${YELLOW}##  Welcome to the SIEM Setup Script!      ##${NC}"
  echo -e "${YELLOW}##  This script will guide you through the ##${NC}"
  echo -e "${YELLOW}##  installation and configuration of     ##${NC}"
  echo -e "${YELLOW}##  Elasticsearch, Kibana, and Filebeat.   ##${NC}"
  echo -e "${YELLOW}##  Please follow the prompts to provide  ##${NC}"
  echo -e "${YELLOW}##  the necessary information.             ##${NC}"
  echo -e "${YELLOW}#############################################${NC}"
  echo -e "Script Author: Ghazi Mabrouki"
  echo -e "Script Created on: $(date '+%Y-%m-%d %H:%M:%S')"
}

# Function for logging with color
log() {
  local color=$1
  local message=$2
  echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${color}${message}${NC}"
}

# Function for error handling with color
handle_error() {
  log "${RED}" "Error: $1"
  exit 1
}

# Function for success message with color
log_success() {
  log "${GREEN}" "$1"
}

get_elastic_password() {
  local elastic_password="${ARIA_ELASTIC_PASSWORD:-}"
  while [ -z "$elastic_password" ]; do
    read -s -p "Enter the password for the elastic user: " elastic_password
    echo
  done
  printf '%s' "$elastic_password"
}

# Function to check for existing installations
check_existing_installations() {
  local existing_installations=false

  if systemctl is-active --quiet elasticsearch || systemctl is-active --quiet kibana || systemctl is-active --quiet filebeat; then
    existing_installations=true
  fi

  echo "$existing_installations"
}

# Function to remove existing Elasticsearch, Kibana, and Filebeat installations
remove_existing_installations() {
  log "${YELLOW}Removing existing installations...${NC}"
  sudo systemctl stop elasticsearch kibana filebeat
  sudo apt-get purge elasticsearch kibana filebeat -y
  sudo rm -rf /etc/elasticsearch /etc/kibana /etc/filebeat /usr/share/elasticsearch /usr/share/kibana /var/lib/elasticsearch /var/lib/kibana /var/log/elasticsearch /var/log/kibana || handle_error "Failed to remove existing installations"
  log_success "Existing installations removed successfully."
}

# Function to install Elasticsearch, Kibana, and Filebeat versions
install_elk_versions() {
  local elk_version="7.17.13"  # Set the desired version

  log "${YELLOW}Installing Elasticsearch, Kibana, and Filebeat version $elk_version...${NC}"

  # Check if the Elastic repository is already added
  if ! grep -q "https://artifacts.elastic.co/packages/7.x/apt" /etc/apt/sources.list.d/elastic-7.x.list; then
    log "Adding the Elastic repository..."
    # Install the GPG key
    curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/elasticsearch.gpg --import && chmod 644 /usr/share/keyrings/elasticsearch.gpg
    # Add the repository
    echo "deb [signed-by=/usr/share/keyrings/elasticsearch.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-7.x.list
    # Update the package information
    apt-get update || handle_error "Failed to update package information"
  fi

  # Install Elasticsearch, Kibana, and Filebeat
  sudo apt-get install elasticsearch="$elk_version" kibana="$elk_version" filebeat="$elk_version" -y || handle_error "Failed to install Elasticsearch, Kibana, and Filebeat"

  log_success "Elasticsearch, Kibana, and Filebeat version $elk_version installed successfully."
}

# Function to create certificates and deploy
create_and_deploy_certificates() {
  local_ip=$(hostname -I | cut -d' ' -f1)
  instances_file="/usr/share/elasticsearch/instances.yml"

  log "${YELLOW}Creating and deploying certificates...${NC}"

  # Forcefully remove certs directory and certs.zip
  sudo rm -rf ~/"certs" ~/"certs.zip"

  cat > "$instances_file" <<EOF
instances:
- name: "elasticsearch"
  ip:
  - "$local_ip"
- name: "filebeat"
  ip:
  - "$local_ip"
- name: "kibana"
  ip:
  - "$local_ip"
EOF

  sudo /usr/share/elasticsearch/bin/elasticsearch-certutil cert ca --pem --in "$instances_file" --keep-ca-key --out ~/"certs.zip" || handle_error "Failed to create certificates"
  unzip ~/"certs.zip" -d ~/"certs"

  mkdir /etc/elasticsearch/certs/ca -p
  cp -R ~/certs/ca/ ~/certs/elasticsearch/* /etc/elasticsearch/certs/
  chown -R elasticsearch: /etc/elasticsearch/certs
  chmod -R 500 /etc/elasticsearch/certs
  chmod 400 /etc/elasticsearch/certs/ca/ca.* /etc/elasticsearch/certs/elasticsearch.*

  mkdir /etc/filebeat/certs/ca -p
  cp -R ~/certs/ca/ ~/certs/filebeat/* /etc/filebeat/certs/
  chmod -R 500 /etc/filebeat/certs
  chmod 400 /etc/filebeat/certs/ca/ca.* /etc/filebeat/certs/filebeat.*

  mkdir /etc/kibana/certs/ca -p
  cp ~/certs/ca/ca.crt /etc/kibana/certs/ca
  cp ~/certs/kibana/* /etc/kibana/certs/
  chown -R kibana: /etc/kibana/certs
  chmod -R 500 /etc/kibana/certs
  chmod 400 /etc/kibana/certs/ca/ca.* /etc/kibana/certs/kibana.*

  log_success "Certificates created and deployed successfully."
}

# Function to configure Elasticsearch
configure_elasticsearch() {
  local_ip=$(hostname -I | cut -d ' ' -f1)
  elasticsearch_config="/etc/elasticsearch/elasticsearch.yml"

  log "${YELLOW}Configuring Elasticsearch...${NC}"

  cat > "$elasticsearch_config" <<EOF
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: none
xpack.security.transport.ssl.key: /etc/elasticsearch/certs/elasticsearch.key
xpack.security.transport.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.crt
xpack.security.transport.ssl.certificate_authorities: /etc/elasticsearch/certs/ca/ca.crt
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.verification_mode: none
xpack.security.http.ssl.key: /etc/elasticsearch/certs/elasticsearch.key
xpack.security.http.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.crt
xpack.security.http.ssl.certificate_authorities: /etc/elasticsearch/certs/ca/ca.crt
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable elasticsearch
  sudo systemctl start elasticsearch

  log "Waiting for Elasticsearch to answer before setting passwords..."
  for _ in {1..30}; do
    if curl -sk "https://$local_ip:9200" >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done

  log "Generate credentials for all the Elastic Stack pre-built roles and users..."
  if [[ -n "${ARIA_ELASTIC_PASSWORD:-}" ]]; then
    {
      printf 'y\n'
      for _ in elastic apm_system kibana logstash_system beats_system remote_monitoring_user; do
        printf '%s\n%s\n' "$ARIA_ELASTIC_PASSWORD" "$ARIA_ELASTIC_PASSWORD"
      done
    } | sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch-setup-passwords interactive
  else
    sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch-setup-passwords interactive
  fi

  log_success "Elasticsearch configured successfully."
}

# Function to configure Kibana
configure_kibana() {
  local_ip=$(hostname -I | cut -d' ' -f1)
  kibana_config="/etc/kibana/kibana.yml"

  log "${YELLOW}Configuring Kibana...${NC}"

  log "Using the shared elastic user password."
  elastic_password="$(get_elastic_password)"

  cat > "$kibana_config" <<EOF
server.port: 5601
server.host: 0.0.0.0
elasticsearch.hosts: ["https://$local_ip:9200"]
xpack.encryptedSavedObjects.encryptionKey: 'fhjskloppd678ehkdfdlliverpoolfcr'
elasticsearch.ssl.certificateAuthorities: /etc/kibana/certs/ca/ca.crt
elasticsearch.ssl.certificate: /etc/kibana/certs/kibana.crt
elasticsearch.ssl.key: /etc/kibana/certs/kibana.key
server.ssl.enabled: true
server.ssl.certificate: /etc/kibana/certs/kibana.crt
server.ssl.key: /etc/kibana/certs/kibana.key
xpack.security.enabled: true
elasticsearch.username: elastic
elasticsearch.password: "$elastic_password"
elasticsearch.ssl.verificationMode: none
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable kibana
  sudo systemctl start kibana

  log_success "Kibana configured successfully."
}

# Function to configure Filebeat
configure_filebeat() {
  local_ip=$(hostname -I | cut -d' ' -f1)
  elastic_ip="$local_ip"  # Use the system's IP address
  filebeat_config="/etc/filebeat/filebeat.yml"
  elastic_password=""

  log "${YELLOW}Configuring Filebeat...${NC}"

  elastic_password="$(get_elastic_password)"

  # Check if Elasticsearch is not in "red" state and Kibana is accessible
  check_services() {
    local elastic_status=$(curl -s -k -u elastic:"$elastic_password" "https://$local_ip:9200/_cat/health" | awk '{print $4}')
    local kibana_status=$(curl -s -k -o /dev/null "https://$local_ip:5601" && echo "OK" || echo "FAILED")

    [ "$elastic_status" != "red" ] && [ "$kibana_status" = "OK" ]
  }

  # Wait for Elasticsearch and Kibana to be up and running
  wait_for_services() {
    local max_attempts=30
    local attempts=0

    while [ "$attempts" -lt "$max_attempts" ]; do
      if check_services; then
        break
      fi

      attempts=$((attempts + 1))
      sleep 10  # Wait for 10 seconds before checking again
    done

    if [ "$attempts" -eq "$max_attempts" ]; then
      handle_error "Timed out waiting for Elasticsearch and Kibana to be up and running or Elasticsearch in 'red' state."
    fi
  }

  wait_for_services

  # Continue with the Filebeat configuration
  cat > "$filebeat_config" <<EOF
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/*.log
- type: filestream
  enabled: false
  paths:
    - /var/log/*.log
filebeat.config.modules:
  path: \${path.config}/modules.d/*.yml
  reload.enabled: false
setup.template.settings:
  index.number_of_shards: 1
setup.kibana:
  host: "https://$elastic_ip:5601"
  ssl.enabled: true
  ssl.verification_mode: none
output.elasticsearch:
  hosts: ["$elastic_ip:9200"]
  protocol: "https"
  username: "elastic"
  password: "$elastic_password"
  ssl.enabled: true
  ssl.verification_mode: none
processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~
EOF

  sudo systemctl daemon-reload
  sudo systemctl start filebeat
  sleep 15
  sudo filebeat setup -e || handle_error "Failed to set up Filebeat"

  # Enable and configure Filebeat System Module for structured auth logs
  log "Enabling Filebeat system module..."
  filebeat modules enable system

  # Configure system module to monitor auth.log with separate index
  # This creates structured authentication data in system-auth-* index
  # while keeping existing logs in filebeat-*
  cat > /etc/filebeat/modules.d/system.yml <<'EOF'
- module: system
  syslog:
    enabled: true
    var.paths: ["/var/log/syslog"]
    var.index_pattern: "system-syslog-%{[agent.version]}-%{+yyyy.MM.dd}"
  auth:
    enabled: true
    var.paths: ["/var/log/auth.log"]
    var.index_pattern: "system-auth-%{[agent.version]}-%{+yyyy.MM.dd}"
EOF

  # Create index pattern for system-auth data in Kibana
  log "Creating Kibana index pattern for system-auth..."
  
  # Wait for some data to be generated
  sleep 10
  
  # Create index pattern via Kibana API (best effort)
  if command -v curl >/dev/null 2>&1 && [[ -f /etc/filebeat/filebeat.yml ]]; then
    # Extract elasticsearch credentials
    ES_USER=$(grep -E '^[[:space:]]*username:' /etc/filebeat/filebeat.yml | head -1 | awk -F: '{print $2}' | tr -d ' "')
    ES_PASS=$(grep -E '^[[:space:]]*password:' /etc/filebeat/filebeat.yml | head -1 | awk -F: '{print $2}' | tr -d ' "')
    ES_HOST=$(grep -E '^[[:space:]]*hosts:' /etc/filebeat/filebeat.yml | head -1 | sed -E 's/.*hosts:[[:space:]]*\[?//; s/\]//; s/".*//' | tr -d ' ')
    KIBANA_URL="https://$(hostname -I 2>/dev/null | awk '{print $1}'):5601"
    
    if [[ -n "$ES_USER" && -n "$ES_PASS" ]]; then
      # Create index pattern for system-auth
      curl -sk -u "${ES_USER}:${ES_PASS}" -X POST "${KIBANA_URL}/api/saved_objects/index-pattern/system-auth" \
        -H "Content-Type: application/json" \
        -d '{"attributes":{"title":"system-auth-*","timeFieldName":"@timestamp"}}' 2>/dev/null || true
      
      # Create index pattern for system-syslog
      curl -sk -u "${ES_USER}:${ES_PASS}" -X POST "${KIBANA_URL}/api/saved_objects/index-pattern/system-syslog" \
        -H "Content-Type: application/json" \
        -d '{"attributes":{"title":"system-syslog-*","timeFieldName":"@timestamp"}}' 2>/dev/null || true
      
      log "Kibana index patterns created for system-auth and system-syslog"
    fi
  fi

  # Restart Filebeat to load new configuration
  systemctl restart filebeat
  sleep 5
  log "Filebeat system module enabled - auth data goes to system-auth-* index"

  log_success "Filebeat configured successfully."
}

# Main script execution
welcome_message
existing_installations=$(check_existing_installations)

if [ "$existing_installations" = true ]; then
  if [[ "${ARIA_ASSUME_YES:-0}" == "1" ]]; then
    remove_existing="y"
    log "${YELLOW}" "Existing installations found; ARIA_ASSUME_YES=1 so they will be removed."
  else
    read -p "Existing installations found. Do you want to remove them? (y/n): " remove_existing
  fi
  if [ "$remove_existing" = "y" ]; then
    remove_existing_installations
  else
    handle_error "Exiting script. Please remove existing installations manually or rerun the script."
  fi
fi

install_elk_versions
create_and_deploy_certificates
configure_elasticsearch
configure_kibana
configure_filebeat

# Display success message at the end
log_success "SIEM setup completed successfully!"

