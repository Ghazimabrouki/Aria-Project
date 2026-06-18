#!/bin/bash

# Color codes for formatting
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SURICATA_TEMPLATE="${SCRIPT_DIR}/suricata_temp.yaml"

# Check for previous Suricata installation
if dpkg -l | grep -q suricata; then
    if [[ "${ARIA_ASSUME_YES:-0}" == "1" ]]; then
        remove_previous="y"
        echo "A previous Suricata installation is detected; ARIA_ASSUME_YES=1 so it will be removed."
    else
        read -p "A previous Suricata installation is detected. Do you want to remove it and continue (y/n)? " remove_previous
    fi

    if [ "$remove_previous" == "y" ]; then
        echo "Removing the previous Suricata installation..."
        apt-get remove --purge -y suricata
    else
        echo "Aborted. Please remove the previous Suricata installation manually and run the script again."
        exit 1
    fi
fi

# Step 1: Install dependencies
echo -e "${GREEN}Installing dependencies...${NC}"
apt-get update
apt-get install -y libpcre3 libpcre3-dbg libpcre3-dev build-essential libpcap-dev \
                libnet1-dev libyaml-0-2 libyaml-dev pkg-config zlib1g zlib1g-dev \
                libcap-ng-dev libcap-ng0 make libmagic-dev \
                libnss3-dev libgeoip-dev liblua5.1-0-dev libhiredis-dev libevent-dev \
                python3-yaml rustc cargo

if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Dependency installation failed.${NC}"
    exit 1
fi

# Step 2: Install Suricata
echo -e "${GREEN}Installing Suricata...${NC}"
add-apt-repository -y ppa:oisf/suricata-stable
apt-get update
apt-get install -y suricata

if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Suricata installation failed.${NC}"
    exit 1
fi

# Step 3: Find the active interface
echo -e "${GREEN}Finding active interface...${NC}"

interface=$(ip route show default | awk '/default/ {print $5; exit}')
if [ -z "$interface" ]; then
    echo -e "${RED}Error: Unable to determine the active interface.${NC}"
    exit 1
fi

echo "Configuration file updated with the active interface: $interface"

# Update the /etc/default/suricata file with the correct IFACE
echo -e "${GREEN}Updating /etc/default/suricata with IFACE=$interface...${NC}"
sed -i "s/^IFACE=.*/IFACE=$interface/" /etc/default/suricata

# Step 4: Update Suricata configuration files
echo -e "${GREEN}Updating Suricata configuration files...${NC}"

# Step 5: Start Suricata
echo -e "${GREEN}Starting Suricata...${NC}"
systemctl start suricata

sleep 10

# Step 6: Update suricata config file
suricata_rendered="$(mktemp)"
sed -E "s/interface: (enp[[:alnum:]_.:-]+|eth[[:alnum:]_.:-]+|ens[[:alnum:]_.:-]+|eno[[:alnum:]_.:-]+|wlan[[:alnum:]_.:-]+)/interface: ${interface}/g"     "$SURICATA_TEMPLATE" > "$suricata_rendered"
cp "$suricata_rendered" /etc/suricata/suricata.yaml
rm -f "$suricata_rendered"

systemctl restart suricata

# Wait for Suricata to start
echo -e "${GREEN}Waiting for Suricata to start...${NC}"
started=false
for _ in {1..30}; do
    if systemctl is-active --quiet suricata || grep -q "Engine started" /var/log/suricata/suricata.log 2>/dev/null; then
        started=true
        break
    fi
    sleep 10
done

if [ "$started" != "true" ]; then
    echo -e "${RED}Error: Suricata failed to start.${NC}"
    systemctl status suricata --no-pager -l || true
    exit 1
else
    echo -e "${GREEN}Suricata is now running.${NC}"
fi

# Step 7: Install and configure suricata-update
echo -e "${GREEN}Installing and configuring suricata-update...${NC}"

apt-get install -y python3-pip

python3 -m pip install --break-system-packages pyyaml || python3 -m pip install pyyaml || {
    echo -e "${RED}Error: failed to install pyyaml.${NC}"
    exit 1
}

python3 -m pip install --break-system-packages https://github.com/OISF/suricata-update/archive/master.zip || python3 -m pip install https://github.com/OISF/suricata-update/archive/master.zip || {
    echo -e "${RED}Error: failed to install suricata-update.${NC}"
    exit 1
}

# To upgrade suricata-update
python3 -m pip install --break-system-packages --pre --upgrade suricata-update || python3 -m pip install --pre --upgrade suricata-update || {
    echo -e "${RED}Error: failed to upgrade suricata-update.${NC}"
    exit 1
}

if ! command -v suricata-update >/dev/null 2>&1; then
    echo -e "${RED}Error: suricata-update command not found after installation.${NC}"
    exit 1
fi

suricata-update
suricata-update update-sources

# To update enabled sources
suricata-update enable-source oisf/trafficid
suricata-update enable-source etnetera/aggressive
suricata-update enable-source sslbl/ssl-fp-blacklist
suricata-update enable-source et/open
suricata-update enable-source tgreen/hunting
suricata-update enable-source sslbl/ja3-fingerprints
suricata-update enable-source ptresearch/attackdetection

# Restart Suricata
echo -e "${GREEN}Restarting Suricata...${NC}"
systemctl restart suricata

# Check for Suricata restart
echo -e "${GREEN}Checking for Suricata restart...${NC}"
restarted=false
for _ in {1..30}; do
    if systemctl is-active --quiet suricata || grep -q "Engine started" /var/log/suricata/suricata.log 2>/dev/null; then
        restarted=true
        break
    fi
    sleep 10
done

if [ "$restarted" != "true" ]; then
    echo -e "${RED}Error: Suricata failed to restart after rule update.${NC}"
    systemctl status suricata --no-pager -l || true
    exit 1
fi

echo -e "${GREEN}Suricata has been restarted with updated rules.${NC}"

# Step 8: Enable and configure Filebeat Suricata module
echo -e "${GREEN}Enabling and configuring Filebeat Suricata module...${NC}"
sudo filebeat modules enable suricata

# Modify the Suricata module settings
echo -e "${GREEN}Modifying Suricata module settings...${NC}"
cat <<EOL > /etc/filebeat/modules.d/suricata.yml
- module: suricata
  eve:
    enabled: true
    var.paths: ["/var/log/suricata/eve.json"]
EOL

# Restart Filebeat
echo -e "${GREEN}Restarting Filebeat...${NC}"
systemctl restart filebeat

# Execute Filebeat setup
echo -e "${GREEN}Running Filebeat setup...${NC}"
filebeat setup -e

echo -e "${GREEN}Filebeat is now configured and running.${NC}"

exit 0
