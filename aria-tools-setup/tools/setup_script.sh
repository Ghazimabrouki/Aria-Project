#!/bin/bash

# Compatibility entrypoint for the ARIA/SOC automatic setup.
# The old menu referenced removed tools such as OTel, Metricbeat, and Prometheus.
# Keep this filename working by forwarding to the maintained runner.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/setup_script_telegraf.sh" "$@"
