#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
tree -I "node_modules|.git|__pycache__|.next|.pytest_cache|*.pyc|*.log|data|_archive" > tree.txt
echo "Generated tree.txt"
