#!/bin/bash
# OpenSOAR Backend - Database Restore Script
# Usage: cd /home/dash/opensoar\ backend && ./scripts/maintenance/restore_db.sh <backup_date>
#
# Restores all persistent ARIA runtime data from data/backups/:
#   - investigations.db (SQLite)
#   - playbooks/ (remediation playbooks, inventories, extracted evidence)
#   - cursors/ (Elasticsearch poll cursors)
#   - seen_ids/ (deduplication IDs)
#   - artifacts/ (tickets, decision logs, pattern tracking, geoip cache)
#   - evidence/ (remote evidence staging)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/.."
cd "$PROJECT_ROOT"

if [ -z "$1" ]; then
    echo "Usage: $0 <backup_date> (format: YYYYMMDD_HHMMSS)"
    echo ""
    echo "Available backups:"
    ls -1 data/backups/*.db 2>/dev/null | xargs -n1 basename | sed 's/investigations_//;s/.db//' || echo "No backups found"
    exit 1
fi

BACKUP_DATE=$1
BACKUP_DIR="data/backups"

echo "[$(date)] Starting restore from backup: $BACKUP_DATE"

# Stop backend (if running)
pkill -f "python.*main.py" || true
pkill -f "uvicorn api.app:app" || true
sleep 2

# Restore investigations DB
if [ -f "$BACKUP_DIR/investigations_$BACKUP_DATE.db" ]; then
    cp --preserve=all "$BACKUP_DIR/investigations_$BACKUP_DATE.db" "data/investigations.db"
    echo "  - Investigations DB restored"
else
    echo "ERROR: Backup file not found: investigations_$BACKUP_DATE.db"
    exit 1
fi

# Restore playbooks
if [ -f "$BACKUP_DIR/playbooks_$BACKUP_DATE.tar.gz" ]; then
    rm -rf data/playbooks
    tar -xzf "$BACKUP_DIR/playbooks_$BACKUP_DATE.tar.gz" -C data
    echo "  - Playbooks restored"
fi

# Restore cursors
if [ -f "$BACKUP_DIR/cursors_$BACKUP_DATE.tar.gz" ]; then
    rm -rf data/cursors
    tar -xzf "$BACKUP_DIR/cursors_$BACKUP_DATE.tar.gz" -C data
    echo "  - Cursors restored"
fi

# Restore seen_ids
if [ -f "$BACKUP_DIR/seen_ids_$BACKUP_DATE.tar.gz" ]; then
    rm -rf data/seen_ids
    tar -xzf "$BACKUP_DIR/seen_ids_$BACKUP_DATE.tar.gz" -C data
    echo "  - Seen IDs restored"
fi

# Restore artifacts
if [ -f "$BACKUP_DIR/artifacts_$BACKUP_DATE.tar.gz" ]; then
    rm -rf data/artifacts
    tar -xzf "$BACKUP_DIR/artifacts_$BACKUP_DATE.tar.gz" -C data
    echo "  - Artifacts restored"
fi

# Restore evidence staging
if [ -f "$BACKUP_DIR/evidence_$BACKUP_DATE.tar.gz" ]; then
    rm -rf data/evidence
    tar -xzf "$BACKUP_DIR/evidence_$BACKUP_DATE.tar.gz" -C data
    echo "  - Evidence restored"
fi

echo "[$(date)] Restore complete!"
echo ""
echo "Restored data summary:"
find data -maxdepth 1 -type d | sort | while read -r dir; do
    count=$(find "$dir" -type f 2>/dev/null | wc -l)
    echo "  $dir: $count files"
done

echo ""
echo "Restart the backend with:"
echo "  ./run_backend.sh"
