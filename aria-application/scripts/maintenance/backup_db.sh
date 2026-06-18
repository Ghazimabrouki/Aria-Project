#!/bin/bash
# OpenSOAR Backend - Database Backup Script
# Run via cron: 0 2 * * * cd /home/dash/opensoar\ backend && ./scripts/maintenance/backup_db.sh
#
# Backs up all persistent ARIA runtime data under data/:
#   - investigations.db (SQLite)
#   - playbooks/ (remediation playbooks, inventories, extracted evidence)
#   - cursors/ (Elasticsearch poll cursors)
#   - seen_ids/ (deduplication IDs)
#   - artifacts/ (tickets, decision logs, pattern tracking, geoip cache)
#   - evidence/ (remote evidence staging, currently mostly empty)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/.."
cd "$PROJECT_ROOT"

BACKUP_DIR="data/backups"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-30}

# Create backup directory
mkdir -p "$BACKUP_DIR"

echo "[$(date)] Starting OpenSOAR backup..."

# Backup SQLite database
DB_PATH="data/investigations.db"
if [ -f "$DB_PATH" ]; then
    cp --preserve=all "$DB_PATH" "$BACKUP_DIR/investigations_$DATE.db"
    echo "  - Investigations DB backed up"
else
    echo "  - WARNING: investigations.db not found at $DB_PATH"
fi

# Backup playbooks (includes evidence subdir)
if [ -d "data/playbooks" ]; then
    tar -czf "$BACKUP_DIR/playbooks_$DATE.tar.gz" -C data playbooks/
    echo "  - Playbooks backed up"
fi

# Backup cursors
if [ -d "data/cursors" ]; then
    tar -czf "$BACKUP_DIR/cursors_$DATE.tar.gz" -C data cursors/
    echo "  - Cursors backed up"
fi

# Backup seen_ids
if [ -d "data/seen_ids" ]; then
    tar -czf "$BACKUP_DIR/seen_ids_$DATE.tar.gz" -C data seen_ids/
    echo "  - Seen IDs backed up"
fi

# Backup artifacts (tickets, decision logs, pattern tracking, geoip cache)
if [ -d "data/artifacts" ]; then
    tar -czf "$BACKUP_DIR/artifacts_$DATE.tar.gz" -C data artifacts/
    echo "  - Artifacts backed up"
fi

# Backup evidence staging directory
if [ -d "data/evidence" ] && [ "$(ls -A data/evidence 2>/dev/null)" ]; then
    tar -czf "$BACKUP_DIR/evidence_$DATE.tar.gz" -C data evidence/
    echo "  - Evidence backed up"
fi

# Cleanup old backups
find "$BACKUP_DIR" -type f -mtime +$RETENTION_DAYS -delete
OLD_COUNT=$(find "$BACKUP_DIR" -type f | wc -l)
echo "[$(date)] Backup complete. Total backup files: $OLD_COUNT"

# List backup files
echo "Backup files:"
ls -lh "$BACKUP_DIR" | tail -10
