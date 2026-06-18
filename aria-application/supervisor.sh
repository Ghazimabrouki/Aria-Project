#!/bin/bash
# Process supervisor - auto-restarts main.py if it dies
# Runs as a robust daemon

LOG_FILE="/tmp/supervisor.log"
MAIN_LOG="/tmp/main_supervisor.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

start_main() {
    cd "/home/dash/opensoar backend"
    python3 main.py > "$MAIN_LOG" 2>&1 &
    MAIN_PID=$!
    log "Started main.py with PID $MAIN_PID"
}

stop_main() {
    if [ -n "$MAIN_PID" ]; then
        kill $MAIN_PID 2>/dev/null
        log "Stopped main.py (PID $MAIN_PID)"
    fi
}

log "Supervisor starting..."
start_main

# Track crash count
CRASH_COUNT=0

while true; do
    sleep 15
    
    # Check if main.py is still running
    if ! kill -0 $MAIN_PID 2>/dev/null; then
        CRASH_COUNT=$((CRASH_COUNT + 1))
        log "main.py died (crash #$CRASH_COUNT), restarting..."
        start_main
    else
        # Reset crash count on successful run
        if [ $CRASH_COUNT -gt 0 ]; then
            log "main.py running stable (was $CRASH_COUNT crashes)"
            CRASH_COUNT=0
        fi
    fi
    
    # Check for crash indicator in logs
    if [ -f /tmp/main.log ] && grep -q "task_crashed" /tmp/main.log 2>/dev/null; then
        NEW_CRASHES=$(grep -c "task_crashed" /tmp/main.log)
        log "Detected $NEW_CRASHES task crashes in logs"
    fi
done