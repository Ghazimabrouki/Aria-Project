#!/bin/bash
# Run API server as independent process - survives main.py restarts

LOG_FILE="/tmp/api_server.log"
PORT=${1:-8001}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

log "Starting API server on port $PORT..."

cd "/home/dash/opensoar backend"

# Check if port is free
if lsof -i :$PORT >/dev/null 2>&1; then
    log "Port $PORT already in use, checking if API is running..."
    if curl -s http://localhost:$PORT/monitor/health >/dev/null 2>&1; then
        log "API already running on port $PORT"
        exit 0
    fi
    log "Port in use but API not responding, will try to start anyway"
fi

# Start uvicorn with proper settings
python3 -m uvicorn api.app:app \
    --host 0.0.0.0 \
    --port $PORT \
    --log-level warning \
    2>&1 | while read line; do
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line" >> "$LOG_FILE"
    done &

log "API server started, waiting for health check..."
sleep 3

# Verify it's running
if curl -s http://localhost:$PORT/monitor/health >/dev/null 2>&1; then
    log "API server ready at http://localhost:$PORT"
else
    log "WARNING: API server may not have started properly"
fi