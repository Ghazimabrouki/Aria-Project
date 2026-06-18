#!/bin/bash
# Start OpenSOAR backend as a persistent daemon
# Logs are written to /var/log/aria/ for production persistence.

cd "$(dirname "$0")"

# Production log directory
LOG_DIR="/var/log/aria"

# Ensure log directory exists and is writable
if [ ! -d "$LOG_DIR" ]; then
    echo "Creating log directory: $LOG_DIR"
    if ! mkdir -p "$LOG_DIR" 2>/dev/null; then
        echo "ERROR: Cannot create log directory $LOG_DIR. Run as root or adjust permissions."
        exit 1
    fi
fi
if [ ! -w "$LOG_DIR" ]; then
    echo "ERROR: Log directory $LOG_DIR is not writable by $(whoami)."
    exit 1
fi

# Activate venv
source .venv/bin/activate

# Kill existing
pkill -f "uvicorn.*8001" 2>/dev/null
pkill -f "python3 main.py" 2>/dev/null
sleep 2

# Start main.py (background services) in new session
exec setsid python3 main.py >> "$LOG_DIR/main.log" 2>&1 &
MAIN_PID=$!
echo "Background services started (PID: $MAIN_PID), logging to $LOG_DIR/main.log"

# Start uvicorn (API server) in new session  
exec setsid python3 -m uvicorn api.app:app --host 0.0.0.0 --port 8001 --timeout-keep-alive 120 \
    >> "$LOG_DIR/api.log" 2>&1 &
API_PID=$!
echo "API server started (PID: $API_PID), logging to $LOG_DIR/api.log"

sleep 5
curl -s http://localhost:8001/health || echo "Health check failed"
