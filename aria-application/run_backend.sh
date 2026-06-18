#!/bin/bash
#
# OpenSOAR Backend Launcher
# 
# This script starts the backend with proper process isolation.
# Each component runs as a separate process, so if one crashes,
# it doesn't kill the entire application.
#
# Logs are written to /var/log/aria/ for production persistence.
# Ensure /var/log/aria exists and is writable by the service user.
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Use system python3 explicitly (the .venv is broken/incompatible)
PYTHON=/usr/bin/python3

# Production log directory
LOG_DIR="/var/log/aria"

# Ensure log directory exists and is writable
_ensure_log_dir() {
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
}
_ensure_log_dir

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Shutting down OpenSOAR Backend..."
    pkill -f "uvicorn api.app:app" 2>/dev/null
    pkill -f "python3 main.py" 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "=== OpenSOAR Backend Starting ==="
echo "  Logs: $LOG_DIR/"

# Start API server in background using nohup
echo "Starting API server on port 8001..."
nohup $PYTHON -m uvicorn api.app:app --host 0.0.0.0 --port 8001 --log-level warning > "$LOG_DIR/api.log" 2>&1 &
API_PID=$!

# Wait for API to start
for i in {1..10}; do
    sleep 1
    if ss -tlnp 2>/dev/null | grep -q ":8001 "; then
        echo "API server started (PID: $API_PID)"
        break
    fi
    if [ $i -eq 10 ]; then
        echo "WARNING: API server may not have started"
    fi
done

# Start main.py in background (it will skip API since we're running it separately)
echo "Starting background services..."
nohup $PYTHON main.py > "$LOG_DIR/main.log" 2>&1 &
MAIN_PID=$!

echo "=== OpenSOAR Backend Running ==="
echo "  API:     http://localhost:8001 (PID: $API_PID)"
echo "  Main:    PID: $MAIN_PID"
echo "  Logs:    $LOG_DIR/"
echo ""
echo "Checking health..."
curl -s http://localhost:8001/health || echo "Note: API may take a moment to start"
echo ""
echo "Use 'curl http://localhost:8001/health' to check API status"
echo "Press Ctrl+C to stop all services"

# Wait indefinitely
while true; do
    sleep 60
    # Check if processes are still running
    if ! kill -0 $API_PID 2>/dev/null; then
        echo "WARNING: API server (PID $API_PID) stopped, restarting..."
        nohup $PYTHON -m uvicorn api.app:app --host 0.0.0.0 --port 8001 --log-level warning > "$LOG_DIR/api.log" 2>&1 &
        API_PID=$!
    fi
    if ! kill -0 $MAIN_PID 2>/dev/null; then
        echo "WARNING: Main service (PID $MAIN_PID) stopped, restarting..."
        nohup $PYTHON main.py > "$LOG_DIR/main.log" 2>&1 &
        MAIN_PID=$!
    fi
done
