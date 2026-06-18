#!/usr/bin/env python3
"""Daemon starter for OpenSOAR backend."""
import os
import sys
import daemon
from pathlib import Path

# Change to app directory
os.chdir(str(Path(__file__).parent))

def main():
    import asyncio
    from api.app import app
    import uvicorn
    
    # Run uvicorn in the main thread
    uvicorn.run(app, host="0.0.0.0", port=8001, timeout_keep_alive=120)

if __name__ == "__main__":
    # Create pid file
    pid_file = "data/artifacts/backend.pid"
    
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))
    
    # Use daemon context
    with daemon.DaemonContext():
        main()