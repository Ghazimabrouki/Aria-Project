"""
WebSocket API for real-time frontend updates.

Provides WebSocket endpoints for:
- Investigation status changes
- Performance alerts
- System health updates

Channels:
- /ws/investigations - Investigation lifecycle events
- /ws/performance - Performance monitoring alerts
- /ws/system - System health changes
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from typing import Dict, List, Any, Optional
import json
import asyncio
import structlog
from datetime import datetime, timezone

logger = structlog.get_logger()

router = APIRouter(tags=["websocket"])


class WebSocketManager:
    """Manages WebSocket connections and broadcasts."""
    
    def __init__(self):
        self.connections: Dict[str, List[WebSocket]] = {
            "investigations": [],
            "performance": [],
            "system": []
        }
    
    async def connect(self, websocket: WebSocket, channel: str):
        """Accept a WebSocket connection and add to channel."""
        await websocket.accept()
        if channel not in self.connections:
            self.connections[channel] = []
        self.connections[channel].append(websocket)
        logger.info("websocket_connected", channel=channel)
    
    def disconnect(self, websocket: WebSocket, channel: str):
        """Remove a WebSocket connection from channel."""
        if channel in self.connections:
            if websocket in self.connections[channel]:
                self.connections[channel].remove(websocket)
                logger.info("websocket_disconnected", channel=channel)
    
    async def broadcast(self, channel: str, message: Dict[str, Any]):
        """Broadcast a message to all connections in a channel."""
        if channel not in self.connections:
            return
        
        disconnected = []
        for websocket in self.connections[channel]:
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.warning("websocket_send_failed", channel=channel, error=str(e))
                disconnected.append(websocket)
        
        # Clean up disconnected clients
        for ws in disconnected:
            self.disconnect(ws, channel)
    
    async def broadcast_investigation_update(self, investigation_id: str, status: str, details: str = ""):
        """Broadcast investigation status update."""
        await self.broadcast("investigations", {
            "type": "investigation_updated",
            "investigation_id": investigation_id,
            "status": status,
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    
    async def broadcast_performance_alert(self, alert: Dict[str, Any]):
        """Broadcast performance alert."""
        await self.broadcast("performance", {
            "type": "performance_alert",
            "alert": alert,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    
    async def broadcast_system_health(self, health: Dict[str, Any]):
        """Broadcast system health change."""
        await self.broadcast("system", {
            "type": "system_health",
            "health": health,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })


# Global manager instance
ws_manager = WebSocketManager()


@router.websocket("/ws/investigations")
async def websocket_investigations(websocket: WebSocket):
    """WebSocket for investigation lifecycle events."""
    channel = "investigations"
    await ws_manager.connect(websocket, channel)
    
    try:
        while True:
            # Keep connection alive, handle incoming messages
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                logger.info("websocket_message", channel=channel, message=message)
            except json.JSONDecodeError:
                logger.warning("websocket_invalid_json", data=data[:100])
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, channel)
    except Exception as e:
        logger.error("websocket_error", channel=channel, error=str(e))
        ws_manager.disconnect(websocket, channel)


@router.websocket("/ws/performance")
async def websocket_performance(websocket: WebSocket):
    """WebSocket for performance monitoring alerts."""
    channel = "performance"
    await ws_manager.connect(websocket, channel)
    
    try:
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                logger.info("websocket_message", channel=channel, message=message)
            except json.JSONDecodeError:
                logger.warning("websocket_invalid_json", data=data[:100])
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, channel)
    except Exception as e:
        logger.error("websocket_error", channel=channel, error=str(e))
        ws_manager.disconnect(websocket, channel)


@router.websocket("/ws/system")
async def websocket_system(websocket: WebSocket):
    """WebSocket for system health updates."""
    channel = "system"
    await ws_manager.connect(websocket, channel)
    
    try:
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                logger.info("websocket_message", channel=channel, message=message)
            except json.JSONDecodeError:
                logger.warning("websocket_invalid_json", data=data[:100])
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, channel)
    except Exception as e:
        logger.error("websocket_error", channel=channel, error=str(e))
        ws_manager.disconnect(websocket, channel)


@router.websocket("/ws")
async def websocket_all(websocket: WebSocket):
    """WebSocket for all events - receives all broadcasts."""
    await ws_manager.connect(websocket, "all")
    
    # Add to all channels
    for channel in ["investigations", "performance", "system"]:
        ws_manager.connections[channel].append(websocket)
    
    try:
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                logger.info("websocket_message", channel="all", message=message)
            except json.JSONDecodeError:
                logger.warning("websocket_invalid_json", data=data[:100])
    except WebSocketDisconnect:
        for channel in ["investigations", "performance", "system", "all"]:
            ws_manager.disconnect(websocket, channel)
    except Exception as e:
        logger.error("websocket_error", channel="all", error=str(e))
        for channel in ["investigations", "performance", "system", "all"]:
            ws_manager.disconnect(websocket, channel)


# ─── Helper functions for other modules to broadcast ────────────────────────

async def broadcast_investigation_change(investigation_id: str, old_status: str, new_status: str, details: str = ""):
    """Broadcast investigation status change. Call this from watcher/AI engine."""
    await ws_manager.broadcast_investigation_update(investigation_id, new_status, details or f"Status changed from {old_status} to {new_status}")


async def broadcast_performance_alert(alert: Dict[str, Any]):
    """Broadcast performance alert. Call this from performance orchestrator."""
    await ws_manager.broadcast_performance_alert(alert)


async def broadcast_system_status(component: str, status: str, message: str = ""):
    """Broadcast system health change."""
    await ws_manager.broadcast_system_health({
        "component": component,
        "status": status,
        "message": message
    })


# ─── Health check endpoint for WebSocket ───────────────────────────────────

@router.get("/ws/health")
async def ws_health():
    """Get WebSocket connection status."""
    return {
        "status": "healthy",
        "connections": {
            channel: len(connections)
            for channel, connections in ws_manager.connections.items()
        },
        "timestamp": datetime.now(timezone.utc).isoformat()
    }