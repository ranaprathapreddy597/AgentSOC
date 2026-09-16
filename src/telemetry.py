"""
AgentSOC - Real-Time Telemetry & WebSocket Engine (telemetry.py)
IEEE Publication Grade Real-Time Dashboard Integration.
Handles low-latency streaming of Enriched Incident Objects (EIO) to Edge-AI monitoring consoles.
"""

import logging
from typing import List, Dict, Any
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


class WebSocketManager:
    """
    Manages active WebSocket connections for the React Dashboard.
    Ensures that real-time telemetry streaming does not block the main AI pipeline,
    and safely handles disconnected or dropped clients in unstable edge environments.
    """

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Accepts a new client connection and adds it to the active pool."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"[Telemetry] Client connected. Active streams: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        """Safely removes a disconnected client from the pool."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"[Telemetry] Client disconnected. Active streams: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        """
        Iterates over all active clients and streams the JSON telemetry payload.
        Includes built-in fault tolerance: if a client connection fails during transmission,
        it drops the client without crashing the server or disrupting other clients.
        """
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"[Telemetry] Failed to transmit to client ({e}). Dropping connection.")
                self.disconnect(connection)
