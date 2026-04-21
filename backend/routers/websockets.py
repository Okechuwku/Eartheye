from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Dict, List
from datetime import datetime, timezone
import json

router = APIRouter(tags=["websockets"])

class ConnectionManager:
    def __init__(self):
        # Map scan_id -> list of active websocket connections
        self.active_connections: Dict[int, List[WebSocket]] = {}
        self.log_history: Dict[int, List[str]] = {}

    async def connect(self, websocket: WebSocket, scan_id: int):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)

        for message in self.log_history.get(scan_id, []):
            await websocket.send_text(message)

    def disconnect(self, websocket: WebSocket, scan_id: int):
        if scan_id in self.active_connections:
            try:
                self.active_connections[scan_id].remove(websocket)
            except ValueError:
                pass
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def _send(self, scan_id: int, payload: dict):
        """Send a structured JSON payload to all clients watching this scan."""
        if scan_id not in self.active_connections:
            return
        message = json.dumps(payload)
        dead = []
        for ws in self.active_connections[scan_id]:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws, scan_id)

    async def broadcast_log(
        self,
        scan_id: int,
        message: str,
        module: str = "System",
        level: str = "info",
    ):
        """
        Broadcast a structured log entry.

        Payload shape:
          {
            "type": "log",
            "scan_id": <int>,
            "module": <str>,
            "level": "info" | "warn" | "error" | "critical" | "success",
            "message": <str>,
            "timestamp": <ISO-8601 UTC string>
          }
        """
        payload = {
            "type": "log",
            "scan_id": scan_id,
            "module": module,
            "level": level,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self._send(scan_id, payload)

    async def broadcast_event(
        self,
        scan_id: int,
        event: str,
        module: str = "System",
        data: dict | None = None,
    ):
        """
        Broadcast a milestone event (module_start, module_complete, scan_complete, scan_failed).

        Payload shape:
          {
            "type": "event",
            "scan_id": <int>,
            "event": <str>,
            "module": <str>,
            "data": { ... },
            "timestamp": <ISO-8601 UTC string>
          }
        """
        payload = {
            "type": "event",
            "scan_id": scan_id,
            "event": event,
            "module": module,
            "data": data or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self._send(scan_id, payload)


manager = ConnectionManager()


@router.websocket("/ws/scan/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: int):
    await manager.connect(websocket, scan_id)
    try:
        while True:
            # Keep the connection alive; we only push from the server side
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)
