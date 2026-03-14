from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Dict, List

router = APIRouter(tags=["websockets"])

class ConnectionManager:
    def __init__(self):
        # Map scan_id to active websocket connections
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
            self.active_connections[scan_id].remove(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def broadcast_log(self, scan_id: int, message: str):
        if scan_id not in self.log_history:
            self.log_history[scan_id] = []
        self.log_history[scan_id].append(message)
        self.log_history[scan_id] = self.log_history[scan_id][-500:]

        if scan_id in self.active_connections:
            dead = []
            for connection in self.active_connections[scan_id]:
                try:
                    await connection.send_text(message)
                except Exception:
                    dead.append(connection)
            for connection in dead:
                try:
                    self.active_connections[scan_id].remove(connection)
                except ValueError:
                    pass
            if not self.active_connections.get(scan_id):
                self.active_connections.pop(scan_id, None)

manager = ConnectionManager()

@router.websocket("/ws/scan/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: int):
    await manager.connect(websocket, scan_id)
    try:
        while True:
            # Maintain connection until client disconnects
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)
