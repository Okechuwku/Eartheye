from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Dict, List

router = APIRouter(tags=["websockets"])

class ConnectionManager:
    def __init__(self):
        # Map scan_id to active websocket connections
        self.active_connections: Dict[int, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, scan_id: int):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)

    def disconnect(self, websocket: WebSocket, scan_id: int):
        if scan_id in self.active_connections:
            self.active_connections[scan_id].remove(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def broadcast_log(self, scan_id: int, message: str):
        if scan_id in self.active_connections:
            for connection in self.active_connections[scan_id]:
                await connection.send_text(message)

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
