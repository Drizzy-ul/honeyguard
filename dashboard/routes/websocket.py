import asyncio
import json
from typing import Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from core.logger import logger
from core.alerting import register_ws_listener, unregister_ws_listener

router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.loop = None

    def set_loop(self, loop):
        self.loop = loop

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"[WS] New SOC Dashboard client connected (Total: {len(self.active_connections)})")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"[WS] SOC Dashboard client disconnected (Total: {len(self.active_connections)})")

    async def broadcast(self, message: dict):
        if not self.active_connections:
            return
        data_text = json.dumps(message)
        dead_connections = set()
        for connection in list(self.active_connections):
            try:
                await connection.send_text(data_text)
            except Exception:
                dead_connections.add(connection)
        for dead in dead_connections:
            self.disconnect(dead)

    def handle_sync_event(self, event: dict):
        """Bridge sync events from threads to async websocket clients."""
        if not self.active_connections:
            return
        if self.loop and self.loop.is_running():
            asyncio.run_coroutine_threadsafe(self.broadcast({"type": "NEW_ATTACK", "data": event}), self.loop)

manager = ConnectionManager()

# Hook into the alerting system's WS broadcast listener
register_ws_listener(manager.handle_sync_event)

@router.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    # Set the running event loop reference
    manager.set_loop(asyncio.get_running_loop())
    await manager.connect(websocket)
    try:
        while True:
            # Keep-alive receive
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("action") == "PING":
                    await websocket.send_json({"type": "PONG"})
            except Exception:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.debug(f"WS error: {e}")
        manager.disconnect(websocket)
