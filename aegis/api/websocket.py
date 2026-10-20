from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect


def build_websocket_router(runtime) -> APIRouter:
    router = APIRouter()

    @router.websocket("/ws")
    async def realtime(websocket: WebSocket):
        await websocket.accept()
        queue = runtime.subscribe()
        try:
            await websocket.send_json({"type": "connected", "payload": {"monitoring": runtime.monitoring}})
            while True:
                message = await queue.get()
                await websocket.send_json(message)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            runtime.unsubscribe(queue)

    return router
