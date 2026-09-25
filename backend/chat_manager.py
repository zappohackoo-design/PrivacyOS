from fastapi import WebSocket
from typing import Dict, List

class ConnectionManager:
    def __init__(self):
        # Maps agent_email -> WebSocket connection
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, email: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[email] = websocket

    def disconnect(self, email: str):
        if email in self.active_connections:
            del self.active_connections[email]

    async def send_personal_message(self, message: dict, recipient_email: str):
        if recipient_email in self.active_connections:
            websocket = self.active_connections[recipient_email]
            await websocket.send_json(message)

manager = ConnectionManager()