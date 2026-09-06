import asyncio
import json
from typing import Any

class EventBus:
    def __init__(self):
        self._subscribers: dict[int, list[asyncio.Queue]] = {}

    def subscribe(self, session_id: int) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(session_id, []).append(q)
        return q

    def unsubscribe(self, session_id: int, q: asyncio.Queue):
        if session_id in self._subscribers:
            self._subscribers[session_id] = [x for x in self._subscribers[session_id] if x is not q]

    async def publish(self, session_id: int, event_type: str, data: Any = None):
        msg = json.dumps({"type": event_type, "session_id": session_id, "data": data}, ensure_ascii=False)
        for q in self._subscribers.get(session_id, []):
            await q.put(msg)

    async def broadcast(self, event_type: str, data: Any = None):
        msg = json.dumps({"type": event_type, "data": data}, ensure_ascii=False)
        for queues in self._subscribers.values():
            for q in queues:
                await q.put(msg)

bus = EventBus()
