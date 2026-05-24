"""
WebSocket support for streaming agent protection.

Endpoints:
  - ws://host:8787/ws/check       — Check individual messages
  - ws://host:8787/ws/stream      — Stream chunks, check on flush
  - ws://host:8787/ws/dashboard   — Real-time attack dashboard feed

Usage (client):
  ws = connect("ws://localhost:8787/ws/check")
  ws.send(json.dumps({"prompt": "..."}))
  response = ws.recv()  # {"verdict": "allow", ...}
"""

import json
import time
from typing import Optional

from fastapi import WebSocket, WebSocketDisconnect

from .classifier import get_classifier
from .ml_classifier import get_ensemble
from .models import CheckRequest, CheckResponse, Detection, Verdict
from .rulesets import get_ruleset_manager


class ConnectionManager:
    """Manages active WebSocket connections."""

    def __init__(self):
        self.active: dict[str, WebSocket] = {}
        self.dashboard_clients: set[WebSocket] = set()

    async def connect(self, ws: WebSocket, client_id: str):
        await ws.accept()
        self.active[client_id] = ws

    def disconnect(self, client_id: str):
        self.active.pop(client_id, None)
        self.dashboard_clients.discard(ws := None)
        # Find by identity
        to_remove = []
        for ws in self.dashboard_clients:
            try:
                pass
            except Exception:
                to_remove.append(ws)
        for ws in to_remove:
            self.dashboard_clients.discard(ws)

    async def broadcast_dashboard(self, event: dict):
        """Send event to all dashboard clients."""
        dead = []
        payload = json.dumps(event)
        for ws in self.dashboard_clients:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.dashboard_clients.discard(ws)


ws_manager = ConnectionManager()


# ── WebSocket route handlers ────────────────────────────────────────


async def ws_check_endpoint(websocket: WebSocket):
    """Check individual prompts via WebSocket."""
    client_id = f"ws_{id(websocket)}"
    await ws_manager.connect(websocket, client_id)
    classifier = get_classifier()
    ensemble = get_ensemble()

    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({
                    "error": "invalid json"
                }))
                continue

            prompt = msg.get("prompt", "")
            agent_id = msg.get("agent_id")
            if not prompt:
                await websocket.send_text(json.dumps({
                    "error": "prompt required"
                }))
                continue

            # Layer 1: Rule-based
            result = classifier.classify(CheckRequest(prompt=prompt, agent_id=agent_id))

            # Layer 2: ML ensemble
            ml_conf, ml_cat, ml_dets = ensemble.predict(prompt)
            if ml_dets:
                result.detections.extend(ml_dets)
                if ml_conf > result.confidence:
                    result.confidence = ml_conf

            # Re-evaluate verdict with combined confidence
            if result.confidence >= classifier.threshold:
                result.verdict = Verdict.BLOCK
                result.blocked = True

            await websocket.send_text(result.model_dump_json())

    except WebSocketDisconnect:
        ws_manager.disconnect(client_id)


async def ws_stream_endpoint(websocket: WebSocket):
    """
    Streaming mode: receive chunks, buffer them, check on flush.

    Client sends:
      {"action": "chunk", "data": "partial text..."}
      {"action": "flush"}  // triggers check on accumulated text
      {"action": "reset"}  // clears buffer
    """
    client_id = f"stream_{id(websocket)}"
    await ws_manager.connect(websocket, client_id)
    classifier = get_classifier()
    ensemble = get_ensemble()
    buffer: list[str] = []

    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({"error": "invalid json"}))
                continue

            action = msg.get("action", "check")

            if action == "chunk":
                buffer.append(msg.get("data", ""))
                await websocket.send_text(json.dumps({
                    "status": "buffered",
                    "chunks": len(buffer),
                    "total_chars": sum(len(c) for c in buffer),
                }))

            elif action == "flush":
                full_text = "".join(buffer)
                if not full_text:
                    await websocket.send_text(json.dumps({
                        "status": "empty",
                        "verdict": "allow",
                    }))
                    continue

                result = classifier.classify(
                    CheckRequest(prompt=full_text, agent_id=msg.get("agent_id"))
                )
                ml_conf, ml_cat, ml_dets = ensemble.predict(full_text)
                if ml_dets:
                    result.detections.extend(ml_dets)
                    if ml_conf > result.confidence:
                        result.confidence = ml_conf

                if result.confidence >= classifier.threshold:
                    result.verdict = Verdict.BLOCK
                    result.blocked = True

                await websocket.send_text(result.model_dump_json())
                buffer = []  # Clear buffer after flush

            elif action == "reset":
                buffer = []
                await websocket.send_text(json.dumps({
                    "status": "reset",
                    "chunks": 0,
                }))

            elif action == "check":
                # Direct check mode (single message)
                prompt = msg.get("prompt", "")
                result = classifier.classify(
                    CheckRequest(prompt=prompt, agent_id=msg.get("agent_id"))
                )
                ml_conf, ml_cat, ml_dets = ensemble.predict(prompt)
                if ml_dets:
                    result.detections.extend(ml_dets)
                    if ml_conf > result.confidence:
                        result.confidence = ml_conf
                if result.confidence >= classifier.threshold:
                    result.verdict = Verdict.BLOCK
                    result.blocked = True
                await websocket.send_text(result.model_dump_json())

    except WebSocketDisconnect:
        ws_manager.disconnect(client_id)


async def ws_dashboard_endpoint(websocket: WebSocket):
    """Real-time attack dashboard feed."""
    await websocket.accept()
    ws_manager.dashboard_clients.add(websocket)

    # Send initial connection message
    await websocket.send_text(json.dumps({
        "type": "connected",
        "timestamp": time.time(),
        "message": "Firewall Dashboard — live feed active",
    }))

    try:
        while True:
            # Keep connection alive, receive pings
            data = await websocket.receive_text()
            msg = json.loads(data)
            if msg.get("type") == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        ws_manager.dashboard_clients.discard(websocket)
