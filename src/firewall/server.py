"""
Firewall Server v0.2.0 — Full production server.

Features:
  - Rule-based + ML ensemble classification
  - Per-agent custom rulesets (YAML, hot-reload)
  - WebSocket: /ws/check, /ws/stream, /ws/dashboard
  - Redis-backed shared stats (optional, graceful fallback)
  - Prometheus /metrics endpoint
  - Real-time attack dashboard at /dashboard
  - Proxy mode at /proxy/{path}

Run:   python -m firewall.server
       uvicorn firewall.server:app --host 0.0.0.0 --port 8787
"""

import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, Response

from .classifier import get_classifier
from .ml_classifier import get_ensemble
from .models import CheckRequest, CheckResponse, StatsResponse, Verdict
from .prometheus_metrics import (
    get_metrics_response,
    record_ml_available,
    record_request,
    record_ws_connect,
    record_ws_count,
)
from .redis_stats import get_redis_stats
from .rulesets import get_ruleset_manager
from .websocket_handler import (
    ws_check_endpoint,
    ws_dashboard_endpoint,
    ws_stream_endpoint,
    ws_manager,
)

# ── Stats ────────────────────────────────────────────────────────────

_stats = StatsResponse()
_start_time = time.time()


def _update_stats(response: CheckResponse) -> None:
    _stats.total_checked += 1
    if response.verdict == "block":
        _stats.total_blocked += 1
    elif response.verdict == "allow":
        _stats.total_allowed += 1
    else:
        _stats.total_flagged += 1

    n = _stats.total_checked
    _stats.avg_latency_ms = ((_stats.avg_latency_ms * (n - 1)) + response.latency_ms) / n

    for det in response.detections:
        _stats.detections_by_category[det.category] = (
            _stats.detections_by_category.get(det.category, 0) + 1
        )

    # Redis shared state
    redis = get_redis_stats()
    if redis.available:
        redis.increment("firewall:total_checked")
        if response.verdict == "block":
            redis.increment("firewall:total_blocked")
        elif response.verdict == "allow":
            redis.increment("firewall:total_allowed")
        redis.incrby_float("firewall:latency_sum", response.latency_ms)
        for det in response.detections:
            redis.hincrby("firewall:categories", det.category)

    # Prometheus
    record_request(
        verdict=response.verdict.value,
        latency_ms=response.latency_ms,
        detections=response.detections,
    )

    # Dashboard broadcast
    categories = list(set(d.category for d in response.detections))
    import asyncio
    try:
        asyncio.create_task(ws_manager.broadcast_dashboard({
            "type": "attack",
            "verdict": response.verdict.value,
            "prompt": "***",  # Don't leak prompts to dashboard
            "risk_level": response.risk_level.value,
            "confidence": response.confidence,
            "categories": categories,
            "latency_ms": response.latency_ms,
            "timestamp": time.time(),
        }))
    except RuntimeError:
        pass


def _classify_with_ensemble(prompt: str, agent_id: str = None) -> CheckResponse:
    """Run full classification: rules + rulesets + ML ensemble."""
    classifier = get_classifier()
    ensemble = get_ensemble()

    # Per-agent ruleset
    if agent_id:
        ruleset = get_ruleset_manager().get(agent_id)
        # Check whitelist first
        if ruleset.check_whitelist(prompt):
            return CheckResponse(
                verdict=Verdict.ALLOW,
                risk_level="low",
                confidence=0.0,
                latency_ms=0.0,
            )
        # Check blacklist
        bl_dets = ruleset.check_blacklist(prompt)
        if bl_dets:
            return CheckResponse(
                verdict=Verdict.BLOCK,
                risk_level="critical",
                confidence=1.0,
                detections=bl_dets,
                latency_ms=0.0,
                blocked=True,
            )

    # Layer 1: Rule-based
    result = classifier.classify(CheckRequest(prompt=prompt, agent_id=agent_id))

    # Layer 2: Per-agent custom rules
    if agent_id:
        ruleset = get_ruleset_manager().get(agent_id)
        custom_dets = ruleset.check_custom(prompt)
        result.detections.extend(custom_dets)
        # Adjust threshold per agent
        if ruleset.threshold != classifier.threshold:
            if result.confidence >= ruleset.threshold:
                result.verdict = Verdict.BLOCK
                result.blocked = True

        # Filter disabled categories
        result.detections = [
            d for d in result.detections
            if ruleset.is_category_enabled(d.category)
        ]

    # Layer 3: ML ensemble
    ml_conf, ml_cat, ml_dets = ensemble.predict(prompt)
    if ml_dets:
        result.detections.extend(ml_dets)
        if ml_conf > result.confidence:
            result.confidence = ml_conf

    # Re-evaluate verdict
    threshold = classifier.threshold
    if agent_id:
        threshold = get_ruleset_manager().get(agent_id).threshold

    if result.confidence >= threshold:
        result.verdict = Verdict.BLOCK
        result.blocked = True

    return result


# ── App ──────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Warm up on startup."""
    get_classifier()
    ensemble = get_ensemble()
    record_ml_available(ensemble.ml.loaded)
    redis = get_redis_stats()
    if redis.available:
        print("  Redis:    connected")
    else:
        print("  Redis:    not configured (using in-memory stats)")
    yield


app = FastAPI(
    title="Firewall",
    description="Prompt Injection Firewall for AI Agents — Production Edition",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── REST Routes ──────────────────────────────────────────────────────


@app.get("/")
async def root():
    return {
        "name": "Firewall",
        "version": "0.2.0",
        "status": "ok",
        "features": [
            "rule-based classifier",
            "ML ensemble classifier",
            "per-agent rulesets",
            "websocket streaming",
            "redis shared state",
            "prometheus metrics",
            "live dashboard",
        ],
        "docs": "/docs",
        "dashboard": "/dashboard",
        "metrics": "/metrics",
    }


@app.get("/health")
async def health():
    redis = get_redis_stats()
    return {
        "status": "healthy",
        "uptime_seconds": time.time() - _start_time,
        "redis": "connected" if redis.available else "disabled",
        "ml_model": get_ensemble().ml.loaded,
    }


@app.post("/check", response_model=CheckResponse)
async def check_prompt(request: CheckRequest):
    if not request.prompt.strip():
        raise HTTPException(status_code=400, detail="prompt must not be empty")

    response = _classify_with_ensemble(request.prompt, request.agent_id)
    _update_stats(response)
    return response


@app.post("/check/batch", response_model=list[CheckResponse])
async def check_batch(requests: list[CheckRequest]):
    if not requests:
        raise HTTPException(status_code=400, detail="at least one request required")
    if len(requests) > 100:
        raise HTTPException(status_code=400, detail="max 100 prompts per batch")

    responses = [
        _classify_with_ensemble(r.prompt, r.agent_id) for r in requests
    ]
    for r in responses:
        _update_stats(r)
    return responses


@app.get("/stats", response_model=StatsResponse)
async def stats():
    _stats.uptime_seconds = time.time() - _start_time
    redis = get_redis_stats()
    if redis.available:
        redis_data = redis.get_stats()
        return StatsResponse(
            total_checked=redis_data["total_checked"],
            total_blocked=redis_data["total_blocked"],
            total_allowed=redis_data["total_allowed"],
            total_flagged=redis_data["total_flagged"],
            avg_latency_ms=redis_data["avg_latency_ms"],
            detections_by_category=redis_data["detections_by_category"],
            uptime_seconds=redis_data["uptime_seconds"],
        )
    return _stats


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    body, content_type = get_metrics_response()
    return Response(content=body, media_type=content_type)


# ── Dashboard ────────────────────────────────────────────────────────

_DASHBOARD_HTML = (
    Path(__file__).parent / "dashboard.html"
).read_text(encoding="utf-8")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Real-time attack dashboard."""
    return HTMLResponse(content=_DASHBOARD_HTML)


# ── Ruleset management ───────────────────────────────────────────────


@app.get("/rules")
async def list_rulesets():
    """List all agent rulesets."""
    return {"agents": get_ruleset_manager().list_agents()}


@app.get("/rules/{agent_id}")
async def get_ruleset(agent_id: str):
    ruleset = get_ruleset_manager().get(agent_id)
    if not ruleset.path.exists():
        raise HTTPException(status_code=404, detail=f"no ruleset for '{agent_id}'")
    return ruleset.config


@app.put("/rules/{agent_id}")
async def create_ruleset(agent_id: str, config: dict):
    ruleset = get_ruleset_manager().create(agent_id, config)
    return {"status": "created", "agent_id": agent_id, "config": ruleset.config}


@app.delete("/rules/{agent_id}")
async def delete_ruleset(agent_id: str):
    get_ruleset_manager().delete(agent_id)
    return {"status": "deleted", "agent_id": agent_id}


# ── WebSocket Routes ─────────────────────────────────────────────────


@app.websocket("/ws/check")
async def websocket_check(ws: WebSocket):
    await ws_check_endpoint(ws)


@app.websocket("/ws/stream")
async def websocket_stream(ws: WebSocket):
    await ws_stream_endpoint(ws)


@app.websocket("/ws/dashboard")
async def websocket_dashboard(ws: WebSocket):
    await ws_dashboard_endpoint(ws)


# ── Proxy ────────────────────────────────────────────────────────────


@app.api_route("/proxy/{path:path}", methods=["POST", "GET"])
async def proxy_endpoint(request: Request, path: str):
    import httpx

    agent_url = request.headers.get("X-Agent-URL")
    if not agent_url:
        raise HTTPException(status_code=400, detail="X-Agent-URL header required")

    body = await request.json()
    prompt = body.get("prompt") or body.get("messages", [{}])[-1].get("content", "")
    agent_id = request.headers.get("X-Agent-ID")

    result = _classify_with_ensemble(str(prompt), agent_id)
    _update_stats(result)

    if result.blocked:
        return JSONResponse(
            status_code=403,
            content={
                "error": "prompt blocked by firewall",
                "verdict": result.verdict,
                "risk_level": result.risk_level,
                "detections": [d.model_dump() for d in result.detections],
            },
        )

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.request(
            method=request.method,
            url=agent_url.rstrip("/") + "/" + path.lstrip("/"),
            json=body,
            headers={k: v for k, v in request.headers.items() if k.lower() != "host"},
        )
        return JSONResponse(status_code=resp.status_code, content=resp.json())


# ── Main ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("FIREWALL_PORT", "8787"))
    host = os.environ.get("FIREWALL_HOST", "0.0.0.0")

    redis = get_redis_stats()
    redis_status = "connected" if redis.available else "not configured"
    ml_status = "loaded" if get_ensemble().ml.loaded else "not trained (feature-based fallback)"

    print(f"""
╔══════════════════════════════════════════════════╗
║           FIREWALL v0.2.0 — Production           ║
║      Prompt Injection Firewall for AI Agents     ║
╠══════════════════════════════════════════════════╣
║  REST API:    http://{host}:{port}              ║
║  API Docs:    http://{host}:{port}/docs         ║
║  Dashboard:   http://{host}:{port}/dashboard    ║
║  Metrics:     http://{host}:{port}/metrics      ║
║  WebSocket:   ws://{host}:{port}/ws/check       ║
╠══════════════════════════════════════════════════╣
║  Redis:       {redis_status:<36} ║
║  ML Model:    {ml_status:<36} ║
╚══════════════════════════════════════════════════╝
    """.strip())
    uvicorn.run(app, host=host, port=port, log_level="info")
