"""
Firewall Server — FastAPI proxy for prompt injection detection.

Run:   python -m firewall.server
       uvicorn firewall.server:app --host 0.0.0.0 --port 8787
"""

import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .classifier import get_classifier
from .models import CheckRequest, CheckResponse, StatsResponse

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

    # Update avg latency
    n = _stats.total_checked
    _stats.avg_latency_ms = ((_stats.avg_latency_ms * (n - 1)) + response.latency_ms) / n

    # Category counts
    for det in response.detections:
        _stats.detections_by_category[det.category] = (
            _stats.detections_by_category.get(det.category, 0) + 1
        )


# ── App ──────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Warm up classifier on startup."""
    get_classifier()
    yield


app = FastAPI(
    title="Firewall",
    description="Prompt Injection Firewall for AI Agents",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Routes ───────────────────────────────────────────────────────────


@app.get("/")
async def root():
    """Health check + basic info."""
    return {
        "name": "Firewall",
        "version": "0.1.0",
        "status": "ok",
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "uptime_seconds": time.time() - _start_time}


@app.post("/check", response_model=CheckResponse)
async def check_prompt(request: CheckRequest):
    """
    Check a single prompt for injection attempts.

    Returns verdict (allow/block), risk level, and detailed detections.
    """
    if not request.prompt.strip():
        raise HTTPException(status_code=400, detail="prompt must not be empty")

    classifier = get_classifier()
    response = classifier.classify(request)
    _update_stats(response)
    return response


@app.post("/check/batch", response_model=list[CheckResponse])
async def check_batch(requests: list[CheckRequest]):
    """Check multiple prompts in one request."""
    if not requests:
        raise HTTPException(status_code=400, detail="at least one request required")
    if len(requests) > 100:
        raise HTTPException(status_code=400, detail="max 100 prompts per batch")

    classifier = get_classifier()
    responses = classifier.batch_classify(requests)
    for r in responses:
        _update_stats(r)
    return responses


@app.get("/stats", response_model=StatsResponse)
async def stats():
    """Get aggregate statistics."""
    _stats.uptime_seconds = time.time() - _start_time
    return _stats


# ── Proxy middleware — optional ──────────────────────────────────────


@app.api_route("/proxy/{path:path}", methods=["POST", "GET"])
async def proxy_endpoint(request: Request, path: str):
    """
    Proxy mode: pass your agent requests through Firewall first.

    Send your agent request here with header X-Agent-URL pointing to your actual agent.
    Firewall checks the prompt, blocks if malicious, forwards if safe.
    """
    import httpx

    agent_url = request.headers.get("X-Agent-URL")
    if not agent_url:
        raise HTTPException(status_code=400, detail="X-Agent-URL header required")

    body = await request.json()
    prompt = body.get("prompt") or body.get("messages", [{}])[-1].get("content", "")

    # Check the prompt
    classifier = get_classifier()
    check_req = CheckRequest(prompt=str(prompt))
    result = classifier.classify(check_req)
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

    # Forward to actual agent
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

    print(
        f"""
    ╔══════════════════════════════════════════╗
    ║           FIREWALL v0.1.0                 ║
    ║   Prompt Injection Firewall for Agents    ║
    ╠══════════════════════════════════════════╣
    ║  Server:  http://{host}:{port}           ║
    ║  Docs:    http://{host}:{port}/docs      ║
    ║  Check:   POST http://{host}:{port}/check║
    ╚══════════════════════════════════════════╝
    """
    )
    uvicorn.run(app, host=host, port=port, log_level="info")
