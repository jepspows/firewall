"""
Prometheus metrics endpoint for Firewall.

Exposes:
  - firewall_requests_total{verdict}
  - firewall_latency_seconds (histogram)
  - firewall_detections_total{category}
  - firewall_active_websockets
  - firewall_uptime_seconds

Endpoint: GET /metrics (Prometheus text format)
"""

import time
from typing import Optional

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

from .redis_stats import get_redis_stats


# ── Metrics ─────────────────────────────────────────────────────────

_registry = CollectorRegistry()

requests_total = Counter(
    "firewall_requests_total",
    "Total requests processed",
    ["verdict"],
    registry=_registry,
)

requests_latency = Histogram(
    "firewall_request_latency_seconds",
    "Request latency in seconds",
    buckets=[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0],
    registry=_registry,
)

detections_total = Counter(
    "firewall_detections_total",
    "Total detections by category",
    ["category"],
    registry=_registry,
)

active_websockets = Gauge(
    "firewall_active_websockets",
    "Number of active WebSocket connections",
    registry=_registry,
)

uptime_seconds = Gauge(
    "firewall_uptime_seconds",
    "Server uptime in seconds",
    registry=_registry,
)

model_available = Gauge(
    "firewall_ml_model_available",
    "Whether ML model is loaded (1) or not (0)",
    registry=_registry,
)


# ── Recording helpers ───────────────────────────────────────────────

_start_time = time.time()


def record_request(verdict: str, latency_ms: float, detections: list):
    """Record a processed request."""
    requests_total.labels(verdict=verdict).inc()
    requests_latency.observe(latency_ms / 1000.0)
    for det in detections:
        detections_total.labels(category=det.category).inc()


def record_ws_connect():
    active_websockets.inc()


def record_ws_disconnect():
    active_websockets.dec()


def record_ws_count(n: int):
    active_websockets.set(n)


def record_ml_available(available: bool):
    model_available.set(1 if available else 0)


def get_metrics_response() -> tuple[str, str]:
    """Return (body, content_type) for Prometheus scrape."""
    uptime_seconds.set(time.time() - _start_time)
    return generate_latest(_registry).decode("utf-8"), CONTENT_TYPE_LATEST
