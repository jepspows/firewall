"""
Redis-backed shared state for multi-instance deployments.

When enabled, all Firewall instances share:
  - Aggregate statistics (total_checked, blocked, etc.)
  - Detection category counts
  - Rate limiting counters

Enable via:
  export FIREWALL_REDIS_URL=redis://localhost:6379/0

If Redis is unavailable, falls back gracefully to in-memory stats.
"""

import json
import os
import time
from typing import Optional

from .models import StatsResponse


REDIS_URL = os.environ.get("FIREWALL_REDIS_URL", "")

# Redis key prefixes
KEY_PREFIX = "firewall:"
KEY_TOTAL_CHECKED = f"{KEY_PREFIX}total_checked"
KEY_TOTAL_BLOCKED = f"{KEY_PREFIX}total_blocked"
KEY_TOTAL_ALLOWED = f"{KEY_PREFIX}total_allowed"
KEY_TOTAL_FLAGGED = f"{KEY_PREFIX}total_flagged"
KEY_LATENCY_SUM = f"{KEY_PREFIX}latency_sum"
KEY_CATEGORIES = f"{KEY_PREFIX}categories"
KEY_START_TIME = f"{KEY_PREFIX}start_time"


class RedisStats:
    """Redis-backed statistics store."""

    def __init__(self):
        self._redis = None
        self._available = False
        self._init_redis()

    def _init_redis(self):
        if not REDIS_URL:
            return
        try:
            import redis
            self._redis = redis.from_url(
                REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
            self._redis.ping()
            self._available = True
            # Set start time if not exists
            self._redis.setnx(KEY_START_TIME, time.time())
        except Exception:
            self._available = False

    @property
    def available(self) -> bool:
        return self._available and self._redis is not None

    def increment(self, key: str, amount: int = 1) -> int:
        if self.available:
            try:
                return int(self._redis.incrby(key, amount))
            except Exception:
                pass
        return 0

    def get_int(self, key: str) -> int:
        if self.available:
            try:
                val = self._redis.get(key)
                return int(val) if val else 0
            except Exception:
                pass
        return 0

    def get_float(self, key: str) -> float:
        if self.available:
            try:
                val = self._redis.get(key)
                return float(val) if val else 0.0
            except Exception:
                pass
        return 0.0

    def incrby_float(self, key: str, amount: float) -> float:
        if self.available:
            try:
                return float(self._redis.incrbyfloat(key, amount))
            except Exception:
                pass
        return 0.0

    def hincrby(self, key: str, field: str, amount: int = 1) -> int:
        if self.available:
            try:
                return int(self._redis.hincrby(key, field, amount))
            except Exception:
                pass
        return 0

    def hgetall(self, key: str) -> dict[str, str]:
        if self.available:
            try:
                return self._redis.hgetall(key) or {}
            except Exception:
                pass
        return {}

    def get_start_time(self) -> float:
        if self.available:
            return self.get_float(KEY_START_TIME)
        return 0.0

    def get_stats(self, local_stats: Optional["StatsResponse"] = None) -> dict:
        """Build stats from Redis or local."""
        if self.available:
            total = self.get_int(KEY_TOTAL_CHECKED)
            latency_sum = self.get_float(KEY_LATENCY_SUM)
            cats = self.hgetall(KEY_CATEGORIES)
            cat_counts = {k: int(v) for k, v in cats.items()}
            uptime = time.time() - self.get_float(KEY_START_TIME)
            return {
                "total_checked": total,
                "total_blocked": self.get_int(KEY_TOTAL_BLOCKED),
                "total_allowed": self.get_int(KEY_TOTAL_ALLOWED),
                "total_flagged": self.get_int(KEY_TOTAL_FLAGGED),
                "avg_latency_ms": round(latency_sum / max(total, 1), 2),
                "detections_by_category": cat_counts,
                "uptime_seconds": uptime,
            }
        if local_stats:
            return local_stats.model_dump()
        return {}


# ── Global instance ────────────────────────────────────────────────

_redis_stats: Optional[RedisStats] = None


def get_redis_stats() -> RedisStats:
    global _redis_stats
    if _redis_stats is None:
        _redis_stats = RedisStats()
    return _redis_stats
