"""Data models for the Firewall API."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Verdict(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    FLAG = "flag"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CheckRequest(BaseModel):
    """Incoming request to scan."""

    prompt: str = Field(..., description="The user prompt to scan")
    agent_id: Optional[str] = Field(None, description="Optional agent identifier for logging")
    session_id: Optional[str] = Field(None, description="Optional session identifier")
    metadata: Optional[dict] = Field(default_factory=dict, description="Arbitrary metadata")


class Detection(BaseModel):
    """A single detection result."""

    rule_name: str
    category: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    matched_pattern: Optional[str] = None
    explanation: str


class CheckResponse(BaseModel):
    """Response after scanning a prompt."""

    verdict: Verdict
    risk_level: RiskLevel
    confidence: float = Field(..., ge=0.0, le=1.0)
    detections: list[Detection] = Field(default_factory=list)
    sanitized_prompt: Optional[str] = None
    latency_ms: float = 0.0
    blocked: bool = False

    @property
    def allowed(self) -> bool:
        return self.verdict == Verdict.ALLOW


class StatsResponse(BaseModel):
    """Aggregate statistics."""

    total_checked: int = 0
    total_blocked: int = 0
    total_allowed: int = 0
    total_flagged: int = 0
    avg_latency_ms: float = 0.0
    detections_by_category: dict[str, int] = Field(default_factory=dict)
    uptime_seconds: float = 0.0
