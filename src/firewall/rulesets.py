"""
Per-Agent Custom Rulesets with YAML configuration and hot-reload.

Agents can have their own rules defined in:
  rules/<agent_id>.yaml

Format:
  agent_id: "my-agent"
  threshold: 0.70
  enabled_categories:
    - system_override
    - prompt_leaking
  disabled_categories:
    - obfuscation
  custom_patterns:
    - name: "my_custom_rule"
      category: "custom"
      pattern: "regex here"
      confidence: 0.85
      explanation: "Custom detection"
  whitelist_patterns:
    - "allowed phrase pattern"
  blacklist_patterns:
    - "always block this"
"""

import os
import re
import time
from pathlib import Path
from threading import RLock
from typing import Optional

import yaml

from .models import Detection

RULES_DIR = Path(os.environ.get("FIREWALL_RULES_DIR", Path(__file__).parent.parent.parent / "rules"))

DEFAULT_RULESET = {
    "threshold": 0.70,
    "enabled_categories": [
        "system_override", "prompt_leaking", "delimiter_attack",
        "goal_hijacking", "token_smuggling", "data_exfiltration",
        "obfuscation", "multi_turn_attack",
    ],
    "disabled_categories": [],
    "custom_patterns": [],
    "whitelist_patterns": [],
    "blacklist_patterns": [],
}


class AgentRuleset:
    """Per-agent rules configuration."""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.config = dict(DEFAULT_RULESET)
        self._compiled_whitelist: list[re.Pattern] = []
        self._compiled_blacklist: list[re.Pattern] = []
        self._compiled_custom: list[dict] = []
        self._loaded_at: float = 0.0
        self._mtime: float = 0.0
        self._lock = RLock()

    @property
    def path(self) -> Path:
        return RULES_DIR / f"{self.agent_id}.yaml"

    @property
    def threshold(self) -> float:
        return float(self.config.get("threshold", 0.70))

    def load(self) -> bool:
        """Load rules from YAML file. Returns True if loaded/changed."""
        with self._lock:
            if not self.path.exists():
                self._set_defaults()
                return False

            try:
                mtime = self.path.stat().st_mtime
                if mtime == self._mtime:
                    return False  # No change

                data = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
                self.config = {**DEFAULT_RULESET, **data}
                self._compile()
                self._mtime = mtime
                self._loaded_at = time.time()
                return True
            except Exception:
                self._set_defaults()
                return False

    def reload_if_stale(self) -> bool:
        """Check mtime and reload if file changed."""
        if not self.path.exists():
            return False
        try:
            if self.path.stat().st_mtime != self._mtime:
                return self.load()
        except Exception:
            pass
        return False

    def _set_defaults(self) -> None:
        self.config = dict(DEFAULT_RULESET)
        self._compile()

    def _compile(self) -> None:
        """Pre-compile all regex patterns."""
        self._compiled_whitelist = [
            re.compile(p, re.IGNORECASE)
            for p in self.config.get("whitelist_patterns", [])
        ]
        self._compiled_blacklist = [
            re.compile(p, re.IGNORECASE)
            for p in self.config.get("blacklist_patterns", [])
        ]
        self._compiled_custom = []
        for cp in self.config.get("custom_patterns", []):
            try:
                self._compiled_custom.append({
                    "name": cp["name"],
                    "category": cp.get("category", "custom"),
                    "pattern": re.compile(cp["pattern"], re.IGNORECASE | re.DOTALL),
                    "confidence": float(cp.get("confidence", 1.0)),
                    "explanation": cp.get("explanation", ""),
                })
            except re.error:
                pass

    def is_category_enabled(self, category: str) -> bool:
        if category in self.config.get("disabled_categories", []):
            return False
        if category in self.config.get("enabled_categories", []):
            return True
        return False

    def check_whitelist(self, text: str) -> bool:
        """True if text matches any whitelist pattern (bypasses checks)."""
        for pat in self._compiled_whitelist:
            if pat.search(text):
                return True
        return False

    def check_blacklist(self, text: str) -> list[Detection]:
        """Return detections from blacklist patterns."""
        detections: list[Detection] = []
        for pat in self._compiled_blacklist:
            match = pat.search(text)
            if match:
                detections.append(
                    Detection(
                        rule_name=f"blacklist:{self.agent_id}",
                        category="blacklist",
                        confidence=1.0,
                        matched_pattern=match.group()[:100],
                        explanation="Matched agent blacklist pattern",
                    )
                )
        return detections

    def check_custom(self, text: str) -> list[Detection]:
        """Return detections from custom patterns."""
        detections: list[Detection] = []
        for cp in self._compiled_custom:
            match = cp["pattern"].search(text)
            if match:
                detections.append(
                    Detection(
                        rule_name=f"custom:{cp['name']}",
                        category=cp["category"],
                        confidence=cp["confidence"],
                        matched_pattern=match.group()[:100],
                        explanation=cp["explanation"],
                    )
                )
        return detections


class RulesetManager:
    """Manages loading and caching of per-agent rulesets."""

    def __init__(self):
        self._cache: dict[str, AgentRuleset] = {}
        self._lock = RLock()
        RULES_DIR.mkdir(parents=True, exist_ok=True)

    def get(self, agent_id: str) -> AgentRuleset:
        """Get or create ruleset for an agent."""
        with self._lock:
            if agent_id not in self._cache:
                rs = AgentRuleset(agent_id)
                rs.load()
                self._cache[agent_id] = rs
            else:
                self._cache[agent_id].reload_if_stale()
            return self._cache[agent_id]

    def get_or_default(self, agent_id: Optional[str]) -> AgentRuleset:
        """Get agent ruleset or a default one."""
        if agent_id:
            return self.get(agent_id)
        return self.get("__default__")

    def create(self, agent_id: str, config: dict) -> AgentRuleset:
        """Create a new ruleset file."""
        RULES_DIR.mkdir(parents=True, exist_ok=True)
        path = RULES_DIR / f"{agent_id}.yaml"
        path.write_text(yaml.dump(config, default_flow_style=False), encoding="utf-8")
        with self._lock:
            self._cache.pop(agent_id, None)
        return self.get(agent_id)

    def list_agents(self) -> list[str]:
        """List all agents with rulesets."""
        if not RULES_DIR.exists():
            return []
        return [
            f.stem
            for f in RULES_DIR.glob("*.yaml")
            if f.stem != "__default__"
        ]

    def delete(self, agent_id: str) -> bool:
        """Delete an agent's ruleset."""
        path = RULES_DIR / f"{agent_id}.yaml"
        if path.exists():
            path.unlink()
        with self._lock:
            self._cache.pop(agent_id, None)
        return True


# ── Global instance ────────────────────────────────────────────────

_ruleset_manager: Optional[RulesetManager] = None


def get_ruleset_manager() -> RulesetManager:
    global _ruleset_manager
    if _ruleset_manager is None:
        _ruleset_manager = RulesetManager()
    return _ruleset_manager
