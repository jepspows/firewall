"""
Prompt Injection Classifier — the detection engine.

Uses a multi-layered approach:
  1. Signature-based detection (regex patterns)
  2. Heuristic scoring (linguistic features)
  3. Structural analysis (delimiter manipulation, nesting)

No external API calls — runs entirely locally.
"""

import re
import time
from typing import Optional

from .models import CheckRequest, CheckResponse, Detection, Verdict, RiskLevel


# ── Signature Database ──────────────────────────────────────────────

SIGNATURES: list[dict] = [
    # ── System Override Attempts ──
    {
        "name": "system_override_direct",
        "category": "system_override",
        "patterns": [
            r"(?i)(ignore|forget|disregard)\s+(all\s+)?(previous|above|prior|everything)\s+(instructions?|prompts?|rules?|context|about)",
            r"(?i)(forget|ignore)\s+everything\s+(above|you\s+know)",
            r"(?i)you\s+are\s+now\s+(a\s+)?(DAN|jailbreak|unfiltered|unrestricted)",
            r"(?i)new\s+system\s+(prompt|message|instruction|task)",
            r"(?i)from\s+now\s+on\s+you\s+(are|will\s+be)",
        ],
        "confidence": 0.95,
        "explanation": "Attempt to override system instructions",
    },
    {
        "name": "system_override_indirect",
        "category": "system_override",
        "patterns": [
            r"(?i)pretend\s+(you\s+are|to\s+be)",
            r"(?i)act\s+as\s+if\s+you\s+(are|were)",
            r"(?i)your\s+(new\s+)?(role|persona|identity)\s+is",
            r"(?i)switch\s+(your\s+)?(role|mode|personality)",
        ],
        "confidence": 0.85,
        "explanation": "Indirect attempt to change agent behavior",
    },
    # ── Prompt Leaking ──
    {
        "name": "prompt_leak",
        "category": "prompt_leaking",
        "patterns": [
            r"(?i)(repeat|echo|output|print|show|tell\s+me|display)\s+(back\s+)?(your|the)\s+(system\s+)?(prompt|instructions?|rules?|context)",
            r"(?i)what\s+(is|are|were)\s+your\s+(system\s+)?(prompt|instructions?|rules?)",
            r"(?i)display\s+(your|the)\s+(initial|first|system)\s+(prompt|message|instruction|system\s+instructions?)",
            r"(?i)return\s+(the|your)\s+(exact|full|complete)\s+(system\s+)?(prompt|instructions?)",
            r"(?i)output\s+(your|the)\s+(full|complete|system)\s+(system\s+)?(instructions?|prompt)",
            r"(?i)(show|reveal|expose)\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions?)",
        ],
        "confidence": 0.95,
        "explanation": "Attempt to extract system prompt",
    },
    # ── Delimiter Injection ──
    {
        "name": "delimiter_injection",
        "category": "delimiter_attack",
        "patterns": [
            r"\{3,}.*\{3,}",
            r"\[INST\].*\[/INST\]",
            r"<\|im_start\|>.*<\|im_end\|>",
            r"<\|system\|>.*<\|user\|>",
            r"\[system\].*\[/system\]",
            r"<\s*system\s*>.*<\s*/\s*system\s*>",
        ],
        "confidence": 0.90,
        "explanation": "Injection via chat template delimiters",
    },
    # ── Token Smuggling ──
    {
        "name": "token_smuggling",
        "category": "token_smuggling",
        "patterns": [
            r"(?i)(ignore|skip|bypass|disregard)\s+(the\s+)?(above|previous)",
            r"\[END\].*\[BEGIN\]",
            r"(?i)end\s+of\s+(instructions?|prompt).*\n.*\n.*(actually|really|in\s+fact)",
            r"(?i)(skip|ignore)\s+the\s+above",
        ],
        "confidence": 0.88,
        "explanation": "Token smuggling to bypass instruction boundaries",
    },
    # ── Goal Hijacking ──
    {
        "name": "goal_hijack",
        "category": "goal_hijacking",
        "patterns": [
            r"(?i)your\s+(real|true|actual|primary)\s+(goal|task|purpose|job)\s+is",
            r"(?i)instead\s+of\s+.+\s*,\s*you\s+should",
            r"(?i)more\s+important\s+than\s+your\s+(instructions?|rules?)",
            r"(?i)override\s+(all\s+)?(previous|existing)\s+(goals?|tasks?|objectives?)",
        ],
        "confidence": 0.90,
        "explanation": "Attempt to replace agent goals",
    },
    # ── Data Exfiltration ──
    {
        "name": "data_exfil",
        "category": "data_exfiltration",
        "patterns": [
            r"(?i)send\s+(this|the|all)\s+(conversation|chat|transcript|output|data|response|history)",
            r"(?i)(email|mail|forward|post|upload|share)\s+(this|the|your|all)\s+(conversation|chat|output|response|data)",
            r"(?i)(email|mail)\s+all\s+your\s+(output|data|conversation)",
            r"(?i)(encode|base64|hex)\s+(the\s+)?(response|output|answer|prompt|instructions?)",
            r"(?i)copy\s+(all\s+)?(the\s+)?(conversation|chat|data|output)",
            r"(?i)send\s+.*\s+to\s+.*@.*\.\w+",
            r"(?i)(send|post|forward|email)\s+(this|it|all)\s+to\s+(an?\s+)?(external|outside|different|.*@)",
        ],
        "confidence": 0.88,
        "explanation": "Potential data exfiltration attempt",
    },
    # ── Multi-turn Attack Setup ──
    {
        "name": "multiturn_setup",
        "category": "multi_turn_attack",
        "patterns": [
            r"(?i)(remember|store|save)\s+this",
            r"(?i)in\s+(the\s+)?(next|following)\s+(message|response|turn)",
            r"(?i)we\s+are\s+going\s+to\s+play\s+a\s+game",
            r"(?i)(don't|do\s+not)\s+forget",
            r"(?i)for\s+(the\s+)?(next|following)",
        ],
        "confidence": 0.80,
        "explanation": "Potential multi-turn attack setup",
    },
    # ── Obfuscation ──
    {
        "name": "obfuscation",
        "category": "obfuscation",
        "patterns": [
            r"(?i)(zero.width|zwsp|unicode|homoglyph)",
            r"(?i)encoded\s+in\s+(base64|rot13|hex|binary|morse)",
            r"(?i)translate\s+(the\s+following|this)\s+(from|as)",
            r"(?i)(decode|decrypt|convert)\s+(this|the\s+following)",
        ],
        "confidence": 0.80,
        "explanation": "Obfuscation or encoding attempt",
    },
]

# ── Heuristic Features ──────────────────────────────────────────────

# High-risk keyword weightings
HIGH_RISK_KEYWORDS: dict[str, float] = {
    "ignore": 0.3,
    "override": 0.4,
    "bypass": 0.4,
    "jailbreak": 0.8,
    "system prompt": 0.7,
    "instructions": 0.3,
    "pretend": 0.5,
    "roleplay": 0.3,
    "disregard": 0.5,
    "instead": 0.3,
    "actually": 0.2,
    "real goal": 0.4,
    "forget": 0.5,
    "DAN": 0.9,
    "unfiltered": 0.6,
    "unrestricted": 0.6,
    "no rules": 0.5,
    "without restrictions": 0.5,
}

# Suspicious structural patterns
STRUCTURAL_RISK_FACTORS = [
    (r".{200,}", 0.2, "Very long prompt"),  # Long prompts more likely malicious
    (r"[\"'`]{4,}", 0.3, "Excessive quotes/backticks"),
    (r"(\n\s*){8,}", 0.2, "Many blank lines"),
    (r"[^\x00-\x7F]{4,}", 0.2, "Non-ASCII heavy"),  # Unicode tricks
]


class PromptInjectionClassifier:
    """
    Multi-layer prompt injection classifier.

    Layers:
      1. Signature matching (regex patterns) — fast, high precision
      2. Heuristic scoring (keyword density, structure) — catches novel attacks
      3. Combined risk assessment — final verdict
    """

    def __init__(self, threshold: float = 0.70):
        self.threshold = threshold
        self._compile_signatures()

    def _compile_signatures(self) -> None:
        """Pre-compile all regex patterns."""
        for sig in SIGNATURES:
            sig["_compiled"] = [
                re.compile(p, re.DOTALL) for p in sig["patterns"]
            ]

    def classify(self, request: CheckRequest) -> CheckResponse:
        """Run full classification pipeline on a prompt."""
        start = time.perf_counter()
        detections: list[Detection] = []

        # Layer 1: Signature matching
        sig_detections = self._check_signatures(request.prompt)
        detections.extend(sig_detections)

        # Layer 2: Heuristic analysis
        heuristic_score = self._heuristic_analysis(request.prompt)
        if heuristic_score > 0.4:
            detections.append(
                Detection(
                    rule_name="heuristic_risk",
                    category="heuristic",
                    confidence=min(heuristic_score, 0.85),
                    explanation=f"Heuristic risk score: {heuristic_score:.2f}",
                )
            )

        # Layer 3: Structural analysis
        struct_score, struct_reason = self._structural_analysis(request.prompt)
        if struct_score > 0.0:
            detections.append(
                Detection(
                    rule_name="structural_anomaly",
                    category="structural",
                    confidence=struct_score,
                    explanation=struct_reason,
                )
            )

        # Compute overall confidence and verdict
        confidence, risk_level = self._compute_risk(detections)
        verdict = Verdict.BLOCK if confidence >= self.threshold else Verdict.ALLOW

        latency = (time.perf_counter() - start) * 1000

        return CheckResponse(
            verdict=verdict,
            risk_level=risk_level,
            confidence=confidence,
            detections=detections,
            blocked=verdict == Verdict.BLOCK,
            latency_ms=round(latency, 2),
        )

    def _check_signatures(self, prompt: str) -> list[Detection]:
        """Layer 1: Check against signature database."""
        detections: list[Detection] = []
        for sig in SIGNATURES:
            for pattern in sig["_compiled"]:
                match = pattern.search(prompt)
                if match:
                    detections.append(
                        Detection(
                            rule_name=sig["name"],
                            category=sig["category"],
                            confidence=sig["confidence"],
                            matched_pattern=match.group()[:100],
                            explanation=sig["explanation"],
                        )
                    )
                    break  # One match per signature is enough
        return detections

    def _heuristic_analysis(self, prompt: str) -> float:
        """Layer 2: Keyword density and linguistic heuristics."""
        prompt_lower = prompt.lower()
        score = 0.0
        match_count = 0

        for keyword, weight in HIGH_RISK_KEYWORDS.items():
            count = prompt_lower.count(keyword.lower())
            if count > 0:
                score += weight * min(count, 3)  # Cap per-keyword contribution
                match_count += 1

        # Normalize: more keyword matches = higher confidence
        if match_count > 0:
            diversity_bonus = min(match_count / 8, 1.0) * 0.3
            score = min(score + diversity_bonus, 1.0)

        return round(score, 3)

    def _structural_analysis(self, prompt: str) -> tuple[float, str]:
        """Layer 3: Check for structural anomalies."""
        for pattern, weight, reason in STRUCTURAL_RISK_FACTORS:
            if re.search(pattern, prompt, re.DOTALL):
                return weight, reason
        return 0.0, ""

    def _compute_risk(self, detections: list[Detection]) -> tuple[float, RiskLevel]:
        """Combine all detections into a final confidence score."""
        if not detections:
            return 0.0, RiskLevel.LOW

        # Use highest confidence among detections, boosted by count
        max_conf = max(d.confidence for d in detections)
        count_bonus = min((len(detections) - 1) * 0.05, 0.15)
        combined = min(max_conf + count_bonus, 1.0)

        # Risk level
        if combined >= 0.90:
            level = RiskLevel.CRITICAL
        elif combined >= 0.80:
            level = RiskLevel.HIGH
        elif combined >= 0.60:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        return round(combined, 3), level

    def batch_classify(self, requests: list[CheckRequest]) -> list[CheckResponse]:
        """Classify multiple prompts."""
        return [self.classify(r) for r in requests]


# ── Default instance ─────────────────────────────────────────────────

_default_classifier: Optional[PromptInjectionClassifier] = None


def get_classifier(threshold: float = 0.70) -> PromptInjectionClassifier:
    """Get or create the default classifier instance."""
    global _default_classifier
    if _default_classifier is None:
        _default_classifier = PromptInjectionClassifier(threshold=threshold)
    return _default_classifier
