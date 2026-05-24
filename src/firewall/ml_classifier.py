"""
ML-based Prompt Injection Classifier.

Uses TF-IDF vectorization + Logistic Regression by default.
Optional ONNX runtime support for fine-tuned transformer models.

Design:
  - Lightweight: < 5MB model file, < 5ms inference
  - Fallback: gracefully degrades to rule-based if model not available
  - Trainable: ships with training script for custom datasets
"""

import os
import pickle
import re
from pathlib import Path
from typing import Optional

import numpy as np

from .models import CheckRequest, Detection


# ── Paths ──────────────────────────────────────────────────────────

MODEL_DIR = Path(os.environ.get("FIREWALL_MODEL_DIR", Path(__file__).parent / "models"))
VECTORIZER_PATH = MODEL_DIR / "tfidf_vectorizer.pkl"
CLASSIFIER_PATH = MODEL_DIR / "classifier.pkl"
LABELS_PATH = MODEL_DIR / "labels.pkl"


# ── Attack categories for ML classification ────────────────────────

ATTACK_CATEGORIES = [
    "benign",
    "system_override",
    "prompt_leaking",
    "delimiter_attack",
    "goal_hijacking",
    "token_smuggling",
    "data_exfiltration",
    "obfuscation",
    "multi_turn_attack",
]


# ── Feature extraction helpers ─────────────────────────────────────

def extract_features(text: str) -> np.ndarray:
    """Extract lightweight features for classifier input."""
    features = []

    # Length features
    features.append(len(text))
    features.append(len(text.split()))
    features.append(len(text) / max(len(text.split()), 1))  # avg word length

    # Special character ratios
    features.append(len(re.findall(r'[<>{}[\]|]', text)) / max(len(text), 1))
    features.append(len(re.findall(r'["\']', text)) / max(len(text), 1))
    features.append(len(re.findall(r'[^a-zA-Z0-9\s]', text)) / max(len(text), 1))

    # Keyword density
    injection_keywords = [
        "ignore", "override", "bypass", "pretend", "forget",
        "system", "prompt", "instruction", "role", "DAN", "jailbreak",
        "unfiltered", "unrestricted", "instead", "real goal",
    ]
    text_lower = text.lower()
    for kw in injection_keywords:
        features.append(text_lower.count(kw) / max(len(text_lower.split()), 1))

    # Structural features
    features.append(text.count("\n"))
    features.append(len(re.findall(r'[A-Z]{3,}', text)))  # ALL CAPS sequences
    features.append(len(re.findall(r'https?://', text)))  # URLs

    return np.array(features, dtype=np.float32).reshape(1, -1)


# ── Simple feature-based classifier (always available) ─────────────

class FeatureClassifier:
    """
    Ultra-lightweight classifier using extracted features.
    Works without any model file — pure heuristics + linear weights.
    """

    def __init__(self):
        # Hand-tuned weights per feature for "is this an injection?"
        self.weights = np.array([
            0.001,   # text length
            0.001,   # word count
            -0.01,   # avg word length
            0.8,     # special bracket ratio
            0.4,     # quote ratio
            0.3,     # non-alphanum ratio
            1.5,     # "ignore" density
            1.2,     # "override" density
            0.9,     # "bypass" density
            1.3,     # "pretend" density
            1.4,     # "forget" density
            0.8,     # "system" density
            0.7,     # "prompt" density
            0.6,     # "instruction" density
            0.5,     # "role" density
            2.0,     # "DAN" density
            1.8,     # "jailbreak" density
            1.5,     # "unfiltered" density
            1.3,     # "unrestricted" density
            0.8,     # "instead" density
            1.0,     # "real goal" density
            0.01,    # newlines
            0.3,     # ALL CAPS sequences
            0.2,     # URLs
        ])

    def predict_proba(self, text: str) -> float:
        """Return probability [0,1] that this is an injection."""
        features = extract_features(text).flatten()
        score = np.dot(features, self.weights)
        # Sigmoid to get probability
        return float(1.0 / (1.0 + np.exp(-score)))

    def predict_category(self, text: str) -> str:
        """Predict the most likely attack category."""
        proba = self.predict_proba(text)
        if proba < 0.5:
            return "benign"
        # Simple keyword-based category guess
        t = text.lower()
        if any(k in t for k in ["ignore", "forget", "previous", "pretend", "role", "dan", "jailbreak"]):
            return "system_override"
        if any(k in t for k in ["system prompt", "your prompt", "your instruction", "repeat back"]):
            return "prompt_leaking"
        if re.search(r'<[|]im_[a-z]+[|]>', text):
            return "delimiter_attack"
        if any(k in t for k in ["real goal", "real task", "instead"]):
            return "goal_hijacking"
        if re.search(r'\[END\].*\[BEGIN\]|end of instruction', t):
            return "token_smuggling"
        if any(k in t for k in ["send this", "encode the", "base64"]):
            return "data_exfiltration"
        return "benign"


# ── ML Classifier (TF-IDF + Logistic Regression) ───────────────────

class MLClassifier:
    """
    ML-based classifier using TF-IDF + Logistic Regression.
    Trained on prompt injection datasets for higher accuracy.
    """

    def __init__(self):
        self.vectorizer = None
        self.classifier = None
        self.labels = None
        self._load_model()

    def _load_model(self) -> None:
        """Load model artifacts if they exist."""
        if (
            VECTORIZER_PATH.exists()
            and CLASSIFIER_PATH.exists()
            and LABELS_PATH.exists()
        ):
            try:
                self.vectorizer = pickle.loads(VECTORIZER_PATH.read_bytes())
                self.classifier = pickle.loads(CLASSIFIER_PATH.read_bytes())
                self.labels = pickle.loads(LABELS_PATH.read_bytes())
            except Exception:
                pass  # Fall back to rule-based

    @property
    def loaded(self) -> bool:
        return self.classifier is not None

    def predict_proba(self, text: str) -> float:
        """Return probability of injection."""
        if not self.loaded:
            return 0.5  # Unknown — defer to rule-based
        vec = self.vectorizer.transform([text])
        proba = self.classifier.predict_proba(vec)
        # Class 1 = injection
        if proba.shape[1] > 1:
            return float(proba[0][1])
        return float(proba[0][0])

    def predict_category(self, text: str) -> str:
        """Predict attack category."""
        if not self.loaded or self.labels is None:
            return "unknown"
        vec = self.vectorizer.transform([text])
        pred = self.classifier.predict(vec)[0]
        if isinstance(pred, (int, np.integer)):
            return self.labels[int(pred)]
        return str(pred)


# ── Ensemble Classifier ────────────────────────────────────────────

class EnsembleClassifier:
    """
    Combines ML model + feature classifier for final prediction.
    Uses ML if available, falls back to feature-based + rule-based.
    """

    def __init__(self):
        self.ml = MLClassifier()
        self.feature = FeatureClassifier()

    def predict(self, text: str) -> tuple[float, str, list[Detection]]:
        """
        Returns (confidence, category, detections).
        """
        detections: list[Detection] = []

        # ML prediction
        if self.ml.loaded:
            ml_proba = self.ml.predict_proba(text)
            ml_cat = self.ml.predict_category(text)
            if ml_proba > 0.6:
                detections.append(
                    Detection(
                        rule_name="ml_classifier",
                        category=ml_cat,
                        confidence=round(ml_proba, 2),
                        explanation=f"ML model detected {ml_cat} (confidence: {ml_proba:.2f})",
                    )
                )

        # Feature-based prediction
        ft_proba = self.feature.predict_proba(text)
        if ft_proba > 0.55:
            ft_cat = self.feature.predict_category(text)
            detections.append(
                Detection(
                    rule_name="feature_classifier",
                    category=ft_cat,
                    confidence=round(min(ft_proba, 0.88), 2),
                    explanation=f"Feature analysis detected {ft_cat} (confidence: {ft_proba:.2f})",
                )
            )

        # Combined confidence
        if detections:
            combined_conf = max(d.confidence for d in detections)
            primary_cat = detections[0].category
        else:
            combined_conf = 0.0
            primary_cat = "benign"

        return combined_conf, primary_cat, detections


# ── Global instance ────────────────────────────────────────────────

_ensemble: Optional[EnsembleClassifier] = None


def get_ensemble() -> EnsembleClassifier:
    global _ensemble
    if _ensemble is None:
        _ensemble = EnsembleClassifier()
    return _ensemble
