"""Prediction wrapper for URL ML risk scoring."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.engines.ml.feature_schema import FEATURE_SCHEMA_VERSION, normalize_feature_map
from src.engines.ml.model import load_model


@dataclass(frozen=True)
class MLPredictionResult:
    """Structured result returned by the ML predictor."""

    status: str
    available: bool
    prediction: str | None
    probability: float | None
    model_version: str | None
    feature_schema_version: str | None
    message: str | None = None


def default_model_path() -> Path | None:
    """Return the configured default artifact path when an explicit model is present.

    The project intentionally does not auto-load a repository-local model artifact;
    ML inference is only enabled when a path is supplied via configuration or an
    environment variable. This preserves the default 'unavailable' behavior in
    environments without a trained artifact.
    """
    return None


def predict_url_features(features: dict[str, Any]) -> MLPredictionResult:
    """Predict phishing probability for a URL feature map if a model is available."""
    path = os.getenv("PHISHGUARD_ML_MODEL_PATH") or os.getenv("ML_MODEL_PATH")
    model_artifact = load_model(path)
    if model_artifact is None:
        return MLPredictionResult(
            status="unavailable",
            available=False,
            prediction=None,
            probability=None,
            model_version=None,
            feature_schema_version=None,
            message="ML model is unavailable; using deterministic analysis only.",
        )

    normalized = normalize_feature_map(features)
    try:
        classifier = model_artifact.model
        vector = [[0 if normalized[name] is None else normalized[name] for name in normalized]]
        probability = classifier.predict_proba(vector)[0][1]
        prediction = "phishing" if probability >= 0.5 else "benign"
        return MLPredictionResult(
            status="ready",
            available=True,
            prediction=prediction,
            probability=float(probability),
            model_version=model_artifact.version,
            feature_schema_version=model_artifact.feature_schema_version,
            message="ML model loaded successfully.",
        )
    except Exception as exc:  # pragma: no cover - defensive guard for corrupted artifacts
        return MLPredictionResult(
            status="unavailable",
            available=False,
            prediction=None,
            probability=None,
            model_version=model_artifact.version,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            message=f"ML prediction failed: {exc}",
        )
