"""Model artifact structures for the ML risk predictor."""

from __future__ import annotations

import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.engines.ml.feature_schema import FEATURE_SCHEMA_VERSION


@dataclass
class ModelArtifact:
    """Container describing a persisted ML model bundle."""

    model: Any
    version: str
    feature_schema_version: str
    metadata: dict[str, Any] = field(default_factory=dict)


def save_model(model: Any, *, path: str | Path, version: str, metadata: dict[str, Any] | None = None) -> None:
    """Persist a model artifact to disk with schema metadata."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    artifact = ModelArtifact(
        model=model,
        version=version,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        metadata=metadata or {},
    )
    with output_path.open("wb") as handle:
        pickle.dump(artifact, handle)


def load_model(path: str | Path | None) -> ModelArtifact | None:
    """Load a model artifact if it exists and validate its compatibility."""
    if not path:
        return None
    artifact_path = Path(path)
    if not artifact_path.exists():
        return None
    with artifact_path.open("rb") as handle:
        artifact = pickle.load(handle)
    if not isinstance(artifact, ModelArtifact):
        return None
    if artifact.feature_schema_version != FEATURE_SCHEMA_VERSION:
        raise ValueError(
            "Model feature schema mismatch: expected "
            f"{FEATURE_SCHEMA_VERSION}, got {artifact.feature_schema_version}."
        )
    return artifact
