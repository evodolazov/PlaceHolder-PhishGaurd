"""Training helpers for the URL ML model."""

from __future__ import annotations

from pathlib import Path

from src.engines.ml.feature_schema import FEATURE_COLUMNS
from src.engines.ml.model import save_model

try:  # pragma: no cover - optional dependency guard
    from sklearn.linear_model import LogisticRegression
except ImportError as exc:  # pragma: no cover - dependency failure path
    raise RuntimeError("scikit-learn is required for ML training.") from exc


def build_demo_dataset() -> tuple[list[list[float | int | bool | None]], list[int]]:
    """Create a tiny deterministic dataset to support the training pipeline."""
    features: list[list[float | int | bool | None]] = []
    labels: list[int] = []

    samples = [
        ({"url_length": 80, "hostname_length": 15, "path_length": 8, "query_length": 0, "fragment_length": 0,
          "dot_count": 2, "hyphen_count": 0, "underscore_count": 0, "slash_count": 2, "question_mark_count": 0,
          "equals_count": 0, "ampersand_count": 0, "at_symbol_count": 0, "digit_count": 0,
          "special_character_count": 0, "subdomain_count": 0, "has_ip_address": False, "has_punycode": False,
          "has_port": False, "is_nonstandard_port": False, "hostname_contains_digits": False, "uses_https": True,
          "suspicious_keyword_count": 1, "port": 0}, 0),
        ({"url_length": 180, "hostname_length": 30, "path_length": 55, "query_length": 40, "fragment_length": 0,
          "dot_count": 5, "hyphen_count": 4, "underscore_count": 2, "slash_count": 5, "question_mark_count": 1,
          "equals_count": 3, "ampersand_count": 2, "at_symbol_count": 0, "digit_count": 8,
          "special_character_count": 4, "subdomain_count": 2, "has_ip_address": False, "has_punycode": False,
          "has_port": False, "is_nonstandard_port": False, "hostname_contains_digits": True, "uses_https": True,
          "suspicious_keyword_count": 6, "port": 0}, 1),
        ({"url_length": 120, "hostname_length": 17, "path_length": 25, "query_length": 10, "fragment_length": 0,
          "dot_count": 3, "hyphen_count": 2, "underscore_count": 0, "slash_count": 3, "question_mark_count": 0,
          "equals_count": 1, "ampersand_count": 1, "at_symbol_count": 0, "digit_count": 0,
          "special_character_count": 1, "subdomain_count": 1, "has_ip_address": False, "has_punycode": False,
          "has_port": False, "is_nonstandard_port": False, "hostname_contains_digits": False, "uses_https": True,
          "suspicious_keyword_count": 0, "port": 0}, 0),
        ({"url_length": 200, "hostname_length": 22, "path_length": 80, "query_length": 52, "fragment_length": 0,
          "dot_count": 4, "hyphen_count": 4, "underscore_count": 1, "slash_count": 6, "question_mark_count": 1,
          "equals_count": 5, "ampersand_count": 2, "at_symbol_count": 0, "digit_count": 4,
          "special_character_count": 7, "subdomain_count": 1, "has_ip_address": False, "has_punycode": False,
          "has_port": False, "is_nonstandard_port": False, "hostname_contains_digits": True, "uses_https": True,
          "suspicious_keyword_count": 5, "port": 0}, 1),
    ]

    for record, label in samples:
        features.append([record.get(name) for name in FEATURE_COLUMNS])
        labels.append(label)

    return features, labels


def train_default_model() -> None:
    """Train a small model and serialize it to the default artifact path."""
    X, y = build_demo_dataset()
    model = LogisticRegression(random_state=42, max_iter=500)
    model.fit(X, y)
    output_path = Path(__file__).resolve().parents[3] / "artifacts" / "ml" / "url_model.pkl"
    save_model(model, path=output_path, version="url-logreg-v1", metadata={"source": "demo-dataset"})


if __name__ == "__main__":
    train_default_model()
    print("ML model trained and saved to artifacts/ml/url_model.pkl")
