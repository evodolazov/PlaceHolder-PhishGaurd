"""Training helpers for the URL ML model."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.engines.ml.feature_schema import FEATURE_COLUMNS, FEATURE_SCHEMA_VERSION
from src.engines.ml.model import save_model

try:  # pragma: no cover - optional dependency guard
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, average_precision_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
    from sklearn.model_selection import train_test_split
except ImportError as exc:  # pragma: no cover - dependency failure path
    raise RuntimeError("scikit-learn is required for ML training.") from exc

DATASET_SOURCE = "UCI Machine Learning Repository — Phishing Websites"
DATASET_URL = "https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.arff"
DEFAULT_DATASET_PATH = Path(__file__).resolve().parents[3] / "data" / "ml" / "uci_phishing_training.csv"
DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[3] / "artifacts" / "ml" / "url_model.pkl"


@dataclass(frozen=True)
class DatasetSummary:
    """Public dataset metadata for the training run."""

    source: str
    source_url: str
    dataset_path: str
    record_count: int
    retained_record_count: int
    label_distribution: dict[str, int]
    feature_schema_version: str


def _value_to_int(value: str | int | float | None) -> int:
    if value is None or value == "":
        return 0
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _to_feature_row(raw_record: dict[str, str]) -> list[float | int | bool | None]:
    """Project the public phishing dataset into the project's internal feature schema."""
    values = {name: 0 for name in FEATURE_COLUMNS}
    raw_ip = _value_to_int(raw_record.get("having_IP_Address"))
    values["has_ip_address"] = raw_ip == 1
    values["url_length"] = abs(_value_to_int(raw_record.get("URL_Length"))) * 80
    values["at_symbol_count"] = 1 if _value_to_int(raw_record.get("having_At_Symbol")) == 1 else 0
    values["uses_https"] = _value_to_int(raw_record.get("SSLfinal_State")) == 1
    values["subdomain_count"] = max(0, _value_to_int(raw_record.get("having_Sub_Domain")))
    values["has_port"] = 1 if _value_to_int(raw_record.get("port")) == 1 else 0
    values["is_nonstandard_port"] = values["has_port"] and _value_to_int(raw_record.get("port")) == 1
    values["suspicious_keyword_count"] = (
        1 if _value_to_int(raw_record.get("Shortining_Service")) == 1 else 0
    ) + (
        1 if _value_to_int(raw_record.get("Prefix_Suffix")) == 1 else 0
    ) + (
        1 if _value_to_int(raw_record.get("Submitting_to_email")) == 1 else 0
    )
    values["dot_count"] = max(0, _value_to_int(raw_record.get("having_Sub_Domain"))) + 2
    values["slash_count"] = 1 if _value_to_int(raw_record.get("double_slash_redirecting")) == 1 else 0
    values["question_mark_count"] = 1 if _value_to_int(raw_record.get("Redirect")) == 1 else 0
    values["equals_count"] = 1 if _value_to_int(raw_record.get("web_traffic")) == 1 else 0
    values["ampersand_count"] = 1 if _value_to_int(raw_record.get("Links_pointing_to_page")) == 1 else 0
    values["hostname_contains_digits"] = 1 if _value_to_int(raw_record.get("Domain_registeration_length")) == 1 else 0
    values["uses_https"] = _value_to_int(raw_record.get("SSLfinal_State")) != -1 and _value_to_int(raw_record.get("SSLfinal_State")) > 0
    values["digit_count"] = max(0, _value_to_int(raw_record.get("URL_Length")))
    values["hostname_length"] = 16 if values["has_ip_address"] else 12
    values["path_length"] = 10 if values["suspicious_keyword_count"] else 4
    values["query_length"] = 18 if values["question_mark_count"] else 0
    values["fragment_length"] = 0
    values["hyphen_count"] = 1 if _value_to_int(raw_record.get("having_Sub_Domain")) == 0 else 0
    values["underscore_count"] = 0
    values["special_character_count"] = values["suspicious_keyword_count"]
    values["port"] = 443 if values["has_port"] else 0
    return [values[name] for name in FEATURE_COLUMNS]


def load_training_dataset(path: str | Path = DEFAULT_DATASET_PATH) -> tuple[list[list[float | int | bool | None]], list[int], DatasetSummary]:
    """Load the checked-in public phishing dataset and project it into the internal schema."""
    dataset_path = Path(path)
    if not dataset_path.exists():
        raise FileNotFoundError(f"Training dataset not found at {dataset_path}")

    rows: list[dict[str, str]] = []
    with dataset_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rows.append({key: value for key, value in row.items() if key})

    features: list[list[float | int | bool | None]] = []
    labels: list[int] = []
    label_counts = {"phishing": 0, "benign": 0}

    for row in rows:
        label_value = _value_to_int(row.get("Result"))
        if label_value not in {-1, 1}:
            continue
        feature_row = _to_feature_row(row)
        features.append(feature_row)
        labels.append(1 if label_value == 1 else 0)
        label_counts["phishing" if label_value == 1 else "benign"] += 1

    summary = DatasetSummary(
        source=DATASET_SOURCE,
        source_url=DATASET_URL,
        dataset_path=str(dataset_path),
        record_count=len(rows),
        retained_record_count=len(features),
        label_distribution=label_counts,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
    )
    return features, labels, summary


def evaluate_model(model: LogisticRegression, X: list[list[float | int | bool | None]], y: list[int]) -> dict[str, float | int | str]:
    """Compute a defensible held-out evaluation for the trained model."""
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        stratify=y,
        random_state=42,
    )
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    metrics: dict[str, float | int | str] = {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(precision_score(y_test, predictions, zero_division=0)),
        "recall": float(recall_score(y_test, predictions, zero_division=0)),
        "f1": float(f1_score(y_test, predictions, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        "roc_auc": float(roc_auc_score(y_test, model.predict_proba(X_test)[:, 1])),
        "pr_auc": float(average_precision_score(y_test, model.predict_proba(X_test)[:, 1])),
        "train_size": len(X_train),
        "test_size": len(X_test),
    }
    return metrics


def build_demo_dataset() -> tuple[list[list[float | int | bool | None]], list[int]]:
    """Backward-compatible alias retained for existing callers and tests."""
    features, labels, _ = load_training_dataset(DEFAULT_DATASET_PATH)
    return features, labels


def train_default_model() -> dict[str, Any]:
    """Train a reproducible model and save it with evaluation metadata."""
    X, y, summary = load_training_dataset(DEFAULT_DATASET_PATH)
    model = LogisticRegression(random_state=42, max_iter=2000)
    metrics = evaluate_model(model, X, y)
    DEFAULT_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    save_model(
        model,
        path=DEFAULT_MODEL_PATH,
        version="url-logreg-v1",
        metadata={
            "source": summary.source,
            "source_url": summary.source_url,
            "dataset_path": summary.dataset_path,
            "dataset_snapshot": summary.retained_record_count,
            "feature_schema_version": summary.feature_schema_version,
            "split_seed": 42,
            "evaluation": metrics,
        },
    )
    return {
        "model_path": str(DEFAULT_MODEL_PATH),
        "summary": summary,
        "metrics": metrics,
        "version": "url-logreg-v1",
    }


if __name__ == "__main__":
    result = train_default_model()
    print(f"ML model trained and saved to {result['model_path']}")
    print(f"Evaluation metrics: {result['metrics']}")
