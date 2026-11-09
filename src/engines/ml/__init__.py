"""Machine-learning support for URL risk prediction."""

from src.engines.ml.feature_schema import FEATURE_COLUMNS, FEATURE_SCHEMA_VERSION, normalize_feature_map
from src.engines.ml.predictor import MLPredictionResult, predict_url_features

__all__ = [
    "FEATURE_COLUMNS",
    "FEATURE_SCHEMA_VERSION",
    "MLPredictionResult",
    "normalize_feature_map",
    "predict_url_features",
]
