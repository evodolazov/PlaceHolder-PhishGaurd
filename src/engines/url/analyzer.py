"""URL analysis orchestration for Milestone 0."""

from __future__ import annotations

from typing import Any

from src.core.config import AppConfig
from src.engines.ml.predictor import predict_url_features
from src.engines.tls.inspector import inspect_tls_url
from src.engines.url.features import extract_features
from src.engines.url.normalizer import normalize_url, validate_url
from src.engines.url.sanitizer import sanitize_url_for_storage
from src.fusion.risk_engine import RiskAssessment, score_url


def analyze_url(raw_url: str, *, allow_tls: bool | None = None) -> dict[str, Any]:
    """Validate, normalize, extract features, score, and prepare evidence."""
    if not validate_url(raw_url):
        raise ValueError("A valid HTTP or HTTPS URL is required.")

    normalized = normalize_url(raw_url)
    features = extract_features(normalized)
    config = AppConfig.from_env()
    ml_result = predict_url_features(features.as_dict()) if config.ml_enabled else {
        "status": "disabled",
        "available": False,
        "prediction": None,
        "probability": None,
        "model_version": None,
        "feature_schema_version": None,
        "message": "ML is disabled by configuration.",
    }
    ml_probability = getattr(ml_result, "probability", None) if hasattr(ml_result, "probability") else ml_result.get("probability")
    risk_assessment: RiskAssessment = score_url(features, normalized, ml_probability=ml_probability)
    safe_url = sanitize_url_for_storage(raw_url)

    effective_tls_enabled = config.tls_enabled if allow_tls is None else allow_tls
    tls_result = inspect_tls_url(raw_url, timeout=config.tls_timeout, allowed_ports=set(config.tls_allowed_ports)) if effective_tls_enabled and normalized.scheme == "https" else {
        "status": "not_applicable",
        "explanation": "TLS inspection is disabled or not applicable for this URL.",
        "hostname": normalized.hostname,
        "validated_ip": None,
        "sni_hostname": normalized.hostname,
        "port": normalized.port or 443,
        "tls_version": None,
        "cipher_suite": None,
        "certificate_subject": None,
        "certificate_issuer": None,
        "subject_alt_names": [],
        "certificate_validity_start": None,
        "certificate_expiration": None,
        "certificate_is_valid": None,
        "hostname_match": None,
        "self_signed": None,
        "serial_number": None,
        "fingerprint_sha256": None,
        "chain_valid": None,
        "inspected_at": None,
        "error": None,
    }

    result = {
        "url": safe_url,
        "normalized_url": normalized.normalized_url,
        "scheme": normalized.scheme,
        "hostname": normalized.hostname,
        "registrable_domain": normalized.registrable_domain,
        "classification": risk_assessment.classification,
        "risk_score": risk_assessment.risk_score,
        "confidence": risk_assessment.confidence,
        "ml_probability": getattr(ml_result, "probability", None) if hasattr(ml_result, "probability") else ml_result.get("probability"),
        "ml_prediction": getattr(ml_result, "prediction", None) if hasattr(ml_result, "prediction") else ml_result.get("prediction"),
        "ml_model_status": getattr(ml_result, "status", None) if hasattr(ml_result, "status") else ml_result.get("status"),
        "ml_model_version": getattr(ml_result, "model_version", None) if hasattr(ml_result, "model_version") else ml_result.get("model_version"),
        "feature_schema_version": getattr(ml_result, "feature_schema_version", None) if hasattr(ml_result, "feature_schema_version") else ml_result.get("feature_schema_version"),
        "tls_status": tls_result.get("status") if isinstance(tls_result, dict) else tls_result.status,
        "tls_version": tls_result.get("tls_version") if isinstance(tls_result, dict) else tls_result.tls_version,
        "tls_cipher": tls_result.get("cipher_suite") if isinstance(tls_result, dict) else tls_result.cipher_suite,
        "tls_subject": tls_result.get("certificate_subject") if isinstance(tls_result, dict) else tls_result.certificate_subject,
        "tls_issuer": tls_result.get("certificate_issuer") if isinstance(tls_result, dict) else tls_result.certificate_issuer,
        "tls_expiration": tls_result.get("certificate_expiration") if isinstance(tls_result, dict) else tls_result.certificate_expiration,
        "tls_hostname_match": tls_result.get("hostname_match") if isinstance(tls_result, dict) else tls_result.hostname_match,
        "tls_fingerprint": tls_result.get("fingerprint_sha256") if isinstance(tls_result, dict) else tls_result.fingerprint_sha256,
        "tls_inspection_timestamp": tls_result.get("inspected_at") if isinstance(tls_result, dict) else tls_result.inspected_at,
        "features": features.as_dict(),
        "evidence": risk_assessment.evidence,
    }

    if isinstance(ml_result, dict):
        result["ml_message"] = ml_result.get("message")
    else:
        result["ml_message"] = ml_result.message

    if isinstance(tls_result, dict):
        result["tls_explanation"] = tls_result.get("explanation")
        result["tls_error"] = tls_result.get("error")
        result["tls_validated_ip"] = tls_result.get("validated_ip")
    else:
        result["tls_explanation"] = tls_result.explanation
        result["tls_error"] = tls_result.error
        result["tls_validated_ip"] = tls_result.validated_ip

    return result
