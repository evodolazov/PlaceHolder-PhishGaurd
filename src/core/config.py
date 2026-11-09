"""Application configuration values loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


@dataclass(frozen=True)
class AppConfig:
    """Simple configuration container for environment-driven settings."""

    database_url: str = "sqlite:///phishguard.db"
    secret_key: str = "dev-secret-key"
    ml_enabled: bool = True
    ml_model_path: str | None = None
    ml_model_version: str = "url-logreg-v1"
    tls_enabled: bool = True
    email_url_tls_inspection: bool = False
    tls_timeout: float = 5.0
    tls_allowed_ports: tuple[int, ...] = (443,)

    @classmethod
    def from_env(cls) -> "AppConfig":
        load_dotenv()

        def _bool(name: str, default: bool) -> bool:
            value = os.getenv(name)
            if value is None:
                return default
            return value.strip().lower() in {"1", "true", "yes", "on"}

        def _ports() -> tuple[int, ...]:
            raw = os.getenv("TLS_ALLOWED_PORTS", "443")
            try:
                return tuple(int(part.strip()) for part in raw.split(",") if part.strip())
            except ValueError:
                return (443,)

        return cls(
            database_url=os.getenv("DATABASE_URL", "sqlite:///phishguard.db"),
            secret_key=os.getenv("SECRET_KEY", "dev-secret-key"),
            ml_enabled=_bool("ML_ENABLED", True),
            ml_model_path=os.getenv("PHISHGUARD_ML_MODEL_PATH") or os.getenv("ML_MODEL_PATH"),
            ml_model_version=os.getenv("ML_MODEL_VERSION", "url-logreg-v1"),
            tls_enabled=_bool("TLS_ENABLED", True),
            email_url_tls_inspection=_bool("EMAIL_URL_TLS_INSPECTION", False),
            tls_timeout=float(os.getenv("TLS_TIMEOUT", "5.0") or "5.0"),
            tls_allowed_ports=_ports(),
        )
