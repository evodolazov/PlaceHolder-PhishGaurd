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

    @classmethod
    def from_env(cls) -> "AppConfig":
        load_dotenv()
        return cls(
            database_url=os.getenv("DATABASE_URL", "sqlite:///phishguard.db"),
            secret_key=os.getenv("SECRET_KEY", "dev-secret-key"),
        )
