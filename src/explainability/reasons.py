"""Evidence model and helpers used by engines to explain risk signals."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Evidence:
    """Generic, structured risk indicator."""

    source: str
    indicator: str
    severity: str
    value: Any
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "indicator": self.indicator,
            "severity": self.severity,
            "value": self.value,
            "description": self.description,
        }


def build_evidence(*, source: str, indicator: str, severity: str, value: Any, description: str) -> Evidence:
    """Create a structured evidence object that is easy to serialize and extend."""
    return Evidence(
        source=source,
        indicator=indicator,
        severity=severity,
        value=value,
        description=description,
    )
