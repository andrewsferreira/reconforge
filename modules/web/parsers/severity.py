"""Severity normalization helpers for web parsers."""

from typing import Optional


_SEVERITY_ALIASES = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "med": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "unknown": "info",
}


def normalize_severity(value: Optional[str], default: str = "info") -> str:
    """Normalize severity labels into: critical/high/medium/low/info."""
    if value is None:
        return default
    normalized = str(value).strip().lower()
    return _SEVERITY_ALIASES.get(normalized, default)
