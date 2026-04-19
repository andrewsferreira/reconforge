"""Official execution entrypoints exposed by ReconForge."""

from reconforge.entrypoints.burp_validation import BurpValidationResult, validate_burp_provider

__all__ = ["BurpValidationResult", "validate_burp_provider"]
