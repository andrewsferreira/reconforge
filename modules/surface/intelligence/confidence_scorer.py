"""ReconForge - Multi-Signal Confidence Scorer

Author: Andrews Ferreira

Implements a multi-signal scoring system for service detection
confidence. Combines port match, banner match, version detection,
and number of detection methods to produce a meaningful confidence
score and label.
"""

from dataclasses import dataclass
from typing import Dict, Optional, Set

from modules.surface.intelligence.correlation_engine import CorrelatedService


@dataclass
class ConfidenceResult:
    """Result of confidence scoring."""
    score: float  # 0.0 - 1.0
    label: str  # "confirmed", "high", "medium", "low"
    signals: Dict[str, bool]  # Which signals contributed
    explanation: str  # Human-readable explanation


class ConfidenceScorer:
    """Multi-signal confidence scoring for service detection.

    Scoring Signals:
    - port_match: Service detected on its known default port
    - banner_match: Banner/product string matches expected service
    - version_detected: Specific version was identified
    - multi_detection: Service confirmed by 2+ detection methods
    - http_confirmed: HTTP probe confirmed web service

    Score Weights:
        port_match:      0.25
        banner_match:    0.25
        version_detected: 0.20
        multi_detection: 0.20
        http_confirmed:  0.10
    """

    WEIGHTS = {
        "port_match": 0.25,
        "banner_match": 0.25,
        "version_detected": 0.20,
        "multi_detection": 0.20,
        "http_confirmed": 0.10,
    }

    LABELS = [
        (0.80, "confirmed"),
        (0.60, "high"),
        (0.40, "medium"),
        (0.0, "low"),
    ]

    def __init__(self, port_map: Optional[Dict[int, str]] = None) -> None:
        """Initialize with optional port-to-service mapping."""
        self._port_map = port_map or {}

    def score_service(self, svc: CorrelatedService) -> ConfidenceResult:
        """Score confidence for a correlated service.

        Args:
            svc: CorrelatedService from the correlation engine.

        Returns:
            ConfidenceResult with score, label, and explanation.
        """
        signals = {
            "port_match": self._check_port_match(svc),
            "banner_match": self._check_banner_match(svc),
            "version_detected": bool(svc.best_version),
            "multi_detection": len(svc.detection_methods) >= 2,
            "http_confirmed": "http_probe" in svc.detection_methods,
        }

        score = sum(
            self.WEIGHTS[signal] for signal, active in signals.items() if active
        )

        label = "low"
        for threshold, lbl in self.LABELS:
            if score >= threshold:
                label = lbl
                break

        explanation = self._build_explanation(svc, signals, score, label)

        return ConfidenceResult(
            score=round(score, 3),
            label=label,
            signals=signals,
            explanation=explanation,
        )

    def score_batch(self, services: Dict[str, CorrelatedService]) -> Dict[str, ConfidenceResult]:
        """Score all services in a map."""
        return {name: self.score_service(svc) for name, svc in services.items()}

    def _check_port_match(self, svc: CorrelatedService) -> bool:
        """Check if the service was found on a known default port."""
        for port in svc.ports:
            expected = self._port_map.get(port)
            if expected and expected == svc.canonical_name:
                return True
        return False

    @staticmethod
    def _check_banner_match(svc: CorrelatedService) -> bool:
        """Check if banner/product data confirms the service identity."""
        if not svc.products:
            return False
        # If we have any non-empty product, consider banner confirmed
        return any(p.strip() for p in svc.products)

    @staticmethod
    def _build_explanation(svc: CorrelatedService, signals: Dict[str, bool],
                           score: float, label: str) -> str:
        """Build human-readable confidence explanation."""
        parts = [f"{svc.display_name or svc.canonical_name}: {label} confidence ({score:.0%})"]

        active = [s for s, v in signals.items() if v]
        if active:
            signal_names = {
                "port_match": "default port detected",
                "banner_match": "banner/product confirmed",
                "version_detected": "version identified",
                "multi_detection": f"{len(svc.detection_methods)} detection methods",
                "http_confirmed": "HTTP probe confirmed",
            }
            details = [signal_names.get(s, s) for s in active]
            parts.append(f"Signals: {', '.join(details)}")

        return " | ".join(parts)
