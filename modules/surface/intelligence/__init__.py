"""ReconForge - Surface Intelligence Package

Provides service intelligence database, normalization, correlation,
deduplication, confidence scoring, and intelligent prioritization
for the attack-surface reconnaissance module.
"""

from modules.surface.intelligence.service_intelligence import ServiceIntelligenceDB
from modules.surface.intelligence.service_normalizer import ServiceNormalizer
from modules.surface.intelligence.correlation_engine import CorrelationEngine
from modules.surface.intelligence.deduplicator import ServiceDeduplicator
from modules.surface.intelligence.confidence_scorer import ConfidenceScorer
from modules.surface.intelligence.attack_prioritizer import AttackPrioritizer

__all__ = [
    "ServiceIntelligenceDB",
    "ServiceNormalizer",
    "CorrelationEngine",
    "ServiceDeduplicator",
    "ConfidenceScorer",
    "AttackPrioritizer",
]
