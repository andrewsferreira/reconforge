"""ReconForge Web Module - Phase implementations.

Author: Andrews Ferreira
"""

from modules.web.phases.content_enumeration import ContentEnumerationPhase
from modules.web.phases.exploit_candidates import ExploitCandidatesPhase
from modules.web.phases.surface_discovery import SurfaceDiscoveryPhase
from modules.web.phases.vulnerability_scanning import VulnerabilityScanningPhase

__all__ = [
    "SurfaceDiscoveryPhase",
    "ContentEnumerationPhase",
    "VulnerabilityScanningPhase",
    "ExploitCandidatesPhase",
]
