"""ReconForge - Attack Surface Correlation Engine

Author: Andrews Ferreira

Correlates ports, services, URLs, and detection methods into a unified
attack surface map. Links HTTP services to discovered URLs, SMB services
to share enumeration, LDAP to AD enumeration, etc.
"""

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from modules.surface.intelligence.service_intelligence import (
    ServiceIntelligenceDB,
)
from modules.surface.intelligence.service_normalizer import ServiceNormalizer


@dataclass
class CorrelatedService:
    """A fully correlated service entry in the attack surface map."""
    canonical_name: str
    display_name: str = ""
    ports: list[int] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    versions: list[str] = field(default_factory=list)
    products: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    detection_methods: set[str] = field(default_factory=set)
    category: str = ""
    attack_context: str = ""
    next_steps: list[str] = field(default_factory=list)
    common_tools: list[str] = field(default_factory=list)
    high_value: bool = False
    cleartext: bool = False
    default_creds: bool = False
    confidence: float = 0.0
    raw_entries: list[dict] = field(default_factory=list)  # original data

    @property
    def best_version(self) -> str:
        """Return the most specific version detected."""
        versions = [v for v in self.versions if v]
        if not versions:
            return ""
        return max(versions, key=len)

    @property
    def port_list(self) -> str:
        """Comma-separated port list."""
        return ", ".join(str(p) for p in sorted(set(self.ports)))

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON output."""
        return {
            "canonical_name": self.canonical_name,
            "display_name": self.display_name,
            "ports": sorted(set(self.ports)),
            "protocols": list(set(self.protocols)),
            "best_version": self.best_version,
            "all_versions": list({v for v in self.versions if v}),
            "products": list({p for p in self.products if p}),
            "urls": self.urls,
            "technologies": list(set(self.technologies)),
            "detection_methods": sorted(self.detection_methods),
            "category": self.category,
            "attack_context": self.attack_context,
            "next_steps": self.next_steps,
            "common_tools": self.common_tools,
            "high_value": self.high_value,
            "cleartext": self.cleartext,
            "default_creds": self.default_creds,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class AttackSurfaceMap:
    """Unified attack surface representation."""
    target: str = ""
    services: dict[str, CorrelatedService] = field(default_factory=dict)
    # Category groupings for quick access
    by_category: dict[str, list[str]] = field(default_factory=dict)
    total_ports: int = 0
    total_services: int = 0
    high_value_count: int = 0

    def get_services_by_category(self, category: str) -> list[CorrelatedService]:
        names = self.by_category.get(category, [])
        return [self.services[n] for n in names if n in self.services]

    def get_high_value(self) -> list[CorrelatedService]:
        return [s for s in self.services.values() if s.high_value]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "total_ports": self.total_ports,
            "total_services": self.total_services,
            "high_value_count": self.high_value_count,
            "services": {k: v.to_dict() for k, v in self.services.items()},
            "by_category": self.by_category,
        }


class CorrelationEngine:
    """Correlates disparate scan data into a unified attack surface map.

    Links:
    - Ports ↔ Services (via normalization + intelligence DB)
    - HTTP services ↔ URLs and technologies
    - SMB services ↔ share enumeration targets
    - LDAP services ↔ AD enumeration targets
    - Multiple detection methods for the same service
    """

    def __init__(
        self,
        intel_db: ServiceIntelligenceDB | None = None,
        normalizer: ServiceNormalizer | None = None,
    ) -> None:
        self._db = intel_db or ServiceIntelligenceDB()
        self._normalizer = normalizer or ServiceNormalizer(self._db)

    def correlate(
        self,
        target: str,
        ports: list[dict],
        services: list[dict],
        http_services: list[dict],
    ) -> AttackSurfaceMap:
        """Build a unified attack surface map from all scan data.

        Args:
            target: Target IP/hostname.
            ports: Port discovery results (phase 1).
            services: Service fingerprint results (phase 2).
            http_services: HTTP probe results (phase 2).

        Returns:
            AttackSurfaceMap with correlated services.
        """
        surface = AttackSurfaceMap(target=target)
        correlated: dict[str, CorrelatedService] = {}

        # Process port discovery data
        for entry in ports:
            self._ingest_entry(correlated, entry, detection_method="port_scan")

        # Process service fingerprint data
        for entry in services:
            self._ingest_entry(correlated, entry, detection_method="version_scan")

        # Process HTTP services - link URLs to services
        for http_svc in http_services:
            self._ingest_http(correlated, http_svc)

        # Enrich all correlated services with intelligence
        for svc in correlated.values():
            self._enrich_service(svc)

        # Build category index
        by_category: dict[str, list[str]] = {}
        for name, svc in correlated.items():
            cat = svc.category or "misc"
            by_category.setdefault(cat, []).append(name)

        # Collect unique ports
        all_ports = set()
        for svc in correlated.values():
            all_ports.update(svc.ports)

        surface.services = correlated
        surface.by_category = by_category
        surface.total_ports = len(all_ports)
        surface.total_services = len(correlated)
        surface.high_value_count = sum(1 for s in correlated.values() if s.high_value)

        return surface

    def _ingest_entry(self, correlated: dict[str, CorrelatedService],
                      entry: dict, detection_method: str) -> None:
        """Ingest a port/service entry into the correlation map."""
        port = entry.get("port", 0)
        service_name = entry.get("service", "")
        version = entry.get("version", "")
        product = entry.get("product", "")
        protocol = entry.get("protocol", "tcp")

        # Normalize the service name
        norm = self._normalizer.normalize(service_name, port, version, product)
        canonical = norm.canonical_name

        if canonical not in correlated:
            correlated[canonical] = CorrelatedService(canonical_name=canonical)

        svc = correlated[canonical]
        if port and port not in svc.ports:
            svc.ports.append(port)
        if protocol and protocol not in svc.protocols:
            svc.protocols.append(protocol)
        if norm.version and norm.version not in svc.versions:
            svc.versions.append(norm.version)
        if version and version not in svc.versions:
            svc.versions.append(version)
        if norm.product and norm.product not in svc.products:
            svc.products.append(norm.product)
        if product and product not in svc.products:
            svc.products.append(product)

        # ServiceDeduplicator.deduplicate_ports() pre-merges port_scan and
        # version_scan entries for the same port and tags the merged entry
        # with the real union of detection methods in "_detection_methods"
        # (see modules/surface/intelligence/deduplicator.py). Callers that
        # pre-dedupe (modules/surface/phases/vector_correlation.py) then
        # call correlate(ports=deduped_services, ...) with a single hardcoded
        # detection_method="port_scan" — using that alone would discard the
        # richer tagging and mean ConfidenceScorer's multi_detection signal
        # (len(detection_methods) >= 2) could never fire for TCP/UDP
        # services, only HTTP. Prefer the entry's own tagging when present.
        entry_detection_methods = entry.get("_detection_methods")
        if entry_detection_methods:
            svc.detection_methods.update(entry_detection_methods)
        else:
            svc.detection_methods.add(detection_method)
        svc.raw_entries.append(entry)

    def _ingest_http(self, correlated: dict[str, CorrelatedService],
                     http_entry: dict) -> None:
        """Ingest an HTTP service entry and link it to the right service."""
        url = http_entry.get("url", "")
        if not url:
            return

        # Group by scheme AND port, not scheme alone — two HTTP services on
        # different ports of the same host (e.g. :80 and :8080) are not
        # necessarily the same logical service and must not be merged
        # (previously both fell into a single "http" bucket, conflating
        # their urls/technologies/products). canonical_name stays the bare
        # scheme ("http"/"https") since that's the key
        # ServiceIntelligenceDB.get_profile() expects in _enrich_service().
        parsed = urlparse(url)
        is_https = parsed.scheme == "https"
        port = parsed.port or (443 if is_https else 80)
        canonical = "https" if is_https else "http"

        # Reuse an existing entry the port/version-scan phase already
        # correlated for this exact port (links the URL probe to the same
        # logical service) rather than always minting a new bucket — only
        # fall back to a fresh scheme:port key when no such entry exists,
        # which is what actually fixes the distinct-ports-getting-merged bug.
        dict_key = next(
            (key for key, svc in correlated.items()
             if svc.canonical_name == canonical and port in svc.ports),
            f"{canonical}:{port}",
        )

        if dict_key not in correlated:
            correlated[dict_key] = CorrelatedService(canonical_name=canonical)

        svc = correlated[dict_key]
        if port not in svc.ports:
            svc.ports.append(port)
        if url not in svc.urls:
            svc.urls.append(url)

        techs = http_entry.get("technologies", [])
        for tech in techs:
            if tech not in svc.technologies:
                svc.technologies.append(tech)

        web_server = http_entry.get("web_server", "")
        if web_server and web_server not in svc.products:
            svc.products.append(web_server)

        svc.detection_methods.add("http_probe")
        svc.raw_entries.append(http_entry)

    def _enrich_service(self, svc: CorrelatedService) -> None:
        """Enrich a correlated service with intelligence data."""
        profile = self._db.get_profile(svc.canonical_name)
        if profile:
            svc.display_name = profile.display_name
            svc.category = profile.category
            svc.attack_context = profile.attack_context
            svc.next_steps = list(profile.next_steps)
            svc.common_tools = list(profile.common_tools)
            svc.high_value = profile.high_value
            svc.cleartext = profile.cleartext
            svc.default_creds = profile.default_creds_common
        else:
            svc.display_name = svc.canonical_name.upper()
            svc.category = "misc"
