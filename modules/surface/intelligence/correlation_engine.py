"""ReconForge - Attack Surface Correlation Engine

Author: Andrews Ferreira

Correlates ports, services, URLs, and detection methods into a unified
attack surface map. Links HTTP services to discovered URLs, SMB services
to share enumeration, LDAP to AD enumeration, etc.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from modules.surface.intelligence.service_intelligence import (
    ServiceIntelligenceDB,
    ServiceProfile,
)
from modules.surface.intelligence.service_normalizer import ServiceNormalizer


@dataclass
class CorrelatedService:
    """A fully correlated service entry in the attack surface map."""
    canonical_name: str
    display_name: str = ""
    ports: List[int] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    versions: List[str] = field(default_factory=list)
    products: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    detection_methods: Set[str] = field(default_factory=set)
    category: str = ""
    attack_context: str = ""
    next_steps: List[str] = field(default_factory=list)
    common_tools: List[str] = field(default_factory=list)
    high_value: bool = False
    cleartext: bool = False
    default_creds: bool = False
    confidence: float = 0.0
    raw_entries: List[Dict] = field(default_factory=list)  # original data

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

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for JSON output."""
        return {
            "canonical_name": self.canonical_name,
            "display_name": self.display_name,
            "ports": sorted(set(self.ports)),
            "protocols": list(set(self.protocols)),
            "best_version": self.best_version,
            "all_versions": list(set(v for v in self.versions if v)),
            "products": list(set(p for p in self.products if p)),
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
    services: Dict[str, CorrelatedService] = field(default_factory=dict)
    # Category groupings for quick access
    by_category: Dict[str, List[str]] = field(default_factory=dict)
    total_ports: int = 0
    total_services: int = 0
    high_value_count: int = 0

    def get_services_by_category(self, category: str) -> List[CorrelatedService]:
        names = self.by_category.get(category, [])
        return [self.services[n] for n in names if n in self.services]

    def get_high_value(self) -> List[CorrelatedService]:
        return [s for s in self.services.values() if s.high_value]

    def to_dict(self) -> Dict[str, Any]:
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
        intel_db: Optional[ServiceIntelligenceDB] = None,
        normalizer: Optional[ServiceNormalizer] = None,
    ) -> None:
        self._db = intel_db or ServiceIntelligenceDB()
        self._normalizer = normalizer or ServiceNormalizer(self._db)

    def correlate(
        self,
        target: str,
        ports: List[Dict],
        services: List[Dict],
        http_services: List[Dict],
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
        correlated: Dict[str, CorrelatedService] = {}

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
        for name, svc in correlated.items():
            self._enrich_service(svc)

        # Build category index
        by_category: Dict[str, List[str]] = {}
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

    def _ingest_entry(self, correlated: Dict[str, CorrelatedService],
                      entry: Dict, detection_method: str) -> None:
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
        svc.detection_methods.add(detection_method)
        svc.raw_entries.append(entry)

    def _ingest_http(self, correlated: Dict[str, CorrelatedService],
                     http_entry: Dict) -> None:
        """Ingest an HTTP service entry and link it to the right service."""
        url = http_entry.get("url", "")
        if not url:
            return

        # Determine if http or https
        is_https = url.startswith("https://")
        canonical = "https" if is_https else "http"

        if canonical not in correlated:
            correlated[canonical] = CorrelatedService(canonical_name=canonical)

        svc = correlated[canonical]
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
