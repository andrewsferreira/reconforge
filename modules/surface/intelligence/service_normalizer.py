"""ReconForge - Service Name Normalizer

Author: Andrews Ferreira

Normalizes inconsistent service names from various tools (nmap, httpx,
banner grabs) to canonical names. Handles case sensitivity, version
string extraction, and common variations.
"""

import re
from dataclasses import dataclass

from modules.surface.intelligence.service_intelligence import ServiceIntelligenceDB


@dataclass
class NormalizedService:
    """Result of service name normalization."""
    canonical_name: str  # Standardized service name
    original_name: str  # Original name before normalization
    version: str = ""  # Extracted version string
    product: str = ""  # Product name (e.g., 'OpenSSH', 'Apache')
    normalized: bool = False  # Whether normalization was applied
    confidence: str = "medium"  # Confidence in normalization


class ServiceNormalizer:
    """Normalizes service names to canonical form.

    Resolves inconsistencies like:
    - http vs HTTP vs www vs web
    - smb vs microsoft-ds vs cifs
    - rdp vs ms-wbt-server
    - ssh vs openssh
    """

    # Regex patterns for version extraction
    _VERSION_PATTERNS = [
        # OpenSSH 8.9p1
        re.compile(r"^(?P<product>[\w.-]+)\s+(?P<version>[\d]+(?:\.[\d]+)*(?:[a-z]\d*)?)\s*(?P<extra>.*)$", re.I),
        # Apache/2.4.51
        re.compile(r"^(?P<product>[\w.-]+)/(?P<version>[\d]+(?:\.[\d]+)*)\s*(?P<extra>.*)$", re.I),
        # Just a version like 7.0
        re.compile(r"^(?P<version>[\d]+(?:\.[\d]+)+)$"),
    ]

    # SSL/TLS prefix patterns
    _SSL_PREFIXES = re.compile(r"^ssl[/|]|^tls[/|]", re.I)

    def __init__(self, intel_db: ServiceIntelligenceDB | None = None) -> None:
        self._db = intel_db or ServiceIntelligenceDB()

    def normalize(self, service_name: str, port: int = 0,
                  version_str: str = "", product_str: str = "") -> NormalizedService:
        """Normalize a service name to its canonical form.

        Resolution priority:
        1. Direct alias match in intelligence DB
        2. SSL-stripped alias match
        3. Port-based resolution (fallback)
        4. Return cleaned original if no match

        Args:
            service_name: Raw service name from tool output.
            port: Port number (used as fallback for resolution).
            version_str: Version string if already extracted.
            product_str: Product name if already extracted.

        Returns:
            NormalizedService with canonical name and metadata.
        """
        if not service_name:
            # Port-only resolution
            canonical = self._db.resolve_by_port(port)
            if canonical:
                return NormalizedService(
                    canonical_name=canonical,
                    original_name="",
                    version=version_str,
                    product=product_str,
                    normalized=True,
                    confidence="low",
                )
            return NormalizedService(
                canonical_name="unknown",
                original_name="",
                version=version_str,
                product=product_str,
            )

        original = service_name
        clean = service_name.strip().lower()

        # Extract version from service name if embedded
        extracted_version = version_str
        extracted_product = product_str
        if not version_str:
            extracted_product, extracted_version = self._extract_version(clean)

        # 1. Direct alias resolution
        canonical = self._db.resolve_canonical(clean)
        if canonical:
            return NormalizedService(
                canonical_name=canonical,
                original_name=original,
                version=extracted_version or version_str,
                product=extracted_product or product_str,
                normalized=(canonical != clean),
                confidence="high",
            )

        # 2. SSL/TLS prefix stripping
        stripped = self._SSL_PREFIXES.sub("", clean)
        if stripped != clean:
            canonical = self._db.resolve_canonical(stripped)
            if canonical:
                # If it's HTTP over SSL, resolve to https
                if canonical == "http":
                    canonical = "https"
                return NormalizedService(
                    canonical_name=canonical,
                    original_name=original,
                    version=extracted_version or version_str,
                    product=extracted_product or product_str,
                    normalized=True,
                    confidence="high",
                )

        # 3. Port-based fallback
        canonical = self._db.resolve_by_port(port)
        if canonical:
            return NormalizedService(
                canonical_name=canonical,
                original_name=original,
                version=extracted_version or version_str,
                product=extracted_product or product_str,
                normalized=True,
                confidence="low",
            )

        # 4. Return cleaned original
        return NormalizedService(
            canonical_name=clean,
            original_name=original,
            version=extracted_version or version_str,
            product=extracted_product or product_str,
            normalized=False,
            confidence="low",
        )

    def _extract_version(self, name: str) -> tuple[str, str]:
        """Extract product and version from a service name string."""
        for pattern in self._VERSION_PATTERNS:
            m = pattern.match(name)
            if m:
                groups = m.groupdict()
                return groups.get("product", ""), groups.get("version", "")
        return "", ""

    def normalize_batch(self, services: list) -> list:
        """Normalize a batch of service dicts in-place and return them.

        Each dict is expected to have 'service' and optionally 'port', 'version', 'product'.
        Adds 'canonical_name', 'normalized', and 'norm_confidence' keys.
        """
        results = []
        for svc in services:
            norm = self.normalize(
                service_name=svc.get("service", ""),
                port=svc.get("port", 0),
                version_str=svc.get("version", ""),
                product_str=svc.get("product", ""),
            )
            svc["canonical_name"] = norm.canonical_name
            svc["original_service"] = norm.original_name
            svc["normalized"] = norm.normalized
            svc["norm_confidence"] = norm.confidence
            if norm.version and not svc.get("version"):
                svc["version"] = norm.version
            if norm.product and not svc.get("product"):
                svc["product"] = norm.product
            results.append(svc)
        return results
