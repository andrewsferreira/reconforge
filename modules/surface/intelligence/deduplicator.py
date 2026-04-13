"""ReconForge - Service Deduplicator

Author: Andrews Ferreira

Detects and merges duplicate service detections from different tools
and scan phases. Ensures the attack surface map has unique, enriched
entries without redundant findings.
"""

from typing import Dict, List, Optional, Set, Tuple


class ServiceDeduplicator:
    """Deduplicates service entries from multiple detection sources.

    Merges complementary data from different detection methods:
    - Port scan data (port + basic service name)
    - Version scan data (port + service + version)
    - HTTP probe data (URL + technologies)
    - Banner grabs (service name + banner text)
    """

    def deduplicate_ports(
        self, ports: List[Dict], services: List[Dict]
    ) -> List[Dict]:
        """Merge port and service lists, deduplicating by port number.

        Keeps the entry with the most information. If version scan
        provides version data that port scan lacks, merge them.

        Args:
            ports: Port discovery results (phase 1).
            services: Service fingerprint results (phase 2).

        Returns:
            Deduplicated list of service entries.
        """
        by_port: Dict[int, Dict] = {}

        # Ingest port scan results first (baseline)
        for entry in ports:
            port = entry.get("port", 0)
            if port:
                by_port[port] = {
                    **entry,
                    "_detection_methods": {"port_scan"},
                }

        # Merge version scan results
        for entry in services:
            port = entry.get("port", 0)
            if not port:
                continue

            if port in by_port:
                existing = by_port[port]
                merged = self._merge_entries(existing, entry)
                merged["_detection_methods"] = existing.get(
                    "_detection_methods", set()
                ) | {"version_scan"}
                by_port[port] = merged
            else:
                by_port[port] = {
                    **entry,
                    "_detection_methods": {"version_scan"},
                }

        return list(by_port.values())

    def deduplicate_http(
        self, http_services: List[Dict]
    ) -> List[Dict]:
        """Deduplicate HTTP service entries by URL.

        Args:
            http_services: HTTP probe results.

        Returns:
            Deduplicated HTTP services.
        """
        by_url: Dict[str, Dict] = {}

        for entry in http_services:
            url = entry.get("url", "")
            if not url:
                continue

            if url in by_url:
                by_url[url] = self._merge_entries(by_url[url], entry)
            else:
                by_url[url] = dict(entry)

        return list(by_url.values())

    def count_detection_methods(self, entry: Dict) -> int:
        """Count how many detection methods found this service."""
        methods = entry.get("_detection_methods", set())
        return len(methods) if isinstance(methods, set) else 1

    @staticmethod
    def _merge_entries(existing: Dict, new: Dict) -> Dict:
        """Merge two entries for the same service, keeping best data.

        Strategy:
        - Non-empty string values in `new` override empty ones in `existing`
        - Lists are merged (union)
        - Sets are merged
        - Detection methods are accumulated
        """
        merged = dict(existing)

        for key, value in new.items():
            if key.startswith("_"):
                # Internal tracking keys
                if key in merged and isinstance(merged[key], set) and isinstance(value, set):
                    merged[key] = merged[key] | value
                continue

            if isinstance(value, str) and value:
                # Prefer longer/more specific string (usually means more info)
                existing_val = merged.get(key, "")
                if not existing_val or (len(value) > len(str(existing_val))):
                    merged[key] = value
            elif isinstance(value, list):
                existing_list = merged.get(key, [])
                if isinstance(existing_list, list):
                    combined = list(existing_list)
                    for item in value:
                        if item not in combined:
                            combined.append(item)
                    merged[key] = combined
                else:
                    merged[key] = value
            elif isinstance(value, (int, float)) and value:
                if not merged.get(key):
                    merged[key] = value

        return merged
