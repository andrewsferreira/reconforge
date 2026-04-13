"""ReconForge API Module - Phase 1: Discovery

Author: Andrews Ferreira

PRIORITY 5 hardened discovery phase:
- Uses enhanced OpenAPI parser with $ref resolution and requestBody support
- Returns parsed OpenApiSpec for downstream phases
- Better spec download and parsing with error reporting
- Technology fingerprinting via httpx
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from modules.api.base import APIPhaseBase
from modules.api.tools.ffuf_api import FfufApiTool
from modules.api.tools.httpx_tool import HttpxTool
from modules.api.parsers.ffuf_parser import FfufApiParser
from modules.api.parsers.openapi_parser import OpenApiParser, OpenApiSpec


# Common API spec paths to probe
SPEC_PATHS = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api-docs.json", "/v1/openapi.json", "/v2/openapi.json",
    "/v3/openapi.json", "/docs", "/redoc", "/swagger-ui",
    "/swagger-ui.html", "/.well-known/openapi.json",
    "/api/swagger.json", "/api/openapi.json",
    "/api/v1/swagger.json", "/api/v2/swagger.json",
]

# Common API base paths
API_BASE_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1", "/graphql",
    "/v1", "/v2", "/v3",
    "/json", "/xml", "/rpc",
]


class DiscoveryPhase(APIPhaseBase):
    """Phase 1 – API endpoint discovery and spec detection."""

    PHASE_NUMBER = 1
    PHASE_NAME = "discovery"
    PHASE_DESCRIPTION = "API endpoint discovery & specification detection"

    def __init__(
        self,
        ffuf: FfufApiTool,
        httpx: HttpxTool,
        ffuf_parser: FfufApiParser,
        openapi_parser: OpenApiParser,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.ffuf = ffuf
        self.httpx = httpx
        self.ffuf_parser = ffuf_parser
        self.openapi_parser = openapi_parser

    def run(self, target_url: str, **kwargs) -> Dict[str, Any]:
        """Execute API discovery phase.

        Args:
            target_url: Target API URL.
            wordlist: Optional custom wordlist.
            headers: Optional HTTP headers.

        Returns:
            Dict with discovered endpoints, specs, parsed spec data, and finding count.
        """
        wordlist = kwargs.get("wordlist", "")
        headers = kwargs.get("headers", [])

        results: Dict[str, Any] = {
            "phase": self.PHASE_NAME,
            "endpoints": [],
            "spec_detected": False,
            "spec_urls": [],
            "spec_data": None,         # Parsed OpenApiSpec for downstream phases
            "spec_summary": {},        # Quick summary of parsed spec
            "api_versions": [],
            "technologies": [],
            "finding_count": 0,
            "success": False,
        }

        finding_count = 0

        # ── httpx probing ───────────────────────────────────────────
        finding_count += self._run_httpx_probe(target_url, headers, results)

        # ── OpenAPI/Swagger spec detection ──────────────────────────
        finding_count += self._detect_api_specs(target_url, headers, results)

        # ── Parse discovered spec (if any) ──────────────────────────
        self._parse_discovered_spec(results)

        # ── ffuf endpoint enumeration ───────────────────────────────
        finding_count += self._run_ffuf_scan(target_url, wordlist, headers, results)

        # ── Enrich endpoints from parsed spec ───────────────────────
        finding_count += self._enrich_from_spec(target_url, results)

        # ── API version detection ───────────────────────────────────
        finding_count += self._detect_api_versions(target_url, headers, results)

        results["finding_count"] = finding_count
        results["success"] = True
        return results

    def _run_httpx_probe(self, target_url: str, headers: List[str],
                         results: Dict) -> int:
        """Probe target with httpx for technology detection."""
        if not self.httpx.is_available():
            self.logger.warning("httpx not available, skipping HTTP probe")
            return 0

        if not self.opsec.check("httpx_api_probe"):
            return 0

        self.tools_used.append("httpx")
        run_result = self.httpx.probe(target_url, headers=headers)

        if not run_result.success:
            self.logger.warning(f"httpx probe failed: {run_result.stderr[:200]}")
            return 0

        # Parse httpx JSON output for technology info
        json_path = self.httpx.get_json_path("probe")
        if json_path.is_file():
            try:
                for line in json_path.read_text().strip().splitlines():
                    data = json.loads(line)
                    tech = data.get("tech", [])
                    if tech:
                        results["technologies"].extend(tech)
                    content_type = data.get("content-type", "")
                    if "json" in content_type.lower() or "xml" in content_type.lower():
                        results.setdefault("content_types", []).append(content_type)
            except (json.JSONDecodeError, OSError):
                pass

        self.notes.add(f"httpx probe completed for {target_url}", "command")
        return 0

    def _detect_api_specs(self, target_url: str, headers: List[str],
                          results: Dict) -> int:
        """Probe for OpenAPI/Swagger specification files."""
        if not self.opsec.check("api_spec_detection"):
            return 0

        finding_count = 0
        self.logger.info("Probing for OpenAPI/Swagger specifications...")

        spec_urls = [f"{target_url}{p}" for p in SPEC_PATHS]
        spec_file = self.phase_output("spec_probe_urls.txt")
        spec_file.write_text("\n".join(spec_urls))

        if self.httpx.is_available():
            self.tools_used.append("httpx")
            run_result = self.httpx.probe_endpoints(
                str(spec_file), headers=headers
            )

            if run_result.success:
                json_path = self.httpx.get_json_path("endpoints")
                if json_path.is_file():
                    try:
                        for line in json_path.read_text().strip().splitlines():
                            data = json.loads(line)
                            status = data.get("status-code", 0)
                            url = data.get("url", "")
                            if status == 200:
                                results["spec_urls"].append(url)
                                results["spec_detected"] = True

                                self.add_finding(
                                    finding_type="exposure",
                                    severity="medium",
                                    confidence="confirmed",
                                    target=url,
                                    description=f"API specification exposed at {url}",
                                    evidence=f"HTTP {status} response",
                                    recommendation="Restrict access to API documentation in production.",
                                    references=["https://owasp.org/API-Security/"],
                                )
                                finding_count += 1

                                self.loot.add(
                                    loot_type="api_doc_url",
                                    value=url,
                                    source="httpx",
                                    module="api",
                                )
                    except (json.JSONDecodeError, OSError):
                        pass

        if results["spec_detected"]:
            self.logger.info(f"Found API specs: {results['spec_urls']}")
            self.notes.add(
                f"API specifications detected: {', '.join(results['spec_urls'])}",
                "finding",
            )
        else:
            self.logger.info("No OpenAPI/Swagger specifications found")

        return finding_count

    def _parse_discovered_spec(self, results: Dict) -> None:
        """Attempt to parse any discovered OpenAPI spec.

        Downloads spec content and feeds it through the enhanced OpenApiParser
        with full $ref resolution and requestBody support.
        """
        if not results.get("spec_urls"):
            return

        # Try to find a local copy of the spec (from httpx download)
        # If not available, we note it for manual download
        for spec_url in results["spec_urls"]:
            # Check if we can find the spec content in raw output dir
            for suffix in (".json", ".yaml", ".yml"):
                if spec_url.endswith(suffix) or suffix in spec_url:
                    # Try to parse from the raw directory
                    spec_filename = spec_url.rstrip("/").split("/")[-1]
                    raw_spec_path = self.output_dir.parent / "raw" / "api" / spec_filename
                    if raw_spec_path.is_file():
                        spec = self.openapi_parser.parse(raw_spec_path)
                        if spec.endpoint_count > 0:
                            results["spec_data"] = spec
                            results["spec_summary"] = spec.summary()
                            self.logger.info(
                                f"Parsed OpenAPI spec: {spec.endpoint_count} endpoints, "
                                f"{len(spec.auth_schemes)} auth schemes"
                            )
                            if spec.parse_warnings:
                                for warn in spec.parse_warnings[:5]:
                                    self.logger.debug(f"Spec warning: {warn}")
                            return

        # If no local file found, note it
        self.notes.add(
            "OpenAPI spec detected but not downloaded locally – "
            "provide spec file with --spec for deep analysis",
            "general",
        )

    def _enrich_from_spec(self, target_url: str, results: Dict) -> int:
        """Enrich endpoint list from parsed OpenAPI spec.

        Adds endpoints from the spec that weren't already discovered by ffuf.
        """
        spec: Optional[OpenApiSpec] = results.get("spec_data")
        if not spec or not isinstance(spec, OpenApiSpec):
            return 0

        finding_count = 0
        existing_paths = {
            ep.get("url", "").rstrip("/").lower()
            for ep in results["endpoints"]
            if isinstance(ep, dict)
        }

        for ep in spec.endpoints:
            # Construct full URL
            base = results.get("spec_data").servers[0] if spec.servers else target_url
            full_url = f"{base.rstrip('/')}{ep.path}"

            if full_url.lower().rstrip("/") in existing_paths:
                continue

            endpoint_info = {
                "url": full_url,
                "method": ep.method,
                "status": 0,  # Not probed yet
                "source": "openapi_spec",
                "has_body": ep.request_body is not None,
                "requires_auth": ep.requires_auth,
                "deprecated": ep.deprecated,
                "param_count": len(ep.parameters),
                "body_fields": ep.request_body.fields if ep.request_body else [],
            }
            results["endpoints"].append(endpoint_info)

        spec_ep_count = sum(
            1 for ep in results["endpoints"]
            if isinstance(ep, dict) and ep.get("source") == "openapi_spec"
        )

        if spec_ep_count > 0:
            self.notes.add(
                f"Enriched endpoint list with {spec_ep_count} endpoints from OpenAPI spec",
                "finding",
            )

            # Report deprecated endpoints from spec
            deprecated = spec.deprecated_endpoints
            if deprecated:
                paths = ", ".join(f"{ep.method} {ep.path}" for ep in deprecated[:5])
                self.add_finding(
                    finding_type="information",
                    severity="low",
                    confidence="confirmed",
                    target=target_url,
                    description=f"Deprecated API endpoints found in spec: {paths}",
                    evidence=f"{len(deprecated)} deprecated endpoints in OpenAPI spec",
                    recommendation=(
                        "Ensure deprecated endpoints are actually removed or "
                        "return appropriate deprecation responses."
                    ),
                )
                finding_count += 1

        return finding_count

    def _run_ffuf_scan(self, target_url: str, wordlist: str,
                       headers: List[str], results: Dict) -> int:
        """Run ffuf for API endpoint enumeration."""
        if not self.ffuf.is_available():
            self.logger.warning("ffuf not available, skipping endpoint enumeration")
            return 0

        if not self.opsec.check("ffuf_api_scan"):
            return 0

        self.tools_used.append("ffuf")
        finding_count = 0

        run_result = self.ffuf.endpoint_scan(
            target_url, wordlist=wordlist, headers=headers,
        )

        if not run_result.success:
            self.logger.warning(f"ffuf scan failed: {run_result.stderr[:200]}")
            return 0

        # Parse results
        json_path = self.ffuf.get_json_path("api_endpoints")
        parsed = self.ffuf_parser.parse_json(json_path)

        for entry in parsed.entries:
            results["endpoints"].append({
                "url": entry.url,
                "status": entry.status,
                "length": entry.length,
                "input": entry.input_word,
                "source": "ffuf",
            })

            classification = self.ffuf_parser.classify_endpoint(entry.url)
            severity = "medium" if classification == "sensitive" else "info"

            self.add_finding(
                finding_type="exposure",
                severity=severity,
                confidence="confirmed",
                target=entry.url,
                description=f"API endpoint discovered: {entry.url} (HTTP {entry.status})",
                evidence=f"Status: {entry.status}, Size: {entry.length}",
                recommendation="Review endpoint access controls.",
            )
            finding_count += 1

            self.loot.add(
                loot_type="api_endpoint",
                value=entry.url,
                source="ffuf",
                module="api",
                metadata={"status": entry.status, "classification": classification},
            )

        self.logger.info(f"ffuf discovered {len(parsed.entries)} endpoints")
        self.notes.add(
            f"ffuf endpoint scan: {len(parsed.entries)} endpoints found",
            "command",
        )

        return finding_count

    def _detect_api_versions(self, target_url: str, headers: List[str],
                             results: Dict) -> int:
        """Detect API version patterns."""
        finding_count = 0
        detected_versions = set()

        for ep in results.get("endpoints", []):
            url = ep.get("url", "").lower() if isinstance(ep, dict) else ""
            for v in ("/v1", "/v2", "/v3", "/v4"):
                if v in url:
                    detected_versions.add(v.strip("/"))

        for spec_url in results.get("spec_urls", []):
            for v in ("/v1", "/v2", "/v3", "/v4"):
                if v in spec_url.lower():
                    detected_versions.add(v.strip("/"))

        results["api_versions"] = sorted(detected_versions)

        if len(detected_versions) > 1:
            self.add_finding(
                finding_type="misconfiguration",
                severity="low",
                confidence="medium",
                target=target_url,
                description=f"Multiple API versions detected: {', '.join(sorted(detected_versions))}",
                evidence=f"Versions: {', '.join(sorted(detected_versions))}",
                recommendation="Ensure older API versions are properly deprecated and secured.",
            )
            finding_count += 1

        return finding_count
