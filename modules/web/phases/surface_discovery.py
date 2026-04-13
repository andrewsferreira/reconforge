"""ReconForge - Phase 1: Surface Discovery

Author: Andrews Ferreira

Technology fingerprinting, WAF detection, and HTTP header analysis.
Uses WhatWeb for technology detection, wafw00f for WAF identification,
and curl for baseline header collection.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from modules.web.base import WebPhaseBase
from modules.web.tools.whatweb import WhatwebTool
from modules.web.tools.wafw00f import Wafw00fTool
from modules.web.tools.curl_tool import CurlTool
from modules.web.parsers.whatweb_parser import WhatwebParser
from modules.web.parsers.wafw00f_parser import Wafw00fParser


class SurfaceDiscoveryPhase(WebPhaseBase):
    """Phase 1 – Identify technologies, WAFs, and server headers."""

    PHASE_NUMBER = 1
    PHASE_NAME = "surface_discovery"
    PHASE_DESCRIPTION = "Surface discovery & technology fingerprinting"

    # Security headers to check.
    # NOTE: Missing headers are informational observations, not vulnerabilities.
    # Their absence does not prove exploitability – they are defence-in-depth
    # measures and their relevance depends on context.
    SECURITY_HEADERS = {
        "x-frame-options": "Missing X-Frame-Options header (clickjacking defence-in-depth)",
        "x-content-type-options": "Missing X-Content-Type-Options header (MIME sniffing defence)",
        "content-security-policy": "Missing Content-Security-Policy header",
        "strict-transport-security": "Missing Strict-Transport-Security (HSTS) header",
        "x-xss-protection": "Missing X-XSS-Protection header (legacy browser defence)",
    }

    def __init__(
        self,
        whatweb: WhatwebTool,
        wafw00f: Wafw00fTool,
        curl: CurlTool,
        whatweb_parser: WhatwebParser,
        wafw00f_parser: Wafw00fParser,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.whatweb = whatweb
        self.wafw00f = wafw00f
        self.curl = curl
        self.whatweb_parser = whatweb_parser
        self.wafw00f_parser = wafw00f_parser

    def run(self, target_url: str, **kwargs) -> Dict[str, Any]:
        """Execute surface discovery phase.

        Args:
            target_url: Target URL to fingerprint.

        Returns:
            Dict with technologies, WAF info, header findings, and counts.
        """
        results: Dict[str, Any] = {
            "phase": self.PHASE_NAME,
            "technologies": [],
            "waf": None,
            "headers": {},
            "finding_count": 0,
            "success": False,
        }

        finding_count = 0

        # ── WhatWeb ────────────────────────────────────────────────
        finding_count += self._run_whatweb(target_url, results)

        # ── wafw00f ────────────────────────────────────────────────
        finding_count += self._run_wafw00f(target_url, results)

        # ── HTTP header analysis ───────────────────────────────────
        finding_count += self._analyse_headers(target_url, results)

        results["finding_count"] = finding_count
        results["success"] = True

        # Save parsed results
        parsed_file = self.phase_output("surface_discovery_results.json")
        parsed_file.write_text(json.dumps(results, indent=2, default=str))

        return results

    # ── WhatWeb ────────────────────────────────────────────────────

    def _run_whatweb(self, target_url: str, results: Dict) -> int:
        """Run WhatWeb technology fingerprinting.

        Returns:
            Number of findings generated.
        """
        count = 0

        if not self.whatweb.is_available():
            self.logger.warning("whatweb not installed – skipping")
            self.notes.add("whatweb not found – skipped", "general")
            return count

        if not self.opsec.check("whatweb_scan"):
            return count

        self.workflow.add_step(
            phase=self.PHASE_NAME,
            hypothesis=f"Target {target_url} uses identifiable technologies",
            command=f"whatweb {target_url}",
            justification="Technology fingerprinting to identify attack surface",
            alternatives=["curl header analysis", "wappalyzer"],
        )

        run_result = self.whatweb.scan(target_url)
        self.tools_used.append("whatweb")

        if not run_result.success:
            self.logger.warning(f"whatweb failed: {run_result.stderr[:200]}")
            self.workflow.record_result(f"Failed: {run_result.stderr[:100]}")
            self.notes.add_command_note(run_result.command, "Failed")
            return count

        # Parse results
        ww_result = self.whatweb_parser.parse_json(self.whatweb.get_json_path())
        if not ww_result.technologies and run_result.stdout:
            ww_result = self.whatweb_parser.parse_text(run_result.stdout)

        tech_names = []
        for tech in ww_result.technologies:
            tech_info = {
                "name": tech.name,
                "version": tech.version,
                "category": tech.category,
            }
            results["technologies"].append(tech_info)
            tech_names.append(tech.name)

            desc = f"Technology detected: {tech.name}"
            if tech.version:
                desc += f" v{tech.version}"

            self.add_finding(
                finding_type="information",
                severity="info",
                confidence="high" if tech.version else "medium",
                target=target_url,
                description=desc,
                evidence=tech.raw_data[:500],
            )
            count += 1

            # Flag X-Powered-By exposure
            if tech.category == "header" and tech.name == "X-Powered-By":
                self.add_finding(
                    finding_type="exposure",
                    severity="low",
                    confidence="confirmed",
                    target=target_url,
                    description=f"X-Powered-By header exposes technology: {tech.version}",
                    evidence=tech.raw_data[:300],
                    recommendation="Remove or obfuscate the X-Powered-By header.",
                )
                count += 1

            # Record technologies as loot
            if tech.version:
                self.loot.add_service(
                    service=tech.name,
                    version=tech.version,
                    port=443 if target_url.startswith("https") else 80,
                    source="whatweb",
                    module="web",
                )

        # Check for CMS detections -> suggest next steps
        cms_names = [t.name.lower() for t in ww_result.technologies if t.category == "cms"]
        if "wordpress" in cms_names:
            self.workflow.suggest_next(
                command=f"wpscan --url {target_url}",
                justification="WordPress detected – run WPScan for plugin/theme vulns",
                priority="high",
            )

        tech_summary = ", ".join(tech_names[:10]) if tech_names else "none identified"
        self.workflow.record_result(f"Technologies: {tech_summary}")
        self.notes.add_command_note(
            f"whatweb {target_url}",
            f"{len(ww_result.technologies)} technologies detected",
        )

        return count

    # ── wafw00f ────────────────────────────────────────────────────

    def _run_wafw00f(self, target_url: str, results: Dict) -> int:
        """Run WAF detection.

        Returns:
            Number of findings generated.
        """
        count = 0

        if not self.wafw00f.is_available():
            self.logger.warning("wafw00f not installed – skipping")
            self.notes.add("wafw00f not found – skipped", "general")
            return count

        if not self.opsec.check("wafw00f_detect"):
            return count

        self.workflow.add_step(
            phase=self.PHASE_NAME,
            hypothesis=f"Target may be behind a WAF/CDN",
            command=f"wafw00f {target_url}",
            justification="WAF detection to inform evasion strategies",
        )

        run_result = self.wafw00f.detect(target_url)
        self.tools_used.append("wafw00f")

        # Parse results
        waf_result = self.wafw00f_parser.parse_file(self.wafw00f.get_output_path())
        if not waf_result.raw_output and run_result.stdout:
            waf_result = self.wafw00f_parser.parse_text(run_result.stdout)

        if waf_result.waf_detected:
            waf_names = waf_result.waf_names
            results["waf"] = {"detected": True, "products": waf_names}

            self.add_finding(
                finding_type="information",
                severity="info",
                confidence="high",
                target=target_url,
                description=f"WAF detected: {', '.join(waf_names)}",
                evidence=waf_result.raw_output[:500],
                recommendation="Account for WAF evasion in subsequent testing.",
            )
            count += 1

            self.notes.add_finding_note(f"WAF detected: {', '.join(waf_names)}")
            self.workflow.record_result(f"WAF: {', '.join(waf_names)}")
            self.workflow.add_rabbit_hole(
                f"WAF ({', '.join(waf_names)}) may block aggressive scans – "
                "adjust rate limiting and encoding"
            )
        else:
            results["waf"] = {"detected": False, "products": []}
            self.add_finding(
                finding_type="information",
                severity="info",
                confidence="medium",
                target=target_url,
                description="No WAF detected",
                evidence=waf_result.raw_output[:300],
            )
            count += 1
            self.workflow.record_result("No WAF detected")

        return count

    # ── Header analysis ────────────────────────────────────────────

    def _analyse_headers(self, target_url: str, results: Dict) -> int:
        """Analyse HTTP response headers for security issues.

        Returns:
            Number of findings generated.
        """
        count = 0

        if not self.curl.is_available():
            return count

        run_result = self.curl.fetch_headers(target_url)
        self.tools_used.append("curl")

        headers_path = self.curl.get_headers_path()
        if not headers_path.is_file():
            if run_result.stdout:
                headers_raw = run_result.stdout
            else:
                return count
        else:
            headers_raw = headers_path.read_text(encoding="utf-8", errors="replace")

        headers_lower = headers_raw.lower()

        # Check for missing security headers
        # These are informational – missing headers are defence-in-depth
        # observations, NOT vulnerabilities or misconfigurations by themselves.
        for header, desc in self.SECURITY_HEADERS.items():
            if header not in headers_lower:
                self.add_finding(
                    finding_type="information",
                    severity="info",
                    confidence="confirmed",
                    target=target_url,
                    description=desc,
                    evidence=f"Header '{header}' not found in response.",
                    recommendation=f"Consider adding the {header} header for defence-in-depth.",
                    references=["https://owasp.org/www-project-secure-headers/"],
                )
                count += 1

        # Check Server header disclosure
        for line in headers_raw.splitlines():
            if line.lower().startswith("server:"):
                server_val = line.split(":", 1)[1].strip()
                results["headers"]["server"] = server_val
                self.add_finding(
                    finding_type="information",
                    severity="info",
                    confidence="confirmed",
                    target=target_url,
                    description=f"Server header discloses: {server_val}",
                    evidence=line.strip(),
                    recommendation="Consider suppressing or generalising the Server header.",
                )
                count += 1
                break

        self.notes.add_command_note(
            f"curl -sI {target_url}",
            f"Header analysis complete, {count} findings",
        )

        return count
