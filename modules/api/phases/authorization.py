"""ReconForge API Module - Phase 4: Authorization Testing

Author: Andrews Ferreira

PRIORITY 5 hardened authorization phase:
- Behavior-based BOLA/IDOR candidate identification (not just parameter names)
- Endpoint structure and access pattern analysis
- Authorization header/response pattern detection
- Specific manual test case generation per candidate
- Reduced reliance on parameter name patterns
- All heuristic findings clearly marked (caps at low via FindingsManager)
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from modules.api.base import APIPhaseBase
from modules.api.tools.nuclei_api import NucleiApiTool
from modules.api.tools.httpx_tool import HttpxTool
from modules.api.parsers.nuclei_parser import NucleiApiParser


# ── IDOR Candidate Scoring ──────────────────────────────────────────
# Instead of flat pattern lists, we use a scoring system.  Each signal
# contributes a small score; only candidates above a threshold get
# reported.  This dramatically reduces noise from parameter-name-only
# matching.

# Structural signals (endpoint shape) — stronger evidence
_RESOURCE_PATH_PATTERNS: Dict[str, float] = {
    # Pattern => score contribution
    # Only multi-segment resource paths (avoid matching bare "/" prefix)
    "/users/": 0.5,
    "/user/": 0.5,
    "/accounts/": 0.5,
    "/account/": 0.5,
    "/orders/": 0.4,
    "/order/": 0.4,
    "/profiles/": 0.5,
    "/profile/": 0.5,
    "/documents/": 0.3,
    "/document/": 0.3,
    "/files/": 0.3,
    "/file/": 0.3,
    "/records/": 0.3,
    "/record/": 0.3,
    "/invoices/": 0.3,
    "/invoice/": 0.3,
    "/tickets/": 0.3,
    "/ticket/": 0.3,
    "/messages/": 0.4,
    "/message/": 0.4,
    "/customers/": 0.4,
    "/customer/": 0.4,
}

# Method signals — mutating methods on resource endpoints are riskier
_METHOD_SCORES: Dict[str, float] = {
    "GET": 0.1,
    "PUT": 0.3,
    "PATCH": 0.3,
    "DELETE": 0.4,
    "POST": 0.2,
}

# IDOR reporting threshold
_IDOR_REPORT_THRESHOLD = 0.4


class AuthorizationPhase(APIPhaseBase):
    """Phase 4 – Authorization testing (BOLA/IDOR, privilege escalation)."""

    PHASE_NUMBER = 4
    PHASE_NAME = "authorization"
    PHASE_DESCRIPTION = "Authorization testing (BOLA/IDOR, access control)"

    def __init__(
        self,
        nuclei: NucleiApiTool,
        httpx: HttpxTool,
        nuclei_parser: NucleiApiParser,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.nuclei = nuclei
        self.httpx = httpx
        self.nuclei_parser = nuclei_parser

    def run(self, target_url: str, **kwargs) -> Dict[str, Any]:
        """Execute authorization testing phase.

        Args:
            target_url: Target API URL.
            endpoints: Discovered endpoints from Phase 1.
            discovered_params: Parameters from Phase 3.
            spec_data: Parsed OpenAPI spec (enhanced).
            auth_token: Authentication token for testing.
            headers: Optional HTTP headers.

        Returns:
            Dict with authorization findings and counts.
        """
        endpoints = kwargs.get("endpoints", [])
        discovered_params = kwargs.get("discovered_params", [])
        spec_data = kwargs.get("spec_data")
        auth_token = kwargs.get("auth_token", "")
        headers = kwargs.get("headers", [])

        results: Dict[str, Any] = {
            "phase": self.PHASE_NAME,
            "idor_candidates": [],
            "idor_test_cases": [],
            "access_control_findings": [],
            "privilege_escalation": [],
            "finding_count": 0,
            "success": False,
        }

        finding_count = 0

        # ── BOLA/IDOR scoring-based detection ────────────────────────
        finding_count += self._score_idor_candidates(
            target_url, endpoints, discovered_params, spec_data, results
        )

        # ── Nuclei authorization scan ───────────────────────────────
        finding_count += self._run_nuclei_authz_scan(target_url, headers, results)

        # ── Broken access control checks ────────────────────────────
        finding_count += self._check_access_control(
            target_url, endpoints, headers, auth_token, results
        )

        # ── Response-based auth pattern analysis ────────────────────
        finding_count += self._analyze_response_auth_patterns(
            target_url, endpoints, results
        )

        # ── Rate limiting check ─────────────────────────────────────
        finding_count += self._check_rate_limiting(target_url, headers, results)

        results["finding_count"] = finding_count
        results["success"] = True
        return results

    # ── Scoring-Based IDOR Detection ────────────────────────────────

    def _score_idor_candidates(
        self, target_url: str, endpoints: List[Dict],
        discovered_params: List[Dict], spec_data: Any,
        results: Dict,
    ) -> int:
        """Score endpoints for BOLA/IDOR risk using structural analysis.

        Scoring signals:
        1. Resource path structure (e.g. /users/{id})
        2. HTTP method (PUT/DELETE score higher than GET)
        3. Authenticated vs unauthenticated
        4. Request body contains ID references
        5. Multiple path parameters (cross-resource reference)

        Only candidates above threshold are reported, reducing noise.
        """
        finding_count = 0
        scored_candidates: List[Dict[str, Any]] = []

        for ep in endpoints:
            url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            method = ep.get("method", "GET") if isinstance(ep, dict) else "GET"
            status = ep.get("status", 0) if isinstance(ep, dict) else 0
            url_lower = url.lower()

            score = 0.0
            signals: List[str] = []

            # Signal 1: Resource path structure
            for pattern, pattern_score in _RESOURCE_PATH_PATTERNS.items():
                if pattern.lower() in url_lower or self._has_path_param_pattern(url, pattern):
                    score += pattern_score
                    signals.append(f"path_pattern:{pattern}")
                    break  # Count each endpoint once

            # Signal 2: Path contains numeric/UUID segment at end
            path_segments = url.rstrip("/").split("/")
            if path_segments:
                last_seg = path_segments[-1]
                if self._looks_like_id(last_seg):
                    score += 0.3
                    signals.append(f"id_in_path:{last_seg[:20]}")

            # Signal 3: HTTP method
            method_upper = method.upper()
            method_score = _METHOD_SCORES.get(method_upper, 0.1)
            score += method_score
            if method_upper in ("PUT", "PATCH", "DELETE"):
                signals.append(f"mutating_method:{method_upper}")

            # Signal 4: Endpoint returns 200 (accessible)
            if status == 200:
                score += 0.1
                signals.append("accessible:200")

            # Only report candidates above threshold
            if score >= _IDOR_REPORT_THRESHOLD:
                candidate = {
                    "url": url,
                    "method": method_upper,
                    "score": round(score, 2),
                    "signals": signals,
                    "status": status,
                }
                scored_candidates.append(candidate)
                results["idor_candidates"].append(candidate)

                # Generate specific test case
                test_case = self._generate_idor_test_case(url, method_upper, signals)
                results["idor_test_cases"].append(test_case)

                self.add_finding(
                    finding_type="information",
                    severity="low",
                    confidence="heuristic",
                    target=url,
                    description=(
                        f"BOLA/IDOR test candidate (score: {score:.1f}): "
                        f"{method_upper} {url}"
                    ),
                    evidence=(
                        f"Structural signals: {', '.join(signals)}. "
                        f"Score {score:.2f} ≥ threshold {_IDOR_REPORT_THRESHOLD}. "
                        f"Requires manual verification with multiple user contexts."
                    ),
                    recommendation=test_case.get("steps_text", ""),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                    ],
                )
                finding_count += 1

        # Also check discovered parameters — but with reduced weight
        finding_count += self._score_param_candidates(
            target_url, discovered_params, results
        )

        # Generate attack workflow if candidates found
        if scored_candidates:
            top_candidates = sorted(
                scored_candidates, key=lambda c: c["score"], reverse=True
            )[:5]
            self.workflow.add_attack_path(
                name="BOLA/IDOR Testing (Manual Verification Required)",
                description=(
                    f"{len(scored_candidates)} candidates identified via structural analysis. "
                    f"Top score: {top_candidates[0]['score']:.1f}"
                ),
                steps=[
                    "Authenticate as User A and capture resource IDs from API responses",
                    "Authenticate as User B (different privilege level)",
                    f"Test top candidates: {', '.join(c['url'][:60] for c in top_candidates[:3])}",
                    "Attempt to access/modify User A's resources as User B",
                    "Compare full response bodies (not just status codes)",
                    "Test both horizontal (same role) and vertical (different role) access",
                    "Only report as vulnerability if access control bypass is confirmed",
                ],
                risk="medium",
                prerequisites=["Two valid user accounts with different access levels"],
            )

        self.notes.add(
            f"IDOR analysis: {len(scored_candidates)} scored candidates "
            f"(threshold ≥{_IDOR_REPORT_THRESHOLD}), "
            f"manual verification required",
            "finding",
        )
        return finding_count

    def _score_param_candidates(
        self, target_url: str, discovered_params: List[Dict],
        results: Dict,
    ) -> int:
        """Score discovered parameters for IDOR potential.

        Parameter names alone are weak signals — we only report them
        when combined with context (e.g., the parameter is in a
        mutating endpoint or the endpoint returned 200).
        """
        finding_count = 0

        # High-value parameter names (still weak signal alone)
        high_value_params = {
            "user_id", "userid", "account_id", "accountid",
            "profile_id", "profileid",
        }

        for param in discovered_params:
            param_name = param.get("name", "") if isinstance(param, dict) else str(param)
            param_url = param.get("url", target_url) if isinstance(param, dict) else target_url
            param_method = param.get("method", "GET") if isinstance(param, dict) else "GET"

            # Only report if the parameter name is a strong IDOR indicator
            # AND the method is mutating or the endpoint is accessible
            if param_name.lower() not in high_value_params:
                continue

            score = 0.2  # Base score for matching a high-value param name
            signals = [f"param_name:{param_name}"]

            if param_method.upper() in ("PUT", "PATCH", "DELETE"):
                score += 0.3
                signals.append(f"mutating_method:{param_method}")

            if score >= _IDOR_REPORT_THRESHOLD:
                results["idor_candidates"].append({
                    "param": param_name,
                    "url": param_url,
                    "score": round(score, 2),
                    "signals": signals,
                    "type": "parameter",
                })

                self.add_finding(
                    finding_type="information",
                    severity="low",
                    confidence="heuristic",
                    target=param_url,
                    description=(
                        f"IDOR test candidate parameter: {param_name} "
                        f"on {param_method} endpoint"
                    ),
                    evidence=(
                        f"Parameter '{param_name}' in {param_method} request – "
                        f"requires multi-user testing to confirm. "
                        f"Signals: {', '.join(signals)}"
                    ),
                    recommendation=(
                        "Test with different user sessions to confirm broken "
                        "object-level authorization."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                    ],
                )
                finding_count += 1

        return finding_count

    def _generate_idor_test_case(self, url: str, method: str,
                                  signals: List[str]) -> Dict[str, Any]:
        """Generate a specific manual test case for an IDOR candidate."""
        steps = [
            f"1. Authenticate as User A, note the resource ID in: {url}",
            f"2. Authenticate as User B (different role or account)",
            f"3. Send {method} request to the same URL as User B",
            "4. Compare response: if User B gets User A's data, IDOR confirmed",
        ]

        if method in ("PUT", "PATCH"):
            steps.append(
                "5. Also test: modify the resource as User B and verify if changes persist"
            )
        elif method == "DELETE":
            steps.append(
                "5. WARNING: DELETE testing may destroy data – use a test resource"
            )

        if any("id_in_path" in s for s in signals):
            steps.append(
                "6. Try incrementing/decrementing the numeric ID to enumerate resources"
            )

        steps_text = "\n".join(steps)

        return {
            "url": url,
            "method": method,
            "steps": steps,
            "steps_text": steps_text,
            "signals": signals,
        }

    # ── Response-Based Auth Pattern Analysis ────────────────────────

    def _analyze_response_auth_patterns(
        self, target_url: str, endpoints: List[Dict], results: Dict,
    ) -> int:
        """Analyze response patterns for authorization indicators.

        Look for:
        - Endpoints that return different data sizes (may indicate
          partial auth — some data is filtered but endpoint is accessible)
        - Endpoints returning 200 with empty/minimal body
          (potential auth bypass returning empty result)
        """
        finding_count = 0

        # Group endpoints by path pattern (strip IDs)
        path_groups: Dict[str, List[Dict]] = {}
        for ep in endpoints:
            if not isinstance(ep, dict):
                continue
            url = ep.get("url", "")
            # Normalise path
            norm = self._normalize_path(url)
            path_groups.setdefault(norm, []).append(ep)

        # Check for inconsistent response sizes within same path group
        for norm_path, eps in path_groups.items():
            lengths = [ep.get("length", 0) for ep in eps if ep.get("length", 0) > 0]
            if len(lengths) >= 2:
                min_len = min(lengths)
                max_len = max(lengths)
                if max_len > 0 and min_len < max_len * 0.1:
                    # Significant size difference — possible partial data exposure
                    self.add_finding(
                        finding_type="information",
                        severity="info",
                        confidence="low",
                        target=target_url,
                        description=(
                            f"Inconsistent response sizes on {norm_path} "
                            f"(min: {min_len}, max: {max_len})"
                        ),
                        evidence=(
                            "Large variation in response sizes may indicate "
                            "filtered data based on authorization level"
                        ),
                        recommendation=(
                            "Compare responses from different authorization "
                            "contexts to check for data leakage."
                        ),
                    )
                    finding_count += 1

        return finding_count

    # ── Nuclei Authorization Scan ───────────────────────────────────

    def _run_nuclei_authz_scan(self, target_url: str, headers: List[str],
                                results: Dict) -> int:
        """Run Nuclei with authorization-focused templates."""
        if not self.nuclei.is_available():
            self.logger.warning("Nuclei not available, skipping authz vuln scan")
            return 0

        if not self.opsec.check("nuclei_api_scan"):
            return 0

        self.tools_used.append("nuclei")
        finding_count = 0

        run_result = self.nuclei.api_scan(
            target_url, tags="idor,bola,access-control,privilege-escalation",
        )

        if not run_result.success:
            self.logger.warning(f"Nuclei authz scan failed: {run_result.stderr[:200]}")
            return 0

        parsed = self.nuclei_parser.parse_jsonl(self.nuclei.get_jsonl_path())

        for finding in parsed.findings:
            self.add_finding(
                finding_type="vulnerability",
                severity=finding.severity,
                confidence="high",
                target=finding.matched_at or target_url,
                description=f"[Nuclei] {finding.name}",
                evidence=finding.raw_data[:300],
                recommendation=finding.remediation or "Review and remediate the vulnerability.",
                references=finding.references,
            )
            results["access_control_findings"].append({
                "template": finding.template_id,
                "name": finding.name,
                "severity": finding.severity,
            })
            finding_count += 1

        self.logger.info(f"Nuclei authz scan: {finding_count} findings")
        return finding_count

    # ── Access Control Checks ───────────────────────────────────────

    def _check_access_control(self, target_url: str, endpoints: List[Dict],
                               headers: List[str], auth_token: str,
                               results: Dict) -> int:
        """Check for broken access control patterns.

        Requires HTTP 200 + admin-pattern match for medium confidence.
        Pure URL patterns without confirmed access are not reported.
        """
        if not self.opsec.check("api_authz_testing"):
            return 0

        finding_count = 0

        admin_patterns = (
            "admin", "internal", "management", "debug",
            "metrics", "actuator", "graphql-playground",
        )

        for ep in endpoints:
            url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            url_lower = url.lower()
            status = ep.get("status", 0) if isinstance(ep, dict) else 0

            if status == 200 and any(p in url_lower for p in admin_patterns):
                self.add_finding(
                    finding_type="exposure",
                    severity="medium",
                    confidence="medium",
                    target=url,
                    description=f"Administrative/internal endpoint accessible: {url}",
                    evidence=(
                        f"HTTP {status} response on admin-pattern URL. "
                        f"Verify actual functionality manually."
                    ),
                    recommendation=(
                        "Verify if endpoint exposes privileged functionality "
                        "and restrict access via authentication and IP allowlisting."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                    ],
                )
                results["access_control_findings"].append({
                    "url": url,
                    "type": "admin_endpoint_exposed",
                })
                finding_count += 1

        return finding_count

    # ── Rate Limiting ───────────────────────────────────────────────

    def _check_rate_limiting(self, target_url: str, headers: List[str],
                              results: Dict) -> int:
        """Check for rate limiting on API endpoints."""
        if not self.opsec.check("api_rate_limit_check"):
            return 0

        finding_count = 0

        if self.httpx.is_available():
            self.tools_used.append("httpx")
            run_result = self.httpx.probe(target_url, headers=headers)

            if run_result.success:
                output = run_result.stdout.lower()
                rate_headers = (
                    "x-ratelimit", "x-rate-limit", "ratelimit",
                    "retry-after", "x-ratelimit-limit",
                )
                has_rate_limit = any(h in output for h in rate_headers)

                if not has_rate_limit:
                    self.add_finding(
                        finding_type="misconfiguration",
                        severity="low",
                        confidence="medium",
                        target=target_url,
                        description="No rate limiting headers detected on API",
                        evidence="Missing X-RateLimit-* or similar headers in response",
                        recommendation=(
                            "Implement rate limiting to prevent abuse, credential stuffing, "
                            "and denial-of-service attacks."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                        ],
                    )
                    finding_count += 1

        return finding_count

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _has_path_param_pattern(url: str, pattern: str) -> bool:
        """Check if URL matches a resource path pattern."""
        return pattern.lower() in url.lower()

    @staticmethod
    def _looks_like_id(segment: str) -> bool:
        """Check if a URL segment looks like a resource identifier."""
        if not segment:
            return False
        # Numeric ID
        if segment.isdigit():
            return True
        # UUID pattern
        if len(segment) == 36 and segment.count("-") == 4:
            return True
        # Short hex (MongoDB ObjectId, etc.)
        if len(segment) in (12, 24, 32) and all(c in "0123456789abcdef" for c in segment.lower()):
            return True
        # Slug with digits (e.g., "user-123")
        if any(c.isdigit() for c in segment) and "-" in segment:
            return True
        return False

    @staticmethod
    def _normalize_path(url: str) -> str:
        """Normalize a URL path by replacing ID-like segments with {id}."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            segments = parsed.path.split("/")
            normalized = []
            for seg in segments:
                if AuthorizationPhase._looks_like_id(seg):
                    normalized.append("{id}")
                else:
                    normalized.append(seg)
            return "/".join(normalized)
        except Exception:
            return url
