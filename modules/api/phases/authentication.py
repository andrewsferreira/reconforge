"""ReconForge API Module - Phase 2: Authentication Analysis

Author: Andrews Ferreira

PRIORITY 5 hardened authentication phase:
- Deep JWT claims extraction (sub, iss, exp, aud, iat, nbf, jti)
- JWT misconfiguration detection (missing exp, weak key indicators,
  kid injection vectors, jku/x5u abuse)
- Signature structure validation
- Actionable recommendations per finding
- Leverages enhanced OpenAPI parser for requestBody-aware auth analysis
- HS256 remains info-only (established in PRIORITY 3)
"""

import base64
import json
import re
import time
from typing import Any

from modules.api.base import APIPhaseBase
from modules.api.parsers.nuclei_parser import NucleiApiParser
from modules.api.parsers.openapi_parser import OpenApiParser, OpenApiSpec
from modules.api.tools.httpx_tool import HttpxTool
from modules.api.tools.nuclei_api import NucleiApiTool

# JWT header pattern (three base64url segments separated by dots)
JWT_PATTERN = re.compile(
    r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
)


def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment with padding correction."""
    segment = segment.replace("-", "+").replace("_", "/")
    padding = 4 - len(segment) % 4
    if padding != 4:
        segment += "=" * padding
    return base64.b64decode(segment)


def _safe_json_decode(segment: str) -> dict | None:
    """Decode a JWT segment to a dict, returning None on failure."""
    try:
        return json.loads(_b64url_decode(segment))
    except Exception:
        return None


class AuthenticationPhase(APIPhaseBase):
    """Phase 2 – Authentication mechanism analysis."""

    PHASE_NUMBER = 2
    PHASE_NAME = "authentication"
    PHASE_DESCRIPTION = "Authentication mechanism analysis & token testing"

    def __init__(
        self,
        httpx: HttpxTool,
        nuclei: NucleiApiTool,
        nuclei_parser: NucleiApiParser,
        openapi_parser: OpenApiParser,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.httpx = httpx
        self.nuclei = nuclei
        self.nuclei_parser = nuclei_parser
        self.openapi_parser = openapi_parser

    def run(self, target_url: str, **kwargs) -> dict[str, Any]:
        """Execute authentication analysis phase.

        Args:
            target_url: Target API URL.
            spec_data: Parsed OpenAPI spec (if available from Phase 1).
            auth_token: Optional auth token for testing.
            headers: Optional HTTP headers.

        Returns:
            Dict with auth mechanisms, weaknesses, and finding count.
        """
        spec_data = kwargs.get("spec_data")
        auth_token = kwargs.get("auth_token", "")
        headers = kwargs.get("headers", [])

        results: dict[str, Any] = {
            "phase": self.PHASE_NAME,
            "auth_mechanisms": [],
            "jwt_findings": [],
            "jwt_claims": {},
            "weaknesses": [],
            "finding_count": 0,
            "success": False,
        }

        finding_count = 0

        # ── Analyze spec auth schemes ───────────────────────────────
        if spec_data and isinstance(spec_data, OpenApiSpec):
            finding_count += self._analyze_spec_auth(spec_data, target_url, results)

        # ── Test auth endpoints ─────────────────────────────────────
        finding_count += self._test_auth_endpoints(target_url, headers, results)

        # ── JWT analysis ────────────────────────────────────────────
        if auth_token:
            finding_count += self._analyze_jwt(auth_token, target_url, results)

        # ── Nuclei auth vulnerability scan ──────────────────────────
        finding_count += self._run_nuclei_auth_scan(target_url, headers, results)

        results["finding_count"] = finding_count

        # Honest success signal: this phase has two kinds of work — tool
        # invocation (httpx/nuclei, tracked via self.tools_used) and pure
        # analysis of already-available input (spec_data from Phase 1,
        # auth_token supplied by the operator), which needs no tool call at
        # all. "success" previously meant only "the method returned without
        # raising" — always True — even when no tool ran AND no input data
        # was available to analyze, i.e. the phase did nothing whatsoever.
        if self.tools_used or spec_data or auth_token:
            results["success"] = True
        else:
            self.logger.warning(
                "Authentication analysis did nothing — no spec_data or "
                "auth_token provided, and httpx/nuclei both unavailable "
                "or blocked by OPSEC policy"
            )
        return results

    # ── OpenAPI Spec Auth Analysis ──────────────────────────────────

    def _analyze_spec_auth(self, spec: OpenApiSpec, target_url: str,
                            results: dict) -> int:
        """Analyze authentication schemes from OpenAPI spec.

        Now leverages enhanced OpenApiSpec with:
        - OAuth2 flow details and scopes
        - Bearer format detection (JWT indicator)
        - OpenID Connect URL extraction
        - RequestBody-aware endpoint analysis
        """
        finding_count = 0

        for scheme in spec.auth_schemes:
            auth_info: dict[str, Any] = {
                "name": scheme.name,
                "type": scheme.auth_type,
                "scheme": scheme.scheme,
                "location": scheme.location,
                "param_name": scheme.param_name,
            }

            # Enrich with OAuth2 details
            if scheme.oauth_flows:
                auth_info["oauth_flows"] = scheme.oauth_flows
            if scheme.bearer_format:
                auth_info["bearer_format"] = scheme.bearer_format
            if scheme.openid_connect_url:
                auth_info["openid_connect_url"] = scheme.openid_connect_url

            results["auth_mechanisms"].append(auth_info)

            # ── Weak auth: API key in query string ──────────────────
            if scheme.is_api_key_in_query:
                self.add_finding(
                    finding_type="misconfiguration",
                    severity="medium",
                    confidence="confirmed",
                    target=target_url,
                    description=f"API key passed in query parameter: {scheme.param_name}",
                    evidence=(
                        f"Security scheme '{scheme.name}' uses query parameter '{scheme.param_name}'. "
                        f"Query parameters are logged in server access logs, browser history, "
                        f"and proxy logs, exposing the API key."
                    ),
                    recommendation=(
                        "Move API key to a custom HTTP header (e.g., X-API-Key) or "
                        "use Authorization header with Bearer scheme."
                    ),
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
                )
                finding_count += 1

            # ── Weak auth: HTTP Basic ───────────────────────────────
            if scheme.auth_type == "http" and scheme.scheme == "basic":
                self.add_finding(
                    finding_type="misconfiguration",
                    severity="medium",
                    confidence="confirmed",
                    target=target_url,
                    description="API uses HTTP Basic authentication",
                    evidence=(
                        f"Security scheme '{scheme.name}' uses Basic auth. "
                        f"Credentials are base64-encoded (not encrypted) in every request."
                    ),
                    recommendation=(
                        "Use token-based authentication (OAuth2, JWT) which avoids sending "
                        "credentials with every request. If Basic is required, enforce HTTPS."
                    ),
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
                )
                finding_count += 1

            # ── OAuth2 without PKCE ─────────────────────────────────
            if scheme.auth_type == "oauth2" and scheme.oauth_flows:
                for flow_name, flow_data in scheme.oauth_flows.items():
                    if flow_name in ("implicit",):
                        self.add_finding(
                            finding_type="misconfiguration",
                            severity="medium",
                            confidence="confirmed",
                            target=target_url,
                            description=f"OAuth2 implicit flow defined in scheme '{scheme.name}'",
                            evidence=(
                                f"OAuth2 implicit flow exposes access tokens in URL fragments. "
                                f"Authorization URL: {flow_data.get('authorizationUrl', 'N/A')}"
                            ),
                            recommendation=(
                                "Replace implicit flow with authorization code flow + PKCE. "
                                "Implicit flow is deprecated in OAuth 2.1."
                            ),
                            references=[
                                "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics",
                                "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                            ],
                        )
                        finding_count += 1

        # ── Sensitive endpoints without auth in spec ────────────────
        finding_count += self._check_unauthenticated_sensitive_endpoints(
            spec, target_url, results
        )

        self.notes.add(
            f"Auth analysis: {len(spec.auth_schemes)} schemes, "
            f"{len(spec.authenticated_endpoints)} auth endpoints, "
            f"{len(spec.unauthenticated_endpoints)} unauth endpoints, "
            f"{len(spec.endpoints_with_body)} with requestBody",
            "finding",
        )
        return finding_count

    def _check_unauthenticated_sensitive_endpoints(
        self, spec: OpenApiSpec, target_url: str, results: dict,
    ) -> int:
        """Check for potentially sensitive endpoints without auth in spec.

        NOTE: Endpoint naming alone is NOT proof of a vulnerability.
        We flag this as heuristic/low since URL patterns are not evidence
        of actual missing authentication – the spec may simply omit
        security definitions for legitimate reasons.
        """
        unauth_eps = spec.unauthenticated_endpoints
        if not (unauth_eps and spec.authenticated_endpoints):
            return 0

        # Only flag endpoints that both match sensitive keywords AND
        # accept user input (parameters or request body) — pure GET
        # with no params on /health or /status are likely fine.
        sensitive_keywords = (
            "admin", "user", "account", "internal", "delete",
            "update", "password", "credential", "config", "setting",
        )
        sensitive_unauth = [
            ep for ep in unauth_eps
            if any(kw in ep.path.lower() for kw in sensitive_keywords)
            and ep.accepts_input
        ]

        if not sensitive_unauth:
            return 0

        paths = ", ".join(
            f"{ep.method} {ep.path}" for ep in sensitive_unauth[:5]
        )
        self.add_finding(
            finding_type="misconfiguration",
            severity="medium",
            confidence="low",
            target=target_url,
            description=f"Potentially sensitive endpoints without authentication in spec: {paths}",
            evidence=(
                f"{len(sensitive_unauth)} endpoints with sensitive-looking paths "
                f"and input parameters lack auth in OpenAPI spec (requires manual verification)"
            ),
            recommendation=(
                "Verify these endpoints actually require authentication and add "
                "security requirements to the spec. Check if the API gateway "
                "enforces auth independently of the spec."
            ),
            references=["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
        )
        return 1

    # ── Auth Endpoint Testing ───────────────────────────────────────

    def _test_auth_endpoints(self, target_url: str, headers: list[str],
                              results: dict) -> int:
        """Test common authentication endpoints."""
        if not self.opsec.check("api_auth_testing"):
            return 0

        finding_count = 0
        auth_paths = [
            "/api/login", "/api/auth", "/api/token", "/api/oauth/token",
            "/auth/login", "/login", "/token", "/oauth/token",
            "/api/v1/auth", "/api/v1/login", "/api/v1/token",
        ]

        if self.httpx.is_available():
            self.tools_used.append("httpx")
            auth_urls = [f"{target_url}{p}" for p in auth_paths]
            urls_file = self.phase_output("auth_probe_urls.txt")
            urls_file.write_text("\n".join(auth_urls))

            run_result = self.httpx.probe_endpoints(str(urls_file), headers=headers)
            if run_result.success:
                json_path = self.httpx.get_json_path("endpoints")
                if json_path.is_file():
                    try:
                        for line in json_path.read_text().strip().splitlines():
                            data = json.loads(line)
                            status = data.get("status-code", 0)
                            url = data.get("url", "")
                            if status in (200, 401, 405):
                                results.setdefault("auth_endpoints", []).append({
                                    "url": url,
                                    "status": status,
                                })
                                if status == 200:
                                    self.add_finding(
                                        finding_type="exposure",
                                        severity="medium",
                                        confidence="medium",
                                        target=url,
                                        description=f"Auth endpoint accessible: {url}",
                                        evidence=f"HTTP {status} – endpoint responds to unauthenticated GET",
                                        recommendation=(
                                            "Ensure auth endpoints have rate limiting, "
                                            "brute-force protection, and account lockout policies."
                                        ),
                                    )
                                    finding_count += 1
                    except (json.JSONDecodeError, OSError):
                        pass

        return finding_count

    # ── JWT Deep Analysis ───────────────────────────────────────────

    def _analyze_jwt(self, token: str, target_url: str,
                      results: dict) -> int:
        """Deep JWT analysis with claims extraction and misconfiguration checks.

        Extracts:
        - Header: alg, typ, kid, jku, x5u, x5c, crit
        - Payload claims: sub, iss, exp, aud, iat, nbf, jti, scope/scp, roles
        - Signature structure validation

        Checks for:
        - alg=none (critical)
        - HS256/384/512 (info only – valid algorithms)
        - Missing exp claim (token never expires)
        - Expired tokens still in use
        - kid parameter injection vectors
        - jku/x5u header abuse potential
        - Weak/empty signature
        - Missing iss/aud claims (reduced validation)
        """
        finding_count = 0

        if not JWT_PATTERN.match(token):
            self.logger.debug("Provided token does not appear to be a JWT")
            return 0

        parts = token.split(".")
        if len(parts) != 3:
            self.logger.debug("Token does not have 3 JWT segments")
            return 0

        header = _safe_json_decode(parts[0])
        payload = _safe_json_decode(parts[1])
        signature_b64 = parts[2]

        if header is None:
            self.logger.warning("Failed to decode JWT header")
            return 0

        alg = str(header.get("alg", ""))
        typ = str(header.get("typ", ""))

        jwt_info: dict[str, Any] = {
            "algorithm": alg,
            "type": typ,
            "header_keys": list(header.keys()),
        }

        # ── Payload claims extraction ───────────────────────────────
        claims: dict[str, Any] = {}
        if payload:
            standard_claims = ("sub", "iss", "exp", "aud", "iat", "nbf", "jti")
            for claim in standard_claims:
                if claim in payload:
                    claims[claim] = payload[claim]

            # Extract scope/roles
            for scope_key in ("scope", "scp", "scopes"):
                if scope_key in payload:
                    claims["scope"] = payload[scope_key]
                    break
            for role_key in ("roles", "role", "groups", "permissions"):
                if role_key in payload:
                    claims["roles"] = payload[role_key]
                    break

            # Count custom claims
            custom_count = len(set(payload.keys()) - set(standard_claims) - {"scope", "scp", "scopes", "roles", "role", "groups", "permissions"})
            claims["_custom_claim_count"] = custom_count

            jwt_info["claims"] = claims
            results["jwt_claims"] = claims

        results["jwt_findings"].append(jwt_info)

        # ── Algorithm checks ────────────────────────────────────────

        # CRITICAL: alg=none
        if alg.lower() == "none":
            self.add_finding(
                finding_type="vulnerability",
                severity="critical",
                confidence="confirmed",
                target=target_url,
                description="JWT uses 'none' algorithm – tokens can be forged without a secret",
                evidence=f"JWT header: alg={alg}",
                recommendation=(
                    "Enforce a strong signing algorithm server-side (RS256, ES256). "
                    "Never accept 'none' algorithm in production. Validate the alg "
                    "header matches the expected algorithm."
                ),
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                    "https://cwe.mitre.org/data/definitions/327.html",
                ],
            )
            finding_count += 1

        elif alg.lower() in ("hs256", "hs384", "hs512"):
            # INFO only: HS256/HS384/HS512 are valid, standard algorithms
            self.add_finding(
                finding_type="information",
                severity="info",
                confidence="confirmed",
                target=target_url,
                description=f"JWT uses symmetric algorithm ({alg}) – valid configuration",
                evidence=f"JWT header: alg={alg}",
                recommendation=(
                    "Asymmetric algorithms (RS256, ES256) are preferred for "
                    "multi-party verification and microservice architectures. "
                    "If HS256 is used, ensure the shared secret is strong (≥256 bits) "
                    "and not derived from a dictionary word."
                ),
            )
            finding_count += 1

        # ── Signature structure ─────────────────────────────────────
        # Same evidence class as the alg=="none" check above: a direct,
        # deterministic structural check on the token the operator
        # supplied (not an inference), so confidence="confirmed" to match
        # rather than the previously inconsistent "high" for equally
        # certain evidence.
        if not signature_b64 or signature_b64 in ("", ".", "AA"):
            self.add_finding(
                finding_type="vulnerability",
                severity="high",
                confidence="confirmed",
                target=target_url,
                description="JWT has empty or trivial signature",
                evidence=f"Signature segment: '{signature_b64[:20]}' (alg: {alg})",
                recommendation=(
                    "Ensure the server validates JWT signatures and rejects "
                    "tokens with empty or malformed signatures."
                ),
                references=[
                    "https://cwe.mitre.org/data/definitions/345.html",
                ],
            )
            finding_count += 1

        # ── Header-based attack vectors ─────────────────────────────

        # kid parameter injection
        kid = header.get("kid")
        if kid is not None:
            jwt_info["kid"] = str(kid)
            self.add_finding(
                finding_type="information",
                severity="info",
                confidence="confirmed",
                target=target_url,
                description=f"JWT header contains 'kid' parameter: {str(kid)[:50]}",
                evidence=f"kid={str(kid)[:100]}",
                recommendation=(
                    "Test for kid injection: SQL injection in kid value, "
                    "path traversal (kid=../../dev/null with empty secret), "
                    "and directory traversal to attacker-controlled key."
                ),
                references=[
                    "https://portswigger.net/web-security/jwt",
                ],
            )
            finding_count += 1

        # jku/x5u header abuse
        for hdr_key in ("jku", "x5u"):
            hdr_val = header.get(hdr_key)
            if hdr_val:
                jwt_info[hdr_key] = str(hdr_val)
                self.add_finding(
                    finding_type="information",
                    severity="low",
                    confidence="confirmed",
                    target=target_url,
                    description=f"JWT header contains '{hdr_key}' pointing to: {str(hdr_val)[:100]}",
                    evidence=f"{hdr_key}={str(hdr_val)[:200]}",
                    recommendation=(
                        f"Test if the server fetches keys from the '{hdr_key}' URL. "
                        f"If so, try pointing it to an attacker-controlled server "
                        f"to supply a custom signing key (SSRF + key confusion)."
                    ),
                    references=[
                        "https://portswigger.net/web-security/jwt",
                    ],
                )
                finding_count += 1

        # ── Payload claim checks ────────────────────────────────────
        if payload:
            finding_count += self._check_jwt_claims(payload, claims, target_url, results)

        # ── Log sanitized token as loot ─────────────────────────────
        self.loot.add(
            loot_type="jwt_token",
            value=self.sanitize_credential(token),
            source="user_provided",
            module="api",
            metadata={
                "algorithm": alg,
                "claims": list(claims.keys()) if claims else [],
                "has_kid": "kid" in header,
            },
        )

        return finding_count

    def _check_jwt_claims(self, payload: dict, claims: dict,
                           target_url: str, results: dict) -> int:
        """Check JWT payload claims for misconfigurations."""
        finding_count = 0
        now_ts = int(time.time())

        # ── Missing exp claim (token never expires) ─────────────────
        if "exp" not in payload:
            self.add_finding(
                finding_type="misconfiguration",
                severity="medium",
                confidence="confirmed",
                target=target_url,
                description="JWT lacks 'exp' (expiration) claim – token never expires",
                evidence="Payload does not contain 'exp' claim",
                recommendation=(
                    "Add an expiration time to all JWTs. Short-lived tokens "
                    "(15-60 minutes) with refresh tokens are recommended."
                ),
                references=[
                    "https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4",
                ],
            )
            finding_count += 1
        else:
            # Check if token is expired
            exp_val = payload["exp"]
            if isinstance(exp_val, (int, float)) and exp_val < now_ts:
                self.add_finding(
                    finding_type="information",
                    severity="info",
                    confidence="confirmed",
                    target=target_url,
                    description="Provided JWT token is expired",
                    evidence=f"exp={exp_val} (expired {now_ts - int(exp_val)} seconds ago)",
                    recommendation=(
                        "Token is expired. If the server still accepts it, "
                        "this indicates the server does not validate expiration."
                    ),
                )
                finding_count += 1

            # Check for excessively long expiration
            if isinstance(exp_val, (int, float)):
                iat_val = payload.get("iat", now_ts)
                if isinstance(iat_val, (int, float)):
                    lifetime_hours = (exp_val - iat_val) / 3600
                    if lifetime_hours > 24:
                        self.add_finding(
                            finding_type="misconfiguration",
                            severity="low",
                            confidence="confirmed",
                            target=target_url,
                            description=f"JWT has long expiration: ~{lifetime_hours:.0f} hours",
                            evidence=f"iat={iat_val}, exp={exp_val}, lifetime={lifetime_hours:.1f}h",
                            recommendation=(
                                "Consider shorter token lifetimes (15-60 minutes) with "
                                "refresh tokens for better security posture."
                            ),
                        )
                        finding_count += 1

        # ── Missing iss claim ───────────────────────────────────────
        if "iss" not in payload:
            self.add_finding(
                finding_type="information",
                severity="info",
                confidence="confirmed",
                target=target_url,
                description="JWT lacks 'iss' (issuer) claim",
                evidence="Payload does not contain 'iss' claim",
                recommendation=(
                    "Include an 'iss' claim and validate it server-side to prevent "
                    "token confusion attacks in multi-service architectures."
                ),
            )
            finding_count += 1

        # ── Missing aud claim ───────────────────────────────────────
        if "aud" not in payload:
            self.add_finding(
                finding_type="information",
                severity="info",
                confidence="confirmed",
                target=target_url,
                description="JWT lacks 'aud' (audience) claim",
                evidence="Payload does not contain 'aud' claim",
                recommendation=(
                    "Include an 'aud' claim and validate it server-side to prevent "
                    "tokens issued for one API from being used on another."
                ),
            )
            finding_count += 1

        # ── Sensitive data in payload ───────────────────────────────
        sensitive_keys = ("password", "secret", "credit_card", "ssn", "card_number")
        exposed = [k for k in payload if k.lower() in sensitive_keys]
        if exposed:
            self.add_finding(
                finding_type="exposure",
                severity="high",
                confidence="confirmed",
                target=target_url,
                description=f"JWT payload contains potentially sensitive claims: {', '.join(exposed)}",
                evidence=f"Claims found: {', '.join(exposed)}",
                recommendation=(
                    "Never store sensitive data (passwords, secrets, PII) in JWT payloads. "
                    "JWT payloads are base64-encoded, not encrypted."
                ),
                references=[
                    "https://cwe.mitre.org/data/definitions/315.html",
                ],
            )
            finding_count += 1

        return finding_count

    # ── Nuclei Auth Scan ────────────────────────────────────────────

    def _run_nuclei_auth_scan(self, target_url: str, headers: list[str],
                               results: dict) -> int:
        """Run Nuclei with auth-related templates."""
        if not self.nuclei.is_available():
            self.logger.warning("Nuclei not available, skipping auth vuln scan")
            return 0

        if not self.opsec.check("nuclei_api_scan"):
            return 0

        self.tools_used.append("nuclei")
        finding_count = 0

        run_result = self.nuclei.api_scan(
            target_url, tags="jwt,oauth,token,api,auth",
        )

        if not run_result.success:
            self.logger.warning(f"Nuclei auth scan failed: {run_result.stderr[:200]}")
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
            finding_count += 1

            results["weaknesses"].append({
                "template": finding.template_id,
                "name": finding.name,
                "severity": finding.severity,
            })

        self.logger.info(f"Nuclei auth scan: {finding_count} findings")
        return finding_count
