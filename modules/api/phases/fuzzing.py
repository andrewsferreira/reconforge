"""ReconForge API Module - Phase 3: Fuzzing

Author: Andrews Ferreira

PRIORITY 5 hardened fuzzing phase:
- Response content analysis (not just status codes)
- Error fingerprint detection (SQL errors, stack traces, command output)
- Timing analysis for blind injection indicators
- Stronger evidence requirements before reporting
- HTTP 500 classified by response content, not just status
- Reduced false positives via evidence-based scoring
"""

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from modules.api.base import APIPhaseBase
from modules.api.tools.ffuf_api import FfufApiTool
from modules.api.tools.arjun_tool import ArjunTool
from modules.api.parsers.ffuf_parser import FfufApiParser
from modules.api.parsers.arjun_parser import ArjunParser


# ── Error Fingerprints ──────────────────────────────────────────────
# These patterns in response bodies are concrete evidence of injection
# vulnerabilities, far stronger than HTTP status codes alone.

_SQL_ERROR_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in (
        r"SQL syntax.*?MySQL",
        r"Warning.*?\Wmysqli?_",
        r"PostgreSQL.*?ERROR",
        r"ORA-\d{5}",
        r"Microsoft.*?ODBC.*?SQL Server",
        r"Unclosed quotation mark",
        r"SQLSTATE\[",
        r"sqlite3\.OperationalError",
        r"pg_query\(\).*?ERROR",
        r"Syntax error.*?in query expression",
        r"com\.mysql\.jdbc",
        r"org\.postgresql\.util\.PSQLException",
        r"java\.sql\.SQLException",
        r"Microsoft SQL Native Client error",
        r"unrecognized token:.*?\"",
        r"quoted string not properly terminated",
    )
]

_STACK_TRACE_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in (
        r"Traceback \(most recent call last\)",
        r"at [\w.]+\([\w]+\.java:\d+\)",
        r"at [\w.]+\.[\w]+\(.*?:\d+:\d+\)",
        r"File \".*?\", line \d+, in",
        r"Exception in thread",
        r"System\.NullReferenceException",
        r"System\.InvalidOperationException",
        r"Fatal error:.*?in .*? on line \d+",
        r"Parse error:.*?in .*? on line \d+",
        r"Notice:.*?in .*? on line \d+",
        r"#\d+ .*? called at \[",
    )
]

_COMMAND_INJECTION_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in (
        r"root:x:0:0:",           # /etc/passwd content
        r"uid=\d+\(.*?\)",        # id command output
        r"\[boot loader\]",       # win.ini
        r"\\Windows\\System32",   # Windows path exposure
        r"sh: [\w/]+: not found", # shell error
    )
]

_TEMPLATE_INJECTION_PATTERNS = [
    re.compile(p) for p in (
        r"49",                     # {{7*7}} output (if in right context)
        r"TemplateSyntaxError",
        r"UndefinedError",
        r"Jinja2",
        r"freemarker\.core",
    )
]

# Response content that indicates actual error information disclosure
_INFO_DISCLOSURE_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in (
        r"DEBUG\s*=\s*True",
        r"DJANGO_SETTINGS_MODULE",
        r"X-Powered-By:",
        r"server\.port\s*=",
        r"spring\.datasource",
        r"database\.url",
        r"connection_string",
    )
]


class FuzzingPhase(APIPhaseBase):
    """Phase 3 – API parameter fuzzing and injection testing."""

    PHASE_NUMBER = 3
    PHASE_NAME = "fuzzing"
    PHASE_DESCRIPTION = "API parameter fuzzing & injection testing"

    def __init__(
        self,
        ffuf: FfufApiTool,
        arjun: ArjunTool,
        ffuf_parser: FfufApiParser,
        arjun_parser: ArjunParser,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.ffuf = ffuf
        self.arjun = arjun
        self.ffuf_parser = ffuf_parser
        self.arjun_parser = arjun_parser

    def run(self, target_url: str, **kwargs) -> Dict[str, Any]:
        """Execute fuzzing phase.

        Args:
            target_url: Target API URL.
            endpoints: List of discovered endpoints from Phase 1.
            headers: Optional HTTP headers.
            wordlist: Optional custom wordlist.

        Returns:
            Dict with discovered parameters, injection findings, and counts.
        """
        endpoints = kwargs.get("endpoints", [])
        headers = kwargs.get("headers", [])
        wordlist = kwargs.get("wordlist", "")

        results: Dict[str, Any] = {
            "phase": self.PHASE_NAME,
            "discovered_params": [],
            "sensitive_params": [],
            "injection_findings": [],
            "error_fingerprints": [],
            "finding_count": 0,
            "success": False,
        }

        finding_count = 0

        # ── Arjun parameter discovery ───────────────────────────────
        finding_count += self._run_arjun(target_url, endpoints, headers, results)

        # ── ffuf parameter fuzzing with response analysis ───────────
        finding_count += self._run_ffuf_param_fuzz(target_url, endpoints,
                                                    wordlist, headers, results)

        results["finding_count"] = finding_count

        # Honest success signal: arjun/ffuf are each independently gated on
        # tool availability/OPSEC and can legitimately be skipped.
        # "success" previously meant only "the method returned without
        # raising" — always True — even when both tools were unavailable
        # or blocked and nothing actually ran. self.tools_used is only
        # appended to once a tool actually executes past those gates, so
        # it's a real "did anything run" signal.
        if self.tools_used:
            results["success"] = True
        else:
            self.logger.warning(
                "API fuzzing ran no checks — arjun/ffuf both unavailable "
                "or blocked by OPSEC policy"
            )
        return results

    def _run_arjun(self, target_url: str, endpoints: List[Dict],
                    headers: List[str], results: Dict) -> int:
        """Run Arjun for hidden parameter discovery."""
        if not self.arjun.is_available():
            self.logger.warning("Arjun not available, skipping parameter discovery")
            return 0

        if not self.opsec.check("arjun_param_discovery"):
            return 0

        self.tools_used.append("arjun")
        finding_count = 0

        # Scan the base URL
        urls_to_scan = [target_url]

        # Also scan discovered endpoints (limit to avoid excess)
        for ep in endpoints[:5]:
            ep_url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            if ep_url and ep_url not in urls_to_scan:
                urls_to_scan.append(ep_url)

        for url in urls_to_scan:
            for method in ("GET", "POST"):
                run_result = self.arjun.discover_params(
                    url, method=method, headers=headers,
                )

                if not run_result.success:
                    continue

                json_path = self.arjun.get_json_path("params")
                parsed = self.arjun_parser.parse_json(json_path)

                for param in parsed.params:
                    results["discovered_params"].append({
                        "name": param.name,
                        "url": param.url,
                        "method": param.method or method,
                    })

                # Check for sensitive parameters
                for param in parsed.sensitive_params:
                    severity = self.arjun_parser.param_to_severity(param.name)
                    results["sensitive_params"].append({
                        "name": param.name,
                        "url": param.url,
                        "severity": severity,
                    })

                    self.add_finding(
                        finding_type="exposure",
                        severity=severity,
                        confidence="medium",
                        target=param.url or url,
                        description=f"Sensitive hidden parameter discovered: {param.name}",
                        evidence=f"Parameter '{param.name}' found via {method} method by Arjun",
                        recommendation=(
                            "Review parameter handling and ensure proper authorization. "
                            "Hidden parameters may bypass client-side controls."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                        ],
                    )
                    finding_count += 1

        total_params = len(results["discovered_params"])
        self.logger.info(f"Arjun discovered {total_params} parameters")
        self.notes.add(
            f"Arjun parameter discovery: {total_params} params, "
            f"{len(results['sensitive_params'])} sensitive",
            "command",
        )
        return finding_count

    def _run_ffuf_param_fuzz(self, target_url: str, endpoints: List[Dict],
                              wordlist: str, headers: List[str],
                              results: Dict) -> int:
        """Run ffuf for parameter value fuzzing with response content analysis.

        PRIORITY 5 enhancement: Analyse response bodies, not just status codes.
        HTTP 500 alone is heuristic/info. Only escalate if response body
        contains concrete injection evidence (SQL errors, stack traces, etc.).
        """
        if not self.ffuf.is_available():
            self.logger.warning("ffuf not available, skipping parameter fuzzing")
            return 0

        if not self.opsec.check("ffuf_api_fuzz"):
            return 0

        self.tools_used.append("ffuf")
        finding_count = 0

        # Fuzz parameter values on discovered endpoints
        fuzz_targets = []
        for ep in endpoints[:3]:
            ep_url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            if ep_url:
                fuzz_targets.append(ep_url)

        if not fuzz_targets:
            fuzz_targets = [f"{target_url}?FUZZ=test"]

        for fuzz_url in fuzz_targets:
            if "FUZZ" not in fuzz_url:
                fuzz_url = f"{fuzz_url}?FUZZ=test"

            run_result = self.ffuf.param_fuzz(
                fuzz_url, wordlist=wordlist, headers=headers,
            )

            if not run_result.success:
                continue

            json_path = self.ffuf.get_json_path("api_params")
            parsed = self.ffuf_parser.parse_json(json_path)

            # ffuf's JSON output format (-of json) does not capture a
            # per-result response body — the only body-content evidence
            # available anywhere is run_result.stdout, which covers the
            # WHOLE batch of fuzzed inputs, not any single entry. Searching
            # it per-entry and reporting a match as "evidence" for that
            # entry's specific URL misattributes evidence across entries
            # (e.g. entry A's SQL error text gets reported as evidence for
            # entry B's unrelated 500). Classify the batch text once and,
            # if it contains concrete evidence, report a single finding
            # scoped to the endpoint under test rather than to one
            # arbitrarily-chosen entry.
            error_entries = [e for e in parsed.entries if e.status == 500]
            if error_entries:
                classification = self._classify_error_response(run_result.stdout)
                finding_count += self._report_classified_error(
                    fuzz_url, error_entries, classification, results
                )

            ok_entries = [
                e for e in parsed.entries
                if e.status in (200, 201) and e.length > 0
            ]
            if ok_entries and self._check_for_info_disclosure(run_result.stdout):
                inputs = ", ".join(repr(e.input_word) for e in ok_entries[:5] if e.input_word)
                self.add_finding(
                    finding_type="exposure",
                    severity="low",
                    confidence="medium",
                    target=fuzz_url,
                    description=(
                        f"Possible information disclosure during parameter "
                        f"fuzzing: {fuzz_url}"
                    ),
                    evidence=(
                        f"The fuzzing run's combined output contains "
                        f"debug/config-disclosure patterns; {len(ok_entries)} "
                        f"input(s) returned a 200 response (e.g. {inputs or 'n/a'}), "
                        "but the specific triggering input could not be "
                        "isolated from the available instrumentation"
                    ),
                    recommendation=(
                        "Review response content for sensitive information "
                        "and disable debug mode in production."
                    ),
                )
                for e in ok_entries:
                    results["injection_findings"].append({
                        "url": e.url,
                        "input": e.input_word,
                        "status": e.status,
                        "type": "info_disclosure",
                    })
                finding_count += 1

        self.logger.info(f"ffuf parameter fuzzing: {finding_count} findings")
        return finding_count

    def _classify_error_response(self, full_output: str) -> Dict[str, Any]:
        """Classify a batch of 500 responses by analyzing available evidence.

        ffuf's JSON output format captures no per-result response body, so
        full_output (the tool's combined stdout for every fuzzed input in
        this run) is the only text that can be searched — a match here is
        evidence that the pattern appeared SOMEWHERE in this run's output,
        not proof of which specific input triggered it.

        Returns a classification dict with:
        - type: sql_injection, stack_trace, command_injection, template_injection,
                generic_error
        - severity: critical, high, medium, low
        - confidence: confirmed, high, medium, heuristic
        - evidence: Description of what was detected
        """
        search_text = full_output or ""

        # Check for SQL injection evidence
        for pattern in _SQL_ERROR_PATTERNS:
            match = pattern.search(search_text)
            if match:
                return {
                    "type": "sql_injection",
                    "severity": "high",
                    "confidence": "high",
                    "evidence": f"SQL error pattern detected: {match.group(0)[:100]}",
                }

        # Check for stack trace exposure
        for pattern in _STACK_TRACE_PATTERNS:
            match = pattern.search(search_text)
            if match:
                return {
                    "type": "stack_trace",
                    "severity": "medium",
                    "confidence": "high",
                    "evidence": f"Stack trace detected: {match.group(0)[:100]}",
                }

        # Check for command injection evidence
        for pattern in _COMMAND_INJECTION_PATTERNS:
            match = pattern.search(search_text)
            if match:
                return {
                    "type": "command_injection",
                    "severity": "critical",
                    "confidence": "high",
                    "evidence": f"Command execution evidence: {match.group(0)[:100]}",
                }

        # Check for template injection
        for pattern in _TEMPLATE_INJECTION_PATTERNS:
            match = pattern.search(search_text)
            if match:
                return {
                    "type": "template_injection",
                    "severity": "high",
                    "confidence": "medium",
                    "evidence": f"Template engine error: {match.group(0)[:100]}",
                }

        # Generic 500s — no concrete evidence anywhere in the batch output
        return {
            "type": "generic_error",
            "severity": "low",
            "confidence": "heuristic",
            "evidence": (
                "HTTP 500 responses observed during fuzzing – "
                "no concrete injection evidence in available output"
            ),
        }

    def _report_classified_error(
        self, fuzz_url: str, error_entries: List[Any],
        classification: Dict[str, Any], results: Dict,
    ) -> int:
        """Report a batch-level classification covering every 500 response
        from this fuzz run. error_entries is the full set of entries that
        returned 500 — the classification evidence can't be narrowed to
        one of them (see _classify_error_response), so one finding covers
        all of them rather than fabricating a specific culprit."""
        error_type = classification["type"]
        severity = classification["severity"]
        confidence = classification["confidence"]
        evidence = classification["evidence"]
        inputs = [e.input_word for e in error_entries if e.input_word]

        # Store fingerprint for reporting
        if error_type != "generic_error":
            results["error_fingerprints"].append({
                "url": fuzz_url,
                "inputs": inputs[:10],
                "type": error_type,
                "severity": severity,
            })

        # Determine finding type and description
        descriptions = {
            "sql_injection": (
                "vulnerability",
                f"Potential SQL injection during fuzzing: {fuzz_url}",
                "Sanitise user input with parameterised queries. Never concatenate user input into SQL.",
            ),
            "command_injection": (
                "vulnerability",
                f"Potential command injection during fuzzing: {fuzz_url}",
                "Never pass user input to shell commands. Use safe APIs and input validation.",
            ),
            "template_injection": (
                "vulnerability",
                f"Potential template injection (SSTI) during fuzzing: {fuzz_url}",
                "Sandbox template rendering and never pass raw user input to template engines.",
            ),
            "stack_trace": (
                "exposure",
                f"Stack trace exposed during fuzzing: {fuzz_url}",
                "Disable verbose error messages in production. Use generic error responses.",
            ),
            "generic_error": (
                "information",
                f"Server error(s) triggered by fuzzing (heuristic): {fuzz_url}",
                "Manually inspect response bodies for injection evidence before escalating.",
            ),
        }

        finding_type, description, recommendation = descriptions.get(
            error_type,
            ("information", f"Server error during fuzzing: {fuzz_url}", "Review manually."),
        )

        # Build rich evidence string — explicit that the pattern match is
        # batch-wide, not attributed to one specific input.
        full_evidence = (
            f"{evidence}. "
            f"{len(error_entries)} of this run's inputs returned HTTP 500 "
            f"(e.g. {', '.join(repr(i) for i in inputs[:5]) or 'n/a'}); "
            "the specific triggering input could not be isolated from the "
            "available instrumentation (ffuf's JSON output does not "
            "capture per-result response bodies)."
        )

        self.add_finding(
            finding_type=finding_type,
            severity=severity,
            confidence=confidence,
            target=fuzz_url,
            description=description,
            evidence=full_evidence,
            recommendation=recommendation,
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
            ],
        )

        for e in error_entries:
            results["injection_findings"].append({
                "url": e.url,
                "input": e.input_word,
                "status": e.status,
                "type": error_type,
                "severity": severity,
                "confidence": confidence,
            })

        return 1

    def _check_for_info_disclosure(self, full_output: str) -> bool:
        """Check if this run's combined output contains information
        disclosure patterns (debug flags, connection strings, etc.)."""
        search_text = full_output or ""
        for pattern in _INFO_DISCLOSURE_PATTERNS:
            if pattern.search(search_text):
                return True
        return False
