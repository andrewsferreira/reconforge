"""ReconForge - Phase 2: Content Enumeration

Author: Andrews Ferreira

Directory, file, and endpoint discovery using ffuf and gobuster.
Identifies hidden paths, backup files, admin panels, and other
interesting content on the target web application.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from modules.web.base import WebPhaseBase
from modules.web.tools.ffuf import FfufTool
from modules.web.tools.gobuster import GobusterTool
from modules.web.parsers.ffuf_parser import FfufParser
from modules.web.parsers.gobuster_parser import GobusterParser


class ContentEnumerationPhase(WebPhaseBase):
    """Phase 2 – Discover hidden directories, files, and endpoints."""

    PHASE_NUMBER = 2
    PHASE_NAME = "content_enumeration"
    PHASE_DESCRIPTION = "Content enumeration & directory discovery"

    # Status codes considered interesting
    INTERESTING_CODES = {200, 204, 301, 302, 307, 401, 403, 405, 500}

    def __init__(
        self,
        ffuf: FfufTool,
        gobuster: GobusterTool,
        ffuf_parser: FfufParser,
        gobuster_parser: GobusterParser,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.ffuf = ffuf
        self.gobuster = gobuster
        self.ffuf_parser = ffuf_parser
        self.gobuster_parser = gobuster_parser

    def run(self, target_url: str, **kwargs) -> Dict[str, Any]:
        """Execute content enumeration phase.

        Args:
            target_url: Target URL to scan.
            **kwargs: Optional ``waf_detected`` (bool) to tune rate limiting.

        Returns:
            Dict with discovered paths and finding count.
        """
        waf_detected = kwargs.get("waf_detected", False)

        results: Dict[str, Any] = {
            "phase": self.PHASE_NAME,
            "paths": [],
            "finding_count": 0,
            "success": False,
        }

        finding_count = 0

        # Prefer ffuf, fall back to gobuster
        finding_count += self._run_ffuf(target_url, results, waf_detected)
        finding_count += self._run_gobuster(target_url, results)

        if finding_count == 0:
            self.add_finding(
                finding_type="information",
                severity="info",
                confidence="low",
                target=target_url,
                description="Content enumeration completed – no notable paths discovered",
            )
            finding_count = 1

        results["finding_count"] = finding_count

        # Honest success signal: ffuf/gobuster are each independently gated
        # on tool availability/OPSEC/wordlist resolution and can legitimately
        # be skipped. "success" previously meant only "the method returned
        # without raising" — always True — even when both tools were
        # unavailable/blocked/missing a wordlist and nothing actually ran
        # (the "no notable paths discovered" filler finding above masked
        # this, since it always fires when finding_count==0). self.tools_used
        # is only appended to once a tool actually executes past those
        # gates, so it's a real "did anything run" signal.
        if self.tools_used:
            results["success"] = True
        else:
            self.logger.warning(
                "Content enumeration ran no checks — ffuf/gobuster both "
                "unavailable, blocked by OPSEC policy, or missing a wordlist"
            )

        # Save parsed results
        parsed_file = self.phase_output("content_enum_results.json")
        parsed_file.write_text(json.dumps(results, indent=2, default=str))

        return results

    # ── ffuf ───────────────────────────────────────────────────────

    def _run_ffuf(self, target_url: str, results: Dict,
                  waf_detected: bool) -> int:
        """Run ffuf directory discovery.

        Returns:
            Number of findings generated.
        """
        count = 0

        if not self.ffuf.is_available():
            self.logger.warning("ffuf not installed – skipping")
            self.notes.add("ffuf not found – skipped", "general")
            return count

        if not self.opsec.check("ffuf_dir_scan"):
            return count

        wordlist = self.resolve_wordlist("ffuf", "common")
        if not wordlist:
            self.logger.warning("No wordlist found for ffuf – skipping")
            return count

        self.workflow.add_step(
            phase=self.PHASE_NAME,
            hypothesis=f"Target has hidden directories and files",
            command=f"ffuf -u {target_url}/FUZZ -w <wordlist>",
            justification="Directory brute-forcing to discover hidden content",
            alternatives=["gobuster dir", "dirsearch", "feroxbuster"],
        )

        run_result = self.ffuf.dir_scan(target_url, wordlist=wordlist)
        self.tools_used.append("ffuf")

        if not run_result.success:
            self.logger.warning(f"ffuf failed: {run_result.stderr[:200]}")
            self.workflow.record_result(f"Failed: {run_result.stderr[:100]}")
            return count

        # Parse results
        ffuf_result = self.ffuf_parser.parse_json(self.ffuf.get_json_path("dirs"))

        for entry in ffuf_result.entries:
            path_info = {
                "url": entry.url,
                "status": entry.status,
                "size": entry.length,
                "words": entry.words,
                "source": "ffuf",
            }
            results["paths"].append(path_info)

            severity = self.ffuf_parser.status_to_severity(entry.status)
            finding_type = "exposure" if entry.status in (401, 403, 500) else "information"

            self.add_finding(
                finding_type=finding_type,
                severity=severity,
                confidence="high" if entry.status in (200, 301, 302) else "medium",
                target=entry.url or target_url,
                description=(
                    f"Discovered path: {entry.url} "
                    f"[Status: {entry.status}, Size: {entry.length}, "
                    f"Words: {entry.words}]"
                ),
                evidence=(
                    f"HTTP {entry.status} – {entry.url} "
                    f"(size={entry.length}, words={entry.words})"
                ),
                recommendation=self.ffuf_parser.status_recommendation(entry.status),
            )
            count += 1

            # Suggest deeper inspection for auth-gated paths
            if entry.status == 401:
                self.workflow.suggest_next(
                    command=f"Credential testing on {entry.url}",
                    justification="401 response – authentication required",
                    priority="medium",
                )
            elif entry.status == 403:
                self.workflow.suggest_next(
                    command=f"403 bypass attempts on {entry.url}",
                    justification="403 Forbidden – may hide sensitive content",
                    priority="low",
                )

        self.workflow.record_result(f"ffuf: {len(ffuf_result.entries)} paths discovered")
        self.notes.add_command_note(
            f"ffuf dir scan on {target_url}",
            f"{len(ffuf_result.entries)} paths found",
        )

        return count

    # ── gobuster ───────────────────────────────────────────────────

    def _run_gobuster(self, target_url: str, results: Dict) -> int:
        """Run gobuster directory discovery.

        Returns:
            Number of findings generated.
        """
        count = 0

        if not self.gobuster.is_available():
            self.logger.warning("gobuster not installed – skipping")
            self.notes.add("gobuster not found – skipped", "general")
            return count

        if not self.opsec.check("gobuster_dir_scan"):
            return count

        wordlist = self.resolve_wordlist("gobuster", "common")
        if not wordlist:
            self.logger.warning("No wordlist found for gobuster – skipping")
            return count

        # Skip if ffuf already found many results
        existing_urls = {p["url"] for p in results.get("paths", [])}
        if len(existing_urls) > 50:
            self.logger.info("ffuf found sufficient paths – skipping gobuster")
            self.notes.add("Skipped gobuster – ffuf already found >50 paths", "general")
            return count

        self.workflow.add_step(
            phase=self.PHASE_NAME,
            hypothesis=f"gobuster may discover paths missed by ffuf",
            command=f"gobuster dir -u {target_url} -w <wordlist>",
            justification="Secondary content discovery tool for coverage",
        )

        run_result = self.gobuster.dir_scan(target_url, wordlist=wordlist)
        self.tools_used.append("gobuster")

        if not run_result.success:
            self.logger.warning(f"gobuster failed: {run_result.stderr[:200]}")
            self.workflow.record_result(f"Failed: {run_result.stderr[:100]}")
            return count

        # Parse results
        gb_result = self.gobuster_parser.parse_dir(
            self.gobuster.get_output_path("dirs"), base_url=target_url
        )

        for entry in gb_result.entries:
            # Skip duplicates already found by ffuf
            if entry.full_url in existing_urls:
                continue

            path_info = {
                "url": entry.full_url,
                "status": entry.status,
                "size": entry.size,
                "source": "gobuster",
            }
            results["paths"].append(path_info)

            severity = self.ffuf_parser.status_to_severity(entry.status)
            finding_type = "exposure" if entry.status in (401, 403, 500) else "information"

            self.add_finding(
                finding_type=finding_type,
                severity=severity,
                confidence="high" if entry.status in (200, 301, 302) else "medium",
                target=entry.full_url or target_url,
                description=(
                    f"Discovered path: {entry.full_url} "
                    f"[Status: {entry.status}, Size: {entry.size}]"
                ),
                evidence=f"HTTP {entry.status} – {entry.full_url} (size={entry.size})",
                recommendation=self.ffuf_parser.status_recommendation(entry.status),
            )
            count += 1

        self.workflow.record_result(f"gobuster: {len(gb_result.entries)} paths discovered")
        self.notes.add_command_note(
            f"gobuster dir scan on {target_url}",
            f"{len(gb_result.entries)} paths found ({count} new)",
        )

        return count
