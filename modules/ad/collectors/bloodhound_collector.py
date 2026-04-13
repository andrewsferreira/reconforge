"""ReconForge AD Collector — Bloodhound graph data gathering.

Author: Andrews Ferreira

Collects AD graph data via bloodhound-python or netexec fallback,
and parses resulting JSON files.
"""

import zipfile
from pathlib import Path
from typing import Any, Dict, List

from modules.ad.collectors.base import CollectorBase, CollectorResult
from modules.ad.tools.bloodhound import BloodhoundTool
from modules.ad.tools.netexec import NetexecTool
from modules.ad.parsers.bloodhound_parser import (
    BloodhoundParser, BloodhoundUser, BloodhoundComputer, BloodhoundGroup,
)
from modules.ad.parsers.netexec_parser import NetexecParser


class BloodhoundCollector(CollectorBase):
    """Pure Bloodhound data collection and JSON parsing."""

    COLLECTOR_NAME = "bloodhound"

    def __init__(
        self,
        bloodhound: BloodhoundTool,
        netexec: NetexecTool,
        bloodhound_parser: BloodhoundParser,
        netexec_parser: NetexecParser,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.bloodhound = bloodhound
        self.netexec = netexec
        self.bh_parser = bloodhound_parser
        self.nxc_parser = netexec_parser

    def collect(
        self,
        target: str,
        domain: str = "",
        base_dn: str = "",
        username: str = "",
        password: str = "",
        dc_ip: str = "",
        **kwargs,
    ) -> CollectorResult:
        """Run collection and parse results."""
        result = CollectorResult(source=self.COLLECTOR_NAME)

        if not username or not password:
            result.errors.append("Credentials required for Bloodhound")
            return result

        # Try bloodhound-python first, then netexec
        method = self._run_bloodhound(
            domain, username, password, dc_ip or target, target
        )
        if not method:
            method = self._run_netexec_fallback(
                target, domain, username, password
            )
        if not method:
            result.errors.append("No collector tool available")
            return result

        result.data["collection_method"] = method

        # Parse JSON files
        parsed = self._parse_json_files()
        result.data.update(parsed)
        result.success = True
        return result

    # ── Internal ───────────────────────────────────────────────────

    def _run_bloodhound(
        self, domain: str, username: str, password: str,
        dc_ip: str, target: str,
    ) -> str:
        """Return collection method name or empty string on failure."""
        if not self.bloodhound.is_available():
            return ""
        if not self.opsec.check("bloodhound_collection"):
            return ""

        run = self.bloodhound.collect_all(
            domain=domain, username=username, password=password,
            dc_ip=dc_ip, nameserver=dc_ip,
        )
        return "bloodhound-python" if run.success else ""

    def _run_netexec_fallback(
        self, target: str, domain: str,
        username: str, password: str,
    ) -> str:
        if not self.netexec.is_available():
            return ""
        if not self.opsec.check("netexec_bloodhound"):
            return ""

        run = self.netexec.bloodhound_ingest(
            target=target, username=username,
            password=password, domain=domain,
        )
        return "netexec" if run.success else ""

    def _parse_json_files(self) -> Dict[str, Any]:
        """Parse bloodhound JSON output files."""
        bh_dir = self.output_dir / "bloodhound"
        if not bh_dir.exists():
            bh_dir = self.output_dir

        json_files = list(bh_dir.glob("*.json"))
        if not json_files:
            for zf in bh_dir.glob("*.zip"):
                try:
                    with zipfile.ZipFile(zf, "r") as z:
                        z.extractall(bh_dir)
                except zipfile.BadZipFile:
                    pass
            json_files = list(bh_dir.glob("*.json"))

        users: List[BloodhoundUser] = []
        groups: List[BloodhoundGroup] = []
        computers: List[BloodhoundComputer] = []
        sessions_count = 0
        domains_count = 0

        for jf in json_files:
            fname = jf.name.lower()
            try:
                data = jf.read_text(encoding="utf-8")
            except OSError:
                continue

            if "user" in fname:
                users.extend(self.bh_parser.parse_users_json(data))
            elif "group" in fname:
                groups.extend(self.bh_parser.parse_groups_json(data))
            elif "computer" in fname:
                computers.extend(self.bh_parser.parse_computers_json(data))
            elif "session" in fname:
                sessions_count += len(self.bh_parser.parse_sessions_json(data))
            elif "domain" in fname:
                domains_count += len(self.bh_parser.parse_domains_json(data))

        return {
            "users": users,
            "groups": groups,
            "computers": computers,
            "users_collected": len(users),
            "groups_collected": len(groups),
            "computers_collected": len(computers),
            "sessions_collected": sessions_count,
            "domains_collected": domains_count,
        }
