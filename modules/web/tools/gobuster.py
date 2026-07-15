"""ReconForge Gobuster Tool Wrapper - Directory and DNS brute-forcing.

Author: Andrews Ferreira

All commands are built as structured argument lists (list[str]) to
prevent shell injection and improve reliability.

Config-aware: when a :class:`ConfigLoader` is provided, timeouts and
mode arguments are read from ``tools.yaml``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from core.runner import RC_PRECONDITION_FAILED, Runner, RunResult
from core.tool_config import ToolConfig

if TYPE_CHECKING:
    from core.config_loader import ConfigLoader


class GobusterTool:
    """Wrapper for gobuster directory brute-forcing."""

    TOOL_NAME = "gobuster"

    DEFAULT_WORDLISTS = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    ]

    def __init__(self, runner: Runner, logger, output_dir: Path,
                 opsec_mode: str = "normal",
                 config: ConfigLoader | None = None):
        self.runner = runner
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.opsec_mode = opsec_mode
        self.tool_cfg = ToolConfig(config, self.TOOL_NAME)

    def is_available(self) -> bool:
        return self.runner.check_tool(self.TOOL_NAME)

    def _threads(self) -> int:
        return {"stealth": 5, "normal": 20, "aggressive": 50}.get(
            self.opsec_mode, 20
        )

    def resolve_wordlist(self, custom: str = "") -> str:
        if custom and Path(custom).is_file():
            return custom
        for wl in self.DEFAULT_WORDLISTS:
            if Path(wl).is_file():
                return wl
        return ""

    def dir_scan(self, target_url: str, wordlist: str = "",
                 timeout: int = 600) -> RunResult:
        """Directory brute-force scan."""
        wordlist = self.resolve_wordlist(wordlist)
        if not wordlist:
            self.logger.warning("No wordlist found for gobuster")
            return RunResult(
                command="gobuster", returncode=RC_PRECONDITION_FAILED, stdout="",
                stderr="No wordlist found", duration=0.0, success=False,
            )

        out_path = self.output_dir / "gobuster_dirs.txt"
        threads = self._threads()
        effective_timeout = self.tool_cfg.mode_timeout("dir", timeout)

        cmd: list[str] = [
            "gobuster", "dir", "-u", target_url, "-w", wordlist,
            "-t", str(threads), "-q", "-o", str(out_path), "--no-color",
        ]

        self.logger.info(f"Running gobuster dir scan on {target_url} (threads={threads})")
        # gobuster's own -o already writes out_path (a tee of the same
        # result lines gobuster prints to stdout in -q mode, so this is
        # likely just redundant rather than corrupting like ffuf/whatweb —
        # still removed for consistency and defense-in-depth).
        return self.runner.run(cmd, timeout=effective_timeout)

    def dns_scan(self, domain: str, wordlist: str = "",
                 timeout: int = 600) -> RunResult:
        """DNS subdomain brute-force scan."""
        wordlist = self.resolve_wordlist(wordlist)
        if not wordlist:
            return RunResult(
                command="gobuster", returncode=RC_PRECONDITION_FAILED, stdout="",
                stderr="No wordlist found", duration=0.0, success=False,
            )

        out_path = self.output_dir / "gobuster_dns.txt"
        threads = self._threads()
        effective_timeout = self.tool_cfg.mode_timeout("vhost", timeout)

        cmd: list[str] = [
            "gobuster", "dns", "-d", domain, "-w", wordlist,
            "-t", str(threads), "-q", "-o", str(out_path), "--no-color",
        ]

        self.logger.info(f"Running gobuster DNS scan on {domain}")
        return self.runner.run(cmd, timeout=effective_timeout)

    def get_output_path(self, scan_type: str = "dirs") -> Path:
        return self.output_dir / f"gobuster_{scan_type}.txt"
