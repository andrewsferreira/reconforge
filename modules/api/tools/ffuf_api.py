"""ReconForge API ffuf Tool Wrapper - API endpoint fuzzing.

Author: Andrews Ferreira

All commands are built as structured argument lists (list[str]) to
prevent shell injection and improve reliability.

Config-aware: when a :class:`ConfigLoader` is provided, timeouts and
mode arguments are read from ``tools.yaml``.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from core.runner import Runner, RunResult, validate_arg
from core.tool_config import ToolConfig

if TYPE_CHECKING:
    from core.config_loader import ConfigLoader


class FfufApiTool:
    """Wrapper for ffuf targeting API endpoints."""

    TOOL_NAME = "ffuf"
    TOOL_CONFIG_KEY = "ffuf_api"

    DEFAULT_API_WORDLISTS = [
        "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
        "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ]

    def __init__(self, runner: Runner, logger, output_dir: Path,
                 opsec_mode: str = "normal",
                 config: Optional["ConfigLoader"] = None):
        self.runner = runner
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.opsec_mode = opsec_mode
        self.tool_cfg = ToolConfig(config, self.TOOL_CONFIG_KEY)

    def is_available(self) -> bool:
        return self.runner.check_tool(self.TOOL_NAME)

    def _threads(self) -> int:
        return {"stealth": 5, "normal": 20, "aggressive": 50}.get(
            self.opsec_mode, 20
        )

    def _rate(self) -> int:
        return {"stealth": 10, "normal": 100, "aggressive": 0}.get(
            self.opsec_mode, 100
        )

    def resolve_wordlist(self, custom: str = "") -> str:
        """Find an API wordlist that exists on disk."""
        if custom and Path(custom).is_file():
            return custom
        for wl in self.DEFAULT_API_WORDLISTS:
            if Path(wl).is_file():
                return wl
        return ""

    def endpoint_scan(self, target_url: str, wordlist: str = "",
                      headers: Optional[List[str]] = None,
                      match_codes: str = "200,201,204,301,302,307,401,403,405,500",
                      timeout: int = 600) -> RunResult:
        """Discover API endpoints via directory fuzzing."""
        validate_arg(target_url, "target_url")
        wordlist = self.resolve_wordlist(wordlist)
        if not wordlist:
            self.logger.warning("No wordlist found for ffuf API scan")
            return RunResult(
                command="ffuf", returncode=-1, stdout="", stderr="No wordlist found",
                duration=0.0, success=False,
            )

        json_path = self.output_dir / "ffuf_api_endpoints.json"
        threads = self._threads()
        rate = self._rate()
        effective_timeout = self.tool_cfg.effective_timeout(self.opsec_mode, timeout)

        cmd: List[str] = [
            "ffuf", "-u", f"{target_url}/FUZZ", "-w", wordlist,
            "-t", str(threads), "-mc", match_codes,
            "-o", str(json_path), "-of", "json", "-noninteractive",
        ]
        if rate > 0:
            cmd += ["-rate", str(rate)]

        if headers:
            for h in headers:
                validate_arg(h, "header")
                cmd += ["-H", h]

        self.logger.info(f"Running ffuf API endpoint scan on {target_url} (threads={threads})")
        return self.runner.run(cmd, timeout=effective_timeout, output_file=json_path)

    def param_fuzz(self, target_url: str, wordlist: str = "",
                   method: str = "GET",
                   headers: Optional[List[str]] = None,
                   timeout: int = 600) -> RunResult:
        """Parameter fuzzing on a known endpoint."""
        validate_arg(target_url, "target_url")
        validate_arg(method, "method")

        wordlist = self.resolve_wordlist(wordlist)
        if not wordlist:
            return RunResult(
                command="ffuf", returncode=-1, stdout="", stderr="No wordlist",
                duration=0.0, success=False,
            )

        json_path = self.output_dir / "ffuf_api_params.json"
        threads = self._threads()
        rate = self._rate()
        effective_timeout = self.tool_cfg.effective_timeout(self.opsec_mode, timeout)

        cmd: List[str] = [
            "ffuf", "-u", target_url, "-w", wordlist,
            "-X", method, "-t", str(threads),
            "-o", str(json_path), "-of", "json",
            "-noninteractive", "-fs", "0",
        ]
        if rate > 0:
            cmd += ["-rate", str(rate)]

        if headers:
            for h in headers:
                validate_arg(h, "header")
                cmd += ["-H", h]

        self.logger.info(f"Running ffuf parameter fuzzing on {target_url}")
        return self.runner.run(cmd, timeout=effective_timeout, output_file=json_path)

    def get_json_path(self, scan_type: str = "api_endpoints") -> Path:
        return self.output_dir / f"ffuf_{scan_type}.json"
