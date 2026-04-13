"""ReconForge httpx Tool Wrapper - HTTP probing.

Author: Andrews Ferreira

All commands are built as structured argument lists (list[str]) to
prevent shell injection and improve reliability.

Config-aware: when a :class:`ConfigLoader` is provided, timeouts are
read from ``tools.yaml``.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from core.runner import Runner, RunResult, validate_arg
from core.tool_config import ToolConfig

if TYPE_CHECKING:
    from core.config_loader import ConfigLoader


class HttpxTool:
    """Wrapper for httpx HTTP probing."""

    TOOL_NAME = "httpx"

    def __init__(self, runner: Runner, logger, output_dir: Path,
                 opsec_mode: str = "normal",
                 config: Optional["ConfigLoader"] = None):
        self.runner = runner
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.opsec_mode = opsec_mode
        self.tool_cfg = ToolConfig(config, self.TOOL_NAME)

    def is_available(self) -> bool:
        return self.runner.check_tool(self.TOOL_NAME)

    def _threads(self) -> int:
        return {"stealth": 5, "normal": 25, "aggressive": 50}.get(
            self.opsec_mode, 25
        )

    def _rate(self) -> int:
        return {"stealth": 10, "normal": 100, "aggressive": 0}.get(
            self.opsec_mode, 100
        )

    def probe(self, target_url: str, paths: Optional[List[str]] = None,
              headers: Optional[List[str]] = None,
              timeout: int = 300) -> RunResult:
        """Probe a target URL for HTTP responses and technology info."""
        validate_arg(target_url, "target_url")

        json_path = self.output_dir / "httpx_probe.json"
        threads = self._threads()
        rate = self._rate()
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)

        cmd: List[str] = [
            "httpx", "-u", target_url, "-json", "-o", str(json_path),
            "-threads", str(threads), "-silent",
            "-status-code", "-content-length", "-title", "-tech-detect",
            "-follow-redirects", "-content-type",
        ]
        if rate > 0:
            cmd += ["-rl", str(rate)]

        if headers:
            for h in headers:
                validate_arg(h, "header")
                cmd += ["-H", h]

        self.logger.info(f"Running httpx probe on {target_url}")
        return self.runner.run(cmd, timeout=effective_timeout, output_file=json_path)

    def probe_endpoints(self, endpoints_file: str,
                        headers: Optional[List[str]] = None,
                        timeout: int = 300) -> RunResult:
        """Probe a list of endpoints from a file."""
        validate_arg(endpoints_file, "endpoints_file")

        json_path = self.output_dir / "httpx_endpoints.json"
        threads = self._threads()
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)

        cmd: List[str] = [
            "httpx", "-l", endpoints_file, "-json", "-o", str(json_path),
            "-threads", str(threads), "-silent",
            "-status-code", "-content-length", "-title", "-tech-detect",
            "-follow-redirects", "-content-type",
        ]

        if headers:
            for h in headers:
                validate_arg(h, "header")
                cmd += ["-H", h]

        self.logger.info(f"Running httpx endpoint probing from {endpoints_file}")
        return self.runner.run(cmd, timeout=effective_timeout, output_file=json_path)

    def get_json_path(self, scan_type: str = "probe") -> Path:
        return self.output_dir / f"httpx_{scan_type}.json"
