"""ReconForge Curl Tool Wrapper - HTTP header analysis.

Author: Andrews Ferreira

All commands are built as structured argument lists (list[str]) to
prevent shell injection and improve reliability.

Config-aware: when a :class:`ConfigLoader` is provided, timeouts are
read from ``tools.yaml``.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from core.runner import Runner, RunResult
from core.tool_config import ToolConfig

if TYPE_CHECKING:
    from core.config_loader import ConfigLoader


class CurlTool:
    """Wrapper for curl HTTP requests."""

    TOOL_NAME = "curl"

    def __init__(self, runner: Runner, logger, output_dir: Path,
                 config: Optional["ConfigLoader"] = None):
        self.runner = runner
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.tool_cfg = ToolConfig(config, self.TOOL_NAME)

    def is_available(self) -> bool:
        return self.runner.check_tool(self.TOOL_NAME)

    def fetch_headers(self, target_url: str, timeout: int = 30) -> RunResult:
        """Fetch HTTP response headers only."""
        out_path = self.output_dir / "headers.txt"
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        cmd: List[str] = [
            "curl", "-sI", "-o", str(out_path),
            "-m", "15", "--connect-timeout", "10",
            target_url,
        ]
        self.logger.info(f"Fetching HTTP headers from {target_url}")
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out_path)

    def fetch_page(self, target_url: str, timeout: int = 30) -> RunResult:
        """Fetch full HTTP response (headers + body)."""
        out_path = self.output_dir / "response.txt"
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        cmd: List[str] = [
            "curl", "-si", "-o", str(out_path),
            "-m", "15", "--connect-timeout", "10",
            target_url,
        ]
        self.logger.info(f"Fetching full response from {target_url}")
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out_path)

    def get_headers_path(self) -> Path:
        return self.output_dir / "headers.txt"
