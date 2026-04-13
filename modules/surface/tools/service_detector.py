"""ReconForge - Service Detector Tool Wrapper

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


class ServiceDetectorTool:
    """Wrapper for httpx-toolkit for HTTP service detection."""

    TOOL_NAME = "httpx"
    TOOL_CONFIG_KEY = "httpx_surface"

    def __init__(self, runner: Runner, logger, output_dir: Path,
                 opsec_mode: str = "normal",
                 config: Optional["ConfigLoader"] = None):
        self.runner = runner
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.opsec_mode = opsec_mode
        self.tool_cfg = ToolConfig(config, self.TOOL_CONFIG_KEY)

    def is_available(self) -> bool:
        """Check if httpx is installed."""
        return self.runner.check_tool(self.TOOL_NAME)

    def probe_services(self, target: str, ports: str = "",
                       timeout: int = 300) -> RunResult:
        """Probe target for HTTP services across discovered ports."""
        output_path = self.output_dir / "service_detection.json"
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        cmd: List[str] = [
            "httpx", "-u", target,
        ]
        if ports:
            cmd += ["-ports", ports]
        cmd += [
            "-json", "-o", str(output_path),
            "-title", "-tech-detect", "-status-code", "-follow-redirects",
        ]
        self.logger.command(" ".join(cmd))
        return self.runner.run(cmd, timeout=effective_timeout)

    def get_output_path(self) -> Path:
        """Return path to JSON output file."""
        return self.output_dir / "service_detection.json"
