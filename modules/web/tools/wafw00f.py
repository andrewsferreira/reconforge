"""ReconForge wafw00f Tool Wrapper - Web Application Firewall detection.

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


class Wafw00fTool:
    """Wrapper for wafw00f WAF detection."""

    TOOL_NAME = "wafw00f"

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

    def detect(self, target_url: str, timeout: int = 120) -> RunResult:
        """Detect WAF/CDN in front of target."""
        out_path = self.output_dir / "wafw00f.txt"
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        cmd: List[str] = ["wafw00f", target_url, "-o", str(out_path)]
        self.logger.info(f"Running wafw00f on {target_url}")
        # wafw00f's own -o already writes out_path; its stdout includes a
        # banner and live detection progress distinct from the file
        # content, so output_file= must not also be passed here (same
        # class of bug fixed in ffuf.py/whatweb.py/arjun_tool.py).
        return self.runner.run(cmd, timeout=effective_timeout)

    def get_output_path(self) -> Path:
        return self.output_dir / "wafw00f.txt"
