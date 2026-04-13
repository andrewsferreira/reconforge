"""ReconForge Nikto Tool Wrapper - Web server vulnerability scanner.

Author: Andrews Ferreira

All commands are built as structured argument lists (list[str]) to
prevent shell injection and improve reliability.

Config-aware: when a :class:`ConfigLoader` is provided, timeouts and
mode arguments are read from ``tools.yaml``.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from core.runner import Runner, RunResult
from core.tool_config import ToolConfig

if TYPE_CHECKING:
    from core.config_loader import ConfigLoader


class NiktoTool:
    """Wrapper for Nikto web vulnerability scanner."""

    TOOL_NAME = "nikto"

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

    def _tuning(self) -> str:
        """Get Nikto tuning options based on OPSEC mode.

        Reads from tools.yaml ``modes.normal.args`` / ``modes.aggressive.args``
        and falls back to hardcoded defaults.
        """
        mode_key = self.opsec_mode if self.opsec_mode in ("normal", "aggressive") else "normal"
        cfg_args = self.tool_cfg.mode_args(mode_key)
        if cfg_args:
            # Extract Tuning value from args like "-Tuning 1,2,3,4,5"
            for part in cfg_args.split():
                if part.startswith("-Tuning"):
                    continue
                if "," in part or part.isdigit():
                    return part
        # Fallback
        if self.opsec_mode == "stealth":
            return "1"
        if self.opsec_mode == "aggressive":
            return ""
        return "12"

    def scan(self, target_url: str, timeout: int = 900) -> RunResult:
        """Run Nikto vulnerability scan."""
        json_path = self.output_dir / "nikto.json"
        raw_path = self.output_dir / "nikto_raw.txt"
        tuning = self._tuning()
        effective_timeout = self.tool_cfg.effective_timeout("normal", timeout)

        cmd: List[str] = [
            "nikto", "-h", target_url,
            "-Format", "json", "-o", str(json_path),
            "-nointeractive",
        ]
        if tuning:
            cmd += ["-Tuning", tuning]

        self.logger.info(f"Running Nikto scan on {target_url}")
        return self.runner.run(cmd, timeout=effective_timeout, output_file=raw_path)

    def get_json_path(self) -> Path:
        return self.output_dir / "nikto.json"

    def get_raw_path(self) -> Path:
        return self.output_dir / "nikto_raw.txt"
