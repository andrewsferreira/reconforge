"""ReconForge SQLMap Tool Wrapper - SQL injection detection.

Author: Andrews Ferreira

All commands are built as structured argument lists (list[str]) to
prevent shell injection and improve reliability.

Config-aware: when a :class:`ConfigLoader` is provided, timeouts and
mode arguments are read from ``tools.yaml``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from core.runner import Runner, RunResult
from core.tool_config import ToolConfig

if TYPE_CHECKING:
    from core.config_loader import ConfigLoader


class SqlmapTool:
    """Wrapper for sqlmap SQL injection scanner."""

    TOOL_NAME = "sqlmap"

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

    def _level(self) -> int:
        return {"stealth": 1, "normal": 1, "aggressive": 3}.get(
            self.opsec_mode, 1
        )

    def _risk(self) -> int:
        return {"stealth": 1, "normal": 1, "aggressive": 2}.get(
            self.opsec_mode, 1
        )

    def scan(self, target_url: str, timeout: int = 900) -> RunResult:
        """Run sqlmap in detection-only mode."""
        output_subdir = self.output_dir / "sqlmap_output"
        output_subdir.mkdir(parents=True, exist_ok=True)
        level = self._level()
        risk = self._risk()
        mode_key = "exploit" if self.opsec_mode == "aggressive" else "detect"
        effective_timeout = self.tool_cfg.mode_timeout(mode_key, timeout)

        cmd: list[str] = [
            "sqlmap", "-u", target_url, "--batch", "--crawl=2",
            f"--level={level}", f"--risk={risk}",
            f"--output-dir={output_subdir}", "--forms",
        ]

        self.logger.info(
            f"Running sqlmap on {target_url} (level={level}, risk={risk})"
        )
        return self.runner.run(cmd, timeout=effective_timeout)

    def get_output_dir(self) -> Path:
        return self.output_dir / "sqlmap_output"
