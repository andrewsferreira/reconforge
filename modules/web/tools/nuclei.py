"""ReconForge Nuclei Tool Wrapper - Template-based vulnerability scanner.

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


class NucleiTool:
    """Wrapper for Nuclei template-based scanner."""

    TOOL_NAME = "nuclei"

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

    def _rate_limit(self) -> int:
        return {"stealth": 20, "normal": 100, "aggressive": 300}.get(
            self.opsec_mode, 100
        )

    def _concurrency(self) -> int:
        return {"stealth": 3, "normal": 10, "aggressive": 25}.get(
            self.opsec_mode, 10
        )

    def _bulk_size(self) -> int:
        return {"stealth": 10, "normal": 25, "aggressive": 50}.get(
            self.opsec_mode, 25
        )

    def scan(self, target_url: str, severity: str = "",
             tags: str = "", timeout: int = 1200) -> RunResult:
        """Run Nuclei vulnerability scan."""
        jsonl_path = self.output_dir / "nuclei.jsonl"
        rate = self._rate_limit()
        concurrency = self._concurrency()
        bulk = self._bulk_size()
        effective_timeout = self.tool_cfg.effective_timeout(
            "cves" if self.opsec_mode != "aggressive" else "all",
            timeout,
        )

        cmd: list[str] = [
            "nuclei", "-u", target_url, "-jsonl", "-o", str(jsonl_path),
            "-rl", str(rate), "-bs", str(bulk), "-c", str(concurrency),
            "-silent", "-nc",
        ]

        if severity:
            cmd += ["-severity", severity]
        if tags:
            cmd += ["-tags", tags]

        self.logger.info(f"Running Nuclei scan on {target_url} (rate={rate})")
        # nuclei's own -jsonl -o already writes jsonl_path, and with -jsonl
        # set nuclei's stdout mirrors the same JSON Lines format (unlike
        # ffuf/whatweb where stdout is a different, non-JSON format), so
        # this is likely already redundant rather than corrupting — still
        # removed for consistency and defense-in-depth.
        return self.runner.run(cmd, timeout=effective_timeout)

    def get_jsonl_path(self) -> Path:
        return self.output_dir / "nuclei.jsonl"
