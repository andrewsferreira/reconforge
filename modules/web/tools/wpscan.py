"""ReconForge WPScan Tool Wrapper - WordPress security scanner.

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


class WpscanTool:
    """Wrapper for WPScan WordPress scanner."""

    TOOL_NAME = "wpscan"

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

    def _enumerate_flags(self) -> str:
        """Enumerate flags based on OPSEC mode.

        Reads from tools.yaml ``modes.enumerate.args`` /
        ``modes.aggressive.args`` and falls back to hardcoded defaults.
        """
        mode_key = "aggressive" if self.opsec_mode == "aggressive" else "enumerate"
        cfg_args = self.tool_cfg.mode_args(mode_key)
        if cfg_args:
            for part in cfg_args.split():
                if part.startswith("--enumerate"):
                    continue
                if "," in part and any(c.isalpha() for c in part):
                    return part
        if self.opsec_mode == "stealth":
            return "vp"
        if self.opsec_mode == "aggressive":
            return "vp,vt,u,ap,at"
        return "vp,vt,u"

    def scan(self, target_url: str, api_token: str = "",
             timeout: int = 900) -> RunResult:
        """Run WPScan against a WordPress site."""
        json_path = self.output_dir / "wpscan.json"
        enum_flags = self._enumerate_flags()
        effective_timeout = self.tool_cfg.effective_timeout(
            "aggressive" if self.opsec_mode == "aggressive" else "enumerate",
            timeout,
        )

        cmd: List[str] = [
            "wpscan", "--url", target_url, "--format", "json",
            "-o", str(json_path), "--enumerate", enum_flags, "--no-banner",
        ]

        if api_token:
            cmd += ["--api-token", api_token]

        self.logger.info(f"Running WPScan on {target_url} (enumerate={enum_flags})")
        return self.runner.run(cmd, timeout=effective_timeout, output_file=json_path)

    def get_json_path(self) -> Path:
        return self.output_dir / "wpscan.json"
