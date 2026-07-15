"""ReconForge WhatWeb Tool Wrapper - Technology fingerprinting.

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


class WhatwebTool:
    """Wrapper for WhatWeb technology fingerprinting."""

    TOOL_NAME = "whatweb"

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

    def _aggression_level(self) -> int:
        """Map OPSEC mode to WhatWeb aggression level (1-4).

        Reads from tools.yaml mode args (e.g. ``"-a 3"``) and falls
        back to hardcoded defaults.
        """
        mode_key = self.opsec_mode if self.opsec_mode in ("normal", "aggressive") else "normal"
        cfg_args = self.tool_cfg.mode_args(mode_key)
        if cfg_args:
            for part in cfg_args.split():
                if part.lstrip("-a").isdigit() and part.startswith("-a"):
                    return int(part[2:])
                if part.isdigit():
                    return int(part)
        return {"stealth": 1, "normal": 3, "aggressive": 4}.get(
            self.opsec_mode, 3
        )

    def scan(self, target_url: str, timeout: int = 300) -> RunResult:
        """Run WhatWeb scan against a target URL."""
        aggression = self._aggression_level()
        json_path = self.output_dir / "whatweb.json"
        effective_timeout = self.tool_cfg.effective_timeout(self.opsec_mode, timeout)

        cmd: list[str] = [
            "whatweb", f"-a{aggression}", "--color=never",
            f"--log-json={json_path}", target_url,
        ]

        self.logger.info(f"Running WhatWeb (aggression={aggression}) on {target_url}")
        # whatweb's own --log-json plugin already writes json_path — do NOT
        # also pass output_file= here, or Runner.run() overwrites the real
        # JSON with whatweb's plain-text stdout summary (different format),
        # which WhatwebParser.parse_json() then silently fails to parse
        # (json.JSONDecodeError per line -> empty result, no technologies
        # detected, no error surfaced). Same class of bug as curl_tool.py.
        return self.runner.run(cmd, timeout=effective_timeout)

    def get_json_path(self) -> Path:
        return self.output_dir / "whatweb.json"
