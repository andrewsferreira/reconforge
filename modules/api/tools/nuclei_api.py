"""ReconForge API Nuclei Tool Wrapper - API-focused vulnerability scanning.

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


class NucleiApiTool:
    """Wrapper for Nuclei targeting API vulnerabilities."""

    TOOL_NAME = "nuclei"
    TOOL_CONFIG_KEY = "nuclei_api"

    # API-relevant tags for focused scanning
    API_TAGS = "api,graphql,swagger,openapi,jwt,oauth,token,idor,ssrf,sqli,xss,rce"

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

    def _rate_limit(self) -> int:
        return {"stealth": 20, "normal": 100, "aggressive": 300}.get(
            self.opsec_mode, 100
        )

    def _concurrency(self) -> int:
        return {"stealth": 3, "normal": 10, "aggressive": 25}.get(
            self.opsec_mode, 10
        )

    def api_scan(self, target_url: str, severity: str = "",
                 tags: str = "", headers: str = "",
                 timeout: int = 1200) -> RunResult:
        """Run Nuclei API-focused vulnerability scan."""
        validate_arg(target_url, "target_url")

        jsonl_path = self.output_dir / "nuclei_api.jsonl"
        rate = self._rate_limit()
        concurrency = self._concurrency()
        scan_tags = tags or self.API_TAGS
        effective_timeout = self.tool_cfg.effective_timeout("api", timeout)

        cmd: List[str] = [
            "nuclei", "-u", target_url, "-jsonl", "-o", str(jsonl_path),
            "-rl", str(rate), "-c", str(concurrency),
            "-silent", "-nc", "-tags", scan_tags,
        ]

        if severity:
            validate_arg(severity, "severity")
            cmd += ["-severity", severity]

        if headers:
            validate_arg(headers, "headers")
            cmd += ["-H", headers]

        self.logger.info(f"Running Nuclei API scan on {target_url} (rate={rate})")
        # See modules/web/tools/nuclei.py::scan() — same reasoning.
        return self.runner.run(cmd, timeout=effective_timeout)

    def get_jsonl_path(self) -> Path:
        return self.output_dir / "nuclei_api.jsonl"
