"""ReconForge Arjun Tool Wrapper - HTTP parameter discovery.

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


class ArjunTool:
    """Wrapper for Arjun HTTP parameter discovery."""

    TOOL_NAME = "arjun"

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
        return {"stealth": 2, "normal": 5, "aggressive": 15}.get(
            self.opsec_mode, 5
        )

    def discover_params(self, target_url: str, method: str = "GET",
                        headers: Optional[List[str]] = None,
                        timeout: int = 300) -> RunResult:
        """Discover hidden HTTP parameters."""
        validate_arg(target_url, "target_url")
        validate_arg(method, "method")

        json_path = self.output_dir / "arjun_params.json"
        threads = self._threads()
        effective_timeout = self.tool_cfg.mode_timeout("normal", timeout)

        cmd: List[str] = [
            "arjun", "-u", target_url, "-m", method,
            "-t", str(threads), "-oJ", str(json_path),
        ]

        if headers:
            for h in headers:
                validate_arg(h, "header")
                cmd += ["--headers", h]

        self.logger.info(f"Running Arjun parameter discovery on {target_url} (method={method})")
        # Arjun's own -oJ already writes json_path — Arjun isn't run with
        # a quiet/silent flag here, so its stdout is a progress display,
        # not JSON. Passing output_file= too would let Runner.run()
        # overwrite the real JSON with that non-JSON stdout, which
        # ArjunParser.parse_json()'s strict json.loads() then fails to
        # parse. Same class of bug fixed in ffuf.py/whatweb.py.
        return self.runner.run(cmd, timeout=effective_timeout)

    def discover_params_json_body(self, target_url: str,
                                   headers: Optional[List[str]] = None,
                                   timeout: int = 300) -> RunResult:
        """Discover hidden parameters via JSON body."""
        validate_arg(target_url, "target_url")

        json_path = self.output_dir / "arjun_json_params.json"
        threads = self._threads()
        effective_timeout = self.tool_cfg.mode_timeout("aggressive", timeout)

        cmd: List[str] = [
            "arjun", "-u", target_url, "-m", "JSON",
            "-t", str(threads), "-oJ", str(json_path),
        ]

        if headers:
            for h in headers:
                validate_arg(h, "header")
                cmd += ["--headers", h]

        self.logger.info(f"Running Arjun JSON parameter discovery on {target_url}")
        return self.runner.run(cmd, timeout=effective_timeout)

    def get_json_path(self, scan_type: str = "params") -> Path:
        return self.output_dir / f"arjun_{scan_type}.json"
