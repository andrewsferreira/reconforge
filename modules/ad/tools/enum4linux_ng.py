"""ReconForge AD - enum4linux-ng Tool Wrapper.

Modern replacement for enum4linux with JSON output support.
Enumerates AD/SMB: users, groups, shares, password policies, domain info.

All commands are built as structured argument lists (list[str]) to
prevent shell injection and improve reliability.

Config-aware: when a :class:`ConfigLoader` is provided, timeouts and
mode arguments are read from ``tools.yaml``.

Author: Andrews Ferreira
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from core.runner import Runner, RunResult
from core.tool_config import ToolConfig

if TYPE_CHECKING:
    from core.config_loader import ConfigLoader


class Enum4linuxNgTool:
    """Wrapper for enum4linux-ng — modern AD/SMB enumeration."""

    TOOL_NAME = "enum4linux-ng"
    TOOL_CONFIG_KEY = "enum4linux_ng"

    def __init__(self, runner: Runner, logger, output_dir: Path,
                 opsec_mode: str = "normal",
                 config: Optional["ConfigLoader"] = None):
        self.runner = runner
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.opsec_mode = opsec_mode
        self.tool_cfg = ToolConfig(config, self.TOOL_CONFIG_KEY)

    def is_available(self) -> bool:
        """Check if enum4linux-ng is installed."""
        return self.runner.check_tool(self.TOOL_NAME)

    # ------------------------------------------------------------------
    # Scan modes
    # ------------------------------------------------------------------

    def full_enum(self, target: str, timeout: int = 600,
                  username: str = "", password: str = "") -> RunResult:
        """Run full enumeration (-A flag)."""
        self.logger.info(f"Running enum4linux-ng full enumeration on {target}")
        out_json = self.output_dir / "enum4linux_ng_full.json"
        out_txt = self.output_dir / "enum4linux_ng_full.txt"
        effective_timeout = self.tool_cfg.mode_timeout("full", timeout)
        cmd: List[str] = ["enum4linux-ng", "-A", "-oJ", str(out_json)]
        cmd += self._cred_args(username, password)
        cmd.append(target)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out_txt)

    def enum_users(self, target: str, timeout: int = 300,
                   username: str = "", password: str = "") -> RunResult:
        """Enumerate domain users (-U flag)."""
        self.logger.info(f"Running enum4linux-ng user enumeration on {target}")
        out = self.output_dir / "enum4linux_ng_users.txt"
        effective_timeout = self.tool_cfg.mode_timeout("users", timeout)
        cmd: List[str] = ["enum4linux-ng", "-U"]
        cmd += self._cred_args(username, password)
        cmd.append(target)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    def enum_groups(self, target: str, timeout: int = 300,
                    username: str = "", password: str = "") -> RunResult:
        """Enumerate domain groups (-G flag)."""
        self.logger.info(f"Running enum4linux-ng group enumeration on {target}")
        out = self.output_dir / "enum4linux_ng_groups.txt"
        effective_timeout = self.tool_cfg.mode_timeout("groups", timeout)
        cmd: List[str] = ["enum4linux-ng", "-G"]
        cmd += self._cred_args(username, password)
        cmd.append(target)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    def enum_shares(self, target: str, timeout: int = 300,
                    username: str = "", password: str = "") -> RunResult:
        """Enumerate SMB shares (-S flag)."""
        self.logger.info(f"Running enum4linux-ng share enumeration on {target}")
        out = self.output_dir / "enum4linux_ng_shares.txt"
        effective_timeout = self.tool_cfg.mode_timeout("shares", timeout)
        cmd: List[str] = ["enum4linux-ng", "-S"]
        cmd += self._cred_args(username, password)
        cmd.append(target)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    def enum_password_policy(self, target: str, timeout: int = 300,
                             username: str = "", password: str = "") -> RunResult:
        """Enumerate password policy (-P flag)."""
        self.logger.info(f"Running enum4linux-ng password policy on {target}")
        out = self.output_dir / "enum4linux_ng_passpol.txt"
        effective_timeout = self.tool_cfg.mode_timeout("password_policy", timeout)
        cmd: List[str] = ["enum4linux-ng", "-P"]
        cmd += self._cred_args(username, password)
        cmd.append(target)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    def enum_rid_cycling(self, target: str, rid_range: str = "500-10000",
                         timeout: int = 600,
                         username: str = "", password: str = "") -> RunResult:
        """RID cycling user enumeration (-R flag)."""
        self.logger.info(f"Running enum4linux-ng RID cycling on {target} (range {rid_range})")
        out = self.output_dir / "enum4linux_ng_rid.txt"
        effective_timeout = self.tool_cfg.mode_timeout("rid_cycling", timeout)
        cmd: List[str] = ["enum4linux-ng", "-R", "-r", rid_range]
        cmd += self._cred_args(username, password)
        cmd.append(target)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _cred_args(username: str, password: str) -> List[str]:
        """Build credential arguments as a list."""
        args: List[str] = []
        if username:
            args += ["-u", username]
        if password:
            args += ["-p", password]
        return args
