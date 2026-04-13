"""ReconForge Enum4linux Tool Wrapper - SMB/NetBIOS enumeration.

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


class Enum4linuxTool:
    """Wrapper for enum4linux SMB/NetBIOS enumeration."""

    TOOL_NAME = "enum4linux"

    def __init__(self, runner: Runner, logger, output_dir: Path,
                 config: Optional["ConfigLoader"] = None):
        self.runner = runner
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.tool_cfg = ToolConfig(config, self.TOOL_NAME)

    def is_available(self) -> bool:
        """Check if enum4linux is installed."""
        return self.runner.check_tool(self.TOOL_NAME)

    def full_enum(self, target: str, timeout: int = 300) -> RunResult:
        """Run full enumeration (-a flag)."""
        self.logger.info(f"Running enum4linux full enumeration on {target}")
        output_file = self.output_dir / "enum4linux_full.txt"
        effective_timeout = self.tool_cfg.mode_timeout("full", timeout)
        cmd: List[str] = ["enum4linux", "-a", target]
        return self.runner.run(cmd, timeout=effective_timeout, output_file=output_file)

    def enum_users(self, target: str, timeout: int = 120) -> RunResult:
        """Enumerate users via RID cycling."""
        self.logger.info(f"Running enum4linux user enumeration on {target}")
        output_file = self.output_dir / "enum4linux_users.txt"
        effective_timeout = self.tool_cfg.mode_timeout("users", timeout)
        cmd: List[str] = ["enum4linux", "-U", target]
        return self.runner.run(cmd, timeout=effective_timeout, output_file=output_file)

    def enum_shares(self, target: str, timeout: int = 120) -> RunResult:
        """Enumerate SMB shares."""
        self.logger.info(f"Running enum4linux share enumeration on {target}")
        output_file = self.output_dir / "enum4linux_shares.txt"
        effective_timeout = self.tool_cfg.mode_timeout("shares", timeout)
        cmd: List[str] = ["enum4linux", "-S", target]
        return self.runner.run(cmd, timeout=effective_timeout, output_file=output_file)

    def enum_groups(self, target: str, timeout: int = 120) -> RunResult:
        """Enumerate groups."""
        self.logger.info(f"Running enum4linux group enumeration on {target}")
        output_file = self.output_dir / "enum4linux_groups.txt"
        effective_timeout = self.tool_cfg.mode_timeout("groups", timeout)
        cmd: List[str] = ["enum4linux", "-G", target]
        return self.runner.run(cmd, timeout=effective_timeout, output_file=output_file)

    def enum_password_policy(self, target: str, timeout: int = 120) -> RunResult:
        """Enumerate password policy."""
        self.logger.info(f"Running enum4linux password policy on {target}")
        output_file = self.output_dir / "enum4linux_passpol.txt"
        effective_timeout = self.tool_cfg.mode_timeout("password_policy", timeout)
        cmd: List[str] = ["enum4linux", "-P", target]
        return self.runner.run(cmd, timeout=effective_timeout, output_file=output_file)

    def enum_os(self, target: str, timeout: int = 60) -> RunResult:
        """Enumerate OS information."""
        self.logger.info(f"Running enum4linux OS detection on {target}")
        output_file = self.output_dir / "enum4linux_os.txt"
        effective_timeout = self.tool_cfg.mode_timeout("os_info", timeout)
        cmd: List[str] = ["enum4linux", "-o", target]
        return self.runner.run(cmd, timeout=effective_timeout, output_file=output_file)
