"""ReconForge SMBClient Tool Wrapper - SMB share access and enumeration.

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


class SmbclientTool:
    """Wrapper for smbclient share enumeration."""

    TOOL_NAME = "smbclient"

    def __init__(self, runner: Runner, logger, output_dir: Path,
                 config: Optional["ConfigLoader"] = None):
        self.runner = runner
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.tool_cfg = ToolConfig(config, self.TOOL_NAME)

    def is_available(self) -> bool:
        """Check if smbclient is installed."""
        return self.runner.check_tool(self.TOOL_NAME)

    def list_shares(self, target: str, username: str = "",
                    password: str = "", timeout: int = 60) -> RunResult:
        """List SMB shares on the target."""
        self.logger.info(f"Listing SMB shares on {target}")
        output_file = self.output_dir / "smbclient_shares.txt"
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)

        cmd: List[str] = ["smbclient", "-L", f"//{target}"]
        if username:
            cmd += ["-U", f"{username}%{password}"]
        else:
            cmd.append("-N")

        return self.runner.run(cmd, timeout=effective_timeout, output_file=output_file)

    def test_share_access(self, target: str, share: str,
                          username: str = "", password: str = "",
                          timeout: int = 30) -> RunResult:
        """Test access to a specific share."""
        self.logger.info(f"Testing access to //{target}/{share}")
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)

        cmd: List[str] = [
            "smbclient", f"//{target}/{share}",
        ]
        if username:
            cmd += ["-U", f"{username}%{password}"]
        else:
            cmd.append("-N")
        cmd += ["-c", "dir"]

        return self.runner.run(cmd, timeout=effective_timeout)

    def list_share_contents(self, target: str, share: str,
                            username: str = "", password: str = "",
                            path: str = "",
                            timeout: int = 60) -> RunResult:
        """List contents of a specific share path."""
        self.logger.info(f"Listing //{target}/{share}/{path}")
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)

        ls_cmd = f"ls {path}/*" if path else "ls"
        cmd: List[str] = [
            "smbclient", f"//{target}/{share}",
        ]
        if username:
            cmd += ["-U", f"{username}%{password}"]
        else:
            cmd.append("-N")
        cmd += ["-c", ls_cmd]

        return self.runner.run(cmd, timeout=effective_timeout)

    def null_session_test(self, target: str, timeout: int = 30) -> RunResult:
        """Test for null session access."""
        self.logger.info(f"Testing null session on {target}")
        return self.list_shares(target, timeout=timeout)
