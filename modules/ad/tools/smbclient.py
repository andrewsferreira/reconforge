"""ReconForge AD - smbclient Tool Wrapper.

SMB share enumeration and access testing for Active Directory.

All commands are built as structured argument lists (list[str]) to
prevent shell injection and improve reliability.

Config-aware: when a :class:`ConfigLoader` is provided, timeouts are
read from ``tools.yaml``.

Author: Andrews Ferreira
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from core.runner import Runner, RunResult
from core.tool_config import ToolConfig

if TYPE_CHECKING:
    from core.config_loader import ConfigLoader


class ADSmbclientTool:
    """Wrapper for smbclient targeting AD environments."""

    TOOL_NAME = "smbclient"

    def __init__(self, runner: Runner, logger, output_dir: Path,
                 opsec_mode: str = "normal",
                 config: ConfigLoader | None = None):
        self.runner = runner
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.opsec_mode = opsec_mode
        self.tool_cfg = ToolConfig(config, self.TOOL_NAME)

    def is_available(self) -> bool:
        """Check if smbclient is installed."""
        return self.runner.check_tool(self.TOOL_NAME)

    # ------------------------------------------------------------------
    # Enumeration methods
    # ------------------------------------------------------------------

    def null_session_list(self, target: str, timeout: int = 60) -> RunResult:
        """List shares via SMB null session (-N -L)."""
        self.logger.info(f"Testing SMB null session share listing on {target}")
        out = self.output_dir / "smb_null_shares.txt"
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        cmd: list[str] = ["smbclient", "-N", "-L", f"//{target}"]
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    def authenticated_list(self, target: str, username: str, password: str,
                           domain: str = "", timeout: int = 60) -> RunResult:
        """List shares with credentials."""
        self.logger.info(f"Listing SMB shares on {target} as {username}")
        out = self.output_dir / "smb_auth_shares.txt"
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        cmd: list[str] = [
            "smbclient", "-L", f"//{target}",
            "-U", f"{username}%{password}",
        ]
        if domain:
            cmd += ["-W", domain]
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    def test_share_access(self, target: str, share: str,
                          username: str = "", password: str = "",
                          timeout: int = 30) -> RunResult:
        """Test access to a specific share."""
        self.logger.info(f"Testing access to //{target}/{share}")
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        cmd: list[str] = [
            "smbclient", f"//{target}/{share}",
        ]
        if username:
            cmd += ["-U", f"{username}%{password}"]
        else:
            cmd.append("-N")
        cmd += ["-c", "dir"]
        return self.runner.run(cmd, timeout=effective_timeout)

    def test_sysvol_access(self, target: str, timeout: int = 30) -> RunResult:
        """Test anonymous access to SYSVOL share."""
        self.logger.info(f"Testing SYSVOL access on {target}")
        return self.test_share_access(target, "SYSVOL", timeout=timeout)

    def test_netlogon_access(self, target: str, timeout: int = 30) -> RunResult:
        """Test anonymous access to NETLOGON share."""
        self.logger.info(f"Testing NETLOGON access on {target}")
        return self.test_share_access(target, "NETLOGON", timeout=timeout)

    def test_admin_shares(self, target: str,
                          username: str = "", password: str = "",
                          timeout: int = 30) -> dict[str, bool]:
        """Test access to administrative shares (C$, ADMIN$, IPC$)."""
        results: dict[str, bool] = {}
        for share in ["C$", "ADMIN$", "IPC$"]:
            res = self.test_share_access(target, share, username, password, timeout)
            results[share] = res.success
        return results
