"""ReconForge AD - Advanced Impacket Tool Wrapper.

Wraps advanced impacket scripts for delegation and privilege analysis:
- findDelegation.py  : Discover delegation configurations
- GetUserSPNs.py     : Kerberoasting / SPN enumeration

All commands are built as structured argument lists (list[str]) to
prevent shell injection and improve reliability.

Config-aware: when a :class:`ConfigLoader` is provided, timeouts are
read from ``tools.yaml``.

Author: Andrews Ferreira
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, TYPE_CHECKING

from core.runner import Runner, RunResult
from core.tool_config import ToolConfig

if TYPE_CHECKING:
    from core.config_loader import ConfigLoader


class AdvancedImpacketTool:
    """Wrapper for advanced Impacket delegation & privilege scripts."""

    # Map of tool logical names to their binary names
    TOOLS = {
        "finddelegation": "findDelegation.py",
        "getuserspns": "GetUserSPNs.py",
    }

    # Fallback names (impacket-* style from pip install)
    TOOLS_ALT = {
        "finddelegation": "impacket-findDelegation",
        "getuserspns": "impacket-GetUserSPNs",
    }

    # Config keys for each sub-tool in tools.yaml
    CONFIG_KEYS = {
        "finddelegation": "impacket_finddelegation",
        "getuserspns": "impacket_getuserspns",
    }

    def __init__(self, runner: Runner, logger, output_dir: Path,
                 opsec_mode: str = "normal",
                 config: Optional["ConfigLoader"] = None):
        self.runner = runner
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.opsec_mode = opsec_mode
        self._config = config
        self._resolved: Dict[str, str] = {}

    def _resolve_binary(self, key: str) -> Optional[str]:
        """Resolve the actual binary name for a tool."""
        if key in self._resolved:
            return self._resolved[key]
        for name in (self.TOOLS.get(key, ""), self.TOOLS_ALT.get(key, "")):
            if name and self.runner.check_tool(name):
                self._resolved[key] = name
                return name
        return None

    def _tool_cfg(self, key: str) -> ToolConfig:
        """Return a ToolConfig for the given sub-tool key."""
        cfg_key = self.CONFIG_KEYS.get(key, key)
        return ToolConfig(self._config, cfg_key)

    def is_available(self, tool: str = "finddelegation") -> bool:
        """Check if a specific advanced impacket tool is available."""
        return self._resolve_binary(tool) is not None

    def any_available(self) -> bool:
        """Check if any advanced impacket tool is available."""
        return any(self._resolve_binary(k) for k in self.TOOLS)

    # ------------------------------------------------------------------
    # findDelegation.py
    # ------------------------------------------------------------------

    def find_delegation(self, target: str, domain: str,
                        username: str = "", password: str = "",
                        dc_ip: str = "",
                        timeout: int = 120) -> RunResult:
        """Discover delegation configurations with findDelegation.py."""
        binary = self._resolve_binary("finddelegation")
        if not binary:
            return self._tool_missing("finddelegation")

        self.logger.info(f"Running findDelegation on {target}")
        out = self.output_dir / "impacket_finddelegation.txt"

        cred = self._build_identity(domain, username, password)
        cmd: List[str] = [binary]
        if dc_ip:
            cmd += ["-dc-ip", dc_ip]
        cmd.append(cred)
        effective_timeout = self._tool_cfg("finddelegation").effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    # ------------------------------------------------------------------
    # GetUserSPNs.py (Kerberoasting)
    # ------------------------------------------------------------------

    def get_user_spns(self, target: str, domain: str,
                      username: str = "", password: str = "",
                      dc_ip: str = "", request: bool = False,
                      timeout: int = 120) -> RunResult:
        """Find accounts with SPNs (Kerberoasting targets)."""
        binary = self._resolve_binary("getuserspns")
        if not binary:
            return self._tool_missing("getuserspns")

        self.logger.info(f"Running GetUserSPNs on {target}")
        out = self.output_dir / "impacket_getuserspns.txt"

        cred = self._build_identity(domain, username, password)
        cmd: List[str] = [binary]
        if dc_ip:
            cmd += ["-dc-ip", dc_ip]
        if request:
            cmd.append("-request")
        cmd.append(cred)
        effective_timeout = self._tool_cfg("getuserspns").effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    # ------------------------------------------------------------------
    # Machine Account Quota (via LDAP query)
    # ------------------------------------------------------------------

    def get_machine_account_quota(self, target: str, domain: str,
                                  username: str = "", password: str = "",
                                  dc_ip: str = "",
                                  timeout: int = 60) -> RunResult:
        """Query ms-DS-MachineAccountQuota attribute via ldapsearch."""
        self.logger.info(f"Querying MachineAccountQuota on {target}")
        out = self.output_dir / "machine_account_quota.txt"

        # Build base DN from domain
        base_dn = ",".join(f"DC={part}" for part in domain.split("."))
        dc = dc_ip or target

        cmd: List[str] = ["ldapsearch", "-H", f"ldap://{dc}"]
        if username and password:
            cmd += ["-D", f"{domain}\\{username}", "-w", password]
        else:
            cmd.append("-x")
        cmd += [
            "-b", base_dn,
            "(objectClass=domain)",
            "ms-DS-MachineAccountQuota",
        ]
        return self.runner.run(cmd, timeout=timeout, output_file=out)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_identity(domain: str, username: str, password: str) -> str:
        """Build impacket DOMAIN/user:password identity string."""
        if username:
            prefix = f"{domain}/" if domain else ""
            return f"{prefix}{username}:{password}"
        prefix = f"{domain}/" if domain else ""
        return f"{prefix}"

    def _tool_missing(self, key: str) -> RunResult:
        """Return a synthetic RunResult for a missing tool."""
        name = self.TOOLS.get(key, key)
        self.logger.warning(f"Advanced impacket tool not found: {name}")
        return RunResult(
            command=name,
            returncode=-2,
            stdout="",
            stderr=f"Tool not found: {name}",
            duration=0.0,
            success=False,
        )
