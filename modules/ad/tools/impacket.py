"""ReconForge AD - Impacket Suite Tool Wrapper.

Wraps key impacket scripts for AD enumeration:
- GetADUsers.py  : User enumeration with attributes
- GetNPUsers.py  : AS-REP roastable user detection
- lookupsid.py   : RID cycling for user/group discovery
- rpcdump.py     : RPC endpoint enumeration

All commands are built as structured argument lists (list[str]) to
prevent shell injection and improve reliability.

Config-aware: when a :class:`ConfigLoader` is provided, timeouts are
read from ``tools.yaml``.

Author: Andrews Ferreira
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from core.runner import RC_TOOL_NOT_FOUND, Runner, RunResult
from core.tool_config import ToolConfig

if TYPE_CHECKING:
    from core.config_loader import ConfigLoader


class ImpacketTool:
    """Wrapper for Impacket suite AD enumeration scripts."""

    # Map of tool logical names to their binary names
    TOOLS = {
        "getadusers": "GetADUsers.py",
        "getnpusers": "GetNPUsers.py",
        "lookupsid": "lookupsid.py",
        "rpcdump": "rpcdump.py",
    }

    # Fallback names (impacket-* style from pip install)
    TOOLS_ALT = {
        "getadusers": "impacket-GetADUsers",
        "getnpusers": "impacket-GetNPUsers",
        "lookupsid": "impacket-lookupsid",
        "rpcdump": "impacket-rpcdump",
    }

    # Config keys for each sub-tool in tools.yaml
    CONFIG_KEYS = {
        "getadusers": "impacket_getadusers",
        "getnpusers": "impacket_getnpusers",
        "lookupsid": "impacket_lookupsid",
        "rpcdump": "impacket_rpcdump",
    }

    def __init__(self, runner: Runner, logger, output_dir: Path,
                 opsec_mode: str = "normal",
                 config: ConfigLoader | None = None):
        self.runner = runner
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.opsec_mode = opsec_mode
        self._config = config
        self._resolved: dict[str, str] = {}

    def _resolve_binary(self, key: str) -> str | None:
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

    def is_available(self, tool: str = "getnpusers") -> bool:
        """Check if a specific impacket tool is available."""
        return self._resolve_binary(tool) is not None

    def any_available(self) -> bool:
        """Check if any impacket tool is available."""
        return any(self._resolve_binary(k) for k in self.TOOLS)

    # ------------------------------------------------------------------
    # GetADUsers.py
    # ------------------------------------------------------------------

    def get_ad_users(self, target: str, domain: str,
                     username: str = "", password: str = "",
                     dc_ip: str = "",
                     timeout: int = 120) -> RunResult:
        """Enumerate AD users with GetADUsers.py."""
        binary = self._resolve_binary("getadusers")
        if not binary:
            return self._tool_missing("getadusers")

        self.logger.info(f"Running GetADUsers on {target}")
        out = self.output_dir / "impacket_getadusers.txt"

        cred = self._build_identity(domain, username, password)
        cmd: list[str] = [binary, "-all"]
        if dc_ip:
            cmd += ["-dc-ip", dc_ip]
        cmd.append(cred)
        effective_timeout = self._tool_cfg("getadusers").effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    # ------------------------------------------------------------------
    # GetNPUsers.py (AS-REP roasting)
    # ------------------------------------------------------------------

    def get_np_users(self, target: str, domain: str,
                     username: str = "", password: str = "",
                     usersfile: str = "", dc_ip: str = "",
                     timeout: int = 120) -> RunResult:
        """Find AS-REP roastable users with GetNPUsers.py."""
        binary = self._resolve_binary("getnpusers")
        if not binary:
            return self._tool_missing("getnpusers")

        self.logger.info(f"Running GetNPUsers on {target}")
        out = self.output_dir / "impacket_getnpusers.txt"

        cred = self._build_identity(domain, username, password)
        cmd: list[str] = [binary]
        if dc_ip:
            cmd += ["-dc-ip", dc_ip]
        if usersfile:
            cmd += ["-usersfile", usersfile]
        else:
            cmd.append("-no-pass")
        cmd.append(cred)
        effective_timeout = self._tool_cfg("getnpusers").effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    # ------------------------------------------------------------------
    # lookupsid.py (RID cycling)
    # ------------------------------------------------------------------

    def lookup_sid(self, target: str, domain: str = "",
                   username: str = "", password: str = "",
                   max_rid: int = 4000,
                   timeout: int = 300) -> RunResult:
        """RID cycling with lookupsid.py."""
        binary = self._resolve_binary("lookupsid")
        if not binary:
            return self._tool_missing("lookupsid")

        self.logger.info(f"Running lookupsid RID cycling on {target} (max RID {max_rid})")
        out = self.output_dir / "impacket_lookupsid.txt"

        if username:
            identity = (f"{domain}/{username}:{password}@{target}"
                        if domain else f"{username}:{password}@{target}")
        else:
            identity = f"anonymous@{target}"

        cmd: list[str] = [binary, identity, str(max_rid)]
        effective_timeout = self._tool_cfg("lookupsid").effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    # ------------------------------------------------------------------
    # rpcdump.py
    # ------------------------------------------------------------------

    def rpc_dump(self, target: str, port: int = 135,
                 timeout: int = 60) -> RunResult:
        """Enumerate RPC endpoints with rpcdump.py."""
        binary = self._resolve_binary("rpcdump")
        if not binary:
            return self._tool_missing("rpcdump")

        self.logger.info(f"Running rpcdump on {target}:{port}")
        out = self.output_dir / "impacket_rpcdump.txt"
        cmd: list[str] = [binary, target, "-port", str(port)]
        effective_timeout = self._tool_cfg("rpcdump").effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_identity(domain: str, username: str, password: str) -> str:
        """Build impacket DOMAIN/user:password identity string."""
        if username:
            prefix = f"{domain}/" if domain else ""
            return f"{prefix}{username}:{password}"
        # Anonymous / no-pass
        prefix = f"{domain}/" if domain else ""
        return f"{prefix}"

    def _tool_missing(self, key: str) -> RunResult:
        """Return a synthetic RunResult for a missing tool."""
        name = self.TOOLS.get(key, key)
        self.logger.warning(f"Impacket tool not found: {name}")
        return RunResult(
            command=name, returncode=RC_TOOL_NOT_FOUND, stdout="",
            stderr=f"Tool not found: {name}",
            duration=0.0, success=False,
        )
