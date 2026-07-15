"""ReconForge LDAPSearch Tool Wrapper - LDAP directory enumeration.

All commands are built as structured argument lists (list[str]) to
prevent shell injection and improve reliability.

Config-aware: when a :class:`ConfigLoader` is provided, timeouts are
read from ``tools.yaml``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from core.runner import Runner, RunResult
from core.tool_config import ToolConfig

if TYPE_CHECKING:
    from core.config_loader import ConfigLoader


class LdapsearchTool:
    """Wrapper for ldapsearch LDAP enumeration."""

    TOOL_NAME = "ldapsearch"

    def __init__(self, runner: Runner, logger, output_dir: Path,
                 config: ConfigLoader | None = None):
        self.runner = runner
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.tool_cfg = ToolConfig(config, self.TOOL_NAME)

    def is_available(self) -> bool:
        """Check if ldapsearch is installed."""
        return self.runner.check_tool(self.TOOL_NAME)

    def get_base_dn(self, target: str, timeout: int = 30) -> RunResult:
        """Discover base DN via rootDSE query (anonymous bind)."""
        self.logger.info(f"Querying rootDSE on {target}")
        output_file = self.output_dir / "ldap_rootdse.txt"
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        cmd: list[str] = [
            "ldapsearch", "-x", "-H", f"ldap://{target}",
            "-s", "base", "(objectClass=*)",
            "namingContexts", "defaultNamingContext",
        ]
        return self.runner.run(cmd, timeout=effective_timeout, output_file=output_file)

    def enum_users(self, target: str, base_dn: str,
                   timeout: int = 120) -> RunResult:
        """Enumerate user objects."""
        self.logger.info(f"Enumerating LDAP users on {target}")
        output_file = self.output_dir / "ldap_users.txt"
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        cmd: list[str] = [
            "ldapsearch", "-x", "-H", f"ldap://{target}",
            "-b", base_dn,
            "(&(objectClass=user)(objectCategory=person))",
            "sAMAccountName", "displayName", "mail", "memberOf", "description",
        ]
        return self.runner.run(cmd, timeout=effective_timeout, output_file=output_file)

    def enum_groups(self, target: str, base_dn: str,
                    timeout: int = 120) -> RunResult:
        """Enumerate group objects."""
        self.logger.info(f"Enumerating LDAP groups on {target}")
        output_file = self.output_dir / "ldap_groups.txt"
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        cmd: list[str] = [
            "ldapsearch", "-x", "-H", f"ldap://{target}",
            "-b", base_dn,
            "(objectClass=group)",
            "cn", "member", "description",
        ]
        return self.runner.run(cmd, timeout=effective_timeout, output_file=output_file)

    def enum_computers(self, target: str, base_dn: str,
                       timeout: int = 120) -> RunResult:
        """Enumerate computer objects."""
        self.logger.info(f"Enumerating LDAP computers on {target}")
        output_file = self.output_dir / "ldap_computers.txt"
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        cmd: list[str] = [
            "ldapsearch", "-x", "-H", f"ldap://{target}",
            "-b", base_dn,
            "(objectClass=computer)",
            "cn", "dNSHostName", "operatingSystem",
        ]
        return self.runner.run(cmd, timeout=effective_timeout, output_file=output_file)

    def full_dump(self, target: str, base_dn: str,
                  timeout: int = 300) -> RunResult:
        """Full LDAP dump (anonymous)."""
        self.logger.info(f"Full LDAP dump on {target}")
        output_file = self.output_dir / "ldap_full_dump.txt"
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        cmd: list[str] = [
            "ldapsearch", "-x", "-H", f"ldap://{target}",
            "-b", base_dn,
            "(objectClass=*)", "*",
        ]
        return self.runner.run(cmd, timeout=effective_timeout, output_file=output_file)

    def authenticated_search(self, target: str, base_dn: str,
                             username: str, password: str,
                             ldap_filter: str = "(objectClass=*)",
                             attributes: str = "*",
                             timeout: int = 120) -> RunResult:
        """Authenticated LDAP search."""
        self.logger.info(f"Authenticated LDAP search on {target}")
        output_file = self.output_dir / "ldap_auth_search.txt"
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        cmd: list[str] = [
            "ldapsearch", "-x", "-H", f"ldap://{target}",
            "-b", base_dn,
            "-D", username, "-w", password,
            ldap_filter, attributes,
        ]
        return self.runner.run(cmd, timeout=effective_timeout, output_file=output_file)
