"""ReconForge AD - ldapsearch Tool Wrapper.

LDAP directory queries for Active Directory enumeration.
Supports anonymous and authenticated binds.

All commands are built as structured argument lists (list[str]) to
prevent shell injection and improve reliability.

Config-aware: when a :class:`ConfigLoader` is provided, timeouts are
read from ``tools.yaml``.

Author: Andrews Ferreira
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from core.runner import Runner, RunResult
from core.tool_config import ToolConfig

if TYPE_CHECKING:
    from core.config_loader import ConfigLoader


class ADLdapsearchTool:
    """Wrapper for ldapsearch targeting Active Directory LDAP."""

    TOOL_NAME = "ldapsearch"

    def __init__(self, runner: Runner, logger, output_dir: Path,
                 opsec_mode: str = "normal",
                 config: Optional["ConfigLoader"] = None):
        self.runner = runner
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.opsec_mode = opsec_mode
        self.tool_cfg = ToolConfig(config, self.TOOL_NAME)

    def is_available(self) -> bool:
        """Check if ldapsearch is installed."""
        return self.runner.check_tool(self.TOOL_NAME)

    # ------------------------------------------------------------------
    # Core LDAP queries
    # ------------------------------------------------------------------

    def anonymous_bind_test(self, target: str, port: int = 389,
                            timeout: int = 30) -> RunResult:
        """Test for anonymous LDAP bind and retrieve RootDSE."""
        self.logger.info(f"Testing anonymous LDAP bind on {target}:{port}")
        out = self.output_dir / "ldap_rootdse.txt"
        cmd: List[str] = [
            "ldapsearch", "-x", "-H", f"ldap://{target}:{port}",
            "-s", "base", "-b", "", "(objectClass=*)", "*", "+",
        ]
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    def query_naming_contexts(self, target: str, port: int = 389,
                              timeout: int = 30) -> RunResult:
        """Retrieve naming contexts (base DN, configuration, schema)."""
        self.logger.info(f"Querying naming contexts on {target}")
        out = self.output_dir / "ldap_naming_contexts.txt"
        cmd: List[str] = [
            "ldapsearch", "-x", "-H", f"ldap://{target}:{port}",
            "-s", "base", "-b", "", "namingContexts",
        ]
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    def query_domain_info(self, target: str, base_dn: str,
                          port: int = 389, timeout: int = 60,
                          username: str = "", password: str = "") -> RunResult:
        """Query domain-level information (functional level, domain SID)."""
        self.logger.info(f"Querying domain info on {target} base={base_dn}")
        out = self.output_dir / "ldap_domain_info.txt"
        cmd = self._bind_args(target, port, username, password)
        cmd += [
            "-b", base_dn,
            "(objectClass=domain)",
            "dc", "name", "distinguishedName", "objectSid",
            "msDS-Behavior-Version",
        ]
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    def query_users(self, target: str, base_dn: str,
                    port: int = 389, timeout: int = 120,
                    username: str = "", password: str = "",
                    size_limit: int = 1000) -> RunResult:
        """Enumerate domain users via LDAP."""
        self.logger.info(f"Enumerating users via LDAP on {target}")
        out = self.output_dir / "ldap_users.txt"
        cmd = self._bind_args(target, port, username, password)
        cmd += [
            "-b", base_dn, "-z", str(size_limit),
            "(&(objectCategory=person)(objectClass=user))",
            "sAMAccountName", "cn", "description", "memberOf",
            "userAccountControl", "pwdLastSet", "lastLogon",
            "servicePrincipalName", "adminCount",
        ]
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    def query_groups(self, target: str, base_dn: str,
                     port: int = 389, timeout: int = 120,
                     username: str = "", password: str = "") -> RunResult:
        """Enumerate domain groups via LDAP."""
        self.logger.info(f"Enumerating groups via LDAP on {target}")
        out = self.output_dir / "ldap_groups.txt"
        cmd = self._bind_args(target, port, username, password)
        cmd += [
            "-b", base_dn,
            "(objectCategory=group)",
            "cn", "description", "member", "groupType",
            "distinguishedName", "adminCount",
        ]
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    def query_computers(self, target: str, base_dn: str,
                        port: int = 389, timeout: int = 120,
                        username: str = "", password: str = "") -> RunResult:
        """Enumerate computer accounts via LDAP."""
        self.logger.info(f"Enumerating computers via LDAP on {target}")
        out = self.output_dir / "ldap_computers.txt"
        cmd = self._bind_args(target, port, username, password)
        cmd += [
            "-b", base_dn,
            "(objectCategory=computer)",
            "cn", "dNSHostName", "operatingSystem",
            "operatingSystemVersion", "operatingSystemServicePack",
            "userAccountControl", "servicePrincipalName", "lastLogon",
        ]
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    def query_trusts(self, target: str, base_dn: str,
                     port: int = 389, timeout: int = 60,
                     username: str = "", password: str = "") -> RunResult:
        """Enumerate domain trust relationships."""
        self.logger.info(f"Enumerating trusts via LDAP on {target}")
        out = self.output_dir / "ldap_trusts.txt"
        cmd = self._bind_args(target, port, username, password)
        cmd += [
            "-b", base_dn,
            "(objectClass=trustedDomain)",
            "cn", "trustPartner", "trustDirection", "trustType",
            "trustAttributes", "flatName",
        ]
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    def query_gpos(self, target: str, base_dn: str,
                   port: int = 389, timeout: int = 120,
                   username: str = "", password: str = "") -> RunResult:
        """Enumerate Group Policy Objects via LDAP."""
        self.logger.info(f"Enumerating GPOs via LDAP on {target}")
        out = self.output_dir / "ldap_gpos.txt"
        cmd = self._bind_args(target, port, username, password)
        cmd += [
            "-b", base_dn,
            "(objectClass=groupPolicyContainer)",
            "displayName", "cn", "gPCFileSysPath",
            "gPCFunctionalityVersion", "versionNumber", "flags",
        ]
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    def query_password_policy(self, target: str, base_dn: str,
                              port: int = 389, timeout: int = 60,
                              username: str = "", password: str = "") -> RunResult:
        """Query default domain password policy."""
        self.logger.info(f"Querying password policy via LDAP on {target}")
        out = self.output_dir / "ldap_passpol.txt"
        cmd = self._bind_args(target, port, username, password)
        cmd += [
            "-b", base_dn,
            "(objectClass=domain)",
            "minPwdLength", "maxPwdAge", "minPwdAge", "pwdHistoryLength",
            "pwdProperties", "lockoutThreshold", "lockoutDuration",
            "lockOutObservationWindow",
        ]
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    def query_spn_accounts(self, target: str, base_dn: str,
                           port: int = 389, timeout: int = 120,
                           username: str = "", password: str = "") -> RunResult:
        """Find accounts with Service Principal Names (Kerberoasting targets)."""
        self.logger.info(f"Finding SPN accounts via LDAP on {target}")
        out = self.output_dir / "ldap_spn_accounts.txt"
        cmd = self._bind_args(target, port, username, password)
        cmd += [
            "-b", base_dn,
            "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
            "sAMAccountName", "servicePrincipalName", "description",
            "memberOf", "pwdLastSet", "adminCount",
        ]
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    def query_asrep_users(self, target: str, base_dn: str,
                          port: int = 389, timeout: int = 120,
                          username: str = "", password: str = "") -> RunResult:
        """Find accounts with pre-auth disabled (AS-REP roastable)."""
        self.logger.info(f"Finding AS-REP roastable users via LDAP on {target}")
        out = self.output_dir / "ldap_asrep_users.txt"
        cmd = self._bind_args(target, port, username, password)
        # UAC flag 4194304 = DONT_REQUIRE_PREAUTH
        cmd += [
            "-b", base_dn,
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
            "sAMAccountName", "cn", "description", "userAccountControl",
        ]
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _bind_args(target: str, port: int = 389,
                   username: str = "", password: str = "") -> List[str]:
        """Build ldapsearch bind arguments as a list."""
        cmd: List[str] = ["ldapsearch"]
        if username and password:
            cmd += ["-H", f"ldap://{target}:{port}",
                    "-D", username, "-w", password]
        else:
            cmd += ["-x", "-H", f"ldap://{target}:{port}"]
        return cmd
