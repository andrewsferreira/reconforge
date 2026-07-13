"""ReconForge AD Collector — LDAP data gathering.

Author: Andrews Ferreira

Collects users, groups, computers, OUs, GPOs, password policy,
SPN accounts, AS-REP roastable accounts, and trusts via LDAP.
"""

from typing import Any, Dict, List, Optional

from modules.ad.collectors.base import CollectorBase, CollectorResult
from modules.ad.tools.ldapsearch import ADLdapsearchTool
from modules.ad.parsers.ldap_parser import ADLdapParser


class LdapCollector(CollectorBase):
    """Pure LDAP data collection — no analysis, no findings."""

    COLLECTOR_NAME = "ldap"

    def __init__(self, ldapsearch: ADLdapsearchTool,
                 ldap_parser: ADLdapParser, **kwargs) -> None:
        super().__init__(**kwargs)
        self.ldapsearch = ldapsearch
        self.parser = ldap_parser

    # ── Main entry ─────────────────────────────────────────────────

    def collect(
        self,
        target: str,
        domain: str = "",
        base_dn: str = "",
        username: str = "",
        password: str = "",
        **kwargs,
    ) -> CollectorResult:
        """Run all LDAP collection steps and return unified result."""
        result = CollectorResult(source=self.COLLECTOR_NAME)

        if not self.ldapsearch.is_available():
            result.errors.append("ldapsearch not available")
            return result

        if not base_dn:
            result.errors.append("No base_dn provided")
            return result

        # Collect all data
        result.data["users"] = self.collect_users(target, base_dn, username, password)
        result.data["groups"] = self.collect_groups(target, base_dn, username, password)
        result.data["computers"] = self.collect_computers(target, base_dn, username, password)
        result.data["spn_accounts"] = self.collect_spn_accounts(target, base_dn, username, password)
        result.data["asrep_users"] = self.collect_asrep_users(target, base_dn, username, password)
        result.data["trusts"] = self.collect_trusts(target, base_dn, username, password)
        result.data["gpos"] = self.collect_gpos(target, base_dn, username, password)
        result.data["password_policy"] = self.collect_password_policy(target, base_dn, username, password)

        result.success = True
        return result

    # ── Individual collectors ──────────────────────────────────────

    def collect_rootdse(self, target: str) -> Dict[str, Any]:
        """Test anonymous bind and extract RootDSE."""
        if not self.opsec.check("ldap_anonymous_bind"):
            return {"anonymous": False}
        run = self.ldapsearch.anonymous_bind_test(target)
        if not run.success:
            return {"anonymous": False}

        anonymous = "namingcontexts" in run.stdout.lower()
        info = self.parser.parse_rootdse(run.stdout)
        return {
            "anonymous": anonymous,
            "base_dn": info.base_dn,
            "domain_name": info.domain_name,
            "forest_name": info.forest_name,
            "config_dn": info.config_dn,
            "schema_dn": info.schema_dn,
            "functional_level": info.functional_level,
            "server_name": info.server_name,
        }

    def collect_users(self, target: str, base_dn: str,
                      username: str = "", password: str = "") -> List[Dict]:
        """Return list of user dicts."""
        if not self.opsec.check("ldap_user_enum"):
            return []
        run = self.ldapsearch.query_users(target, base_dn, username=username, password=password)
        if not run.success:
            return []
        users = self.parser.parse_users(run.stdout)
        return [
            {
                "username": u.sam_account_name,
                "cn": u.cn,
                "description": u.description,
                "disabled": u.is_disabled,
                "admin_count": u.admin_count,
                "has_spn": u.has_spn,
                "dont_require_preauth": u.dont_require_preauth,
                "pwd_last_set": u.pwd_last_set,
                "last_logon": u.last_logon,
                "member_of": u.member_of,
                "is_admin": u.is_admin,
            }
            for u in users
        ]

    def collect_groups(self, target: str, base_dn: str,
                       username: str = "", password: str = "") -> List[Dict]:
        """Return list of group dicts."""
        if not self.opsec.check("ldap_group_enum"):
            return []
        run = self.ldapsearch.query_groups(target, base_dn, username=username, password=password)
        if not run.success:
            return []
        groups = self.parser.parse_groups(run.stdout)
        return [
            {
                "cn": g.cn,
                "description": g.description,
                "members": g.members,
                "member_count": len(g.members),
                "admin_count": g.admin_count,
            }
            for g in groups
        ]

    def collect_computers(self, target: str, base_dn: str,
                          username: str = "", password: str = "") -> List[Dict]:
        """Return list of computer dicts."""
        if not self.opsec.check("ldap_computer_enum"):
            return []
        run = self.ldapsearch.query_computers(target, base_dn, username=username, password=password)
        if not run.success:
            return []
        computers = self.parser.parse_computers(run.stdout)
        return [
            {
                "cn": c.cn,
                "dns_hostname": c.dns_hostname,
                "os": c.os,
                "os_version": c.os_version,
                "is_dc": c.is_dc,
            }
            for c in computers
        ]

    def collect_spn_accounts(self, target: str, base_dn: str,
                             username: str = "", password: str = "") -> List[Dict]:
        """Return list of SPN account dicts (Kerberoasting targets)."""
        if not self.opsec.check("ldap_spn_query"):
            return []
        run = self.ldapsearch.query_spn_accounts(target, base_dn, username=username, password=password)
        if not run.success:
            return []
        spn_users = self.parser.parse_spn_accounts(run.stdout)
        return [
            {
                "username": u.sam_account_name,
                "spn": u.spn,
                "description": u.description,
                "admin_count": u.admin_count,
                "pwd_last_set": u.pwd_last_set,
            }
            for u in spn_users
        ]

    def collect_asrep_users(self, target: str, base_dn: str,
                            username: str = "", password: str = "") -> List[Dict]:
        """Return list of users with pre-auth disabled."""
        if not self.opsec.check("ldap_asrep_query"):
            return []
        run = self.ldapsearch.query_asrep_users(target, base_dn, username=username, password=password)
        if not run.success:
            return []
        users = self.parser.parse_asrep_users(run.stdout)
        return [
            {"username": u.sam_account_name}
            for u in users if u.sam_account_name
        ]

    def collect_trusts(self, target: str, base_dn: str,
                       username: str = "", password: str = "") -> List[Dict]:
        """Return list of trust relationship dicts."""
        if not self.opsec.check("ldap_trust_enum"):
            return []
        run = self.ldapsearch.query_trusts(target, base_dn, username=username, password=password)
        if not run.success:
            return []
        trusts = self.parser.parse_trusts(run.stdout)
        return [
            {
                "partner": t.trust_partner,
                "direction": t.direction_str,
                "type": t.type_str,
                "flat_name": t.flat_name,
            }
            for t in trusts
        ]

    def collect_gpos(self, target: str, base_dn: str,
                     username: str = "", password: str = "") -> List[Dict]:
        """Return list of GPO dicts."""
        if not self.opsec.check("ldap_gpo_enum"):
            return []
        run = self.ldapsearch.query_gpos(target, base_dn, username=username, password=password)
        if not run.success:
            return []
        gpos = self.parser.parse_gpos(run.stdout)
        return [
            {
                "display_name": g.display_name,
                "cn": g.cn,
                "gpc_file_path": g.gpc_file_path,
                "version": g.version,
            }
            for g in gpos
        ]

    def collect_password_policy(self, target: str, base_dn: str,
                                username: str = "", password: str = "") -> Dict:
        """Return password policy dict."""
        if not self.opsec.check("ldap_password_policy"):
            return {}
        run = self.ldapsearch.query_password_policy(target, base_dn, username=username, password=password)
        if not run.success:
            return {}
        policy = self.parser.parse_password_policy(run.stdout)
        return {
            "min_length": policy.min_length,
            "complexity": policy.complexity,
            "lockout_threshold": policy.lockout_threshold,
            "lockout_duration": policy.lockout_duration,
            "lockout_observation_window": policy.lockout_observation_window,
            "history_length": policy.history_length,
            "max_age": policy.max_age,
            "min_age": policy.min_age,
        }
