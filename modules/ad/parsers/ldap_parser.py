"""ReconForge AD - LDAP Output Parser.

Parses ldapsearch text output to extract:
- Naming contexts (base DN, config DN, schema DN)
- Users with AD attributes
- Groups with membership
- Computer accounts
- Trust relationships
- GPOs
- Password policies
- Service Principal Names (Kerberoasting targets)
- AS-REP roastable users

Author: Andrews Ferreira
"""

from dataclasses import dataclass, field
from typing import Dict, List

from modules.ad.parsers.ldif_utils import split_ldif_entries


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class LdapUser:
    """An AD user extracted from LDAP."""
    sam_account_name: str = ""
    cn: str = ""
    description: str = ""
    member_of: List[str] = field(default_factory=list)
    user_account_control: int = 0
    pwd_last_set: str = ""
    last_logon: str = ""
    spn: List[str] = field(default_factory=list)
    admin_count: int = 0
    dn: str = ""

    @property
    def is_disabled(self) -> bool:
        return bool(self.user_account_control & 0x0002)

    @property
    def dont_require_preauth(self) -> bool:
        return bool(self.user_account_control & 0x400000)

    @property
    def has_spn(self) -> bool:
        return len(self.spn) > 0

    @property
    def is_admin(self) -> bool:
        return self.admin_count == 1


@dataclass
class LdapGroup:
    """An AD group extracted from LDAP."""
    cn: str = ""
    description: str = ""
    members: List[str] = field(default_factory=list)
    group_type: str = ""
    dn: str = ""
    admin_count: int = 0


@dataclass
class LdapComputer:
    """A computer account extracted from LDAP."""
    cn: str = ""
    dns_hostname: str = ""
    os: str = ""
    os_version: str = ""
    os_sp: str = ""
    user_account_control: int = 0
    spn: List[str] = field(default_factory=list)
    last_logon: str = ""
    dn: str = ""

    @property
    def is_dc(self) -> bool:
        """Check SERVER_TRUST_ACCOUNT flag (0x2000) for domain controllers."""
        return bool(self.user_account_control & 0x2000)


@dataclass
class LdapTrust:
    """A domain trust extracted from LDAP."""
    cn: str = ""
    trust_partner: str = ""
    trust_direction: int = 0
    trust_type: int = 0
    trust_attributes: int = 0
    flat_name: str = ""

    @property
    def direction_str(self) -> str:
        return {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}.get(
            self.trust_direction, "Unknown"
        )

    @property
    def type_str(self) -> str:
        return {1: "Downlevel", 2: "Uplevel", 3: "MIT", 4: "DCE"}.get(
            self.trust_type, "Unknown"
        )


@dataclass
class LdapGPO:
    """A Group Policy Object extracted from LDAP."""
    display_name: str = ""
    cn: str = ""
    gpc_file_path: str = ""
    version: str = ""
    flags: str = ""
    dn: str = ""


@dataclass
class LdapDomainInfo:
    """Domain-level information from LDAP."""
    base_dn: str = ""
    config_dn: str = ""
    schema_dn: str = ""
    domain_name: str = ""
    forest_name: str = ""
    functional_level: str = ""
    domain_sid: str = ""
    default_naming_context: str = ""
    server_name: str = ""


@dataclass
class LdapPasswordPolicy:
    """Domain password policy from LDAP."""
    min_length: int = 0
    max_age: str = ""
    min_age: str = ""
    history_length: int = 0
    complexity: bool = False
    lockout_threshold: int = 0
    lockout_duration: str = ""
    lockout_observation_window: str = ""


class ADLdapParser:
    """Parse ldapsearch output for Active Directory objects."""

    # ------------------------------------------------------------------
    # Entry-level parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _split_entries(text: str) -> List[Dict[str, List[str]]]:
        """Split ldapsearch text output into a list of attribute dicts.

        Each entry is separated by a blank line.  Attributes that appear
        multiple times are collected into lists.
        """
        return split_ldif_entries(text)

    @staticmethod
    def _first(d: Dict[str, List[str]], key: str, default: str = "") -> str:
        vals = d.get(key, [])
        return vals[0] if vals else default

    @staticmethod
    def _all(d: Dict[str, List[str]], key: str) -> List[str]:
        return d.get(key, [])

    @staticmethod
    def _int(d: Dict[str, List[str]], key: str, default: int = 0) -> int:
        val = d.get(key, [""])[0] if d.get(key) else ""
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    # ------------------------------------------------------------------
    # Naming contexts / RootDSE
    # ------------------------------------------------------------------

    def parse_rootdse(self, text: str) -> LdapDomainInfo:
        """Parse RootDSE / naming-contexts output."""
        info = LdapDomainInfo()
        entries = self._split_entries(text)
        if not entries:
            return info

        entry = entries[0]
        contexts = self._all(entry, "namingcontexts")
        for ctx in contexts:
            ctx_lower = ctx.lower()
            if ctx_lower.startswith("cn=configuration"):
                info.config_dn = ctx
            elif ctx_lower.startswith("cn=schema"):
                info.schema_dn = ctx
            elif "domaindnszones" not in ctx_lower and "forestdnszones" not in ctx_lower:
                if not info.base_dn:
                    info.base_dn = ctx

        info.default_naming_context = self._first(entry, "defaultnamingcontext", info.base_dn)
        info.server_name = self._first(entry, "servername")
        info.domain_name = self._first(entry, "ldapservicename").split("@")[-1] if self._first(entry, "ldapservicename") else ""
        info.forest_name = self._first(entry, "rootdomainnamingcontext")

        # Functional level
        fl = self._first(entry, "domainfunctionalitylevel") or self._first(entry, "domaincontrollerfunctionalitylevel")
        if not fl:
            fl = self._first(entry, "supportedldapversion")
        info.functional_level = self._resolve_functional_level(fl)

        # Derive domain name from base DN
        if not info.domain_name and info.base_dn:
            info.domain_name = self._dn_to_domain(info.base_dn)

        return info

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def parse_users(self, text: str) -> List[LdapUser]:
        """Parse LDAP user query output."""
        users: List[LdapUser] = []
        for entry in self._split_entries(text):
            sam = self._first(entry, "samaccountname")
            if not sam:
                continue
            user = LdapUser(
                sam_account_name=sam,
                cn=self._first(entry, "cn"),
                description=self._first(entry, "description"),
                member_of=self._all(entry, "memberof"),
                user_account_control=self._int(entry, "useraccountcontrol"),
                pwd_last_set=self._first(entry, "pwdlastset"),
                last_logon=self._first(entry, "lastlogon"),
                spn=self._all(entry, "serviceprincipalname"),
                admin_count=self._int(entry, "admincount"),
                dn=self._first(entry, "dn"),
            )
            users.append(user)
        return users

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------

    def parse_groups(self, text: str) -> List[LdapGroup]:
        """Parse LDAP group query output."""
        groups: List[LdapGroup] = []
        for entry in self._split_entries(text):
            cn = self._first(entry, "cn")
            if not cn:
                continue
            group = LdapGroup(
                cn=cn,
                description=self._first(entry, "description"),
                members=self._all(entry, "member"),
                group_type=self._first(entry, "grouptype"),
                dn=self._first(entry, "dn"),
                admin_count=self._int(entry, "admincount"),
            )
            groups.append(group)
        return groups

    # ------------------------------------------------------------------
    # Computers
    # ------------------------------------------------------------------

    def parse_computers(self, text: str) -> List[LdapComputer]:
        """Parse LDAP computer query output."""
        computers: List[LdapComputer] = []
        for entry in self._split_entries(text):
            cn = self._first(entry, "cn")
            if not cn:
                continue
            comp = LdapComputer(
                cn=cn,
                dns_hostname=self._first(entry, "dnshostname"),
                os=self._first(entry, "operatingsystem"),
                os_version=self._first(entry, "operatingsystemversion"),
                os_sp=self._first(entry, "operatingsystemservicepack"),
                user_account_control=self._int(entry, "useraccountcontrol"),
                spn=self._all(entry, "serviceprincipalname"),
                last_logon=self._first(entry, "lastlogon"),
                dn=self._first(entry, "dn"),
            )
            computers.append(comp)
        return computers

    # ------------------------------------------------------------------
    # Trusts
    # ------------------------------------------------------------------

    def parse_trusts(self, text: str) -> List[LdapTrust]:
        """Parse LDAP trust query output."""
        trusts: List[LdapTrust] = []
        for entry in self._split_entries(text):
            cn = self._first(entry, "cn")
            if not cn:
                continue
            trust = LdapTrust(
                cn=cn,
                trust_partner=self._first(entry, "trustpartner"),
                trust_direction=self._int(entry, "trustdirection"),
                trust_type=self._int(entry, "trusttype"),
                trust_attributes=self._int(entry, "trustattributes"),
                flat_name=self._first(entry, "flatname"),
            )
            trusts.append(trust)
        return trusts

    # ------------------------------------------------------------------
    # GPOs
    # ------------------------------------------------------------------

    def parse_gpos(self, text: str) -> List[LdapGPO]:
        """Parse LDAP GPO query output."""
        gpos: List[LdapGPO] = []
        for entry in self._split_entries(text):
            dn_val = self._first(entry, "dn")
            display = self._first(entry, "displayname")
            if not display and not dn_val:
                continue
            gpo = LdapGPO(
                display_name=display,
                cn=self._first(entry, "cn"),
                gpc_file_path=self._first(entry, "gpcfilesyspath"),
                version=self._first(entry, "versionnumber"),
                flags=self._first(entry, "flags"),
                dn=dn_val,
            )
            gpos.append(gpo)
        return gpos

    # ------------------------------------------------------------------
    # Password policy
    # ------------------------------------------------------------------

    def parse_password_policy(self, text: str) -> LdapPasswordPolicy:
        """Parse LDAP password policy query output."""
        policy = LdapPasswordPolicy()
        for entry in self._split_entries(text):
            policy.min_length = self._int(entry, "minpwdlength")
            policy.max_age = self._first(entry, "maxpwdage")
            policy.min_age = self._first(entry, "minpwdage")
            policy.history_length = self._int(entry, "pwdhistorylength")
            # pwdProperties bitmask: bit 0 = complexity enabled
            pwd_props = self._int(entry, "pwdproperties")
            policy.complexity = bool(pwd_props & 1)
            policy.lockout_threshold = self._int(entry, "lockoutthreshold")
            policy.lockout_duration = self._first(entry, "lockoutduration")
            policy.lockout_observation_window = self._first(entry, "lockoutobservationwindow")
            if policy.min_length or policy.lockout_threshold:
                break  # Got domain entry
        return policy

    # ------------------------------------------------------------------
    # SPN / AS-REP
    # ------------------------------------------------------------------

    def parse_spn_accounts(self, text: str) -> List[LdapUser]:
        """Parse SPN-filtered user query (Kerberoasting targets)."""
        return self.parse_users(text)

    def parse_asrep_users(self, text: str) -> List[LdapUser]:
        """Parse AS-REP roastable user query."""
        return self.parse_users(text)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _dn_to_domain(dn: str) -> str:
        """Convert a base DN to a domain name (DC=corp,DC=local -> corp.local)."""
        parts = []
        for component in dn.split(","):
            component = component.strip()
            if component.upper().startswith("DC="):
                parts.append(component[3:])
        return ".".join(parts)

    @staticmethod
    def _resolve_functional_level(level_str: str) -> str:
        """Resolve numeric functional level to human-readable string."""
        levels = {
            "0": "Windows 2000",
            "1": "Windows Server 2003 Interim",
            "2": "Windows Server 2003",
            "3": "Windows Server 2008",
            "4": "Windows Server 2008 R2",
            "5": "Windows Server 2012",
            "6": "Windows Server 2012 R2",
            "7": "Windows Server 2016",
        }
        return levels.get(str(level_str).strip(), level_str or "Unknown")
