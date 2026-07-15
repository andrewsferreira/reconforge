"""ReconForge AD - Bloodhound-Python JSON Output Parser.

Parses bloodhound-python generated JSON files:
- users.json    : Domain user objects with properties and memberships
- groups.json   : Group objects with members and admin flags
- computers.json: Computer accounts with sessions and local admins
- domains.json  : Domain objects with trusts and policies
- sessions.json : Active session data (who is logged in where)

Author: Andrews Ferreira
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class BloodhoundUser:
    """A user object from bloodhound JSON output."""
    object_id: str = ""
    principal_name: str = ""
    display_name: str = ""
    description: str = ""
    enabled: bool = True
    admin_count: bool = False
    has_spn: bool = False
    dont_req_preauth: bool = False
    password_not_reqd: bool = False
    pwd_last_set: int = 0
    last_logon: int = 0
    spn_targets: list[str] = field(default_factory=list)
    member_of: list[str] = field(default_factory=list)
    is_da: bool = False
    is_high_value: bool = False
    sensitive: bool = False
    unconstraineddelegation: bool = False
    allowedtodelegate: list[str] = field(default_factory=list)

    @property
    def sam_account_name(self) -> str:
        """Extract sAMAccountName from principal name (USER@DOMAIN)."""
        if "@" in self.principal_name:
            return self.principal_name.split("@")[0]
        return self.principal_name


@dataclass
class BloodhoundGroup:
    """A group object from bloodhound JSON output."""
    object_id: str = ""
    principal_name: str = ""
    description: str = ""
    admin_count: bool = False
    members: list[dict[str, str]] = field(default_factory=list)
    member_count: int = 0
    is_high_value: bool = False

    @property
    def name(self) -> str:
        if "@" in self.principal_name:
            return self.principal_name.split("@")[0]
        return self.principal_name


@dataclass
class BloodhoundComputer:
    """A computer object from bloodhound JSON output."""
    object_id: str = ""
    principal_name: str = ""
    os: str = ""
    enabled: bool = True
    unconstraineddelegation: bool = False
    allowedtodelegate: list[str] = field(default_factory=list)
    allowedtoact: list[dict[str, str]] = field(default_factory=list)
    has_laps: bool = False
    local_admins: list[dict[str, str]] = field(default_factory=list)
    sessions: list[dict[str, str]] = field(default_factory=list)
    is_dc: bool = False

    @property
    def hostname(self) -> str:
        if "@" in self.principal_name:
            return self.principal_name.split("@")[0]
        return self.principal_name


@dataclass
class BloodhoundDomain:
    """A domain object from bloodhound JSON output."""
    object_id: str = ""
    name: str = ""
    functional_level: str = ""
    trusts: list[dict[str, str]] = field(default_factory=list)
    child_domains: list[str] = field(default_factory=list)
    user_count: int = 0
    group_count: int = 0
    computer_count: int = 0


@dataclass
class BloodhoundSession:
    """A session object from bloodhound JSON output."""
    user_sid: str = ""
    computer_sid: str = ""
    user_name: str = ""
    computer_name: str = ""


class BloodhoundParser:
    """Parse bloodhound-python JSON output files."""

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def parse_users_json(self, data: str) -> list[BloodhoundUser]:
        """Parse bloodhound users JSON output.

        Args:
            data: Raw JSON string or file path to users JSON.

        Returns:
            List of BloodhoundUser objects.
        """
        raw = self._load_json(data)
        if not raw:
            return []

        users: list[BloodhoundUser] = []
        entries = raw.get("data", raw) if isinstance(raw, dict) else raw

        if isinstance(entries, dict):
            entries = [entries]

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            props = self._dict_field(entry, "Properties", "properties")

            user = BloodhoundUser(
                object_id=self._str_field(entry, "ObjectIdentifier", "objectid"),
                principal_name=props.get("name", ""),
                display_name=props.get("displayname", ""),
                description=props.get("description", ""),
                enabled=props.get("enabled", True),
                admin_count=props.get("admincount", False),
                has_spn=props.get("hasspn", False),
                dont_req_preauth=props.get("dontreqpreauth", False),
                password_not_reqd=props.get("passwordnotreqd", False),
                pwd_last_set=props.get("pwdlastset", 0),
                last_logon=props.get("lastlogon", 0),
                spn_targets=props.get("serviceprincipalnames", []),
                is_high_value=props.get("highvalue", False),
                sensitive=props.get("sensitive", False),
                unconstraineddelegation=props.get(
                    "unconstraineddelegation", False),
                allowedtodelegate=props.get("allowedtodelegate", []),
            )

            # Check group memberships
            member_of = entry.get("MemberOf",
                                  entry.get("memberof", []))
            if isinstance(member_of, list):
                user.member_of = [
                    m.get("ObjectIdentifier", m) if isinstance(m, dict)
                    else str(m)
                    for m in member_of
                ]

            users.append(user)

        return users

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------

    def parse_groups_json(self, data: str) -> list[BloodhoundGroup]:
        """Parse bloodhound groups JSON output.

        Args:
            data: Raw JSON string or file path.

        Returns:
            List of BloodhoundGroup objects.
        """
        raw = self._load_json(data)
        if not raw:
            return []

        groups: list[BloodhoundGroup] = []
        entries = raw.get("data", raw) if isinstance(raw, dict) else raw

        if isinstance(entries, dict):
            entries = [entries]

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            props = self._dict_field(entry, "Properties", "properties")
            members_raw = entry.get("Members",
                                    entry.get("members", []))

            group = BloodhoundGroup(
                object_id=self._str_field(entry, "ObjectIdentifier", "objectid"),
                principal_name=props.get("name", ""),
                description=props.get("description", ""),
                admin_count=props.get("admincount", False),
                members=members_raw if isinstance(members_raw, list) else [],
                member_count=len(members_raw) if isinstance(members_raw, list) else 0,
                is_high_value=props.get("highvalue", False),
            )
            groups.append(group)

        return groups

    # ------------------------------------------------------------------
    # Computers
    # ------------------------------------------------------------------

    def parse_computers_json(self, data: str) -> list[BloodhoundComputer]:
        """Parse bloodhound computers JSON output.

        Args:
            data: Raw JSON string or file path.

        Returns:
            List of BloodhoundComputer objects.
        """
        raw = self._load_json(data)
        if not raw:
            return []

        computers: list[BloodhoundComputer] = []
        entries = raw.get("data", raw) if isinstance(raw, dict) else raw

        if isinstance(entries, dict):
            entries = [entries]

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            props = self._dict_field(entry, "Properties", "properties")

            comp = BloodhoundComputer(
                object_id=self._str_field(entry, "ObjectIdentifier", "objectid"),
                principal_name=props.get("name", ""),
                os=props.get("operatingsystem", ""),
                enabled=props.get("enabled", True),
                unconstraineddelegation=props.get(
                    "unconstraineddelegation", False),
                allowedtodelegate=props.get("allowedtodelegate", []),
                has_laps=props.get("haslaps", False),
                is_dc=props.get("isdc", False),
            )

            # Local admins
            local_admins = entry.get("LocalAdmins",
                                     entry.get("localadmins", []))
            if isinstance(local_admins, list):
                comp.local_admins = local_admins

            # Sessions
            sessions = entry.get("Sessions",
                                 entry.get("sessions", []))
            if isinstance(sessions, list):
                comp.sessions = sessions

            # AllowedToAct (RBCD)
            allowed = entry.get("AllowedToAct",
                                entry.get("allowedtoact", []))
            if isinstance(allowed, list):
                comp.allowedtoact = allowed

            computers.append(comp)

        return computers

    # ------------------------------------------------------------------
    # Domains
    # ------------------------------------------------------------------

    def parse_domains_json(self, data: str) -> list[BloodhoundDomain]:
        """Parse bloodhound domains JSON output.

        Args:
            data: Raw JSON string or file path.

        Returns:
            List of BloodhoundDomain objects.
        """
        raw = self._load_json(data)
        if not raw:
            return []

        domains: list[BloodhoundDomain] = []
        entries = raw.get("data", raw) if isinstance(raw, dict) else raw

        if isinstance(entries, dict):
            entries = [entries]

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            props = self._dict_field(entry, "Properties", "properties")

            domain = BloodhoundDomain(
                object_id=self._str_field(entry, "ObjectIdentifier", "objectid"),
                name=props.get("name", ""),
                functional_level=props.get("functionallevel", ""),
            )

            # Trusts
            trusts = entry.get("Trusts", entry.get("trusts", []))
            if isinstance(trusts, list):
                domain.trusts = trusts

            # Child domains
            children = entry.get("ChildObjects",
                                 entry.get("childobjects", []))
            if isinstance(children, list):
                domain.child_domains = [
                    c.get("ObjectIdentifier", str(c))
                    if isinstance(c, dict) else str(c)
                    for c in children
                ]

            domains.append(domain)

        return domains

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def parse_sessions_json(self, data: str) -> list[BloodhoundSession]:
        """Parse bloodhound sessions JSON output.

        Args:
            data: Raw JSON string or file path.

        Returns:
            List of BloodhoundSession objects.
        """
        raw = self._load_json(data)
        if not raw:
            return []

        sessions: list[BloodhoundSession] = []
        entries = raw.get("data", raw) if isinstance(raw, dict) else raw

        if isinstance(entries, dict):
            entries = [entries]

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            session = BloodhoundSession(
                user_sid=self._str_field(entry, "UserSID", "usersid"),
                computer_sid=self._str_field(entry, "ComputerSID", "computersid"),
                user_name=self._str_field(entry, "UserName", "username"),
                computer_name=self._str_field(entry, "ComputerName", "computername"),
            )
            sessions.append(session)

        return sessions

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _dict_field(entry: dict, *keys: str) -> dict:
        """Return the first key's value that is itself a dict.

        Unlike ``dict.get(key, fallback)``, this also falls through past a
        key that is present but explicitly ``null`` in the source JSON —
        bloodhound-python has been observed to emit exactly that for
        malformed/incomplete collector output, the same crash class fixed
        for ``api/nuclei_parser.py``'s ``"info": null`` case.
        """
        for key in keys:
            value = entry.get(key)
            if isinstance(value, dict):
                return value
        return {}

    @staticmethod
    def _str_field(entry: dict, *keys: str, default: str = "") -> str:
        """Return the first key's value that is a string, else *default*."""
        for key in keys:
            value = entry.get(key)
            if isinstance(value, str):
                return value
        return default

    @staticmethod
    def _load_json(data: str) -> dict | list | None:
        """Load JSON from a string or file path.

        Args:
            data: JSON string or path to a .json file.

        Returns:
            Parsed JSON object, or None on failure.
        """
        if not data:
            return None

        # Try as file path first
        path = Path(data)
        if path.exists() and path.is_file():
            try:
                with open(path, encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass

        # Try as raw JSON string
        try:
            return json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return None
