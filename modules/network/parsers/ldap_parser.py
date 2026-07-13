"""ReconForge LDAP Parser - Parse ldapsearch output.

Extracts:
- Base DN and naming contexts
- User objects (sAMAccountName, displayName, mail)
- Group objects and memberships
- Computer objects
- Domain information
- Password policy settings
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class LdapObject:
    """A generic LDAP object."""
    dn: str = ""
    attributes: Dict[str, List[str]] = field(default_factory=dict)

    def get(self, attr: str, default: str = "") -> str:
        """Get first value of an attribute."""
        vals = self.attributes.get(attr, [])
        return vals[0] if vals else default

    def get_all(self, attr: str) -> List[str]:
        """Get all values of an attribute."""
        return self.attributes.get(attr, [])


@dataclass
class LdapResult:
    """Parsed LDAP search result."""
    target: str = ""
    base_dn: str = ""
    naming_contexts: List[str] = field(default_factory=list)
    default_naming_context: str = ""
    domain_name: str = ""
    objects: List[LdapObject] = field(default_factory=list)
    users: List[Dict[str, str]] = field(default_factory=list)
    groups: List[Dict[str, str]] = field(default_factory=list)
    computers: List[Dict[str, str]] = field(default_factory=list)
    anonymous_bind: bool = False
    raw_output: str = ""
    errors: List[str] = field(default_factory=list)


class LdapParser:
    """Parse ldapsearch output into structured data."""

    def parse(self, text: str, target: str = "") -> LdapResult:
        """Parse ldapsearch output.

        Args:
            text: Raw ldapsearch output text.
            target: Target IP or hostname.

        Returns:
            LdapResult with extracted data.
        """
        result = LdapResult(target=target, raw_output=text)

        if not text.strip():
            result.errors.append("Empty output")
            return result

        # Check for errors
        if "ldap_bind: Invalid credentials" in text:
            result.errors.append("Invalid credentials")
            return result
        if "Can't contact LDAP server" in text:
            result.errors.append("Cannot contact LDAP server")
            return result
        if "Operations error" in text and "result: 1" in text:
            result.errors.append("Operations error - may need authentication")
            return result

        result.anonymous_bind = True

        # Parse all LDAP objects
        objects = self._parse_objects(text)
        result.objects = objects

        # Extract naming contexts and base DN
        self._extract_naming_contexts(objects, result)

        # Classify objects
        for obj in objects:
            self._classify_object(obj, result)

        # Derive domain name from base DN
        if result.base_dn:
            result.domain_name = self._dn_to_domain(result.base_dn)

        return result

    def parse_rootdse(self, text: str, target: str = "") -> LdapResult:
        """Parse rootDSE query output specifically.

        Args:
            text: Raw ldapsearch rootDSE output.
            target: Target IP or hostname.

        Returns:
            LdapResult with naming context information.
        """
        result = self.parse(text, target)

        # Extra parsing for rootDSE attributes
        for obj in result.objects:
            for ctx in obj.get_all("namingContexts"):
                if ctx not in result.naming_contexts:
                    result.naming_contexts.append(ctx)

            default_ctx = obj.get("defaultNamingContext")
            if default_ctx:
                result.default_naming_context = default_ctx
                if not result.base_dn:
                    result.base_dn = default_ctx

        # If no default naming context, try to find one
        if not result.base_dn and result.naming_contexts:
            # Pick the one that looks like a domain DN
            for ctx in result.naming_contexts:
                if ctx.upper().startswith("DC="):
                    result.base_dn = ctx
                    break
            if not result.base_dn:
                result.base_dn = result.naming_contexts[0]

        return result

    def _parse_objects(self, text: str) -> List[LdapObject]:
        """Parse LDIF-formatted objects from ldapsearch output."""
        objects = []
        current_obj: Optional[LdapObject] = None
        current_attr = ""

        for line in text.splitlines():
            # Skip comments and empty lines between objects
            if line.startswith("#"):
                continue

            if not line.strip():
                if current_obj and (current_obj.dn or current_obj.attributes):
                    objects.append(current_obj)
                    current_obj = None
                    current_attr = ""
                continue

            # Continuation line (starts with space)
            if line.startswith(" ") and current_obj and current_attr:
                vals = current_obj.attributes.get(current_attr, [])
                if vals:
                    vals[-1] += line.strip()
                continue

            # DN line
            if line.lower().startswith("dn:"):
                if current_obj and (current_obj.dn or current_obj.attributes):
                    objects.append(current_obj)
                current_obj = LdapObject()
                current_obj.dn = line.split(":", 1)[1].strip()
                current_attr = ""
                continue

            # Attribute line
            if ":" in line:
                if current_obj is None:
                    current_obj = LdapObject()

                parts = line.split(":", 1)
                attr_name = parts[0].strip()
                attr_value = parts[1].strip() if len(parts) > 1 else ""

                # Handle base64 encoded values (attr:: value)
                if attr_value.startswith(":"):
                    attr_value = attr_value[1:].strip()
                    # Keep as-is for now; could base64 decode

                if attr_name not in current_obj.attributes:
                    current_obj.attributes[attr_name] = []
                current_obj.attributes[attr_name].append(attr_value)
                current_attr = attr_name

        # Don't forget the last object
        if current_obj and (current_obj.dn or current_obj.attributes):
            objects.append(current_obj)

        return objects

    def _extract_naming_contexts(self, objects: List[LdapObject],
                                  result: LdapResult):
        """Extract naming contexts from parsed objects."""
        for obj in objects:
            for ctx in obj.get_all("namingContexts"):
                if ctx not in result.naming_contexts:
                    result.naming_contexts.append(ctx)

            default_ctx = obj.get("defaultNamingContext")
            if default_ctx and not result.default_naming_context:
                result.default_naming_context = default_ctx
                result.base_dn = default_ctx

    def _classify_object(self, obj: LdapObject, result: LdapResult):
        """Classify an LDAP object as user, group, or computer."""
        object_classes = [oc.lower() for oc in obj.get_all("objectClass")]

        if "person" in object_classes or "user" in object_classes:
            user = {
                "dn": obj.dn,
                "username": obj.get("sAMAccountName"),
                "display_name": obj.get("displayName"),
                "email": obj.get("mail"),
                "description": obj.get("description"),
                "member_of": obj.get_all("memberOf"),
            }
            if user["username"]:
                result.users.append(user)

        elif "group" in object_classes:
            group = {
                "dn": obj.dn,
                "name": obj.get("cn"),
                "description": obj.get("description"),
                "members": obj.get_all("member"),
            }
            if group["name"]:
                result.groups.append(group)

        elif "computer" in object_classes:
            computer = {
                "dn": obj.dn,
                "name": obj.get("cn"),
                "dns_hostname": obj.get("dNSHostName"),
                "os": obj.get("operatingSystem"),
            }
            if computer["name"]:
                result.computers.append(computer)

    @staticmethod
    def _dn_to_domain(dn: str) -> str:
        """Convert a DN to domain name (DC=domain,DC=local -> domain.local)."""
        parts = []
        for component in dn.split(","):
            component = component.strip()
            if component.upper().startswith("DC="):
                parts.append(component.split("=", 1)[1])
        return ".".join(parts)

    def get_usernames(self, result: LdapResult) -> List[str]:
        """Get clean list of usernames."""
        return [u["username"] for u in result.users if u["username"]]

    def get_admin_users(self, result: LdapResult) -> List[Dict]:
        """Get users that are members of admin groups."""
        admin_groups = {"Domain Admins", "Administrators", "Enterprise Admins"}
        admins = []
        for user in result.users:
            for group_dn in user.get("member_of", []):
                for admin_group in admin_groups:
                    if admin_group.lower() in group_dn.lower():
                        admins.append(user)
                        break
        return admins
