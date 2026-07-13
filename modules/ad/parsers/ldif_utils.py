"""Shared LDIF entry-splitting for AD module ldapsearch-output parsers.

Extracted from what were two independently-maintained, byte-for-byte
identical copies of this algorithm (modules/ad/parsers/ldap_parser.py's
ADLdapParser._split_entries and modules/ad/parsers/delegation_parser.py's
DelegationParser._split_ldap_entries — the latter's own docstring said
"Replicates the pattern from ADLdapParser._split_entries", i.e. the
duplication was already self-acknowledged in code).

modules/network/parsers/ldap_parser.py has a third, independently-written
LDIF splitter (LdapParser._parse_objects) that is NOT consolidated here:
it returns a different type (LdapObject with a dedicated .dn field, not a
bare dict), and — more importantly — it preserves attribute name casing
(callers look up mixed-case LDAP attribute names like "sAMAccountName",
"dNSHostName", "operatingSystem"), whereas this function lowercases keys.
Unifying it would mean either rewriting every case-sensitive .get() call
site in that file or adding a case-mode parameter — a larger, riskier
change than the two truly-identical AD-module copies warranted, so it was
deliberately left as-is.

Author: Andrews Ferreira
"""

from typing import Dict, List


def split_ldif_entries(text: str) -> List[Dict[str, List[str]]]:
    """Split ldapsearch text output into a list of attribute dicts.

    Each entry is separated by a blank line. Attributes that appear
    multiple times are collected into lists. Attribute names are
    lowercased; ``# comment``, ``search:``, and ``result:`` metadata
    lines are skipped.
    """
    entries: List[Dict[str, List[str]]] = []
    current: Dict[str, List[str]] = {}
    prev_key = ""

    for raw_line in text.splitlines():
        line = raw_line.rstrip()

        # Skip comments and search result metadata
        if line.startswith("#") or line.startswith("search:") or line.startswith("result:"):
            continue

        # Blank line = end of entry
        if not line:
            if current:
                entries.append(current)
                current = {}
                prev_key = ""
            continue

        # Continuation line (starts with space)
        if line.startswith(" ") and prev_key:
            current[prev_key][-1] += line.strip()
            continue

        # Normal attribute line
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            # Base64 encoded value
            if value.startswith(":"):
                value = value[1:].strip()
            current.setdefault(key, []).append(value)
            prev_key = key

    if current:
        entries.append(current)

    return entries
