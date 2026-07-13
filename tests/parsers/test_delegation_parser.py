"""Smoke tests for modules.ad.parsers.delegation_parser – DelegationParser.

Phase 7-G: proves DelegationParser.parse_unconstrained() still works
end-to-end after _split_ldap_entries() was refactored to delegate to the
shared modules.ad.parsers.ldif_utils.split_ldif_entries().
"""

import textwrap

from modules.ad.parsers.delegation_parser import DelegationParser


def test_parse_unconstrained_end_to_end():
    parser = DelegationParser()
    text = textwrap.dedent("""\
        dn: CN=DC01,OU=Domain Controllers,DC=corp,DC=local
        sAMAccountName: DC01$
        userAccountControl: 532480
        objectClass: computer

        dn: CN=svc-legacy,CN=Users,DC=corp,DC=local
        sAMAccountName: svc-legacy
        userAccountControl: 524288
        objectClass: user
    """)

    entries = parser.parse_unconstrained(text)

    assert len(entries) == 2
    dc_entry = next(e for e in entries if e.account_name == "DC01$")
    assert dc_entry.is_dc is True
    assert dc_entry.account_type == "computer"

    svc_entry = next(e for e in entries if e.account_name == "svc-legacy")
    assert svc_entry.is_dc is False
    assert svc_entry.account_type == "user"
