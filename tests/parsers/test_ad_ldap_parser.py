"""Smoke tests for modules.ad.parsers.ldap_parser – ADLdapParser.

Phase 7-G: proves ADLdapParser.parse_users() still works end-to-end
after _split_entries() was refactored to delegate to the shared
modules.ad.parsers.ldif_utils.split_ldif_entries().
"""

import textwrap

from modules.ad.parsers.ldap_parser import ADLdapParser


def test_parse_users_end_to_end():
    parser = ADLdapParser()
    text = textwrap.dedent("""\
        dn: CN=Alice,CN=Users,DC=corp,DC=local
        sAMAccountName: alice
        cn: Alice Smith
        description: Domain user
        memberOf: CN=Domain Admins,CN=Users,DC=corp,DC=local
        adminCount: 1

        dn: CN=Bob,CN=Users,DC=corp,DC=local
        sAMAccountName: bob
        cn: Bob Jones
    """)

    users = parser.parse_users(text)

    assert len(users) == 2
    assert users[0].sam_account_name == "alice"
    assert users[0].cn == "Alice Smith"
    assert users[0].admin_count == 1
    assert "CN=Domain Admins,CN=Users,DC=corp,DC=local" in users[0].member_of
    assert users[1].sam_account_name == "bob"
