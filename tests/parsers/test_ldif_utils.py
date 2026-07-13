"""Tests for modules.ad.parsers.ldif_utils.split_ldif_entries.

Phase 7-G: extracted from two byte-for-byte identical implementations
(ADLdapParser._split_entries and DelegationParser._split_ldap_entries).
"""

import textwrap

from modules.ad.parsers.ldif_utils import split_ldif_entries


def test_splits_multiple_entries_on_blank_line():
    text = textwrap.dedent("""\
        dn: CN=Alice,CN=Users,DC=corp,DC=local
        sAMAccountName: alice
        mail: alice@corp.local

        dn: CN=Bob,CN=Users,DC=corp,DC=local
        sAMAccountName: bob
    """)
    entries = split_ldif_entries(text)
    assert len(entries) == 2
    assert entries[0]["samaccountname"] == ["alice"]
    assert entries[1]["samaccountname"] == ["bob"]


def test_attribute_names_are_lowercased():
    text = "dn: CN=Alice\nsAMAccountName: alice\n"
    entries = split_ldif_entries(text)
    assert entries[0]["samaccountname"] == ["alice"]
    assert "sAMAccountName" not in entries[0]


def test_repeated_attribute_collected_into_list():
    text = "dn: CN=Group\nmember: CN=Alice\nmember: CN=Bob\n"
    entries = split_ldif_entries(text)
    assert entries[0]["member"] == ["CN=Alice", "CN=Bob"]


def test_continuation_line_appended_to_previous_value():
    """LDIF continuation lines (leading space) are appended directly with
    no separator inserted, matching ldapsearch's own line-folding output."""
    text = "dn: CN=Alice\ndescription: Long text here\n and more text\n"
    entries = split_ldif_entries(text)
    assert entries[0]["description"] == ["Long text hereand more text"]


def test_base64_marker_stripped():
    text = "dn: CN=Alice\njpegphoto:: AAAA\n"
    entries = split_ldif_entries(text)
    assert entries[0]["jpegphoto"] == ["AAAA"]


def test_search_and_result_metadata_lines_skipped():
    text = "search: 2\nresult: 0 Success\ndn: CN=Alice\nmail: a@corp.local\n"
    entries = split_ldif_entries(text)
    assert len(entries) == 1
    assert "search" not in entries[0]
    assert "result" not in entries[0]


def test_comment_lines_skipped():
    text = "# extended LDIF\ndn: CN=Alice\nmail: a@corp.local\n"
    entries = split_ldif_entries(text)
    assert len(entries) == 1
    assert entries[0]["mail"] == ["a@corp.local"]


def test_empty_text_returns_empty_list():
    assert split_ldif_entries("") == []
