"""Tests for modules.network.parsers.smb_parser – SmbParser.

Phase 7-H: the network variant's access-denied detection only checked a
few explicit NT_STATUS_* strings, missing NT_STATUS_ACCOUNT_DISABLED and
bare ACCESS_DENIED/LOGON_FAILURE forms that modules/ad/parsers/smb_parser.py
already caught. Ported the broader pattern list.
"""

from modules.network.parsers.smb_parser import SmbParser


def test_parse_share_access_denies_on_account_disabled():
    parser = SmbParser()
    text = "tree connect failed: NT_STATUS_ACCOUNT_DISABLED"
    share = parser.parse_share_access(text, "C$")
    assert share.accessible is False
    assert share.permissions == "denied"


def test_parse_share_access_denies_on_bare_access_denied():
    """Some smbclient versions/locales emit ACCESS_DENIED without the
    NT_STATUS_ prefix — must still be classified as denied, not as a
    successful read."""
    parser = SmbParser()
    text = "ACCESS_DENIED listing \\\\target\\C$"
    share = parser.parse_share_access(text, "C$")
    assert share.accessible is False
    assert share.permissions == "denied"


def test_parse_share_access_still_classifies_bad_network_name_separately():
    """NT_STATUS_BAD_NETWORK_NAME must remain its own "not_found"
    classification, not get folded into "denied"."""
    parser = SmbParser()
    text = "tree connect failed: NT_STATUS_BAD_NETWORK_NAME"
    share = parser.parse_share_access(text, "MISSING$")
    assert share.accessible is False
    assert share.permissions == "not_found"


def test_parse_share_access_allows_normal_listing():
    parser = SmbParser()
    text = "  file.txt   1234  Mon Jan  1 00:00:00 2024\n"
    share = parser.parse_share_access(text, "public")
    assert share.accessible is True
    assert share.permissions == "read"


def test_parse_share_list_null_session_denied_on_account_disabled():
    parser = SmbParser()
    text = "Sharename       Type      Comment\nsession setup failed: NT_STATUS_ACCOUNT_DISABLED"
    result = parser.parse_share_list(text, target="10.10.10.1")
    assert result.null_session is False
    assert result.errors
