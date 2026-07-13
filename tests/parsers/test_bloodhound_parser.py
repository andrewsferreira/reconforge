"""Tests for modules.ad.parsers.bloodhound_parser – BloodhoundParser.

Phase 7-D: every parse_*_json() method previously assumed each entry in
the parsed JSON list was a dict (entry.get(...)), raising an uncaught
AttributeError on a malformed non-dict entry and aborting the whole
file's parse. Now each loop skips non-dict entries instead of crashing.
"""

import json

import pytest

from modules.ad.parsers.bloodhound_parser import BloodhoundParser


@pytest.fixture
def parser():
    return BloodhoundParser()


def _users_payload(entries):
    return json.dumps({"data": entries})


def test_parse_users_json_valid_entry(parser):
    data = _users_payload([
        {"ObjectIdentifier": "S-1-5-21-1", "Properties": {"name": "alice@corp.local"}},
    ])
    users = parser.parse_users_json(data)
    assert len(users) == 1
    assert users[0].sam_account_name == "alice"


def test_parse_users_json_skips_non_dict_entries(parser):
    """A malformed export with a bare string/number entry mixed in with
    real dict entries must not crash the whole parse — the bad entry is
    skipped, the good ones are still returned."""
    data = _users_payload([
        "not-a-dict-entry",
        {"ObjectIdentifier": "S-1-5-21-1", "Properties": {"name": "alice@corp.local"}},
        42,
        None,
    ])
    users = parser.parse_users_json(data)
    assert len(users) == 1
    assert users[0].sam_account_name == "alice"


def test_parse_groups_json_skips_non_dict_entries(parser):
    data = json.dumps({"data": ["bad", {"ObjectIdentifier": "S-1", "Properties": {"name": "Domain Admins@corp.local"}}]})
    groups = parser.parse_groups_json(data)
    assert len(groups) == 1
    assert groups[0].name == "Domain Admins"


def test_parse_computers_json_skips_non_dict_entries(parser):
    data = json.dumps({"data": [123, {"ObjectIdentifier": "S-1", "Properties": {"name": "DC01@corp.local"}}]})
    computers = parser.parse_computers_json(data)
    assert len(computers) == 1
    assert computers[0].hostname == "DC01"


def test_parse_domains_json_skips_non_dict_entries(parser):
    data = json.dumps({"data": [[], {"ObjectIdentifier": "S-1", "Properties": {"name": "corp.local"}}]})
    domains = parser.parse_domains_json(data)
    assert len(domains) == 1
    assert domains[0].name == "corp.local"


def test_parse_sessions_json_skips_non_dict_entries(parser):
    data = json.dumps({"data": [True, {"UserSID": "S-1-user", "ComputerSID": "S-1-comp"}]})
    sessions = parser.parse_sessions_json(data)
    assert len(sessions) == 1
    assert sessions[0].user_sid == "S-1-user"


def test_parse_users_json_all_non_dict_returns_empty_not_crash(parser):
    data = _users_payload(["a", "b", "c"])
    users = parser.parse_users_json(data)
    assert users == []


def test_parse_users_json_missing_file_returns_empty(parser):
    users = parser.parse_users_json("")
    assert users == []


def test_parse_users_json_malformed_json_returns_empty(parser):
    users = parser.parse_users_json("{not valid json")
    assert users == []
