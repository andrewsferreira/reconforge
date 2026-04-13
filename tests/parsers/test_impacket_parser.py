"""Tests for AD Impacket parser coverage."""

from modules.ad.parsers.impacket_parser import ImpacketParser


def test_parse_getnpusers_extracts_hashes_and_usernames():
    parser = ImpacketParser()
    text = """
    [*] Getting TGT for user
    $krb5asrep$23$svc_sql@CORP.LOCAL:ABCDEF012345
    $krb5asrep$23$backup_svc@CORP.LOCAL:1234567890AB
    """
    hashes = parser.parse_getnpusers(text)

    assert len(hashes) == 2
    assert hashes[0].username == "svc_sql"
    assert hashes[1].username == "backup_svc"


def test_parse_lookupsid_and_extract_helpers():
    parser = ImpacketParser()
    text = """
      500: CORP\\Administrator (SidTypeUser)
      512: CORP\\Domain Admins (SidTypeGroup)
      513: CORP\\Domain Users (SidTypeAlias)
    """
    entries = parser.parse_lookupsid(text)
    users = parser.extract_users_from_rid(entries)
    groups = parser.extract_groups_from_rid(entries)

    assert len(entries) == 3
    assert users == ["Administrator"]
    assert "Domain Admins" in groups
    assert "Domain Users" in groups


def test_parse_rpcdump_builds_endpoint_blocks():
    parser = ImpacketParser()
    text = """
Protocol: [ncacn_ip_tcp]
Provider: Remote Service Control Manager
UUID : 367abb81-9844-35f1-ad32-98f038001003
Bindings: ncacn_ip_tcp:10.10.10.10[135]
Protocol: [ncacn_np]
Provider: Workstation Service
UUID : 6bffd098-a112-3610-9833-46c3f87e345a
Bindings: ncacn_np:10.10.10.10[\\pipe\\wkssvc]
    """
    endpoints = parser.parse_rpcdump(text)

    assert len(endpoints) == 2
    assert endpoints[0].uuid == "367abb81-9844-35f1-ad32-98f038001003"
    assert "ncacn_ip_tcp" in endpoints[0].bindings
    assert endpoints[1].annotation == "Workstation Service"
