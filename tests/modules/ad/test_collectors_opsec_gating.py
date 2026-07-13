"""Phase 12-C/D/E/F: modules/ad/collectors/{ldap,smb,dns,kerberos}_collector.py
had zero opsec.check() calls despite core/detection_map.py defining specific
policy entries for exactly these operations (ldap_user_enum, smb_share_access,
nmap_ad_service_scan, impacket_lookupsid, etc.) — every enumeration query ran
unconditionally regardless of --opsec mode. These tests confirm each method
now honors a blocking opsec check and still runs when the check passes.
"""

from types import SimpleNamespace

from modules.ad.collectors.dns_collector import DnsCollector
from modules.ad.collectors.kerberos_collector import KerberosCollector
from modules.ad.collectors.ldap_collector import LdapCollector
from modules.ad.collectors.smb_collector import SmbCollector


def _ok_run(stdout="", success=True):
    return SimpleNamespace(success=success, stdout=stdout, stderr="")


def _opsec(allowed: bool):
    return SimpleNamespace(check=lambda *a, **k: allowed)


# ── LdapCollector ────────────────────────────────────────────────────

def _make_ldap_collector(allowed: bool) -> LdapCollector:
    c = LdapCollector.__new__(LdapCollector)
    c.opsec = _opsec(allowed)
    c.ldapsearch = SimpleNamespace(
        anonymous_bind_test=lambda *a, **k: _ok_run(),
        query_users=lambda *a, **k: _ok_run(),
        query_groups=lambda *a, **k: _ok_run(),
        query_computers=lambda *a, **k: _ok_run(),
        query_spn_accounts=lambda *a, **k: _ok_run(),
        query_asrep_users=lambda *a, **k: _ok_run(),
        query_trusts=lambda *a, **k: _ok_run(),
        query_gpos=lambda *a, **k: _ok_run(),
        query_password_policy=lambda *a, **k: _ok_run(),
    )
    c.parser = SimpleNamespace(
        parse_rootdse=lambda s: SimpleNamespace(
            base_dn="", domain_name="", forest_name="", config_dn="",
            schema_dn="", functional_level="", server_name="",
        ),
        parse_users=lambda s: [],
        parse_groups=lambda s: [],
        parse_computers=lambda s: [],
        parse_spn_accounts=lambda s: [],
        parse_asrep_users=lambda s: [],
        parse_trusts=lambda s: [],
        parse_gpos=lambda s: [],
        parse_password_policy=lambda s: SimpleNamespace(
            min_length=0, complexity=False, lockout_threshold=0,
            lockout_duration=0, lockout_observation_window=0,
            history_length=0, max_age=0, min_age=0,
        ),
    )
    return c


def test_ldap_collect_rootdse_blocked_by_opsec():
    c = _make_ldap_collector(allowed=False)
    assert c.collect_rootdse("10.10.10.1") == {"anonymous": False}


def test_ldap_collect_rootdse_runs_when_allowed():
    c = _make_ldap_collector(allowed=True)
    result = c.collect_rootdse("10.10.10.1")
    assert "anonymous" in result


def test_ldap_collect_users_blocked_by_opsec():
    c = _make_ldap_collector(allowed=False)
    assert c.collect_users("10.10.10.1", "DC=corp,DC=local") == []


def test_ldap_collect_password_policy_blocked_by_opsec():
    c = _make_ldap_collector(allowed=False)
    assert c.collect_password_policy("10.10.10.1", "DC=corp,DC=local") == {}


def test_ldap_collect_password_policy_runs_when_allowed():
    c = _make_ldap_collector(allowed=True)
    result = c.collect_password_policy("10.10.10.1", "DC=corp,DC=local")
    assert "min_length" in result


# ── SmbCollector ─────────────────────────────────────────────────────

def _make_smb_collector(allowed: bool) -> SmbCollector:
    c = SmbCollector.__new__(SmbCollector)
    c.opsec = _opsec(allowed)
    c.smbclient = SimpleNamespace(
        is_available=lambda: True,
        null_session_list=lambda *a, **k: _ok_run(),
        authenticated_list=lambda *a, **k: _ok_run(),
        test_share_access=lambda *a, **k: _ok_run(),
    )
    c.enum4linux_ng = SimpleNamespace(
        is_available=lambda: True,
        full_enum=lambda *a, **k: _ok_run(),
        output_dir=SimpleNamespace(__truediv__=lambda self, other: SimpleNamespace(exists=lambda: False)),
    )
    c.smb_parser = SimpleNamespace(
        parse_share_list=lambda text, anonymous: SimpleNamespace(
            null_session_allowed=False, shares=[],
        ),
        parse_share_access=lambda text, name: SimpleNamespace(accessible=False, permissions=[]),
    )
    c.enum_parser = SimpleNamespace(
        parse_text=lambda s: SimpleNamespace(
            users=[], groups=[], shares=[], password_policy={}, domain_sid="",
        ),
    )
    return c


def test_smb_null_session_blocked_by_opsec():
    c = _make_smb_collector(allowed=False)
    result = c.collect_null_session("10.10.10.1")
    assert result == {"allowed": False, "shares": []}


def test_smb_null_session_runs_when_allowed():
    c = _make_smb_collector(allowed=True)
    result = c.collect_null_session("10.10.10.1")
    assert "allowed" in result


def test_smb_collect_shares_blocked_by_opsec():
    c = _make_smb_collector(allowed=False)
    assert c.collect_shares("10.10.10.1", "alice", "pass") == []


def test_smb_admin_share_probe_skipped_when_share_access_allowed_but_admin_shares_blocked():
    """smb_share_access (medium) and smb_admin_shares (high) are gated
    separately — a caller allowed to list shares in "normal" mode should
    not also get the noisier SYSVOL/NETLOGON admin-share access probe."""
    c = SmbCollector.__new__(SmbCollector)
    calls = []
    c.opsec = SimpleNamespace(check=lambda name: calls.append(name) or name == "smb_share_access")
    c.smbclient = SimpleNamespace(
        is_available=lambda: True,
        authenticated_list=lambda *a, **k: _ok_run(),
        test_share_access=lambda *a, **k: _ok_run(),
    )
    c.smb_parser = SimpleNamespace(
        parse_share_list=lambda text, anonymous: SimpleNamespace(null_session_allowed=False, shares=[]),
        parse_share_access=lambda text, name: SimpleNamespace(accessible=False, permissions=[]),
    )

    shares = c.collect_shares("10.10.10.1", "alice", "pass")

    assert "smb_share_access" in calls
    assert "smb_admin_shares" in calls
    assert shares == []  # admin-share probe skipped, no other shares discovered


def test_smb_enum4linux_blocked_by_opsec():
    c = _make_smb_collector(allowed=False)
    assert c.collect_enum4linux("10.10.10.1") == {}


# ── DnsCollector ─────────────────────────────────────────────────────

def _make_dns_collector(allowed: bool) -> DnsCollector:
    c = DnsCollector.__new__(DnsCollector)
    c.opsec = _opsec(allowed)
    c.nmap = SimpleNamespace(
        is_available=lambda: True,
        ad_service_scan=lambda *a, **k: _ok_run(),
        dns_srv_lookup=lambda *a, **k: _ok_run(stdout="srv record data"),
        output_dir=SimpleNamespace(__truediv__=lambda self, other: SimpleNamespace(exists=lambda: False)),
    )
    c.nmap_parser = SimpleNamespace(
        parse_text=lambda s: SimpleNamespace(
            domain_name="", forest_name="", ldap_base_dn="", dc_hostname="",
            functional_level="", smb_signing="", kerberos_detected=False,
            open_ports=[], services=[],
        ),
    )
    return c


def test_dns_collect_ad_services_blocked_by_opsec():
    c = _make_dns_collector(allowed=False)
    assert c.collect_ad_services("10.10.10.1") == {}


def test_dns_collect_srv_records_blocked_by_opsec():
    c = _make_dns_collector(allowed=False)
    assert c.collect_srv_records("10.10.10.1", "corp.local") == ""


def test_dns_collect_srv_records_runs_when_allowed():
    c = _make_dns_collector(allowed=True)
    assert c.collect_srv_records("10.10.10.1", "corp.local") == "srv record data"


# ── KerberosCollector ────────────────────────────────────────────────

def _make_kerberos_collector(allowed: bool) -> KerberosCollector:
    c = KerberosCollector.__new__(KerberosCollector)
    c.opsec = _opsec(allowed)
    c.opsec_mode = "normal"
    c.nmap = SimpleNamespace(
        is_available=lambda: True,
        kerberos_scan=lambda *a, **k: _ok_run(stdout="88/tcp open kerberos"),
    )
    c.impacket = SimpleNamespace(
        is_available=lambda *a, **k: True,
        get_np_users=lambda *a, **k: _ok_run(),
        lookup_sid=lambda *a, **k: _ok_run(),
    )
    c.impacket_parser = SimpleNamespace(
        parse_getnpusers=lambda s: [],
        parse_lookupsid=lambda s: [],
        extract_users_from_rid=lambda e: [],
        extract_groups_from_rid=lambda e: [],
    )
    return c


def test_kerberos_detect_blocked_by_opsec():
    c = _make_kerberos_collector(allowed=False)
    assert c.detect_kerberos("10.10.10.1") is False


def test_kerberos_detect_runs_when_allowed():
    c = _make_kerberos_collector(allowed=True)
    assert c.detect_kerberos("10.10.10.1") is True


def test_kerberos_asrep_hashes_blocked_by_opsec():
    c = _make_kerberos_collector(allowed=False)
    assert c.collect_asrep_hashes("10.10.10.1", "corp.local", "alice", "pass") == []


def test_kerberos_rid_cycling_blocked_by_opsec():
    """Phase 12-F regression: previously RID cycling only scaled max_rid by
    opsec_mode=="aggressive" but ran unconditionally in every mode, despite
    impacket_lookupsid being classified "high" noise (aggressive-only)."""
    c = _make_kerberos_collector(allowed=False)
    assert c.collect_rid_cycling("10.10.10.1", "corp.local") == {"users": [], "groups": []}


def test_kerberos_rid_cycling_runs_when_allowed():
    c = _make_kerberos_collector(allowed=True)
    result = c.collect_rid_cycling("10.10.10.1", "corp.local")
    assert result == {"users": [], "groups": []}
