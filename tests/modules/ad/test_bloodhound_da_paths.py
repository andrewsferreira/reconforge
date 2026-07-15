"""Phase 11-A: BloodhoundCollectionPhase._identify_da_paths()'s Kerberoast/
AS-REP -> DA branches checked group membership via _is_privileged_group(gid),
matching readable substrings like "domain admins" against gid — but
user.member_of holds BloodHound ObjectIdentifier SIDs (e.g.
"S-1-5-21-...-512"), never readable names (see modules/ad/parsers/
bloodhound_parser.py's MemberOf/ObjectIdentifier parsing). The check could
never match, so these two branches never fired regardless of input. Fixed to
check membership against results["da_users"], the SID-keyed list
PrivilegeAnalyzer already builds from the same "Domain Admins" group data.
"""

from types import SimpleNamespace

from modules.ad.phases.bloodhound_collection import BloodhoundCollectionPhase


def _make_phase() -> BloodhoundCollectionPhase:
    phase = BloodhoundCollectionPhase.__new__(BloodhoundCollectionPhase)
    phase.logger = SimpleNamespace(info=lambda *a, **k: None, warning=lambda *a, **k: None)
    return phase


def _user(**kwargs):
    defaults = {
        "object_id": "", "sam_account_name": "", "enabled": True,
        "has_spn": False, "dont_req_preauth": False, "member_of": [],
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_kerberoastable_da_member_produces_path():
    phase = _make_phase()
    user = _user(
        object_id="S-1-5-21-1-2-3-1105", sam_account_name="svc_sql",
        has_spn=True, member_of=["S-1-5-21-1-2-3-512"],
    )
    results = {"da_users": ["S-1-5-21-1-2-3-1105"]}

    paths = phase._identify_da_paths({"users": [user], "computers": []}, results)

    types = [p["type"] for p in paths]
    assert "kerberoast_to_da" in types


def test_kerberoastable_non_da_member_produces_no_path():
    """Regression: a kerberoastable account that is NOT a DA member must not
    be reported as a Kerberoast-to-DA path — the old string-substring bug
    always returned False here too, but for the wrong reason (it couldn't
    match anything, ever, DA member or not)."""
    phase = _make_phase()
    user = _user(
        object_id="S-1-5-21-1-2-3-2201", sam_account_name="svc_backup",
        has_spn=True,
    )
    results = {"da_users": ["S-1-5-21-1-2-3-1105"]}

    paths = phase._identify_da_paths({"users": [user], "computers": []}, results)

    assert paths == []


def test_asrep_roastable_da_member_produces_path():
    phase = _make_phase()
    user = _user(
        object_id="S-1-5-21-1-2-3-1106", sam_account_name="admin_bob",
        dont_req_preauth=True,
    )
    results = {"da_users": ["S-1-5-21-1-2-3-1106"]}

    paths = phase._identify_da_paths({"users": [user], "computers": []}, results)

    types = [p["type"] for p in paths]
    assert "asrep_to_da" in types


def test_disabled_da_member_kerberoastable_produces_no_path():
    phase = _make_phase()
    user = _user(
        object_id="S-1-5-21-1-2-3-1105", sam_account_name="svc_sql",
        has_spn=True, enabled=False,
    )
    results = {"da_users": ["S-1-5-21-1-2-3-1105"]}

    paths = phase._identify_da_paths({"users": [user], "computers": []}, results)

    assert paths == []


def test_no_da_users_produces_no_kerberoast_or_asrep_paths():
    phase = _make_phase()
    user = _user(
        object_id="S-1-5-21-1-2-3-1105", sam_account_name="svc_sql",
        has_spn=True, dont_req_preauth=True,
    )
    results = {"da_users": []}

    paths = phase._identify_da_paths({"users": [user], "computers": []}, results)

    assert paths == []


def test_unconstrained_delegation_path_unaffected_by_da_users_fix():
    phase = _make_phase()
    comp = SimpleNamespace(unconstraineddelegation=True, is_dc=False, hostname="SRV-WEB01")
    results = {"da_users": []}

    paths = phase._identify_da_paths({"users": [], "computers": [comp]}, results)

    assert len(paths) == 1
    assert paths[0]["type"] == "unconstrained_to_da"
