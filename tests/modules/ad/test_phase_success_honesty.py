"""Phase 17: identity_enumeration.py, configuration_enumeration.py, and
passive_recon.py hardcoded results["success"] = True unconditionally at
the end of run(), regardless of whether any of their several independent,
best-effort collection paths (LDAP, RID cycling, AS-REP roasting,
enum4linux-ng, null session, anonymous LDAP) actually produced anything.
"success" meant only "the method returned without raising" — a target
with no usable credentials and no null-session/anonymous access still
reported success=True with zero real data collected. Fixed by gating
success on whether at least one collection path actually yielded a
positive result.
"""

from types import SimpleNamespace

from core.findings_manager import FindingsManager
from modules.ad.phases.identity_enumeration import IdentityEnumerationPhase
from modules.ad.phases.configuration_enumeration import ConfigurationEnumerationPhase
from modules.ad.phases.passive_recon import PassiveReconPhase


def _empty_analyzer():
    return SimpleNamespace(analyze=lambda *a, **k: SimpleNamespace(data={}, findings=[]))


def _empty_builder():
    return SimpleNamespace(build=lambda *a, **k: SimpleNamespace(chains=[], suggestions=[]))


def _base_stubs(phase, phase_name: str, module: str) -> None:
    phase.PHASE_NAME = phase_name
    phase.logger = SimpleNamespace(
        info=lambda *a, **k: None, warning=lambda *a, **k: None,
        finding=lambda *a, **k: None, debug=lambda *a, **k: None,
    )
    phase.notes = SimpleNamespace(
        add=lambda *a, **k: None, add_phase_start=lambda *a, **k: None,
        add_phase_end=lambda *a, **k: None, add_finding_note=lambda *a, **k: None,
        add_command_note=lambda *a, **k: None,
    )
    phase.findings = FindingsManager()
    phase.loot = SimpleNamespace(
        add=lambda **k: None, add_user=lambda **k: None,
        add_share=lambda **k: None, add_hash=lambda **k: None,
        add_service=lambda **k: None,
    )
    phase.workflow = SimpleNamespace(
        add_step=lambda **k: None, record_result=lambda *a, **k: None,
        add_attack_path=lambda **k: None, suggest_next=lambda **k: None,
        add_rabbit_hole=lambda *a, **k: None,
    )
    phase.opsec = SimpleNamespace(check=lambda *a, **k: True)


def _make_identity_phase() -> IdentityEnumerationPhase:
    phase = IdentityEnumerationPhase.__new__(IdentityEnumerationPhase)
    _base_stubs(phase, "identity_enumeration", "ad")
    phase.ldap_collector = SimpleNamespace(
        collect_users=lambda *a, **k: [],
        collect_groups=lambda *a, **k: [],
        collect_computers=lambda *a, **k: [],
        collect_spn_accounts=lambda *a, **k: [],
        collect_asrep_users=lambda *a, **k: [],
    )
    phase.kerberos_collector = SimpleNamespace(
        collect_rid_cycling=lambda *a, **k: {"users": []},
        collect_asrep_hashes=lambda *a, **k: [],
    )
    phase.enum4linux_ng = SimpleNamespace(is_available=lambda: False)
    phase.smb_collector = SimpleNamespace(collect_enum4linux=lambda *a, **k: {"users": []})
    phase.relationship_analyzer = _empty_analyzer()
    phase.misconfig_analyzer = _empty_analyzer()
    phase.kerberoast_builder = _empty_builder()
    phase.asrep_builder = _empty_builder()
    return phase


def test_identity_enumeration_reports_failure_when_nothing_collected():
    phase = _make_identity_phase()

    results = phase.run(target="10.0.0.1", domain="corp.local", base_dn="",
                         username="", password="", opsec_mode="normal")

    assert results["success"] is False
    assert results["total_users"] == 0


def test_identity_enumeration_reports_success_when_users_collected():
    phase = _make_identity_phase()
    phase.ldap_collector.collect_users = lambda *a, **k: [{"username": "alice"}]

    results = phase.run(target="10.0.0.1", domain="corp.local", base_dn="DC=corp,DC=local",
                         username="svc", password="pw", opsec_mode="normal")

    assert results["success"] is True
    assert results["total_users"] == 1


def _make_configuration_phase() -> ConfigurationEnumerationPhase:
    phase = ConfigurationEnumerationPhase.__new__(ConfigurationEnumerationPhase)
    _base_stubs(phase, "configuration_enumeration", "ad")
    phase.ldap_collector = SimpleNamespace(
        collect_password_policy=lambda *a, **k: {},
        collect_trusts=lambda *a, **k: [],
        collect_gpos=lambda *a, **k: [],
        collect_computers=lambda *a, **k: [],
    )
    phase.smb_collector = SimpleNamespace(collect_shares=lambda *a, **k: [])
    phase.enum4linux_ng = SimpleNamespace(is_available=lambda: False)
    phase.misconfig_analyzer = _empty_analyzer()
    phase.trust_analyzer = _empty_analyzer()
    phase.permission_analyzer = _empty_analyzer()
    phase.gpo_builder = _empty_builder()
    phase.privesc_builder = _empty_builder()
    return phase


def test_configuration_enumeration_reports_failure_when_nothing_collected():
    phase = _make_configuration_phase()

    results = phase.run(target="10.0.0.1", domain="corp.local", base_dn="",
                         username="", password="", opsec_mode="normal")

    assert results["success"] is False
    assert results["trusts"] == []


def test_configuration_enumeration_reports_success_when_shares_collected():
    phase = _make_configuration_phase()
    phase.smb_collector.collect_shares = lambda *a, **k: [{"name": "SYSVOL", "accessible": False}]

    results = phase.run(target="10.0.0.1", domain="corp.local", base_dn="",
                         username="", password="", opsec_mode="normal")

    assert results["success"] is True
    assert len(results["shares"]) == 1


def _make_passive_recon_phase() -> PassiveReconPhase:
    phase = PassiveReconPhase.__new__(PassiveReconPhase)
    _base_stubs(phase, "passive_recon", "ad")
    phase.dns_collector = SimpleNamespace(
        collect_ad_services=lambda *a, **k: {},
        collect_srv_records=lambda *a, **k: "",
    )
    phase.ldap_collector = SimpleNamespace(collect_rootdse=lambda *a, **k: {})
    phase.smb_collector = SimpleNamespace(collect_null_session=lambda *a, **k: {"allowed": False, "shares": []})
    phase.kerberos_collector = SimpleNamespace(detect_kerberos=lambda *a, **k: False)
    phase.permission_analyzer = _empty_analyzer()
    phase.acl_path_builder = _empty_builder()
    return phase


def test_passive_recon_reports_failure_when_no_signal_found():
    phase = _make_passive_recon_phase()

    results = phase.run(target="10.0.0.1", domain="")

    assert results["success"] is False
    assert results["kerberos_detected"] is False


def test_passive_recon_reports_success_when_kerberos_detected():
    phase = _make_passive_recon_phase()
    phase.kerberos_collector.detect_kerberos = lambda *a, **k: True

    results = phase.run(target="10.0.0.1", domain="")

    assert results["success"] is True
    assert results["kerberos_detected"] is True
