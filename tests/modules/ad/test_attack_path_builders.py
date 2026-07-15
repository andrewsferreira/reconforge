"""Phase 10-J: modules/ad/attack_paths/* had zero test coverage before this
phase — the 6 builders + base dataclasses are exercised only indirectly
(and, in bloodhound_collection's confidence test, deliberately stubbed
out). These tests cover each builder's chain-generation branches and the
empty-input no-op case directly.
"""

from types import SimpleNamespace

from modules.ad.attack_paths.acl_paths import AclPathBuilder
from modules.ad.attack_paths.asrep_paths import AsrepPathBuilder
from modules.ad.attack_paths.delegation_paths import DelegationPathBuilder
from modules.ad.attack_paths.gpo_paths import GpoPathBuilder
from modules.ad.attack_paths.kerberoast_paths import KerberoastPathBuilder
from modules.ad.attack_paths.privilege_escalation_paths import PrivilegeEscalationPathBuilder

# ── AclPathBuilder ──────────────────────────────────────────────────

def test_acl_builder_empty_input_produces_no_chains():
    result = AclPathBuilder().build({}, target="10.10.10.1", domain="corp.local")
    assert result.chains == []
    assert result.suggestions == []


def test_acl_builder_bloodhound_paths_produce_chains():
    result = AclPathBuilder().build(
        {"bloodhound_attack_paths": [
            {"type": "GenericAll", "source": "userA", "target": "DA", "steps": ["x"], "risk": "critical"}
        ]},
        target="10.10.10.1", domain="corp.local",
    )
    assert len(result.chains) == 1
    assert result.chains[0].name == "Attack Path: GenericAll"
    assert result.chains[0].risk == "critical"


def test_acl_builder_session_paths_produce_critical_chain():
    result = AclPathBuilder().build(
        {"session_paths": [{"host": "SRV01", "user": "DA_admin"}]},
        target="10.10.10.1", domain="corp.local",
    )
    assert len(result.chains) == 1
    assert result.chains[0].risk == "critical"
    assert "SRV01" in result.chains[0].name


def test_acl_builder_smb_relay_produces_chain_and_suggestion():
    result = AclPathBuilder().build(
        {"smb_relay_viable": True}, target="10.10.10.1", domain="corp.local",
    )
    assert any(c.name == "SMB Relay Attack" for c in result.chains)
    assert any("ntlmrelayx" in s.command for s in result.suggestions)


# ── KerberoastPathBuilder ───────────────────────────────────────────

def test_kerberoast_builder_no_spn_accounts_produces_no_chains():
    result = KerberoastPathBuilder().build({}, target="10.10.10.1", domain="corp.local")
    assert result.chains == []
    assert result.suggestions == []


def test_kerberoast_builder_produces_main_chain():
    result = KerberoastPathBuilder().build(
        {"kerberoastable": ["svc_sql"]}, target="10.10.10.1", domain="corp.local",
    )
    names = [c.name for c in result.chains]
    assert "Kerberoasting → Service Account Compromise" in names
    assert "Kerberoast Privileged Account → Domain Admin" not in names


def test_kerberoast_builder_flags_privileged_account():
    result = KerberoastPathBuilder().build(
        {"kerberoastable": ["svc_sql"], "privileged_users": ["svc_sql"]},
        target="10.10.10.1", domain="corp.local",
    )
    names = [c.name for c in result.chains]
    assert "Kerberoast Privileged Account → Domain Admin" in names
    critical = [c for c in result.chains if c.risk == "critical"]
    assert critical


# ── AsrepPathBuilder ────────────────────────────────────────────────

def test_asrep_builder_no_users_produces_no_chains():
    result = AsrepPathBuilder().build({}, target="10.10.10.1", domain="corp.local")
    assert result.chains == []


def test_asrep_builder_flags_privileged_account():
    result = AsrepPathBuilder().build(
        {"asreproastable": ["svc_backup"], "privileged_users": ["svc_backup"]},
        target="10.10.10.1", domain="corp.local",
    )
    names = [c.name for c in result.chains]
    assert "AS-REP Roast Privileged Account → Domain Admin" in names


# ── DelegationPathBuilder ───────────────────────────────────────────

def test_delegation_builder_empty_input_produces_no_chains():
    result = DelegationPathBuilder().build({}, target="10.10.10.1", domain="corp.local")
    assert result.chains == []


def test_delegation_builder_unconstrained_delegation_produces_chain():
    entry = SimpleNamespace(is_dc=False, account_name="SRV-WEB01$", account_type="computer")
    result = DelegationPathBuilder().build(
        {"unconstrained_delegation": [entry]}, target="10.10.10.1", domain="corp.local",
    )
    assert any(c.chain_type == "unconstrained_delegation" for c in result.chains)
    assert any("SRV-WEB01$" in c.name for c in result.chains)


def test_delegation_builder_skips_dc_unconstrained_entries():
    dc_entry = SimpleNamespace(is_dc=True, account_name="DC01$", account_type="computer")
    result = DelegationPathBuilder().build(
        {"unconstrained_delegation": [dc_entry]}, target="10.10.10.1", domain="corp.local",
    )
    assert result.chains == []


def test_delegation_builder_rbcd_produces_chain():
    entry = SimpleNamespace(target_account="SRV-FILE01$")
    result = DelegationPathBuilder().build(
        {"rbcd": [entry], "machine_account_quota": 10}, target="10.10.10.1", domain="corp.local",
    )
    assert any(c.chain_type == "rbcd" for c in result.chains)


# ── GpoPathBuilder ──────────────────────────────────────────────────

def test_gpo_builder_empty_input_produces_no_chains():
    result = GpoPathBuilder().build({}, target="10.10.10.1", domain="corp.local")
    assert result.chains == []


def test_gpo_builder_gpos_present_produces_credential_hunting_chain():
    result = GpoPathBuilder().build(
        {"gpos": [{"name": "Default Domain Policy"}]}, target="10.10.10.1", domain="corp.local",
    )
    assert any(c.name == "GPO Credential Hunting" for c in result.chains)


def test_gpo_builder_accessible_sysvol_produces_second_chain():
    result = GpoPathBuilder().build(
        {"gpos": [{"name": "x"}], "shares": [{"name": "SYSVOL", "accessible": True}]},
        target="10.10.10.1", domain="corp.local",
    )
    names = [c.name for c in result.chains]
    assert "GPO Credential Hunting" in names
    assert "SYSVOL Credential Hunting" in names


# ── PrivilegeEscalationPathBuilder ──────────────────────────────────

def test_privesc_builder_empty_input_produces_no_chains():
    result = PrivilegeEscalationPathBuilder().build({}, target="10.10.10.1", domain="corp.local")
    assert result.chains == []


def test_privesc_builder_weak_password_policy_produces_spray_chain():
    result = PrivilegeEscalationPathBuilder().build(
        {"password_policy": {"lockout_threshold": 0, "min_length": 6, "complexity": False}},
        target="10.10.10.1", domain="corp.local",
    )
    names = [c.name for c in result.chains]
    assert "Weak Password Policy → Password Spraying" in names


def test_privesc_builder_password_spray_suggestion_has_no_hardcoded_password():
    """Phase 10-G regression: the suggested spray command previously
    embedded a literal password ('Spring2026!') as if it were a real,
    ready-to-run credential rather than a placeholder wordlist reference."""
    result = PrivilegeEscalationPathBuilder().build(
        {"password_policy": {"lockout_threshold": 0, "min_length": 6, "complexity": False}},
        target="10.10.10.1", domain="corp.local",
    )
    spray_suggestions = [s for s in result.suggestions if "crackmapexec" in s.command]
    assert spray_suggestions
    for s in spray_suggestions:
        assert "Spring2026" not in s.command
        assert "-p passwords.txt" in s.command


def test_privesc_builder_privileged_targeting_chain():
    result = PrivilegeEscalationPathBuilder().build(
        {"privileged_users": ["admin_bob"]}, target="10.10.10.1", domain="corp.local",
    )
    names = [c.name for c in result.chains]
    assert "Privileged Account Targeting" in names


def test_privesc_builder_trust_exploitation_chain():
    result = PrivilegeEscalationPathBuilder().build(
        {"trusts": [{"partner": "child.corp.local", "direction": "bidirectional"}]},
        target="10.10.10.1", domain="corp.local",
    )
    names = [c.name for c in result.chains]
    assert "Trust Exploitation: child.corp.local" in names
