"""Phase 10-F: PassiveReconPhase._generate_workflow must use the real
AclPathBuilder instead of hand-rolling a partial duplicate of its SMB-relay
chain. Previously self.acl_path_builder was instantiated (passive_recon.py
__init__) but .build() was never called anywhere in the codebase — the
inline block reproduced the "SMB Relay Attack" chain without the builder's
accompanying ntlmrelayx NextStepSuggestion reaching the report from this
phase (it does reach it via other paths, but this phase silently dropped
it for its own inline chain).
"""


from core.attack_workflow import AttackWorkflow
from modules.ad.attack_paths.acl_paths import AclPathBuilder
from modules.ad.phases.passive_recon import PassiveReconPhase


def _make_phase() -> PassiveReconPhase:
    phase = PassiveReconPhase.__new__(PassiveReconPhase)
    phase.workflow = AttackWorkflow()
    phase.acl_path_builder = AclPathBuilder()
    return phase


def test_smb_relay_chain_comes_from_acl_path_builder():
    phase = _make_phase()
    results = {"anonymous_ldap": False, "null_session": False, "kerberos_detected": False}
    analysis_data = {"smb_relay_viable": True}

    phase._generate_workflow("10.10.10.1", results, analysis_data)

    names = [p.name for p in phase.workflow.attack_paths]
    assert "SMB Relay Attack" in names

    commands = [s["command"] for s in phase.workflow.get_suggestions()]
    assert "ntlmrelayx.py -tf targets.txt -smb2support" in commands


def test_no_smb_relay_chain_when_not_viable():
    phase = _make_phase()
    results = {"anonymous_ldap": False, "null_session": False, "kerberos_detected": False}
    analysis_data = {}

    phase._generate_workflow("10.10.10.1", results, analysis_data)

    names = [p.name for p in phase.workflow.attack_paths]
    assert "SMB Relay Attack" not in names


def test_acl_path_builder_bloodhound_paths_also_surface_from_passive_recon():
    """Confirms the wiring uses the builder's full output, not just the
    smb_relay branch — pre-computed bloodhound_attack_paths (when present
    in analysis_data) should also flow through into the workflow."""
    phase = _make_phase()
    results = {"anonymous_ldap": False, "null_session": False, "kerberos_detected": False}
    analysis_data = {
        "bloodhound_attack_paths": [
            {"type": "GenericAll", "source": "userA", "target": "DA",
             "steps": ["Abuse GenericAll on DA group"], "risk": "critical"}
        ]
    }

    phase._generate_workflow("10.10.10.1", results, analysis_data)

    names = [p.name for p in phase.workflow.attack_paths]
    assert "Attack Path: GenericAll" in names
