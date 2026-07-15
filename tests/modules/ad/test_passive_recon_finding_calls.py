"""Regression test for a real crash bug found by widening mypy's scope to
check modules/ against core/logger.py's real ReconLogger.finding()
signature: PassiveReconPhase._apply_rootdse() called
self.logger.finding(description) with only one argument, but
ReconLogger.finding(self, severity, description) requires two -- any run
that actually found an anonymous LDAP bind would have raised
TypeError: finding() missing 1 required positional argument: 'description'
before ever recording the finding. The identical bug, and identical fix,
also applied to the SMB-null-session call site in run() (same file).
"""

from unittest.mock import MagicMock

from core.logger import ReconLogger
from modules.ad.phases.passive_recon import PassiveReconPhase


def _make_phase() -> PassiveReconPhase:
    phase = PassiveReconPhase.__new__(PassiveReconPhase)
    phase.logger = MagicMock(spec=ReconLogger)
    phase.loot = MagicMock()
    return phase


def test_apply_rootdse_records_finding_with_severity_and_description_when_anonymous_bind_allowed():
    phase = _make_phase()
    results = {"anonymous_ldap": False, "base_dn": "", "domain": "", "forest_name": ""}
    rootdse = {"anonymous": True, "base_dn": "DC=corp,DC=local"}

    # A spec'd mock enforces ReconLogger's real signature -- this call
    # would raise TypeError if the bug regressed.
    phase._apply_rootdse(rootdse, results)

    phase.logger.finding.assert_called_once_with(
        "medium", "Anonymous LDAP bind ALLOWED — extracting domain info"
    )
    assert results["anonymous_ldap"] is True


def test_apply_rootdse_does_not_log_a_finding_when_bind_is_not_anonymous():
    phase = _make_phase()
    results = {"anonymous_ldap": False, "base_dn": "", "domain": "", "forest_name": ""}
    rootdse = {"anonymous": False}

    phase._apply_rootdse(rootdse, results)

    phase.logger.finding.assert_not_called()
    assert results["anonymous_ldap"] is False
