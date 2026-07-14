from core.risk_policy import RiskPolicyEngine


def test_classify_risk_levels():
    assert RiskPolicyEngine.classify_risk(["nmap", "-sV", "10.10.10.1"]) == "low"
    assert RiskPolicyEngine.classify_risk(["nuclei", "-u", "https://x"]) == "medium"
    assert RiskPolicyEngine.classify_risk(["sqlmap", "-u", "https://x", "--os-shell"]) == "high"


def test_check_is_a_noop_by_default(monkeypatch):
    """RECONFORGE_POLICY_ENFORCE is unset by default (docs/CONFIGURATION.md
    documents this deliberate off-by-default). Even a high-risk command
    must pass through unblocked when it isn't set."""
    monkeypatch.delenv("RECONFORGE_POLICY_ENFORCE", raising=False)
    decision = RiskPolicyEngine.check(["sqlmap", "-u", "https://x", "--os-shell"])
    assert decision.allowed is True


def test_check_blocks_high_risk_command_below_approval_tier(monkeypatch):
    monkeypatch.setenv("RECONFORGE_POLICY_ENFORCE", "1")
    monkeypatch.setenv("RECONFORGE_APPROVAL_TIER", "low")
    decision = RiskPolicyEngine.check(["sqlmap", "-u", "https://x", "--os-shell"])
    assert decision.allowed is False
    assert "high" in decision.reason


def test_check_allows_command_at_or_above_approval_tier(monkeypatch):
    monkeypatch.setenv("RECONFORGE_POLICY_ENFORCE", "1")
    monkeypatch.setenv("RECONFORGE_APPROVAL_TIER", "high")
    decision = RiskPolicyEngine.check(["sqlmap", "-u", "https://x", "--os-shell"])
    assert decision.allowed is True
