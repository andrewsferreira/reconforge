from core.risk_policy import RiskPolicyEngine


def test_classify_risk_levels():
    assert RiskPolicyEngine.classify_risk(["nmap", "-sV", "10.10.10.1"]) == "low"
    assert RiskPolicyEngine.classify_risk(["nuclei", "-u", "https://x"]) == "medium"
    assert RiskPolicyEngine.classify_risk(["sqlmap", "-u", "https://x", "--os-shell"]) == "high"
