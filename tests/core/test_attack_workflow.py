"""Tests for core.attack_workflow."""

from core.attack_workflow import AttackWorkflow


def test_suggest_next_deduplicates_and_promotes_priority():
    wf = AttackWorkflow()
    wf.suggest_next("nmap -sV 10.10.10.10", "Baseline service detection", "medium")
    wf.suggest_next("nmap -sV 10.10.10.10", "Target has HTTP and LDAP", "high")

    suggestions = wf.get_suggestions()
    assert len(suggestions) == 1
    assert suggestions[0]["priority"] == "high"
    assert "Baseline service detection" in suggestions[0]["justification"]
    assert "Target has HTTP and LDAP" in suggestions[0]["justification"]


def test_to_markdown_includes_attack_path_tactic_and_technique():
    wf = AttackWorkflow()
    wf.add_attack_path(
        name="Kerberoast to Lateral Movement",
        description="Request service tickets and crack offline.",
        steps=["Enumerate SPNs", "Request TGS", "Crack hashes"],
        risk="high",
        tactic="Credential Access",
        technique_id="T1558.003",
    )

    markdown = wf.to_markdown()
    assert "**Tactic:** Credential Access" in markdown
    assert "**Technique:** T1558.003" in markdown
