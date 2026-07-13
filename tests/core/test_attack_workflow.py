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


def test_add_attack_path_exact_name_duplicate_is_collapsed():
    """Phase 10-E regression: independent phases/builders (e.g. LDAP-based
    identity enumeration and BloodHound collection) commonly derive the
    same named chain from overlapping data — add_attack_path() previously
    had no dedup at all, unlike suggest_next()."""
    wf = AttackWorkflow()
    first = wf.add_attack_path(
        name="Kerberoasting → Service Account Compromise",
        description="Request service tickets and crack offline.",
        steps=["Enumerate SPNs", "Request TGS", "Crack hashes"],
        risk="high",
    )
    second = wf.add_attack_path(
        name="Kerberoasting → Service Account Compromise",
        description="Request service tickets and crack offline.",
        steps=["Enumerate SPNs", "Request TGS", "Crack hashes"],
        risk="high",
    )

    assert len(wf.attack_paths) == 1
    assert second is first


def test_add_attack_path_different_name_is_not_a_duplicate():
    wf = AttackWorkflow()
    wf.add_attack_path(name="Trust Exploitation: CORP-A", description="x", steps=["a"], risk="medium")
    wf.add_attack_path(name="Trust Exploitation: CORP-B", description="x", steps=["a"], risk="medium")

    assert len(wf.attack_paths) == 2


def test_to_markdown_shows_duplicate_attack_path_count():
    wf = AttackWorkflow()
    wf.add_attack_path(name="Privileged Account Targeting", description="x", steps=["a"], risk="critical")
    wf.add_attack_path(name="Privileged Account Targeting", description="x", steps=["a"], risk="critical")

    markdown = wf.to_markdown()
    assert "**Duplicates Merged:** 1" in markdown


def test_to_markdown_omits_duplicate_note_when_none_present():
    wf = AttackWorkflow()
    wf.add_attack_path(name="Privileged Account Targeting", description="x", steps=["a"], risk="critical")

    markdown = wf.to_markdown()
    assert "Duplicates Merged" not in markdown
