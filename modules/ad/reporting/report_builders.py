"""ReconForge AD Module - Report data builders.

Author: Andrews Ferreira

Helper functions that assemble data dictionaries for each reporter
from the raw scan results, findings, workflow, and loot.
"""

from typing import Dict, Any, List

from modules.ad.attack_paths.base import AttackChain, NextStepSuggestion


def build_attack_surface_data(
    target: str, domain: str, dc_ip: str, opsec_mode: str,
    username: str, findings_mgr, loot, workflow,
) -> Dict[str, Any]:
    """Build data dict for AttackSurfaceReporter."""
    severity_counts = findings_mgr.count_by_severity()
    critical_high = (
        findings_mgr.get_by_severity("critical")
        + findings_mgr.get_by_severity("high")
    )
    return {
        "target": target,
        "domain": domain,
        "dc_ip": dc_ip,
        "opsec_mode": opsec_mode,
        "authenticated": bool(username),
        "severity_counts": severity_counts,
        "loot_summary": loot.summary(),
        "critical_high_findings": [
            {
                "severity": f.severity,
                "description": f.description,
                "target": f.target,
                "confidence": f.confidence,
                "recommendation": f.recommendation,
            }
            for f in critical_high
        ],
        "attack_paths": workflow.attack_paths,
        "suggestions": [
            {"command": s["command"], "justification": s["justification"],
             "priority": s["priority"]}
            for s in workflow.get_suggestions()[:10]
        ],
    }


def build_hvt_data(results: Dict, domain: str, target: str) -> Dict[str, Any]:
    """Build data dict for HighValueTargetsReporter."""
    identity = results.get("phases", {}).get("identity", {})
    bh = results.get("phases", {}).get("bloodhound", {})
    return {
        "domain": domain,
        "target": target,
        "da_users": bh.get("da_users", []),
        "privileged_users": identity.get("privileged_users", []),
        "kerberoastable": (
            bh.get("kerberoastable", [])
            or [sa["username"] for sa in identity.get("service_accounts", [])]
        ),
        "asreproastable": bh.get("asreproastable", []) or identity.get("asrep_users", []),
        "unconstrained_computers": bh.get("unconstrained_computers", []),
        "domain_controllers": (
            results.get("phases", {}).get("configuration", {}).get("domain_controllers", [])
        ),
        "high_value_targets": bh.get("high_value_targets", []),
    }


def build_path_data(workflow, domain: str, target: str) -> Dict[str, Any]:
    """Build data dict for AttackPathReporter."""
    chains = [
        AttackChain(
            name=ap.name, description=ap.description,
            steps=ap.steps, risk=ap.risk,
            prerequisites=ap.prerequisites,
            references=ap.references,
        )
        for ap in workflow.attack_paths
    ]
    suggestions = [
        NextStepSuggestion(
            command=s["command"], justification=s["justification"],
            priority=s["priority"],
        )
        for s in workflow.get_suggestions()
    ]
    return {
        "domain": domain, "target": target,
        "chains": chains, "suggestions": suggestions,
    }


def build_remediation_data(
    findings_mgr, domain: str, target: str,
) -> Dict[str, Any]:
    """Build data dict for RemediationReporter."""
    all_findings = []
    for sev in ["critical", "high", "medium", "low"]:
        for f in findings_mgr.get_by_severity(sev):
            all_findings.append({
                "severity": f.severity,
                "description": f.description,
                "recommendation": f.recommendation,
                "references": f.references if hasattr(f, "references") else [],
            })
    return {
        "domain": domain,
        "target": target,
        "findings": all_findings,
    }


def build_ad_summary_data(
    results: Dict, domain: str, target: str, dc_ip: str, workflow,
) -> Dict[str, Any]:
    """Build data dict for ADSummaryReporter."""
    return {
        "domain": domain,
        "target": target,
        "dc_ip": dc_ip,
        "phases": results.get("phases", {}),
        "attack_paths": workflow.attack_paths,
    }
