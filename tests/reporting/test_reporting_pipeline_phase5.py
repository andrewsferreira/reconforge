import json
from datetime import datetime, timezone

from core.reporting.models import ErrorSummary, ReportingBundle, ReportingMetadata
from core.reporting.pipeline import ReportingPipeline
from core.reporting.renderers.executive_summary import ExecutiveSummaryRenderer
from core.schemas.contracts import CorrelationResult, EvidenceItem, ExecutionResult, NormalizedObservation


def _sample_bundle() -> ReportingBundle:
    metadata = ReportingMetadata(
        run_id="run-123",
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by="pytest",
        target="api.example.com",
        scope_id="scope-1",
        approval_id="APP-1",
    )
    execution = ExecutionResult(
        run_id="run-123",
        provider="mcp:nmap",
        target="api.example.com",
        action="service_scan",
        status="success",
        started_at=datetime.now(timezone.utc).isoformat(),
        finished_at=datetime.now(timezone.utc).isoformat(),
        duration_seconds=0.2,
        raw_result={"service": "http", "port": 443},
        normalized=[
            NormalizedObservation(
                observation_type="service_fingerprint",
                target="api.example.com",
                attributes={"service": "http", "port": 443},
                evidence_id="ev-1",
            )
        ],
    )
    evidence = EvidenceItem(
        evidence_id="ev-1",
        run_id="run-123",
        timestamp=datetime.now(timezone.utc).isoformat(),
        provider="mcp:nmap",
        target="api.example.com",
        action="service_scan",
        raw_ref="raw/raw_results.json",
        normalized_ref="normalized/normalized_observations.json",
        status="success",
    )
    finding = CorrelationResult(
        target="api.example.com",
        finding_keys=["http_tls_service"],
        confidence=0.74,
        priority="medium",
        evidence_ids=["ev-1"],
    )
    return ReportingBundle(
        metadata=metadata,
        execution_results=[execution],
        normalized_observations=execution.normalized,
        correlated_findings=[finding],
        evidence_items=[evidence],
        limitations=["Single provider used; coverage may be incomplete."],
        inferred_commentary=["HTTP service likely front-end entry point."],
        llm_narrative="Derived narrative: prioritize endpoint inventory before deeper tests.",
        errors=[ErrorSummary(code="WARN_PARTIAL", message="No DNS provider configured", source="pipeline")],
    )


def test_json_export_integrity_and_traceability(tmp_path):
    bundle = _sample_bundle()
    artifacts = ReportingPipeline().generate(bundle, tmp_path)

    summary = json.loads((tmp_path / "reporting" / "structured" / "execution_summary.json").read_text())
    evidence_refs = json.loads((tmp_path / "reporting" / "structured" / "evidence_references.json").read_text())

    assert summary["run_id"] == "run-123"
    assert summary["correlated_finding_count"] == 1
    assert evidence_refs["finding_to_evidence"][0]["evidence_ids"] == ["ev-1"]


def test_markdown_report_contains_evidence_references_and_boundaries(tmp_path):
    bundle = _sample_bundle()
    ReportingPipeline().generate(bundle, tmp_path)

    technical = (tmp_path / "reporting" / "reports" / "technical_report.md").read_text()

    assert "Correlated Findings" in technical
    assert "`ev-1`" in technical
    assert "Fact vs Interpretation Boundary" in technical
    assert "LLM Narrative (Derived, Non-Authoritative)" in technical


def test_manifest_generation_and_layered_structure(tmp_path):
    bundle = _sample_bundle()
    ReportingPipeline().generate(bundle, tmp_path)

    manifest_path = tmp_path / "reporting" / "manifests" / "report_manifest.json"
    manifest = json.loads(manifest_path.read_text())

    assert manifest["entry_count"] >= 6
    assert manifest["root_chain_hash"]
    assert any("reports/technical_report.md" in e["path"] for e in manifest["entries"])


def test_missing_partial_data_is_rendered_explicitly(tmp_path):
    metadata = ReportingMetadata(
        run_id="run-empty",
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by="pytest",
        target="empty.example.com",
    )
    bundle = ReportingBundle(metadata=metadata)

    ReportingPipeline().generate(bundle, tmp_path)
    technical = (tmp_path / "reporting" / "reports" / "technical_report.md").read_text()

    assert "No normalized observations available." in technical
    assert "No correlated findings were produced." in technical


def test_report_stability_under_conflicting_observations(tmp_path):
    bundle = _sample_bundle()
    bundle.normalized_observations.append(
        NormalizedObservation(
            observation_type="service_fingerprint",
            target="api.example.com",
            attributes={"service": "https", "port": 8443},
            evidence_id="ev-2",
        )
    )
    bundle.evidence_items.append(
        EvidenceItem(
            evidence_id="ev-2",
            run_id="run-123",
            timestamp=datetime.now(timezone.utc).isoformat(),
            provider="mcp:httpx",
            target="api.example.com",
            action="http_probe",
            raw_ref="raw/raw_results.json",
            normalized_ref="normalized/normalized_observations.json",
            status="success",
        )
    )

    ReportingPipeline().generate(bundle, tmp_path)
    data = json.loads((tmp_path / "reporting" / "structured" / "normalized_observations.json").read_text())

    assert len(data["items"]) == 2
    assert data["counts_by_target"]["api.example.com"] == 2


def test_executive_summary_is_grounded_in_actual_findings():
    bundle = _sample_bundle()
    summary = ExecutiveSummaryRenderer().render(bundle)

    assert "Major Finding Clusters (Correlated Layer)" in summary
    assert "Critical: `0`" in summary
    assert "Medium: `1`" in summary
    assert "ev-1" in summary
