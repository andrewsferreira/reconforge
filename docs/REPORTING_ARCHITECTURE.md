# ReconForge Reporting Architecture (Phase 5)

> **⚠️ Status: implemented and tested in isolation, not yet wired to live data.**
> Everything described below is real, working code with its own test suite
> (`tests/reporting/test_reporting_pipeline_phase5.py`) — but that suite
> constructs a `ReportingBundle` by hand from synthetic `core/schemas/contracts.py`
> objects. No module, the `reconforge workflow` command, or any other live
> code path currently builds a `ReportingBundle` from real execution
> results and calls `ReportingPipeline.generate()`. Until that integration
> exists, running ReconForge against a real target will **not** produce
> any of the `outputs/<target>/reporting/` artifacts documented here — you
> get each module's `quick_report.md` instead (see
> [ARCHITECTURE.md](ARCHITECTURE.md)). Treat this document as a design
> spec for a not-yet-connected pipeline, not a description of current CLI
> output. See [docs/ARCHITECTURE_REVIEW.md](ARCHITECTURE_REVIEW.md) for
> the tracked decision on whether/how to wire this in.

## Purpose

Phase 5 introduces an enterprise-oriented reporting pipeline that transforms
execution outputs into structured, traceable artifacts for operators,
engineering systems, and executive stakeholders.

The pipeline is intentionally **downstream-only**:

1. Execution layer records results
2. Normalization layer standardizes observations
3. Correlation layer aggregates and prioritizes findings
4. Reporting layer exports and renders artifacts without changing technical truth

Reporting never performs orchestration decisions, scope policy decisions, or
provider execution.

---

## Trust Boundaries

### Trusted (Core)
- `core/policy/target_scope.py`
- `core/schemas/*`
- `core/reporting/*`

### Semi-trusted (Adapters)
- `core/adapters/*`
- Adapter outputs are treated as untrusted input until normalized/correlated.

### Untrusted (External systems)
- MCP providers
- External tool outputs
- External APIs

**Rule:** Executive and markdown reports consume normalized/correlated data and
explicit evidence references; they do not consume raw provider text as truth.

---

## Reporting Components

## 1) Structured Exporters
- `core/reporting/exporters/json_exporter.py`
  - `execution_summary.json`
  - `normalized_observations.json`
  - `correlated_findings.json`
  - `evidence_references.json`
  - `error_summary.json`
  - `run_metadata.json`

## 2) Renderers
- `core/reporting/renderers/technical_markdown.py`
  - Technical evidence-oriented report
  - Explicit sections for facts, interpretation, errors, and limitations
- `core/reporting/renderers/executive_summary.py`
  - Evidence-grounded executive summary
  - Prioritization and confidence signals without speculative impact claims

## 3) Manifest Builder
- `core/reporting/exporters/manifest_builder.py`
  - Deterministic artifact manifest with chained hashes
  - Helps audit artifact integrity and report package completeness

## 4) Pipeline
- `core/reporting/pipeline.py`
  - Writes all artifacts under deterministic layer directories
  - Produces report bundle and manifest in one controlled operation

---

## Output Structure

All phase-5 artifacts are written below:

```text
outputs/<target>/reporting/
  raw/
    raw_results.json
  normalized/
    normalized_observations.json
  correlated/
    correlated_findings.json
  reports/
    technical_report.md
    executive_summary.md
  structured/
    execution_summary.json
    normalized_observations.json
    correlated_findings.json
    evidence_references.json
    error_summary.json
    run_metadata.json
  manifests/
    report_manifest.json
```

This structure separates raw, normalized, correlated, and narrative artifacts.

---

## Evidence Traceability Model

A finding in reporting is traceable via this chain:

1. `correlated_findings[].evidence_ids[]`
2. `evidence_references.evidence_items[]`
3. evidence fields (`provider`, `target`, `action`, `raw_ref`, `normalized_ref`)
4. raw and normalized artifact paths in output layers

The technical markdown report prints evidence IDs for each correlated finding.

---

## Fact vs Interpretation Rules

### Facts (authoritative)
- execution results
- normalized observations
- correlated findings
- evidence records

### Derived interpretation (non-authoritative)
- inferred commentary
- LLM narrative (if provided)

The technical report includes a dedicated “Fact vs Interpretation Boundary”
section so readers can distinguish evidence-backed facts from narrative context.

---

## Enterprise Use Notes and Limitations

- Reports are machine-readable first; narrative is additive.
- If data is partial, reports must state missing coverage explicitly.
- Executive summary does not claim exploitability or business impact without
  evidence-backed correlated findings.
- Output schemas are versioned at exporter level (`schema_version`).

---

## Integration Guidance

Use `ReportingPipeline.generate(bundle, base_output_dir)` where `bundle`
contains:
- run metadata
- execution results
- normalized observations
- correlated findings
- evidence items
- errors/limitations
- optional inferred commentary
- optional LLM narrative

The pipeline is designed for incremental adoption and would not require
rewriting existing module execution paths — but as noted at the top of
this document, nothing currently calls it with a real `ReportingBundle`.
Adopting it means writing a mapper from `core/findings_manager.Finding`
/ `core/runner.RunResult` / `core/attack_workflow` data into
`core/schemas/contracts.py`'s dataclasses, which is real integration
work, not a config flag.
