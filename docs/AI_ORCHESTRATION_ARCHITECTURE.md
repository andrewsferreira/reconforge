# ReconForge AI-Orchestrated Architecture

> **Status note (2026-07-14, Phase 30):** This is implemented, in `core/ai_orchestration.py::AIOrchestrationLayer`, wired into `core/workflow_orchestrator.py` — not a proposal. It genuinely does normalize findings across modules into a host→service→endpoint graph, score them, and dynamically queue follow-up module steps during a `reconforge workflow` run.
>
> What it is **not**: despite the "AI"/"Central Intelligence Engine"/"AI Triage" language below, there is no machine-learning model or LLM call anywhere in this codebase (verified by repo-wide search). Every decision here is a fixed rule: keyword-set membership checks (e.g. `{"http","https","http-alt"}` seen → recommend the `web` module), a 4-entry hardcoded banner→CVE lookup table, hand-written confidence literals per recommendation type (0.93 for HTTP→web, 0.9 for LDAP/Kerberos/SMB→AD, 0.72 for HTTP→api), and a linear weighted score (`0.35·severity + 0.30·exploit_likelihood + 0.20·reachability + 0.15·asset_criticality`, scaled by a confidence multiplier). It is a genuinely useful deterministic correlation/prioritization engine — consistent with this project's "Deterministic-by-default behavior" principle (`AGENTS.md`) — read the "AI" branding below as a design metaphor, not a technology claim.

```text
                   ┌────────────────────────────────────────────────┐
                   │            Workflow Orchestrator              │
                   │  (conditional + adaptive module scheduling)   │
                   └───────────────┬────────────────────────────────┘
                                   │ module outputs
            ┌──────────────────────▼──────────────────────┐
            │          AI Orchestration Layer             │
            │                                              │
            │  1) Central Intelligence Engine              │
            │     - normalize findings/signals             │
            │     - infer exploit hypotheses               │
            │     - map service banners -> CVE hints       │
            │                                              │
            │  2) Context Builder                          │
            │     - host -> service -> endpoint graph      │
            │     - relationships + weighted edges         │
            │                                              │
            │  3) Decision Engine                          │
            │     - confidence-driven next modules         │
            │     - adaptive flow instead of static order  │
            │                                              │
            │  4) AI Triage                                │
            │     score = f(severity, likelihood,          │
            │               reachability, criticality)     │
            └──────┬──────────────────────┬────────────────┘
                   │                      │
                   │                      └────────► Prioritized attack paths
                   │
                   └────────► Executive + technical + narrative report sections
```

## Differentiation Outcomes

- ReconForge shifts from phase chaining to **decision-centric offensive reasoning**.
- Raw scanner outputs become **correlated attack hypotheses**.
- Outputs prioritize **exploitability and business impact**, not only CVSS-like severity.

## Real Tool Signal Ingestion

- Nmap host/service data is translated to graph edges and exploit cues.
- Burp/proxy events are scored for missing controls and authz edge cases.
- HTTP scanner findings become behavior-level evidence in attack-path ranking.

## MCP Ingestion Path (2026-07-15)

The ingestion methods above (`ingest_nmap_scan`/`ingest_module_result`/`ingest_proxy_logs`/
`ingest_http_scan`) all assume a live, in-process `WorkflowOrchestrator` holding one
`AIOrchestrationLayer` instance across an entire multi-step `reconforge workflow` run — the
raw `module.run()` result dict is available because the orchestrator never leaves memory
between steps. An MCP-driven execution has no equivalent: `reconforge_execute_approved_phase`/
`reconforge_start_execution` run exactly one module/phase per call and never hold that result
past the call, so the only cross-call artifact is the module's persisted `findings.json`.

`AIOrchestrationLayer.ingest_findings()` is a fifth ingestion method built for exactly that
case — it takes already-persisted Finding records (`core/findings_manager.py`'s on-disk
schema: `module`/`finding_type`/`severity`/`confidence`/`target`/`description`/`references`)
and normalizes them into the same `CorrelatedSignal`/graph representation the other four
ingestion paths produce, so `top_attack_paths()` works unchanged regardless of which path fed
it. A new `recommend_modules()` decision method is its MCP-appropriate counterpart to
`decide_next_actions()`: the latter needs raw port/service graph nodes only the live
orchestrator ever has, so the former answers a narrower, still-honest question from what an
MCP call actually has — "which modules haven't been assessed yet for this target, and does
what's already been found raise the value of assessing them" — never a prediction of what will
succeed. `reconforge/mcp/services.py::recommend_next_steps()` is the sole caller, backing the
`reconforge_recommend_next_steps` MCP tool (see `docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md`'s
MCP-Phase16 entry) — this is what lets Claude decide which module to direct a scan toward next
instead of a human doing that triage by hand.
