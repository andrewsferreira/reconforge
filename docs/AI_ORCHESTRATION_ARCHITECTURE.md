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
