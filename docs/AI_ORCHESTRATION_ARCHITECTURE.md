# ReconForge AI-Orchestrated Architecture

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
