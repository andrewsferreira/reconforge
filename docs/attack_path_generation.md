# Attack Path Generation Engine

## Purpose

Transforms isolated classified findings into candidate multi-step attack paths, then replays each
step live and tags the result honestly: `unreachable` (a step's request errored/timed out),
`reachable` (every step got a response, but at least one didn't match its expected success signal),
or `corroborated` (every step both completed and matched its expected signal). Even `corroborated`
is a heuristic replay that survived a live retest — it is **not** confirmed exploitation, which
requires authorized-lab validation (see `docs/FINDINGS.md` for the broader confidence model).

## Inputs (required)

- endpoints
- classified findings
- parameter profiles
- relationships/correlations

Execution is rejected if required intelligence data is incomplete.

## Command

```bash
reconforge burp attack-paths \
  --mcp-url http://127.0.0.1:9876 \
  --endpoint "https://target.local/api/user?user_id=1" \
  --endpoint "https://target.local/api/order?user_id=1" \
  --allow-domain target.local \
  --refinement-rounds 2 \
  --json \
  --output mcp_validation/attack_paths.json
```

## Engine phases

1. Build graph (`endpoint`, `parameter`, `finding`, `cluster` nodes + edges)
2. Map findings to attack primitives
3. Generate compatible candidate chains
4. Replay each step via MCP-backed request execution and tag it `unreachable` / `reachable` /
   `corroborated`
5. Score and prioritize by corroboration tier plus impact/confidence/step-count
6. Run refinement loop for deeper chains
7. Emit failure analysis if no candidate paths remain reachable

## Output structure

`AttackPathReport` contains:

- `graph`
- `primitives`
- `attack_paths` (replayed, tiered, and prioritized — see the `status` field on each path:
  `unreachable` / `reachable` / `corroborated`)
- `refinement_rounds`
- `failure_analysis`

Each `AttackPath` contains:

- reproducible ordered steps
- primitive linkage
- replay evidence per step (the actual HTTP response observed on retest)
- reachability/corroboration status, confidence, priority, and score

## Failure handling

If no paths remain reachable after replay, report includes explicit root-cause hints:

- missing relationships
- insufficient finding diversity
- weak mutation coverage
