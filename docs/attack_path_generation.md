# Attack Path Generation Engine

## Purpose

Transforms isolated classified findings into validated, evidence-backed, multi-step attack paths.

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
4. Validate each step via MCP-backed request execution
5. Prioritize validated paths
6. Run refinement loop for deeper chains
7. Emit failure analysis if no paths validate

## Output structure

`AttackPathReport` contains:

- `graph`
- `primitives`
- `attack_paths` (validated and prioritized)
- `refinement_rounds`
- `failure_analysis`

Each `AttackPath` contains:

- reproducible ordered steps
- primitive linkage
- validation evidence per step
- confidence, priority, and score

## Failure handling

If no paths are produced, report includes explicit root-cause hints:

- missing relationships
- insufficient finding diversity
- weak mutation coverage
