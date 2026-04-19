# Burp MCP Web Lifecycle Validation

This command validates full automated request lifecycle behavior through ReconForge + Burp MCP:

1. baseline request + replay consistency
2. controlled mutation execution
3. response classification and anomaly extraction
4. session continuity checks
5. structured output only (no raw MCP payload forwarding)
6. gap analysis
7. re-test with expanded mutations

## CLI

```bash
reconforge burp lifecycle-validate \
  --target-url https://example.com/api/resource?id=1 \
  --mcp-url http://127.0.0.1:9876 \
  --allow-domain example.com \
  --deny-domain google.com \
  --json \
  --output mcp_validation/lifecycle_report.json
```

## Output

The lifecycle report contains:

- `baseline_request`
- `baseline_replay`
- `mutations_tested`
- `anomalies_detected`
- `session_valid`
- `phase_status`
- `gap_analysis`
- `retest_summary`

All request/response records are normalized to `HTTPObservation` before analysis.

## Determinism and safety

- Request-capable actions execute through Burp provider methods only (scope validation enforced upstream).
- Mutation sets are deterministic from request inputs.
- Output is structured and machine-consumable.
