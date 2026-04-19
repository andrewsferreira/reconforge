# Burp MCP Validation Entrypoint

The Burp MCP validation entrypoint is the official readiness check for the ReconForge Burp provider adapter.

It validates provider behavior through the provider abstraction (not the raw SSE client) and is safe for manual operator checks, CI smoke checks, and orchestration preflight gates.

## What the validation checks

Validation flow:

1. Initialize `BurpMcpProvider`
2. Connect to Burp MCP and establish session transport
3. Confirm session metadata (`session_id`) handling
4. Discover capabilities (`tools/list`)
5. Apply provider policy classification (allowed vs blocked tools)
6. Execute one safe operation (`get_proxy_http_history`, fallback `get_proxy_http_history_regex`)
7. Validate response normalization shape and classify readiness

## Official invocation methods

### Project CLI (recommended)

```bash
reconforge burp validate
```

With explicit options:

```bash
reconforge burp validate \
  --url http://127.0.0.1:9876 \
  --rpc-timeout 8 \
  --connect-timeout 3 \
  --debug \
  --json \
  --output mcp_validation/report.json
```

### Module execution

```bash
python -m reconforge.burp.validate --json
```

### Programmatic usage

```python
from reconforge.entrypoints.burp_validation import validate_burp_provider

result = validate_burp_provider()
print(result.to_dict())
```

## Configuration inputs

Supported configuration precedence:

1. CLI args (`--url`, `--rpc-timeout`, `--connect-timeout`, `--debug`)
2. Environment variables:
   - `BURP_MCP_URL`
   - `BURP_MCP_RPC_TIMEOUT_SECONDS`
   - `BURP_MCP_CONNECT_TIMEOUT_SECONDS`
   - `BURP_MCP_READ_TIMEOUT_SECONDS`
   - `BURP_MCP_MAX_RETRIES`
   - `BURP_MCP_DEBUG`
3. Provider defaults from `BurpMcpConfig`

## Output model

The validator always returns a structured result model (`BurpValidationResult`) and supports optional JSON emission.

Key JSON fields:

- `provider_name`
- `provider_type`
- `connection_status`
- `session_status`
- `session_id`
- `capability_discovery_status`
- `total_tools`
- `discovered_tools`
- `allowed_tools`
- `blocked_tools`
- `safe_test_name`
- `safe_test_status`
- `safe_test_latency_ms`
- `safe_test_summary`
- `warnings`
- `errors`
- `readiness_status`

## Readiness states

- `READY`
  - Connection established
  - Session established
  - Capabilities discovered
  - Safe test succeeded with valid normalized response
- `PARTIAL`
  - Provider reachable/session usable but one or more checks degraded (for example safe tool denied, timeout during probe, or capability issues)
- `FAILED`
  - Connection/session establishment failed, or validation could not safely proceed

## Safe test behavior

The validation probe intentionally uses read-oriented safe operations only:

- Primary: `get_proxy_http_history`
- Fallback: `get_proxy_http_history_regex`

The probe must not alter Burp configuration, intercept mode, editor state, or task execution state.
