# Burp MCP Validation Entrypoint

The Burp MCP validation entrypoint is the official internal method for verifying Burp connectivity and safe provider operation inside ReconForge.

## Why this exists

ReconForge must preserve adapter-only integration and keep orchestration/policy inside the core platform. This validator checks that the Burp provider can:

1. Establish SSE connectivity
2. Acquire session metadata
3. Discover capabilities
4. Apply capability policy filtering
5. Execute a single safe probe (`get_proxy_http_history` or fallback `get_proxy_http_history_regex`)
6. Return normalized data structures

## Usage

### CLI (official)

```bash
reconforge burp validate
```

Optional flags:

```bash
reconforge burp validate --url http://127.0.0.1:9876 --json --output mcp_validation/report.json
```

### Module CLI

```bash
python -m reconforge.burp.validate --json
```

### Programmatic

```python
from reconforge.entrypoints.burp_validation import validate_burp_provider

result = validate_burp_provider()
print(result.to_dict())
```

See `examples/validate_burp_provider.py` for a complete runnable example.

## Configuration

Validation URL precedence:

1. `--url` CLI argument
2. `BURP_MCP_URL` environment variable
3. default `http://127.0.0.1:9876`

## Structured output fields

The validator emits human-readable output and structured JSON with fields including:

- `connection_status`
- `session_id`
- `total_tools`
- `allowed_tools`
- `blocked_tools`
- `test_execution_success`
- `test_execution_latency`
- `errors`
- `warnings`
- `readiness_status`

## Readiness status semantics

- `READY`: Connected, tools discovered, and safe execution probe succeeded with normalized response shape.
- `PARTIAL`: Connected but one or more validation checks failed (e.g., no safe allowed tool, capability issue, timeout).
- `FAILED`: Could not establish stable provider/session connectivity or fatal validation failure occurred.

## Error handling coverage

The entrypoint handles and reports:

- Burp not reachable
- SSE/session protocol failures
- Missing `sessionId`
- Capability discovery failures
- Empty tool set
- Safe tool execution failures
- Timeout waiting for JSON-RPC/SSE response

## Burp Community limitations

Burp Community feature access may vary by extension/plugin behavior. In restricted environments:

- Tool count may be lower than expected
- Some tool calls can be blocked by policy or server-side capability restrictions
- Validation can return `PARTIAL` even with successful connectivity

## Next steps after validation

1. Keep policy-allowed tool set constrained to approved recon actions.
2. Add environment-specific smoke tests in CI using a controlled mock MCP endpoint.
3. Integrate this validation as a preflight gate in orchestration workflows where Burp-dependent actions are required.
