# Burp MCP Validation Module

This module validates a locally running Burp MCP server using the integrated
ReconForge Burp provider implementation under `core/adapters/burp/`. It runs
an actual MCP client flow (SSE + JSON-RPC), with session/message-endpoint
handling and a safe tool execution check.

## Structure

```text
mcp_validation/
  burp/
    __init__.py
    client.py
    connection.py
    models.py
    rpc.py
    validator.py
  run_validation.py
  report.json            # produced by validation run
```

## What it validates

1. Reachability and SSE connection stability
2. Session/message endpoint discovery (when exposed)
3. `tools/list`
4. Generic `tools/call`
5. One safe tool execution attempt (read-only candidate)
6. Structured recommendation output

## Run

```bash
python mcp_validation/run_validation.py --url http://127.0.0.1:9876 --output mcp_validation/report.json -v
```

## Output report fields

- `success`
- `recommendation`
- `connection`
- `tool_count`
- `tools`
- `missing_features`
- `restricted_features`
- `safe_execution`
- `errors`
- `notes`

## Integration readiness

The validation package is now a thin operational harness around core adapter
code, avoiding duplicate protocol logic and drift.
