# Burp MCP Integration (ReconForge)

## Overview

Burp MCP support is now integrated as a first-class optional provider under the
core adapter architecture:

```text
core/adapters/burp/
  __init__.py
  config.py
  exceptions.py
  models.py
  connection.py
  rpc.py
  capabilities.py
  policy.py
  normalizers.py
  client.py
  provider.py
```

This absorbs the previously standalone SSE client behavior into reusable core
modules while preserving a clear separation of responsibilities:

- ReconForge (`reconforge/cli.py`, `WorkflowOrchestrator`) remains orchestrator
  and policy authority — no execution or scope decision lives in the adapter.
- Burp is an external provider.
- Burp adapter/provider contains transport and capability translation only,
  and enforces its own scope check (`core/policy/target_scope.py`'s
  `DomainScopeValidator`) before every HTTP request it issues.

(An earlier, separate "Model 1" generic orchestrator/policy stack —
`core/orchestrator/*`, `core/policy/scope_policy.py` — was never wired to
this or any other live code path and was removed; see
[docs/ARCHITECTURE_REVIEW.md](ARCHITECTURE_REVIEW.md).)

## Migration from standalone logic

The existing working SSE client behavior was modularized as:

- **SSE transport/session handling:** `connection.py`
- **JSON-RPC request/correlation:** `rpc.py`
- **capability discovery:** `client.py` + `capabilities.py`
- **capability gating policy:** `policy.py`
- **safe provider API:** `provider.py`
- **normalization boundary:** `normalizers.py`

Validation tooling (`mcp_validation/`) now wraps core provider code instead of
maintaining a divergent copy.

## Initial safe API (enabled)

Only the following Burp tools are exposed by provider methods:

- `send_http1_request`
- `send_http2_request`
- `get_proxy_http_history`
- `get_proxy_http_history_regex`

Provider methods:

- `BurpMcpProvider.send_http1_request(...)`
- `BurpMcpProvider.send_http2_request(...)`
- `BurpMcpProvider.get_proxy_http_history(...)`
- `BurpMcpProvider.get_proxy_http_history_regex(...)`

## Default-blocked tool categories

Blocked by policy keyword/category defaults:

- configuration-changing tools
- intercept toggling/control tools
- editor-modifying tools
- task engine / intrusive automation tools
- scanner/intruder/UI-driving categories

These tools may be discovered and recorded but remain disabled by default.

## Configuration

Use `BurpMcpConfig`:

- `base_url`
- `sse_path`
- `message_path_fallback`
- `connect_timeout_seconds`
- `read_timeout_seconds`
- `rpc_timeout_seconds`
- `max_retries`
- `debug_logging`
- `lab_mode`

## Basic connectivity/capability check

Validation command:

```bash
python mcp_validation/run_validation.py --url http://127.0.0.1:9876 --output mcp_validation/report.json -v
```

This checks:

1. SSE reachability
2. session and endpoint hint handling
3. tools/list
4. one safe tool call
5. structured recommendation

## Normalization boundary

Burp-specific payloads are normalized into `NormalizedBurpHttpRecord` fields:

- URL
- host
- method
- status code
- response body length
- request/response headers
- provider/tool origin
- evidence source

This prevents raw Burp response structures from leaking directly into broader
ReconForge layers.

## Current limitations / future work

- Burp tool argument schemas are not yet mapped to strongly typed per-tool
  argument classes.
- Scope-policy wrappers are expected to be applied at orchestrator/provider-call
  integration points.
- Additional read-only Burp capabilities can be enabled by policy expansion
  without redesign.
