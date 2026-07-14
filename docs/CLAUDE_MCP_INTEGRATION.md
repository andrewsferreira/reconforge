# Claude MCP Integration — Setup Guide

This is the user-facing setup guide for connecting Claude Desktop or Claude Code to ReconForge's
MCP server. For the design rationale, threat model, and phase-by-phase implementation log, see
[`CLAUDE_MCP_IMPLEMENTATION_PLAN.md`](CLAUDE_MCP_IMPLEMENTATION_PLAN.md). This guide only covers
*how to connect and use it*.

## What this is

`reconforge mcp serve` starts an MCP (Model Context Protocol) server over stdio. It lets an MCP
client — Claude Desktop, Claude Code, or any other MCP-compatible client — inspect ReconForge's
state (modules, engagements, findings, reports) and plan or dry-run recon workflows, all read-only
by default. One tool, `reconforge_execute_approved_phase`, can trigger real (non-dry-run) module
execution, but only when the operator has independently created an active engagement and a scope
authorization file beforehand — the server never grants itself permission to run anything (see
"Security model" below).

ReconForge is the MCP *server* here; Claude is the MCP *client*. This is the reverse of
`core/adapters/burp/`, where ReconForge acts as an MCP *client* against Burp Suite's server.

## Prerequisites

- ReconForge installed with the `mcp` extra: `pip install -e ".[mcp]"` (or `reconforge[mcp]` from
  PyPI, once published). This installs the official `mcp` Python SDK (`mcp>=1.2.0`) alongside
  ReconForge's base dependencies.
- Python 3.10+.
- Verify the server starts: `reconforge mcp serve` should block waiting for stdio input (Ctrl+C to
  exit). If it exits immediately with an error, the `mcp` extra likely isn't installed.

## Connecting Claude Desktop

Add an entry to Claude Desktop's config file (`~/Library/Application Support/Claude/claude_desktop_config.json`
on macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "reconforge": {
      "command": "reconforge",
      "args": ["mcp", "serve"]
    }
  }
}
```

If `reconforge` isn't on the `PATH` Claude Desktop uses (common with virtualenvs), point `command`
at the absolute path to the installed console script instead, e.g.
`"/path/to/venv/bin/reconforge"`. Restart Claude Desktop after editing the config.

## Connecting Claude Code

```bash
claude mcp add reconforge -- reconforge mcp serve
```

Or add the same `mcpServers` block shown above to a project's `.mcp.json`. Run `claude mcp list` to
confirm ReconForge shows up and is reachable.

## Security model (summary)

Full detail lives in `CLAUDE_MCP_IMPLEMENTATION_PLAN.md`; the short version:

- **Claude is treated as untrusted.** Every tool argument is independently re-validated
  server-side (target format, module/phase names, scope/approval matching) — nothing from the
  request is taken on faith just because it came from an LLM.
- **12 of 13 tools are read-only.** They inspect state, plan workflows, or run
  `core/runner.py`'s `dry_run=True` code path, which never invokes a real subprocess.
- **The one execution tool never self-approves.** `reconforge_execute_approved_phase` requires all
  of the following, independently re-checked in `services.py`, not merely echoed back from the
  request:
  - An **active engagement** (created beforehand via `reconforge workflow`, see below).
  - A **scope authorization file** and matching **approval ID** (the same mechanism the CLI's
    `--enforce-scope`/`--scope-file`/`--approval-id` flags already use).
  - `explicit_confirmation: true` in the request itself.
  - The requested phase must not classify as `CREDENTIAL_USE` or `PROHIBITED` — AD's
    `delegation`/`bloodhound` phases and any credential-brute-force path are rejected outright,
    with no way to supply credentials through MCP at all.
  - **INTRUSIVE-tier phases** (`web`'s `exploit`, `api`'s `authorization`) additionally require
    `config/mcp.yaml`'s `mcp.allow_intrusive_execution: true` — off by default, and not settable
    via the MCP request itself. Meeting every requirement above still isn't enough for these two
    phases unless an operator has explicitly opted the whole server in by editing that file. See
    [CONFIGURATION.md](CONFIGURATION.md#mcpyaml).
- **Findings and report content separate server-generated structure from target-derived text.**
  Every response carries `trusted_metadata`/`untrusted_evidence` fields (or a flat
  `trust: "server_generated"` marker) so a scanned target can never plant instructions that look
  like they came from ReconForge or the operator — verified by a 26-payload adversarial test suite.
- **No credentials ever flow through MCP responses.** Secret-redaction patterns from
  `core/logger.py::sanitize_log()` apply to everything read-only tools return.

## Tool reference

| Tool | What it does |
|---|---|
| `reconforge_get_status` | Version, OS, module list, tool availability, enabled security controls. |
| `reconforge_list_modules` | The five modules with their valid phases, wrapped tools, target types. |
| `reconforge_get_module_details` | Full phase/tool/target-type detail for one named module. |
| `reconforge_list_engagements` | Engagements saved under `<output_base>/workflow/`. |
| `reconforge_get_engagement` | Status, scope, modules run, findings/loot summary, timeline. |
| `reconforge_get_scope` | Read a scope authorization file's allowed targets, approval id, expiry. |
| `reconforge_plan_workflow` | Propose which modules/phases would run for a target — never executes. |
| `reconforge_dry_run` | Show the exact sanitized commands that would run, via the real command-construction code path — never runs an external tool. |
| `reconforge_get_findings` | List sanitized findings, filterable by target/module/severity/confidence. |
| `reconforge_get_finding` | Fetch one sanitized finding by id. |
| `reconforge_summarize_findings` | Deterministic aggregation — counts, top risks, no evidence text. |
| `reconforge_generate_report` | Render a markdown report (technical or executive) from findings. |
| `reconforge_execute_approved_phase` | Run one real module phase — the only tool that executes anything; see "Security model" above. |

## Walkthrough: read-only exploration

Once connected, a typical read-only session looks like asking Claude:

1. *"What's the current status of ReconForge?"* → `reconforge_get_status`
2. *"What phases does the AD module support?"* → `reconforge_get_module_details` for `ad`
3. *"Plan a recon workflow against 10.10.10.5"* → `reconforge_plan_workflow`
4. *"Show me the exact commands for the network module's discovery phase against that target"* →
   `reconforge_dry_run` — nothing runs, just the sanitized command that *would* run
5. *"What findings do we have for that target so far?"* → `reconforge_get_findings` /
   `reconforge_summarize_findings`
6. *"Generate an executive report"* → `reconforge_generate_report`

None of the above can execute anything — they either read existing state or exercise the same
`dry_run=True` path the CLI's own `--dry-run` flag uses.

## Walkthrough: authorizing real execution

`reconforge_execute_approved_phase` deliberately cannot be satisfied by anything Claude supplies on
its own — the operator has to create the preconditions out-of-band, the same way `--enforce-scope`
already requires for CLI-driven runs:

1. **Create a scope authorization file** (YAML), naming exactly what's authorized:

   ```yaml
   allowed_targets:
     - "10.10.10.5"
   approval_id: "ENGAGEMENT-2026-001"
   valid_until: "2026-08-01T00:00:00+00:00"
   ```

2. **Start an engagement**, which is what makes `engagement_id` resolvable:

   ```bash
   reconforge workflow --target 10.10.10.5 --engagement "Q3 Pentest" \
     --scope-file scope.yaml --approval-id ENGAGEMENT-2026-001
   ```

   This writes `outputs/workflow/<engagement_id>.json` with `status: "active"`.

3. **Ask Claude to run a specific phase**, supplying the same `scope_file`, `approval_id`, and the
   `engagement_id` from step 2, plus `explicit_confirmation: true`. Only then does
   `reconforge_execute_approved_phase` proceed — and only for phases classified below
   `CREDENTIAL_USE`/`PROHIBITED` in `reconforge/mcp/policy.py`.

Any one of these missing or mismatched — wrong approval ID, target outside the scope file's
`allowed_targets`, an inactive/nonexistent engagement, `explicit_confirmation` omitted — and the
tool returns a `PolicyBlockedError`, not a partial or best-effort execution.

## Known limitations

See `CLAUDE_MCP_IMPLEMENTATION_PLAN.md` §13 for the complete list. The two most relevant to end
users right now:

- **No credentialed execution.** AD's `delegation`/`bloodhound` phases and any brute-force path are
  not reachable through MCP at all — run those via the CLI directly with your own `-u`/`-p` flags.
- **One execution at a time, per server process.** A process-wide lock serializes
  `reconforge_execute_approved_phase` calls; a second call while one is in flight is rejected with
  `ExecutionConflictError` rather than queued. A full execution-job model (start/status/cancel) is
  planned for a later phase.
