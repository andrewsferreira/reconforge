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
  server-side (target format, module/phase names, scope matching) — nothing from the request is
  taken on faith just because it came from an LLM.
- **13 of 18 tools are read-only.** They inspect state, plan workflows, or run
  `core/runner.py`'s `dry_run=True` code path, which never invokes a real subprocess.
- **Real execution requires a human operator's approval, given genuinely out-of-band.** No MCP
  request field — not `explicit_confirmation`, not anything else Claude can set — is ever accepted
  as proof a human reviewed anything, because Claude can generate that value itself. Instead:
  1. `reconforge_request_execution` creates a pending request. This is the *only* thing it can
     do — it never executes anything and never grants its own approval. The request captures every
     parameter of the operation (target, module, phase, OPSEC profile, scope) and sits in
     `awaiting_operator_approval` status, tied to a stable `request_id`.
  2. A human operator reviews and approves it by running `reconforge mcp approvals approve
     <request_id>` **in a separate terminal, outside the MCP session and outside Claude's reach
     entirely.** Nothing in `reconforge/mcp/` — no tool, no resource — can move a request out of
     `awaiting_operator_approval`. That command is the only code path that can.
  3. Only then can `reconforge_execute_approved_phase` or `reconforge_start_execution` — which
     take **only** a `request_id`, nothing else — consume the approval and run. Consumption is
     atomic and single-use: a `request_id` that has already run, or that was never approved, or
     that has expired, always fails, and a second attempt to consume the same approval can never
     succeed even under a race (verified with real concurrent threads and a real separate OS
     process in `tests/mcp/test_approvals.py` and `tests/mcp/test_stdio_transport_integrity.py`).
  4. Every approval is bound to a canonical hash of the exact operation it was created for
     (engagement, normalized target, module, phase, OPSEC profile, tier, scope reference). If any
     of those fields were altered on disk after approval, the hash recomputed at execution time
     won't match and the request is rejected — approval cannot be silently retargeted.
  5. Approvals expire (`config/mcp.yaml`'s `mcp.approval_ttl_minutes`, default 30 minutes) whether
     or not anyone acts on them, and an operator can `reconforge mcp approvals deny`/`revoke` a
     request at any point before it's consumed.
  - The requested phase must not classify as `CREDENTIAL_USE` or `PROHIBITED` — AD's
    `delegation`/`bloodhound` phases and any credential-brute-force path are rejected outright at
    request-creation time, with no way to supply credentials through MCP at all.
  - **INTRUSIVE-tier phases** (`web`'s `exploit`, `api`'s `authorization`) additionally require
    `config/mcp.yaml`'s `mcp.allow_intrusive_execution: true` — off by default, and not settable
    via the MCP request itself. Meeting every requirement above still isn't enough for these two
    phases unless an operator has explicitly opted the whole server in by editing that file. See
    [CONFIGURATION.md](CONFIGURATION.md#mcpyaml).
  - Engagement and scope validity are checked twice: once when the request is created, and again,
    fresh, at the moment of consumption — time passes between approval and execution, and either
    could have changed in between. A request whose preconditions no longer hold is still consumed
    (fail-closed): a burned approval forcing a fresh request is safer than executing against a
    stale precondition or leaving a spent approval reusable.
- **No MCP-reachable path can read, create, or forge an approval secret.** There is no tool or
  resource that returns an approval's request hash, and no argument to any execution tool other
  than the opaque `request_id` a client already received from `reconforge_request_execution`.
- **Findings and report content separate server-generated structure from target-derived text.**
  Every response carries `trusted_metadata`/`untrusted_evidence` fields (or a flat
  `trust: "server_generated"` marker) so a scanned target can never plant instructions that look
  like they came from ReconForge or the operator — verified by a 26-payload adversarial test suite.
- **No credentials ever flow through MCP responses.** Secret-redaction patterns from
  `core/logger.py::sanitize_log()` apply to everything read-only tools return.
- **Every tool call is audited.** A single JSON line goes to stderr for every call to any of the
  18 tools, success or failure — timestamp, a `session_id` shared by every event from the same
  server process (so a sequence of Claude-directed calls can be reconstructed from stderr even
  when several sessions' logs are interleaved), tool name, outcome, sanitized arguments
  (`approval_id` is always redacted). Claude Desktop/Claude Code capture a server's stderr as logs,
  so this needs no extra configuration to see.
- **Every response carries a `schema_version`.** This is the response *shape's* contract version
  (bumped only on a breaking field removal/repurpose), distinct from `reconforge_version` — lets a
  client detect a genuinely incompatible response shape rather than assuming the API never changes.

## Tool reference

| Tool | What it does |
|---|---|
| `reconforge_get_status` | Version, OS, module list, tool availability, enabled security controls. |
| `reconforge_list_modules` | The five modules with their valid phases, wrapped tools, target types. |
| `reconforge_get_module_details` | Full phase/tool/target-type detail for one named module. |
| `reconforge_list_engagements` | Engagements saved under `<output_base>/workflow/`. |
| `reconforge_get_engagement` | Status, scope, modules run, findings/loot summary, timeline. |
| `reconforge_get_scope` | Read a scope authorization file's allowed targets and expiry, and whether an approval id is configured (the value itself is never returned — see "Security model"). |
| `reconforge_plan_workflow` | Propose which modules/phases would run for a target — never executes. |
| `reconforge_dry_run` | Show the exact sanitized commands that would run, via the real command-construction code path — never runs an external tool. |
| `reconforge_get_findings` | List sanitized findings, filterable by target/module/severity/confidence. |
| `reconforge_get_finding` | Fetch one sanitized finding by id. |
| `reconforge_summarize_findings` | Deterministic aggregation — counts, top risks, no evidence text. |
| `reconforge_recommend_next_steps` | Which modules haven't been assessed yet for a target and which already-gathered findings are worth prioritizing — a deterministic, rule-based ranking over findings already on disk (not ML/LLM, not a prediction). Use this to decide where to direct the next `reconforge_request_execution` call. |
| `reconforge_generate_report` | Render a markdown report (technical or executive) from findings. |
| `reconforge_request_execution` | Create a pending, out-of-band approval request for one real module phase. Never executes anything and never grants its own approval — see "Security model" above. |
| `reconforge_get_approval_status` | Poll a request's status: `awaiting_operator_approval`, `approved`, `denied`, `expired`, `consumed`, or `revoked`. No secret material returned. |
| `reconforge_execute_approved_phase` | Run one real module phase and block until it finishes. Takes only an already-approved `request_id`; see "Security model" above. |
| `reconforge_start_execution` | Same `request_id`-only interface and approval requirement as above, but returns a `job_id` immediately instead of blocking — for phases that might take longer than you want to wait on one call. |
| `reconforge_get_execution_status` | Poll a job started by `reconforge_start_execution` — status, and the result once completed. |

## Resource reference

Alongside the 18 tools above, the server exposes 7 read-only MCP *resources* — a separate,
argument-free content-exposure primitive addressed by URI (`resources/list` and `resources/read`)
rather than an invoked call. Useful for a client that wants to load reference material ambiently
instead of asking a question through a tool call. Every URI comes from a hardcoded allowlist in
`reconforge/mcp/resources.py`; there is no way to request a path outside this list.

| URI | Content |
|---|---|
| `reconforge://docs/claude-mcp-integration` | This document. |
| `reconforge://docs/architecture` | `docs/ARCHITECTURE.md` — system architecture. |
| `reconforge://docs/modules` | `docs/MODULES.md` — narrative module/phase reference. |
| `reconforge://docs/configuration` | `docs/CONFIGURATION.md` — config.yaml/opsec.yaml/mcp.yaml reference. |
| `reconforge://docs/findings` | `docs/FINDINGS.md` — finding fields, severity/confidence taxonomy. |
| `reconforge://docs/limitations` | `docs/LIMITATIONS.md` — documented gaps and non-goals. |
| `reconforge://modules` | Live JSON module catalog — the same data `reconforge_list_modules` returns, computed from the same code path so the two can't drift. |

## Safe demonstration

For the safest possible end-to-end look at this integration — no Claude client, no third-party
tooling, no real network access — run `examples/claude_mcp/dry_run_against_lab.py`. It starts
`lab/vulnerable_app.py` (the first-party, stdlib-only local target, see README.md's "Local
Validation Lab" section) on loopback, then calls `reconforge_dry_run` against it through a real
MCP client/server session and prints the JSON result. Nothing is ever actually sent to the lab
server — `dry_run` only constructs the command ReconForge *would* run — but the target is
concretely real and reachable rather than a synthetic placeholder IP.

```bash
pip install -e ".[mcp]"
python examples/claude_mcp/dry_run_against_lab.py
```

## Walkthrough: read-only exploration

Once connected, a typical read-only session looks like asking Claude:

1. *"What's the current status of ReconForge?"* → `reconforge_get_status`
2. *"What phases does the AD module support?"* → `reconforge_get_module_details` for `ad`
3. *"Plan a recon workflow against 10.10.10.5"* → `reconforge_plan_workflow`
4. *"Show me the exact commands for the network module's discovery phase against that target"* →
   `reconforge_dry_run` — nothing runs, just the sanitized command that *would* run
5. *"What findings do we have for that target so far?"* → `reconforge_get_findings` /
   `reconforge_summarize_findings`
6. *"Which module should we run next, and what's worth prioritizing?"* →
   `reconforge_recommend_next_steps` — a coverage-gap recommendation over findings already
   gathered, so Claude can direct the next step of a multi-module scan instead of a human doing
   that triage by hand
7. *"Generate an executive report"* → `reconforge_generate_report`

None of the above can execute anything — they either read existing state or exercise the same
`dry_run=True` path the CLI's own `--dry-run` flag uses.

## Walkthrough: authorizing real execution

Real execution is a two-stage flow: Claude can *ask*, but only a human operator sitting at a
separate terminal can turn that ask into an approval. Nothing Claude supplies in the MCP request
itself — no field, no flag — can substitute for that human step.

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

3. **Ask Claude to request execution of a specific phase**, supplying `scope_file`, `approval_id`,
   and the `engagement_id` from step 2. `reconforge_request_execution` validates all of this
   immediately — wrong approval ID, target outside `allowed_targets`, an inactive/nonexistent
   engagement, or a `CREDENTIAL_USE`/`PROHIBITED`-tier phase all fail right here with a
   `PolicyBlockedError`. If it succeeds, Claude gets back a `request_id` and the request sits in
   `awaiting_operator_approval` — nothing has run, and nothing can run yet.

4. **You, the operator, review and approve it yourself**, in a separate terminal:

   ```bash
   reconforge mcp approvals inspect <request_id>   # see exactly what was requested
   reconforge mcp approvals approve <request_id>   # or `deny <request_id> --reason "..."`
   ```

   This is the only step in the entire flow Claude cannot perform or influence — it doesn't run
   inside the MCP session, and no MCP tool can call it.

5. **Ask Claude to run the approved request**, supplying only the `request_id` from step 3.
   `reconforge_execute_approved_phase` re-verifies the approval is genuine, unexpired, unconsumed,
   and hash-matches exactly what was requested, then runs it — consuming the approval in the same
   atomic step, so the same `request_id` can never be used twice.

For a phase that might run long, use `reconforge_start_execution` instead of
`reconforge_execute_approved_phase` in step 5 — identical `request_id`-only interface, but it
returns a `job_id` immediately; poll `reconforge_get_execution_status` with that id until `status`
is `completed` or `failed`.

Approvals expire after `mcp.approval_ttl_minutes` (default 30) if step 5 never happens — check
`reconforge_get_approval_status`/`reconforge mcp approvals list` if a request seems to have gone
stale.

## Known limitations

See `CLAUDE_MCP_IMPLEMENTATION_PLAN.md` §13 for the complete list. The three most relevant to end
users right now:

- **No credentialed execution.** AD's `delegation`/`bloodhound` phases and any brute-force path are
  not reachable through MCP at all — run those via the CLI directly with your own `-u`/`-p` flags.
- **Free-form `scope_file`/`output_base` path parameters.** These are still plain strings supplied
  in the MCP request rather than server-controlled logical references — replacing them with an
  opaque, server-validated `scope_id`/`workspace_id` plus a path resolver that rejects traversal and
  symlink escapes is a known, deliberately deferred gap, not yet built.
- **One execution at a time, per server process.** A process-wide lock serializes every execution
  tool call — `reconforge_execute_approved_phase`, and `reconforge_start_execution`'s background
  job. A second call while one is in flight is rejected with `ExecutionConflictError` immediately,
  rather than queued.
- **No execution cancellation.** `core/runner.py`'s subprocess execution has no cooperative-
  cancellation hook, so a `reconforge_start_execution` job cannot actually be stopped once running
  — it runs to completion or failure. There is deliberately no `cancel` tool: one that only worked
  in the sub-millisecond window before a job's worker thread starts would be misleading rather than
  useful. Job state is also in-memory only — a server restart loses any in-flight or completed job
  you haven't already read via `reconforge_get_execution_status`.
