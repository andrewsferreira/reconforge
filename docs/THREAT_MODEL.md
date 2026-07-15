# ReconForge Threat Model

> Status: whole-system threat model, covering the CLI/library surface. For the
> MCP server's own adversary model (Claude as an untrusted planning layer,
> scanned targets as an untrusted content source), see
> [`CLAUDE_MCP_IMPLEMENTATION_PLAN.md` §2 "Trust Boundaries" and §4 "MCP Threat
> Model"](CLAUDE_MCP_IMPLEMENTATION_PLAN.md#2-trust-boundaries) — that
> document is not duplicated here, only cross-referenced.

## 1. Purpose and Scope

This document states, in one place, what ReconForge is trying to protect,
who it does and doesn't trust, and what happens at each boundary where
untrusted input crosses into a more trusted context. Every claim below is
traceable to a specific file, function, or test — where a claim can't be
backed by code, it's listed under [§7 Residual Risks](#7-known-residual-risks)
instead of asserted as a mitigation.

**In scope:** the `reconforge` CLI/library, the five recon modules, the
credential/loot/findings storage layer, the workflow orchestrator, and the
MCP server's *system-level* boundaries (the parts not already covered by the
MCP-specific document linked above).

**Out of scope:** the third-party tools ReconForge shells out to (`nmap`,
`sqlmap`, `nuclei`, etc.) — their own vulnerabilities are their own upstream
projects' responsibility, not ReconForge's. See
[SECURITY.md](../SECURITY.md#scope) for the disclosure-scope statement this
mirrors.

## 2. Assets

What this system is actually trying to protect, roughly in order of how bad
it would be if each were compromised:

1. **The operator's authorization boundary.** ReconForge exists to run real
   reconnaissance tooling against real targets. The single worst outcome is
   the tool running against a target the operator never authorized.
2. **Credentials and secrets encountered during an engagement** — captured
   loot (passwords, hashes, tokens), and any credentials the operator
   supplies via `-u`/`-p` flags.
3. **Target data returned in findings/evidence** — HTTP response bodies,
   LDAP attribute values, file listings, etc., captured as evidence. This is
   the target's data, not the operator's; it must not leak beyond the
   engagement's own output directory (e.g. via a webhook, a log line, or an
   MCP response).
4. **The operator's own host** — the machine running ReconForge. A
   compromised target or a malicious tool should not be able to escalate
   into arbitrary code execution on the operator's machine via ReconForge
   itself.
5. **The integrity of findings/evidence.** A finding's `confidence` label
   and its evidence text need to mean what they claim, or a downstream
   report becomes actively misleading (see the confidence model in
   [FINDINGS.md](FINDINGS.md)) — this isn't a confidentiality asset, but a
   correctness one worth naming here because several fixed bugs (severity
   inflation, decorative `success=True`) were exactly this kind of failure.

## 3. Actors and Trust Levels

| Actor | Trust level | Why |
|---|---|---|
| **The operator** (person running `reconforge ...` or approving MCP requests) | Fully trusted | They already have shell access to the machine; ReconForge's job is to help them, not to defend against them. |
| **The scanned target** | Untrusted | Everything a target returns — HTTP bodies, LDAP/SMB attribute values, banners, filenames, error messages — is attacker-controllable content, whether or not the target is actually malicious. |
| **External tools invoked as subprocesses** (`nmap`, `sqlmap`, etc.) | Semi-trusted, output untrusted | ReconForge trusts that these binaries do roughly what they claim to do, but never trusts their *output* — stdout/stderr is parsed defensively (see [§5.2](#52-subprocess-execution-and-tool-output)) and never re-interpreted as a command. |
| **Claude / an MCP client** | Untrusted for anything with a side effect | See the MCP-specific document linked above. Summarized in [§5.5](#55-the-mcp-server-claude-as-a-client). |
| **Configured webhook endpoints** (`RECONFORGE_SIEM_WEBHOOK`, etc.) | Trusted by construction, but their URLs are operator-set | Not target- or Claude-controlled; see [§5.4](#54-network-egress-outside-subprocess-tools). |

## 4. Trust Boundary Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│ OPERATOR (trusted)                                                │
│  CLI flags, --scope-file, --approval-id, -u/-p credentials,       │
│  reconforge mcp approvals approve <id>                            │
└──────────────────────────────────────────────────────────────────┘
              │ crosses into: argparse + core/validators.py +
              │ core/target_parser.py (reject, never "clean and continue")
              ▼
┌──────────────────────────────────────────────────────────────────┐
│ AUTHORIZATION GATE                                                 │
│  reconforge/cli.py::require_authorization() -- refuses to run     │
│  anything non-dry-run without --authorized-target, --lab-mode,    │
│  or a validated --enforce-scope (core/authorization_gate.py)      │
└──────────────────────────────────────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────────────────┐
│ CORE (trusted, but every command re-validated per-call)           │
│  core/runner.py::Runner -- list[str] args only, shell=False       │
│  always, validate_arg() on every argument, scope re-checked at    │
│  every execution (not just once at startup)                       │
└──────────────────────────────────────────────────────────────────┘
              │ subprocess boundary
              ▼
┌──────────────────────────────────────────────────────────────────┐
│ EXTERNAL TOOL (semi-trusted binary, untrusted output)              │
│  nmap / sqlmap / nuclei / etc. -- runs against the target,         │
│  writes to raw_dir under the engagement's own output tree          │
└──────────────────────────────────────────────────────────────────┘
              │ stdout/stderr crosses back in -- now UNTRUSTED
              ▼
┌──────────────────────────────────────────────────────────────────┐
│ PARSERS (defensive: try/except around every field access,          │
│ never eval/exec, never re-invoke a subprocess based on parsed      │
│ content)                                                            │
└──────────────────────────────────────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────────────────┐
│ FINDINGS / LOOT / OUTPUT (target-derived content, at rest)          │
│  core/logger.py::sanitize_log() strips known secret patterns       │
│  from anything logged; loot/credential-vault encryption is         │
│  opt-in (--encrypt-loot), off by default with a logged warning     │
└──────────────────────────────────────────────────────────────────┘
              │
              ├──▶ reports (Markdown/JSON) -- operator-facing, local disk only
              │
              └──▶ MCP responses -- see CLAUDE_MCP_IMPLEMENTATION_PLAN.md §2/§4
                    for how target-derived content crossing back out to an
                    LLM client is kept labeled untrusted end-to-end
```

## 5. Threats and Mitigations

### 5.1 Running against an unauthorized target

**Threat:** the tool executes real reconnaissance against a target the
operator never actually authorized — by mistake, a copy-pasted target, or
scope creep during an auto-handoff workflow.

**Mitigations:**
- Every active (non-dry-run) invocation requires one of `--authorized-target`,
  `--lab-mode`, or a validated `--enforce-scope` — enforced by
  `reconforge/cli.py::require_authorization()`, which raises before any
  module is even constructed. `--dry-run` is the only exempt path, since it
  never executes anything.
- `--enforce-scope` is checked against `core/authorization_gate.py::ScopeAuthorization.assert_authorized()`
  at *every* command execution inside `Runner.run()`, not once at startup —
  including targets discovered mid-run via workflow auto-handoff, not just
  the initial `--target`.
- Matching is exact-string only today (no CIDR/domain-suffix matching) —
  documented as a known gap in [§7](#7-known-residual-risks), not silently
  assumed to be broader than it is.

### 5.2 Subprocess execution and tool output

**Threat:** target-controlled content (a hostname, an HTTP response, a
filename returned by a tool) is interpreted as a command rather than data,
leading to command injection on the operator's own machine.

**Mitigations:**
- `shell=True` does not appear anywhere in the codebase's execution path.
  `core/runner.py::Runner.run()` always calls `subprocess.run()` with a
  `list[str]` argument vector; a string command form is only ever
  `shlex.split()` before reaching `subprocess.run()`, never handed to a
  shell.
- `validate_arg()` rejects shell metacharacters in any argument before it
  reaches `subprocess.run()`, as a second layer on top of `list[str]`
  already making shell injection structurally inert.
- Target strings are validated by `core/target_parser.py` before ever being
  used to build a command; `validate_url()`/`validate_domain()` hardened
  against embedded credentials and control characters for the web/API/AD
  target paths specifically.
- Parsed tool output is never `eval`'d, `exec`'d, or fed back into a new
  subprocess invocation as a command fragment.

### 5.3 Credential and secret handling

**Threat:** credentials captured during an engagement (loot, `-u`/`-p`
flags, tokens) leak into logs, reports, or disk in plaintext where they
weren't expected to.

**Mitigations:**
- `core/logger.py::sanitize_log()` redacts a broad set of secret patterns
  (bearer/negotiate tokens, `-p`/`-w`/`-U` CLI flag values, AWS key IDs,
  cookies, private keys, `user:pass@host` credentials in URLs) from every
  log line, command-log entry, and session note — not just a narrow subset.
- The credential vault and loot manager support Fernet encryption at rest
  via `--encrypt-loot`, but it is **opt-in, not the default** — `CredentialVault(encrypt=False)`/`LootManager(encrypt=False)`
  by construction. When encryption is off, a `UserWarning` is logged
  ("Writing loot/vault to `<path>` in PLAINTEXT ... Pass `--encrypt-loot` to
  encrypt") so the operator isn't silently unprotected. This is a real,
  documented gap, not something the docs quietly imply is on by default.
- Credentials are never logged to MCP audit events: `reconforge/mcp/audit.py`
  unconditionally redacts `approval_id` and passes every other string
  argument through `sanitize_log()`.

### 5.4 Network egress outside subprocess tools

**Threat:** ReconForge itself (not a wrapped tool) makes an outbound
network request that leaks scan data or engagement details somewhere the
operator didn't expect.

ReconForge makes direct outbound HTTP requests (i.e. not via a shelled-out
tool) from exactly three places:

- **`core/cve_enricher.py`** — optional, env-gated live NVD CVE lookups,
  rate-limited to avoid hammering NVD's public API.
- **`core/external_integrations.py::dispatch_workflow_event()`** — optional
  SIEM/ticketing/approval webhook dispatch, gated behind three specific env
  vars (`RECONFORGE_SIEM_WEBHOOK`, `RECONFORGE_TICKETING_WEBHOOK`,
  `RECONFORGE_APPROVAL_WEBHOOK`) that are unset by default. The destination
  URL comes from the operator's own environment, never from target- or
  Claude-controlled input; non-`http(s)` schemes are rejected before
  `urlopen()` regardless.
- **`core/secrets_manager.py`** — optional secret-backend lookups (e.g. a
  vault endpoint), same scheme-check discipline.

All three are opt-in (require an explicit env var or CLI flag) and none
accept a target- or model-controlled URL — the URL always comes from the
operator's own configuration.

### 5.5 The MCP server: Claude as a client

**Threat:** an MCP client (Claude) either supplies adversarial tool
arguments, or a scanned target embeds a prompt-injection payload in
evidence text that an MCP response later carries back to Claude.

Covered in depth by the MCP-specific document
([`CLAUDE_MCP_IMPLEMENTATION_PLAN.md` §2, §4](CLAUDE_MCP_IMPLEMENTATION_PLAN.md#2-trust-boundaries)),
summarized here:

- Every MCP tool argument is re-validated server-side by the same
  `core/validators.py`/`core/target_parser.py` the CLI uses — nothing from
  a request is trusted just because it came from a well-formed tool call.
- Real execution requires a human operator's out-of-band approval — see
  [`CLAUDE_MCP_INTEGRATION.md`'s security model](CLAUDE_MCP_INTEGRATION.md#security-model-summary)
  for the full `reconforge_request_execution` → `reconforge mcp approvals
  approve` → `reconforge_execute_approved_phase` flow. No MCP request field
  can substitute for the out-of-band step.
- Target-derived content returned in MCP responses carries an explicit
  `trust: "server_generated"` marker or a `trusted_metadata`/
  `untrusted_evidence` field split, verified by a 26-payload adversarial
  test suite (`tests/mcp/test_sanitization.py`) proving injection payloads
  stay inert.
- There is no MCP tool that reads arbitrary files, dumps environment
  variables, reads credential-vault contents, or widens scope — these are
  absent by design, not present-with-a-check, so there's nothing for a
  successful prompt injection against Claude to invoke even in the worst
  case.

### 5.6 Findings/evidence integrity

**Threat:** a finding's confidence or severity label overstates what was
actually observed, misleading whoever reads the report into treating a
heuristic as confirmed.

**Mitigations:**
- Severity is capped by confidence — `core/findings_manager.py` clamps
  severity so a `heuristic`-confidence finding can never present as
  `critical`, regardless of what the underlying issue would be if real. See
  [FINDINGS.md](FINDINGS.md) for the full table.
- This is a correctness property with real regression coverage, not just a
  design intent: several previously-shipped bugs (BloodHound DA-path
  findings mislabeled `confirmed`, nuclei severity/confidence inversion,
  sqlmap negation-unaware false positives) were found and fixed with
  dedicated tests — see `docs/ARCHITECTURE_REVIEW.md`'s Phase 8 entries for
  the specific fixes.
- Module `run()` methods report `success` based on whether a check actually
  executed, not decoratively — a class of bug (`success=True` regardless of
  whether anything ran) was found and fixed across all five modules; see
  Phase 17/19/26/27 in `docs/ARCHITECTURE_REVIEW.md`.

## 6. Non-Goals

Explicitly not attempted by this threat model or by ReconForge itself:

- **Defending against a malicious operator.** The operator has shell access
  to the machine already; ReconForge does not try to constrain what an
  operator who already controls the process can do.
- **Guaranteeing OPSEC/stealth.** The `stealth`/`normal`/`aggressive` OPSEC
  profiles document *expected* noise level, not a guarantee of not being
  detected — see [LIMITATIONS.md](LIMITATIONS.md).
- **Securing the third-party tools ReconForge invokes.** Their own
  vulnerabilities are out of scope — see [SECURITY.md](../SECURITY.md#scope).
- **Defending against a compromised operator machine.** If the machine
  running ReconForge is already compromised (keylogger, root access by an
  attacker, etc.), no application-layer control here helps.

## 7. Known Residual Risks

Deliberately not claimed as mitigated, tracked for future work rather than
silently omitted:

- **Scope matching is exact-string only.** No CIDR- or domain-suffix-aware
  matching yet — a scope file listing `10.10.10.5` does not automatically
  authorize `10.10.10.5:8080` or a discovered subdomain. See
  `docs/ARCHITECTURE_REVIEW.md` for the tracked gap.
- **Loot/credential encryption is opt-in, not default.** See [§5.3](#53-credential-and-secret-handling).
- **MCP's `scope_file`/`output_base` request parameters are free-form path
  strings**, not server-controlled logical references with a
  traversal-safe resolver — a deliberately deferred Priority-0 item from
  the MCP security hardening pass (see `CLAUDE_MCP_INTEGRATION.md`'s Known
  Limitations section).
- **No true streaming output-size enforcement.** `core/runner.py`'s output
  truncation happens after `subprocess.run()` has already buffered the full
  output in memory — a genuinely huge tool output is fully buffered before
  being truncated, not bounded during capture.
- **Global test coverage is ~70%, not the 85-90% a security-critical
  codebase would ideally carry.** See `pyproject.toml`'s `[tool.coverage.report]`
  comment for the current lowest-coverage files, tracked as ongoing work.
- **No formal fuzzing or third-party penetration test of ReconForge itself**
  has been performed. All security-property claims above are backed by
  targeted unit/adversarial tests, not an independent audit.

## 8. Verification

Every mitigation named above is either directly covered by an automated
test (`pytest`, `tests/mcp/test_sanitization.py`'s adversarial suite,
etc.) or enforced structurally (the absence of `shell=True`, the absence
of certain MCP tools). Quality gates run on every push
(`.github/workflows/quality-gates.yml`): Ruff, MyPy, Bandit, pip-audit, the
full pytest suite with a coverage floor, and a documentation-link checker.
See [README.md § Quality Gates](../README.md#quality-gates) for the current
scope of each.

This document is reviewed and updated whenever a security-relevant
architectural change lands — see `CHANGELOG.md` for the history of such
changes (search for `security(`-prefixed commits).
