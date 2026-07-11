# ReconForge — Architecture Review

**Date:** 2026-07-11
**Scope:** Full repository audit prior to public release, per the ReconForge engineering mandate (see [AGENTS.md](../AGENTS.md)).
**Method:** Static review of `core/`, `modules/`, `reconforge/`, `mcp_validation/`, `tests/`, `docs/`, `.github/`, and packaging config, cross-checked against actual command execution (`pytest`, `ruff check`, `mypy`, `bandit`) rather than documentation claims alone.
**Status of this document:** living. Update it as remediation lands; do not delete resolved items — mark them done and keep the history.

---

## 1. Current Architecture (as it actually runs today)

The **real, working, end-to-end path** is:

```
reconforge/cli.py (argparse dispatcher)
  -> enforce_scope_gate()          [core/authorization_gate.py, opt-in via --enforce-scope]
  -> modules/{network,ad,web,api,surface}/<name>_module.py
       -> phase classes (modules/<name>/phases/*.py, modules/<name>/base.py)
            -> tool wrappers (modules/<name>/tools/*.py)
                 -> core/runner.py (Runner.run) — the ONE subprocess execution layer
            -> parsers (modules/<name>/parsers/*.py)
       -> core/findings_manager.py (FindingsManager)
       -> module-local quick_report.md (OutputManager)
```

`core/workflow_orchestrator.py` (`WorkflowOrchestrator`) is a second layer that chains the same five modules together for the `reconforge workflow` subcommand, feeding a shared `WorkflowContext` and driving `FindingsManager`, `CredentialVault`, `LootManager`, `AttackWorkflow`, `core/ai_orchestration.py`, and `core/post_exploitation.py`.

A **separate, narrower path** exists for Burp Suite MCP integration: `reconforge/burp/*.py` → `reconforge/entrypoints/*.py` → `core/adapters/burp/*` → `core/orchestrator/execution_coordinator.py` → `core/policy/scope_policy.py`. This path uses a completely different orchestration and scope-enforcement stack than the recon modules above (see §5, Duplicated Components).

`core/attack_workflow.py` is not an orchestrator — it's a kill-chain/hypothesis log (`AttackWorkflow.add_step/record_result/add_attack_path`) used by every module's phase base class to produce narrative Markdown. The name collision with `core/workflow_orchestrator.py` and `core/orchestrator/workflow_engine.py` is confusing but the three files are not functionally competing (the third, `workflow_engine.py`, is dead — see §8).

### What the CLI actually installs

`pyproject.toml` registers `reconforge = "reconforge:main"`. `reconforge/__init__.py` re-exports `main` from `reconforge/cli.py`. The installed CLI never imports `core/orchestrator/`, `core/policy/`, or `core/schemas/` except transitively through the Burp subcommands.

---

## 2. Strengths

These should be preserved and are worth highlighting publicly — they are genuine evidence of engineering discipline:

- **No `shell=True` anywhere.** A repo-wide grep across ~36k LOC found zero uses of `shell=True`, `os.system`, `os.popen`, `eval`, or `exec`. Every subprocess call goes through one function, `core/runner.py::Runner.run()`, using `subprocess.run(list[str], ...)`.
- **Severity and confidence are genuinely separated.** `core/findings_manager.py` implements explicit confidence levels (`confirmed/high/medium/low/heuristic`) with a documented, enforced severity cap table (`_CONFIDENCE_SEVERITY_CAP`) — a `heuristic`-confidence finding cannot present as `critical` severity. This is exactly the model the task brief asks for, already partially built.
- **The one HTML report path is safe.** `core/output_manager.py::_write_html_report` runs `html.escape()` over the entire rendered document before embedding it — no injection route was found. No CDN references, no inline unescaped tool output.
- **`core/runner.py` has real operator-safety features**: timeout handling, a dry-run mode, a kill-switch (env var/file based), structured JSONL audit events, and binary-existence checks at ~29 call sites.
- **`AGENTS.md` documents a specific, non-generic operating contract** — scope/policy enforcement must live in code, not prompts; LLMs are restricted to summarization/classification and explicitly barred from execution/scope decisions. This is unusual rigor for how the project was built, even though the current state doesn't yet meet its own bar (see §6).
- **`docs/LIMITATIONS.md`, `docs/ARCHITECTURE.md`, `docs/TERMINOLOGY.md`, `docs/SEVERITY_CRITERIA.md`, `docs/SUPPORT_MATRIX.md`** are specific and largely honest about scope — they explicitly disclaim being an exploitation framework and document OPSEC gating. These are the strongest docs in the repo.
- **`CONTRIBUTING.md` and `CHANGELOG.md`** are project-specific, not boilerplate, and reference real file paths and conventions.
- **Real parser test coverage exists** for the well-covered tools (nmap, ffuf, arjun, impacket, nuclei-api, and the web module's ffuf/gobuster/nikto/nuclei/wafw00f/whatweb) — tests exercise actual parsing logic against fixture strings, not just mocks.
- **`core/reporting/exporters/manifest_builder.py`** implements a real SHA-256 hash-chain over report artifacts — a genuine integrity feature, even though the pipeline it belongs to is currently unreachable from the CLI (see §8).

---

## 3. Architectural Weaknesses

- **Two parallel orchestration architectures that don't interoperate.** The real recon flow (§1) and a second, generic orchestration stack (`core/orchestrator/execution_coordinator.py`, `module_router.py`, `workflow_engine.py`, `core/policy/scope_policy.py`, `core/schemas/contracts.py`) coexist. The second stack is only reachable through the Burp subcommand and is otherwise exercised solely by `tests/core_foundation/*`. A contributor reading the codebase has no way to tell which is canonical without tracing imports.
- **Two independent scope/authorization mechanisms** with no shared code: `core/authorization_gate.py::ScopeAuthorization` (used by the CLI's recon subcommands) vs. `core/policy/scope_policy.py::ScopePolicy` (used only by the Burp path). A scope bug fixed in one does not protect the other.
- **Three reporting pipelines, two of them dead**: per-module hand-rolled `quick_report.md` (actually runs), `core/output_manager.py::generate_engagement_report()` (zero callers outside its own definition, no test), and the structured `core/reporting/` "Phase 5" pipeline (only reachable via `OutputManager.generate_reporting_bundle()`, which is itself never called in production — only by its own test).
- **Attack-path modeling is narrower than the product's stated scope.** `reconforge/attack_paths/engine.py` builds a graph of only `endpoint`/`parameter`/`finding`/`cluster` nodes (HTTP-only). The AD module has no representation in any attack graph — no asset/user/group/credential/session/privilege/trust nodes exist anywhere, despite AD being one of the five advertised modules.

---

## 4. Security Risks

Ordered by severity; full remediation ownership in §10.

| # | Risk | Evidence | Severity |
|---|------|----------|----------|
| S1 | Target hostname validation accepts **any** string unconditionally — no rejection path exists | `core/target_parser.py:47-52` — the regex match branch and the no-match branch both execute `target.hostname = target_str` and return normally. This is the parser actually imported by `modules/network`, `modules/ad`, `modules/surface`. | **P0** |
| S2 | Scope/authorization is never enforced at the point commands actually execute | `core/runner.py` contains zero references to `authorization_gate`, `ScopeAuthorization`, `ScopeValidator`, or `DomainScopeValidator`. The one component that would enforce scope deterministically before execution (`ExecutionCoordinator` + `ScopeValidator`) is instantiated only in `tests/core_foundation/test_execution_coordinator_foundation.py`. | **P0** |
| S3 | No re-validation of scope for redirects or newly discovered targets | Scope is checked once, at CLI parse time, against the original `--target` string only. No code path re-checks a target after an HTTP redirect, DNS resolution, or discovery of a new host/asset mid-run (`reconforge/intelligence/engine.py`'s `HttpMutationEngine` issues new requests with no scope check on mutated URLs). | **P0** |
| S4 | `--enforce-scope` is opt-in (default off on all six subcommands), single-shot, and does exact-string matching only (no CIDR/domain-suffix matching) | `reconforge/cli.py:324-337`, `core/authorization_gate.py:52-62` | **P1** |
| S5 | Command strings — potentially containing target-supplied or credential-adjacent data — flow unredacted into persisted logs | `Runner._command_log` → `save_command_log()` and `NotesManager.add_command_note()` bypass `core/logger.py::sanitize_log()`, which is only applied on the JSONL audit stream and inside specific `command()`/`loot()`/`credential()` helpers. | **P0** |
| S6 | `validate_arg()` shell-metacharacter guard is applied inconsistently | Only used in `modules/api/tools/{arjun_tool,ffuf_api,httpx_tool,nuclei_api}.py`. Zero uses across `modules/network` (19 files), `modules/web` (27 files), `modules/ad` (58 files). No leading-`-` flag-injection guard anywhere. | **P2** |
| S7 | Credential vault / loot manager: encryption optional (default off), Fernet key stored at a fixed predictable path next to the data it protects, silent plaintext fallback if `cryptography` is missing | `core/credential_vault.py`, `core/loot_manager.py` — keys at `~/.reconforge/{vault,loot}.key`, chmod 0600, adjacent to the encrypted file itself. | **P1** |
| S8 | Two silently-swallowed `except Exception: pass` blocks | `core/secrets_manager.py:48`, `modules/surface/parsers/surface_parser.py:160` | **P2** |
| S9 | `core/validators.py` — the correct, strict target validators (RFC952/1123 hostname regex, IP/CIDR/URL/domain checks) — is entirely unused; no module imports it | Confirmed via repo-wide grep for `validate_target`, `validate_hostname`, `from core.validators`. | **P1** |
| S10 | Risk policy engine disabled by default | `core/risk_policy.py` requires `RECONFORGE_POLICY_ENFORCE=1`; off by default means the one policy gate inside `Runner.run()` does nothing unless an operator knows to set an env var. | **P2** |
| S11 | Unexplained 255KB Fernet-encrypted blob tracked in git since the initial commit, not referenced anywhere in code/docs/config | `.abacus.donotdelete` — verified via `file`, `git log`, and repo-wide grep for "abacus" (zero references). Content and origin unknown; likely a platform artifact, but must be identified and either documented or removed before any public push. | **P0** |

---

## 5. Duplicated Components

| Component A | Component B | Notes | Severity |
|---|---|---|---|
| `core/authorization_gate.py` | `core/policy/scope_policy.py` + `core/policy/target_scope.py` | Three independent scope-checking implementations, two of them (`scope_policy.py`, `target_scope.py`) duplicating allow/deny/subdomain logic between themselves too. | P1/P2 |
| `modules/network/tools/{nmap,smbclient,ldapsearch}.py` | `modules/ad/tools/{nmap,smbclient,ldapsearch}.py` | Same binaries wrapped twice with parallel classes and separate parsers (`modules/network/parsers/*` vs `modules/ad/parsers/*`). A flag/CVE fix to one will not propagate to the other. | P2 |
| `core/adapters/burp/*` (wired into `reconforge burp` subcommands) | `mcp_validation/burp/*` | `mcp_validation/` is a ~600+ LOC standalone second Burp MCP client, imported only by its own test (`tests/mcp_validation/test_burp_validator.py`), never wired into the CLI or `pyproject.toml`. It also contains a real syntax error (`mcp_validation/run_validation.py:30,35`) that currently breaks `ruff check .` and `mypy .`. | P1 |
| Per-module `quick_report.md` (live) | `OutputManager.generate_engagement_report()` + `core/reporting/` "Phase 5" pipeline (both dead) | See §3 and §8. | P1 |
| `core/config_loader.py` / `core/tool_config.py` / `core/profile_loader.py` | — | **Not flagged** — reviewed and confirmed to be an intentional layering (raw loader → typed tool view → OPSEC profile view), not duplication. | — |

---

## 6. Misleading / Unverified Claims

These directly contradict the "honest claims" priority in the engineering mandate and must be corrected before public release.

| Claim | Reality | Location |
|---|---|---|
| "375/375 tests passing" | Actual collected test count is **445**, with **4 failing** (`tests/test_cli_surface_encrypt_loot.py`, `tests/test_scope_gate_cli_p10.py`), verified by running `pytest --collect-only -q` and `pytest -q` directly. No two documents in the repo agree: README says 375, `CHANGELOG.md`/`CONTRIBUTING.md` say 348, `docs/FINAL_STABILIZATION_REPORT.md` says 375, `docs/INDEPENDENT_SECURITY_ASSESSMENT_2026-04-13.md` says 383. | `README.md:5,142,190` and 4 other files |
| Quick Start commands work as documented | `python reconforge.py network --target ...` fails — `reconforge.py` was deleted in commit `9bc56bc` when the code moved into the `reconforge/` package. Verified directly: `No such file or directory`. Occurs 25 times across README + docs, and leaks into the installed CLI's own `--help` epilog. | `README.md`, `docs/ARCHITECTURE.md`, `docs/USAGE.md`, `docs/MODULES.md`, `docs/FAQ.md`, `docs/WORKFLOW_GUIDE.md`, others |
| "Internal use — see project documentation for terms" (License section) | No terms exist anywhere in the repo. No LICENSE file. This line is incompatible with a public open-source release — as written, nobody may legally fork, use, or contribute to the project. | `README.md:193-195` |
| `docs/PROJECT_SCORECARD.md` self-score of 9.5/10; `docs/INDEPENDENT_SECURITY_ASSESSMENT_2026-04-13.md` styled as an "Avaliação Profissional Independente" (Independent Professional Assessment), scored 7.8/10 | No named evaluator, no stated methodology, no evidence of third-party review. Reads as an AI-generated self-review presented as external validation, including a fabricated-sounding "383 testes passando localmente" claim that doesn't match the actual test count. Publishing these as-is is a credibility risk. | `docs/PROJECT_SCORECARD.md`, `docs/INDEPENDENT_SECURITY_ASSESSMENT_2026-04-13.md` |
| `docs/SUPPORT_MATRIX.md` — "Docker ✅ Supported" | No `Dockerfile` exists anywhere in the repository. | `docs/SUPPORT_MATRIX.md:33` |
| CI quality gates pass | Running the exact commands from `.github/workflows/quality-gates.yml` locally: `mypy` fails (`Cannot read file 'reconforge.py'`), `bandit` skips the same missing file and separately reports 67 low/8 medium/1 high findings, `ruff check .` fails on a real syntax error in `mcp_validation/run_validation.py`. **The pipeline as configured would not currently pass on `main`.** | `.github/workflows/quality-gates.yml:30,33` |
| `docs/FINAL_STABILIZATION_REPORT.md` verdict "READY FOR DOCUMENTATION" | Correctly marked "HISTORICAL DOCUMENT" at the top (good practice), but predates the current 445-test/broken-CI state and could mislead a reader skimming for current status. | `docs/FINAL_STABILIZATION_REPORT.md` |

Note: `README.md` itself, independent of the two self-assessment docs, is comparatively restrained — no "enterprise-grade"/"autonomous"/"fully automated" language was found in it. The overclaiming problem is concentrated in `PROJECT_SCORECARD.md` and `INDEPENDENT_SECURITY_ASSESSMENT_2026-04-13.md`, and in the stale test-count line.

---

## 7. Untested Assumptions

- That `--enforce-scope` protects operators from scanning out-of-scope infrastructure — false in practice for redirects, DNS-resolved hosts, and any target discovered mid-run (§4, S3).
- That a fixed-path Fernet key stored beside its own ciphertext constitutes meaningful secret protection against any threat model beyond "opportunistic file browsing" — it does not protect against local compromise, and this limitation is not documented anywhere.
- That a non-erroring HTTP response during attack-path "validation" confirms the underlying vulnerability claim. `reconforge/attack_paths/engine.py::_validate_paths` only checks `response_status != 0` (i.e., the request didn't time out/error) before marking a path `validated=True`; `_prioritize_path` then sets `reliability=1.0` and factors it directly into a `critical` priority score. An IDOR or auth-bypass "candidate" that merely returns HTTP 200 on a mutated request can surface in a report as a validated, critical attack path without ever confirming unauthorized data access actually occurred.
- That the mocked unit-test suite (real parser logic, but `Runner.run()` always mocked) demonstrates the tool adapters work against real tool output. No integration tests against real installed binaries were found, and there is currently no local lab (Phase 17 of the engineering mandate) to validate this end-to-end. This is a real gap, not a documentation gap — it should be labeled honestly rather than implied by "445 tests passing."
- That `reconforge/intelligence/engine.py`'s hardcoded per-rule confidence constants (0.6–0.85 for things like `IDOR_candidate`, `auth_bypass_candidate`) reflect actual evidentiary strength. They are fixed literals keyed to a response-length/status-code heuristic, not derived from confirmed evidence — an unconfirmed "candidate" can reach `critical`/`high` priority downstream.

---

## 8. Dead Code

| Item | Evidence | Recommendation |
|---|---|---|
| `core/orchestrator/` (`execution_coordinator.py`, `module_router.py`, `workflow_engine.py`) + `core/policy/scope_policy.py` + `core/schemas/contracts.py` | Reachable only via the Burp subcommand path and `tests/core_foundation/*`; not part of the five recon modules' data path | Either wire into the real recon flow as the canonical execution layer, or delete and consolidate on `core/runner.py` + `core/authorization_gate.py`. Do not keep both indefinitely. |
| `core/output_manager.py::generate_engagement_report()` | Zero callers outside its own definition; no test file | Delete, or wire in as the canonical multi-module report and delete the per-module `quick_report.md` duplication instead. |
| `core/reporting/` package (`pipeline.py`, `models.py`, `exporters/`, `renderers/`) | Only reachable via `OutputManager.generate_reporting_bundle()`, itself never called except by `tests/reporting/test_reporting_pipeline_phase5.py` | This is the most structurally sound reporting code in the repo (has a real hash-chain manifest). Recommend wiring this in as the canonical reporting pipeline (Phase 16 of the mandate) rather than deleting it. |
| `mcp_validation/` (entire package) | Orphaned duplicate of `core/adapters/burp/*`; contains a syntax error breaking CI | Delete. `reconforge/burp/*` + `core/adapters/burp/*` is the wired, tested path. |
| `core/orchestrator/workflow_engine.py` | 26-line frozen-dataclass pair, zero execution logic | Delete as part of the `core/orchestrator/` decision above. |
| `core/exceptions.py` typed exception hierarchy (`ToolNotFoundError`, `ExecutionError`, timeout error) | Only reachable via `run_or_raise()`/`check_tool_or_raise()`, which have zero production or test call sites; real call sites check magic negative return codes instead | Wire these into `Runner.run()`'s actual call sites (this is explicitly required by the engineering mandate: "never use broad exception handlers... convert errors into typed, meaningful exceptions"). |
| `core/validators.py` | Correct, unused (§4, S9) | Wire into `core/target_parser.py` and delete the broken inline hostname check, rather than deleting the validators. |

---

## 9. Incomplete / Overstated Features

- **AD attack-graph coverage**: the AD module (`modules/ad/`) is one of five advertised modules, but no attack-path graph node/edge type represents AD objects (users, groups, credentials, sessions, trusts, delegation). Attack-path generation only exists for HTTP endpoints/parameters.
- **Finding model field gaps**: `core/findings_manager.py`'s `Finding` has `id, finding_type, severity, confidence, target, module, phase, description, evidence, recommendation, references, timestamp`. Missing relative to the mandate's target schema: `title`, `source_tool`, `affected_asset`, `port`, `protocol`, `service`, `raw_evidence_reference`, `confidence_reason`, `status` (open/resolved/false-positive lifecycle), `attack_technique`, `cwe`, `capec`, `mitre_attack`, `execution_id` (on the finding itself, not just the wrapping contract), `parser_version`.
- **No finding-level deduplication/correlation.** Real correlation logic exists for web/API vulnerability classification (`reconforge/intelligence/engine.py::_apply_correlation_boost`, which correctly preserves prior evidence when boosting confidence) and for credential fingerprinting (`core/credential_vault.py`), but `core.findings_manager.Finding` objects have no merge/dedup key at all — the same issue detected by two tools produces two disconnected findings.
- **Tool adapters with parsing logic inlined into phase files instead of a dedicated, tested parser module**: `modules/web/tools/sqlmap.py` (parsed inline in `modules/web/phases/exploit_candidates.py`), `modules/network/tools/hydra.py` (parsed inline in `modules/network/phases/authentication_checks.py`), `modules/api/tools/httpx_tool.py` (parsed inline across `modules/api/phases/discovery.py`, `authentication.py`, `authorization.py`). Functional, but below the parser-test coverage bar and inconsistent with the rest of the codebase's pattern.
- **No reproducible local lab exists yet** (Phase 17 of the mandate) — there is no `demo/`, `labs/`, or `examples/` environment that lets a reviewer run a complete, safe ReconForge assessment against a known target locally. This is required before the project can back up its "445 tests passing" claim with anything beyond mocked unit tests.

---

## 10. Public-Release Blockers (P0) — Summary

These must be resolved before the repository is made public, in this order (each unblocks or de-risks the next):

1. **Licensing**: add a real LICENSE file (Apache-2.0 or MIT recommended), remove the "Internal use" line from README, add third-party tool disclaimer and ethical-use policy (Phase 24).
2. **Unexplained tracked artifact**: identify the origin and purpose of `.abacus.donotdelete`; remove it from the repo (and from git history if it contains anything sensitive) unless it is documented and demonstrably necessary.
3. **Broken documentation**: fix all 25 `reconforge.py` references (README + 6 docs files) to the real entrypoint, and correct the test-count claim everywhere it appears (`README.md:5,142,190`, `CHANGELOG.md`, `CONTRIBUTING.md`, `docs/FINAL_STABILIZATION_REPORT.md`, `docs/INDEPENDENT_SECURITY_ASSESSMENT_2026-04-13.md`) to the actual, currently-passing number.
4. **Fix the 4 failing tests** so the corrected test-count claim is true.
5. **Fix `core/target_parser.py`'s hostname validation** (S1) — wire in `core/validators.py`'s real hostname/IP/CIDR/URL checks and remove the unconditional fallback that accepts any string.
6. **Wire scope/authorization enforcement into `core/runner.py`** (S2) so it applies at every command execution, not just once at CLI-parse time, and re-validate scope for redirects/discovered targets (S3).
7. **Fix command-log/session-note redaction** (S5) so raw command strings pass through `sanitize_log()` before persistence.
8. **Fix CI itself**: correct the mypy/bandit target paths, remove `mcp_validation/` (or fix its syntax error) so `ruff check .` passes, and confirm the full pipeline is green before claiming it in any README badge.

---

## 11. Prioritized Remediation Plan

### P0 — Blocks public release
- [ ] Add LICENSE (Apache-2.0 or MIT), fix README license section, add ethical-use/disclosure policy — §10.1
- [ ] Investigate and remove/document `.abacus.donotdelete` — §10.2
- [ ] Fix all `reconforge.py` references across README + docs — §10.3
- [ ] Reconcile and correct test-count claims across all 5 documents — §10.3
- [ ] Fix the 4 currently-failing tests — §10.4
- [ ] Fix `core/target_parser.py` hostname validation bypass (wire in `core/validators.py`) — §4 S1, §10.5
- [ ] Enforce scope/authorization inside `core/runner.py` at every execution, not just CLI-parse time — §4 S2, §10.6
- [ ] Re-validate scope on redirects / newly discovered targets — §4 S3, §10.6
- [ ] Route command logs and session notes through `sanitize_log()` before persistence — §4 S5, §10.7
- [ ] Fix CI so it actually passes: correct mypy/bandit file targets, resolve the `mcp_validation` syntax error (by fixing or removing the package) — §10.8

### P1 — Major quality/security issues
- [ ] Consolidate the two orchestration architectures (`core/orchestrator/*` vs the real recon flow) — decide, document, delete the loser — §3, §8
- [ ] Consolidate the two scope/authorization mechanisms — §4 S4, §5
- [ ] Remove `mcp_validation/` (duplicate of `core/adapters/burp/*`) — §5, §8
- [ ] Decide the fate of the two dead reporting pipelines (`OutputManager.generate_engagement_report`, `core/reporting/`) — wire one in as canonical, delete the rest — §3, §8
- [ ] Wire `core/validators.py` into actual target parsing everywhere — §4 S9, §8
- [ ] Fix attack-path "validated" semantics so HTTP-request-succeeded is not conflated with vulnerability-confirmed — §7
- [ ] Replace hardcoded confidence constants in `reconforge/intelligence/engine.py` with evidence-derived scoring — §7
- [ ] Re-label or remove `docs/PROJECT_SCORECARD.md` and `docs/INDEPENDENT_SECURITY_ASSESSMENT_2026-04-13.md` as self-assessments — §6
- [ ] Widen ruff ruleset beyond syntax-error-only checks; enable mypy strict mode across the real package tree, not 3 files — §10.8
- [ ] Pin GitHub Actions to commit SHA; add Dependabot/Renovate and a gitleaks step
- [ ] Add typed exception usage at real `Runner` call sites instead of magic return-code checks — §8
- [ ] Encrypt credential vault / loot manager by default; move the key off the same path as the data — §4 S7

### P2 — Important improvements
- [ ] Consolidate `modules/network/tools/*` and `modules/ad/tools/*` duplicate wrappers where the underlying tool is identical — §5
- [ ] Add dedicated parser modules + tests for sqlmap, hydra, httpx inline-parsed adapters — §9
- [ ] Apply `validate_arg()` consistently across all tool wrappers, not just `modules/api/*` — §4 S6
- [ ] Extend the `Finding` model with missing fields (CWE/CAPEC/MITRE ATT&CK, port/protocol/service, status, confidence_reason, raw_evidence_reference) — §9
- [ ] Add finding-level deduplication/correlation — §9
- [ ] Extend attack-path graph to cover AD/network assets, not just HTTP endpoints — §9
- [ ] Fix the two silently-swallowed `except Exception: pass` blocks — §4 S8
- [ ] Enable risk policy enforcement by default (or document clearly why it defaults off) — §4 S10
- [ ] Add `[tool.coverage]` config with the 85% gate codified, not just passed via CLI flag
- [ ] Add SECURITY.md and CODE_OF_CONDUCT.md

### P3 — Optional enhancements
- [ ] Add framework/tool version + config-hash provenance to reports
- [ ] Remove the 29 tracked PDF duplicates of Markdown docs from git
- [ ] Add packaging extras (`reconforge[ad]`, `reconforge[web]`, `reconforge[api]`)
- [ ] Add a documentation link checker and Docker lint job (once/if a Dockerfile is added)

---

## 12. Method Note

This review was produced by four parallel, independent research passes over the repository (subprocess/credential security; architecture and duplication; scope/findings/attack-path/reporting; documentation/licensing/CI), followed by direct verification of the highest-severity claims (`.abacus.donotdelete` file inspection, `core/target_parser.py` source read, README license text, `reconforge.py` reference count, and live `pytest`/`mypy`/`bandit`/`ruff` runs). Findings are cited with file:line references throughout; anything not independently re-verified in this pass is marked as such in §6 and should be re-checked before being cited externally.
