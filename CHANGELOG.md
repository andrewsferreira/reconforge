# Changelog

All notable changes to ReconForge are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (see [docs/VERSIONING.md](docs/VERSIONING.md)).


## [2.6.3] — 2026-07-14

Claude MCP Integration — Phase 1 (Repository Assessment): the first phase of a large, explicitly incremental effort to let Claude Desktop/Claude Code act as an MCP client against a new ReconForge-hosted MCP server, scoped read-only-first per the operator's own working rules. PATCH per `docs/VERSIONING.md` — planning documentation only, no `reconforge/mcp/` package or other code exists yet.

### Added

- `docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md`: architectural assessment, trust-boundary diagram, MCP threat model, the `trusted_metadata`/`untrusted_evidence` response-shape split for prompt-injection resistance, a `SAFE_READ_ONLY → PROHIBITED` execution-tier policy table, the human-approval model (reuses `core/authorization_gate.py::ScopeAuthorization` unchanged), representative request/response schemas, a testing strategy, a migration plan, and known limitations. Identifies `core/runner.py`'s existing `Runner(dry_run=True)` code path and `core/adapters/burp/`'s policy/normalization-boundary pattern as the primitives new MCP tools should wrap rather than duplicate.
- `docs/DOCUMENTATION_INDEX.md`: new entry for the plan document under "Architecture & Design".

### Notes

- No code changes. `reconforge/mcp/` and the `mcp` SDK dependency are not yet added — that begins at Phase 2, pending explicit operator go-ahead, per this project's phase-checkpoint discipline and the operator's own instruction not to implement unrestricted active execution first.

## [2.6.2] — 2026-07-14

Phase 30 (AI Orchestration Honesty Pass): triggered by a direct question about whether the project's "AI orchestration" claims reflect real integration or aspirational branding. PATCH per `docs/VERSIONING.md` — documentation correction and test coverage, no behavior change.

### Fixed

- `docs/DOCUMENTATION_INDEX.md`: the Phase-22-written entry for `docs/AI_ORCHESTRATION_ARCHITECTURE.md` incorrectly called the AI orchestration layer "proposed" and pointed to the wrong files as its implementation. Corrected: `core/ai_orchestration.py::AIOrchestrationLayer` is real and wired into `core/workflow_orchestrator.py` — confirmed via direct investigation, not dead code.
- `docs/AI_ORCHESTRATION_ARCHITECTURE.md`: added a status note clarifying the layer is genuinely implemented and integrated, but is a deterministic rule-based correlation/scoring engine (fixed keyword sets, hardcoded confidence literals, a linear weighted formula) — no machine-learning model or LLM call exists anywhere in this codebase, confirmed via repo-wide search.
- `core/ai_orchestration.py`: lightly softened the module docstring's "intelligence-driven" framing, no public API changes.

### Added

- `tests/core/test_ai_orchestration.py`: 11 new tests with exact value assertions (weighted risk-score formula, per-port exploit-likelihood rules, CVE-hint banner matching, per-module signal ingestion, score-cutoff filtering, service-based recommendations) — only 2 tests existed for 431 lines of code prior to this phase.

11 new tests added (881 → 892); full suite, ruff, mypy, and bandit all pass.

## [2.6.1] — 2026-07-14

Phase 29 (Risk Policy Documentation + False-Claim Fix): closed the pre-existing P2 item on the risk policy engine's off-by-default status, via the "document why" branch rather than "enable by default" (which would silently block core AD-module functionality). PATCH per `docs/VERSIONING.md` — documentation and test coverage only, no behavior change.

### Fixed

- `docs/CONFIGURATION.md`: removed a materially false claim ("no environment variable overrides... the YAML files are authoritative") — a repo-wide grep found 10+ genuinely behavior-affecting `RECONFORGE_*` environment variables, including an entirely undocumented emergency kill switch (`RECONFORGE_KILL_SWITCH`/`RECONFORGE_KILL_SWITCH_FILE`). Added a new "Environment Variables" reference section covering all of them, plus a corrected (500+ tests stale) trailing test-count claim and a doc version stamp bump (1.1.0 → 1.2.0).

### Added

- `tests/core/test_risk_policy.py`: 3 new tests for `RiskPolicyEngine.check()` — the default-off (unset `RECONFORGE_POLICY_ENFORCE`) case had no direct coverage at all despite being the behavior every user actually experiences.

3 new tests added (878 → 881); full suite, ruff, mypy, and bandit all pass.

## [2.6.0] — 2026-07-14

Phase 28 (Packaging Extras): closed the pre-existing P3 item to add per-module packaging extras. MINOR per `docs/VERSIONING.md` — new backward-compatible install capability, no existing behavior changed.

### Added

- `pyproject.toml`: `reconforge[ad]` (`enum4linux-ng`, `impacket`, `bloodhound`, `netexec`), `reconforge[web]` (`wafw00f`), `reconforge[api]` (`arjun`) — scoped to exactly the tools each module has that are actually `pip install`-able per `docs/SUPPORT_MATRIX.md`, confirmed by reading that doc's per-module tables rather than guessing. `network`/`surface` correctly received no extras group (100% apt/system tools in both). Versions deliberately left unpinned — third-party tools outside this project's release cycle.
- `README.md`: Quick Start now documents the three new `pip install -e ".[...]"` commands.
- `docs/SUPPORT_MATRIX.md`: cross-reference note for the new extras; doc's own version stamp bumped 1.1.0 → 1.2.0.

No code changes; verified via `pip install -e . --dry-run` and the full packaging smoke test. Full suite re-run to confirm zero impact (878 passing, unchanged); ruff, mypy, and bandit all pass.

## [2.5.11] — 2026-07-14

Phase 27 (Network Module Success-Honesty Sweep): closed the remainder of the gap Phase 17 believed was already covered for the network module. PATCH per `docs/VERSIONING.md` — bug fix, no new public surface.

### Fixed

- `modules/network/phases/port_scanning.py`, `authentication_checks.py`, `service_enumeration.py`: each `run()` set `results["success"] = True` unconditionally regardless of whether any tool actually executed — the same "decorative success" class fixed in Phase 17/26. Fixed to `results["success"] = bool(self.tools_used)`.
- `modules/network/base.py`'s `self.tools_used` list had never been populated by any of the module's 4 phase files since the network module's creation (permanently empty), also making its own `"Tools: none"` summary log line always wrong. Now wired at each real tool-invocation point (nmap, smbclient, hydra, enum4linux, ldapsearch).

6 new tests added (872 → 878) — one false-case/true-case pair per file, with all 3 false-case tests confirmed to fail against the pre-fix code; full suite, ruff, mypy, and bandit all pass.

## [2.5.10] — 2026-07-14

Phase 26 (Surface Module Success-Honesty Correction): closed a gap Phase 17 incorrectly believed was already covered. PATCH per `docs/VERSIONING.md` — bug fix, no new public surface.

### Fixed

- `modules/surface/phases/service_fingerprint.py`: `run()` set `results["success"] = True` unconditionally regardless of whether `_run_version_scan()`/`_run_http_probe()` actually executed a tool — both can silently no-op (opsec-blocked, nmap/httpx unavailable, no candidate ports). Same "decorative success" class Phase 17 fixed across 11 AD/web/api files; missed there because the early returns live inside this file's two private sub-methods, invisible from `run()`'s own control flow. Fixed to `results["success"] = bool(self.tools_used)`, matching Phase 17's established pattern.

4 new tests added (868 → 872) — the first regression coverage this file has ever had; full suite, ruff, mypy, and bandit all pass.

## [2.5.9] — 2026-07-14

Phase 25 (Stealth-Mode Port Scan Fix): closed the pre-existing P2 item to audit `OpsecChecker`'s interaction with tool-level OPSEC intensity scaling. PATCH per `docs/VERSIONING.md` — bug fix restoring intended runtime behavior, no new public surface.

### Fixed

- `core/detection_map.py`: `"nmap_syn_scan"` was misclassified `noise="medium"` despite its own description ("SYN stealth scan") — `is_allowed()` only permits `"low"`-noise techniques in stealth mode, so `--opsec stealth` silently produced **zero port-scan results** in both `network/phases/port_scanning.py` and `surface/phases/port_discovery.py`, the two production call sites that gate their entire scan on this technique with no lower-noise fallback. Reclassified to `noise="low"`, matching a plain SYN scan's genuinely quieter profile relative to a full TCP connect scan and unblocking downstream logic in both phases that was clearly written assuming stealth-mode SYN scans do find ports.

5 new tests added (863 → 868) — two integration-style regression tests per affected module using the real `OpsecChecker` (not a stub), confirmed to fail against the pre-fix classification and pass after it; full suite, ruff, mypy, and bandit all pass.

## [2.5.8] — 2026-07-14

Phase 24 (Remove Tracked PDF Duplicates): closed the pre-existing P3 item to remove the 29 tracked PDF exports of Markdown docs from git. PATCH per `docs/VERSIONING.md` — repo-hygiene cleanup, no change to ReconForge's runtime public surface.

### Removed

- 29 tracked PDF files (2.0MB total): 26 confirmed duplicates of a same-directory `.md` source by basename, 2 more (`AD_MODULE_SUMMARY.pdf`, `WEB_MODULE_SUMMARY.pdf`) matched to their real `docs/`-located `.md` source, and `CLEANUP_REPORT.pdf` — present unreferenced since the initial commit, with no `.md` source ever tracked and unreadable content in this environment — removed as an unauditable opaque binary rather than a confirmed duplicate. Confirmed via repo-wide grep that no code, CI, or tooling referenced any of the 29 paths before deleting.

### Fixed

- `docs/DOCUMENTATION_INDEX.md`: removed the 20 now-dangling "PDF" links pointing at the deleted files (caught immediately by Phase 23's `scripts/check_doc_links.py`) and updated the header/File Format Summary table to reflect the removal instead of leaving a stale "29 PDF exports" claim.

No code changes; full suite re-run to confirm zero impact (863 passing, unchanged). ruff, mypy, and bandit all pass.

## [2.5.7] — 2026-07-14

Phase 23 (Documentation Link Checker): closed the pre-existing P3 item to add a CI documentation-link check. PATCH per `docs/VERSIONING.md` — new dev/CI tooling script, no change to ReconForge's runtime public surface.

### Added

- `scripts/check_doc_links.py`: verifies every internal Markdown link in the repo (discovered via `git ls-files '*.md'`, so it automatically respects `.gitignore`) resolves to a real file, skipping external `http(s)://`/`mailto:` links and in-page `#anchor`s. Wired into `.github/workflows/quality-gates.yml` as a new "Documentation link check" step and into the normal test suite via `tests/test_doc_links.py` (4 tests).
- `bandit`'s CI scan scope expanded to include `scripts/` (previously only `core modules reconforge mcp_validation`).

### Fixed

- `docs/DOCUMENTATION_MAP.md`: the checker's first run immediately found 7 dead links in a second, independent documentation index never touched by the Phase 19/22 `DOCUMENTATION_INDEX.md` repairs — references to the same class of long-deleted files (`AUDIT_REPORT.md`, `PHASE_1_CONSISTENCY_AUDIT.md`, `STABILIZATION_CHECK_P6/7/8/9.md`). Fixed using the struck-through-entry convention Phase 22 established, plus one illustrative example link rewritten as inline code.

4 new tests added (859 → 863); full suite, ruff, mypy, and bandit all pass.

## [2.5.6] — 2026-07-14

Phase 22 (Documentation Index Completion): closed the ~20-file gap `docs/DOCUMENTATION_INDEX.md` was left with in Phase 19. PATCH per `docs/VERSIONING.md` — documentation-only update.

### Documented

- `docs/DOCUMENTATION_INDEX.md`: wrote real entries for all 24 previously-undocumented files (20 in `docs/`, 4 at project root — `AGENTS.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`), each read before writing its description. Fixed a second dead link Phase 19 missed (`AUDIT_REPORT.md`, struck through) and gave `ARCHITECTURE_REVIEW.md` — the audit's actual living successor — its own entry. Correctly flagged `PROJECT_SCORECARD.md`/`INDEPENDENT_SECURITY_ASSESSMENT_2026-04-13.md` as author self-assessments. Added two new sections (§6 Burp MCP/Intelligence Engine Guides, §7 Root-Level Project Files) rather than force-fitting unrelated docs into existing categories. Updated the header, Quick Links table, and File Format Summary to reflect the now-complete inventory (all 46 non-index Markdown files have an entry, cross-checked via a full `find`-based inventory).

No code changes; full suite re-run to confirm zero impact (859 passing, unchanged). ruff, mypy, and bandit all pass.

## [2.5.5] — 2026-07-13

Phase 21 (Report-Generation Error Handling): closed the item deferred in Phase 15, unblocked now that Phase 17's `results["success"]`-honesty redesign has shipped. PATCH per `docs/VERSIONING.md` — reuses the existing `core/exceptions.py::ModuleError`, no new public surface.

### Fixed

- `network_module.py`/`ad_module.py`/`web_module.py`/`api_module.py`/`surface_module.py::_generate_reports()`: all 5 wrapped 9-10 independent report-file writes in an identical bare `except Exception as e: self.logger.error(...)` with no re-raise. A failure partway through (e.g. a disk-full error, a JSON-serialization error) silently left later artifacts — including the evidence manifest itself — un-written while the calling module's `run()` still returned a normal-looking success. All 5 now re-raise `ModuleError(module, message) from e` instead of swallowing. Confirmed both real call sites already handle this correctly: `reconforge/cli.py`'s top-level `except ReconForgeError` turns it into a clean CLI error, and `WorkflowOrchestrator.run()`'s per-step `except Exception` marks the step failed and continues rather than crashing the whole workflow — no caller-side changes needed.

7 new tests added (852 → 859); full suite, ruff, mypy, and bandit all pass.

## [2.5.4] — 2026-07-13

Phase 20 (CVE Enricher Hardening): closed the last open item from Phase 8's confidence-model audit. PATCH per `docs/VERSIONING.md` — internal reliability hardening, no new public surface.

### Fixed

- `core/cve_enricher.py::lookup_cves_for_cpe()`: `FindingsManager.add()` is called in tight per-share/per-user/per-port loops throughout phase code, and each call can reach this function when `RECONFORGE_NVD_LOOKUP=1` is set. Previously it re-read the on-disk CVE cache from disk on every single call (no in-memory fast path) and had no rate-limiting between live NVD API requests — a real risk of the NVD API rate-limiting or blocking the operator's IP on an engagement with many findings that each embed a different CPE string. Added a process-lifetime in-memory cache and a 6-second minimum interval between live requests (under NVD's documented public-API limit of ~5 requests/30s without a key).

4 new tests added (848 → 852); full suite, ruff, mypy, and bandit all pass.

## [2.5.3] — 2026-07-13

Phase 19 (Correctness & Consistency Cleanup): three small, bounded items batched together. PATCH per `docs/VERSIONING.md` — pure bug fixes and a docs correction, no new public surface.

### Fixed

- `network/phases/port_scanning.py::_scan_host()`: the host-matching loop's `if host.ip == target or not host_result["open_ports"]:` condition meant "no ports found yet" rather than "no matching host found" — if nmap's XML listed the target's own zero-open-port entry first, the loop kept going and processed a second, unrelated host's ports into the same result, misattributing them to the scanned target. Now matches by IP first, falling back to nmap's sole reported host only when there is exactly one.
- `web/phases/exploit_candidates.py`: wpscan-parsed plugin/theme inventory confidence raised from `high` to `confirmed`, matching the WordPress-version finding from the same tool and evidence class two blocks above.
- `api/phases/authentication.py`: JWT empty/trivial-signature check confidence raised from `high` to `confirmed`, matching the `alg=="none"` check just above it — both are deterministic structural checks on the operator-supplied token.

### Documented

- `docs/DOCUMENTATION_INDEX.md`: removed 4 dead links to files deleted at an earlier, undocumented cleanup point; corrected the file-count header and format-summary table (47 Markdown / 29 PDF, was claiming "20 Markdown"); added an explicit "known gap" note for the ~20 real files still missing per-file entries; fixed the false "auto-maintained" footer claim.

3 new tests added (845 → 848); full suite, ruff, mypy, and bandit all pass.

## [2.5.2] — 2026-07-13

Phase 18 (Secrets/Credential Hardening): closed three P2 items open since Phases 13-14 around `core/credential_vault.py`/`core/loot_manager.py`/`core/engagement.py`. PATCH per `docs/VERSIONING.md` — pure bug fixes and a re-verification, no new public surface.

### Fixed

- `core/credential_vault.py::CredentialVault.save()`/`load()`: `Fernet(key)` raises a raw `ValueError` (confirmed empirically) on a malformed/truncated key file (e.g. disk full mid-write on `~/.reconforge/vault.key`) — both methods now wrap key construction and raise the typed `CredentialVaultError` instead, consistent with every other failure mode already fixed in Phase 14.
- `core/loot_manager.py::LootManager.add()`: dedup for `loot_type == "user"` is now case-insensitive (`"Administrator"` from RID cycling and `"administrator"` from an authenticated LDAP query are the same account), mirroring `CredentialVault._fingerprint()`'s established precedent. Other loot types (`credential`, `hash`, `token`, ...) remain case-sensitive since their `value` may embed case-meaningful secret material.

### Verified (no code change)

- `EngagementManager.save()` writing `module_results` unencrypted: a repo-wide grep for literal `results["password"/"secret"/"credential"/"token"]` assignments across all 24 `modules/*/phases/*.py` files found zero matches. Module-level phase results carry only counts/summaries/non-secret recon data; actual credential/hash/token material is routed exclusively through `CredentialVault`/`LootManager`. Closed as verified-not-a-bug.

4 new tests added (841 → 845); full suite, ruff, mypy, and bandit all pass.

## [2.5.1] — 2026-07-13

Phase 17 (Result Honesty): `results["success"]` was hardcoded `True` unconditionally at the end of `run()` in 11 of 13 AD/web/API `modules/*/phases/*.py` files, regardless of whether any actual work happened — a violation of this project's own "Evidence over narration" principle, flagged as deferred across Phases 11/13/15. PATCH per `docs/VERSIONING.md` — the `success` field already existed; this fixes its semantics, adding no new public surface.

### Fixed

- `modules/ad/phases/{identity_enumeration,configuration_enumeration,passive_recon}.py`: `success` now requires at least one collection path (LDAP, RID cycling, AS-REP roasting, null session, anonymous LDAP) to have actually yielded data, rather than merely "the method returned without raising."
- `modules/web/phases/{surface_discovery,content_enumeration,exploit_candidates,vulnerability_scanning}.py` and `modules/api/phases/{discovery,authentication,authorization,fuzzing}.py`: `success` now requires `self.tools_used` to be non-empty (only appended to once a tool actually executes past its availability/OPSEC gates). Four of these phases had a "no findings" filler finding that always fires when `finding_count == 0`, specifically masking the "every tool unavailable/blocked, nothing ran at all" case. `authentication.py`/`authorization.py` additionally count pure structural analysis on already-available input (`spec_data`/`auth_token`, `endpoints`/`discovered_params`) that needs no tool call.
- `exploit_candidates.py`'s deliberate `opt_in=False` skip path is unchanged and correctly stays `success=True` — a deliberate skip-by-design is not a failure.

`network`/`surface` modules' phase files were re-audited and confirmed already correct — not part of this fix set. `bloodhound_collection.py`/`delegation_discovery.py` were already fixed in Phase 11.

23 new tests added (818 → 841); full suite, ruff, mypy, and bandit all pass.

## [2.5.0] — 2026-07-13

Phase 16 (Reproducible Lab): README's "Local Validation Lab" section referenced `http://127.0.0.1:8008` with nothing anywhere in the repo that actually defined or served that target — the reproducibility claim was aspirational. MINOR per `docs/VERSIONING.md` — adds a new first-party capability (`lab/`), not a bug fix.

### Added

- `lab/vulnerable_app.py`: a pure-stdlib, loopback-only HTTP test target (`http.server.BaseHTTPRequestHandler`/`ThreadingHTTPServer`, no third-party dependencies, no external downloads). Refuses to bind to anything but `127.0.0.1`/`localhost`/`::1` via a `_validate_loopback_host()` argparse validator. Serves deliberately weak endpoints aligned with what ReconForge's own `web`/`api` modules check: `/` omits all security headers, `/search?q=` reflects the query parameter unescaped, `/admin` and `/robots.txt` provide predictable/enumerable paths, `/api/status` returns a JSON fingerprint, and `/login` (GET+POST) is a fake login form that never actually authenticates.
- `tests/lab/test_vulnerable_app.py`: 11 tests exercising the lab server's real HTTP responses (via a background-thread `ThreadingHTTPServer` on an ephemeral loopback port) and the loopback-only guard's accept/reject behavior.

### Documented

- README's "Local Validation Lab" section now instructs starting `lab/vulnerable_app.py` before the existing `reconforge web` smoke-test command, and describes the weaknesses it actually serves instead of assuming a pre-existing target.
- `docs/ARCHITECTURE_REVIEW.md`: marked the "No reproducible local lab exists yet" §9 item resolved.

Net +11 tests (807 → 818); full suite, ruff, mypy, and bandit all pass.

## [2.4.3] — 2026-07-13

Phase 15 (Reporting): re-verified the standing decision to keep `core/reporting/` (dead code since Phase 1) against 14 phases of evidence, and audited the live reporting paths. PATCH per `docs/VERSIONING.md` — the deleted code had zero external callers/documented interface (never wired into the CLI), so this isn't a breaking module removal in the sense the policy protects against; the manifest-ordering fix is a pure bug fix.

### Removed

- `core/reporting/` (`pipeline.py`, `models.py`, `exporters/`, `renderers/`, `serializers/`) and its exclusive dependency `core/schemas/` (`contracts.py`) — confirmed 100% orphaned (only reachable from their own dedicated test file). Their one claimed unique asset, a SHA-256 hash-chain integrity manifest, was already duplicated and live in `core/output_manager.py::write_evidence_manifest()`, actively used by all 5 real modules. Wiring the dead pipeline in for real would require a substantial new adapter layer, not a config flag — a multi-day effort disproportionate to a bug-fix phase. Also removed the now-inaccurate `docs/REPORTING_ARCHITECTURE.md` and the dead pipeline's dedicated test file.

### Fixed

- `network_module.py`/`web_module.py`/`api_module.py`/`surface_module.py`: `write_evidence_manifest()` — which hashes every artifact in the module output directory into a tamper-evidence chain — was called *before* `quick_report.md` was written, so the primary human-facing report was silently excluded from its own integrity chain in every real run (`ad_module.py` already had the correct order). Fixed by moving the manifest write to genuinely be the last artifact written.

### Documented (not yet fixed — tracked as follow-ups)

- All 5 modules' `_generate_reports()` wrap 9-10 independent file writes in a single bare `except Exception: log and continue`, with no re-raise and no typed exception — a partial failure leaves later artifacts unwritten while `run()` still reports overall success. Deferred pending the larger `results["success"]`-honesty redesign already scoped out in Phase 11.

Net +1 test (806 → 807 — 6 dead-pipeline tests removed, 7 new tests added); full suite, ruff, mypy, and bandit all pass.

## [2.4.2] — 2026-07-13

Phase 14 (Credential/Loot Handling): audited `core/credential_vault.py::CredentialVault` and `core/loot_manager.py::LootManager`, closing two P2 items Phase 9 had flagged. Pure bug fixes — no new public fields/methods/capabilities — so PATCH per `docs/VERSIONING.md`.

### Fixed

- `CredentialVault._fingerprint()`: case-sensitive `username`/`domain`/`service` matching meant "Administrator" and "administrator" discovered by two different tools were treated as distinct credentials instead of the same account. Now normalized to lowercase before fingerprinting; `secret` (password/hash/token material) is deliberately left case-sensitive.
- `LootManager.add()`: always kept the first-seen entry on an exact `(loot_type, value)` duplicate regardless of the rediscovery's confidence — a username first seen via unauthenticated RID cycling ("high") later reconfirmed via authenticated LDAP ("confirmed", richer metadata) silently lost the stronger evidence. Now upgrades the existing entry in place when the new discovery has strictly higher confidence.
- `CredentialVault.load()`: had no exception handling around `json.loads()`, `Fernet.decrypt()`, or `Credential(**item)` reconstruction — a corrupted/hand-edited vault file, or one decrypted with the wrong key, crashed with a raw exception instead of the typed `CredentialVaultError` the method's own docstring already claimed. Same shape as Phase 13's `EngagementManager.load()` fix.

### Documented (not yet fixed — tracked as follow-ups)

- `LootManager.add()`'s O(n) linear-scan dedup vs. `CredentialVault`'s O(1) set-based approach (performance, not correctness).
- `LootManager`'s own case-sensitive value matching (needs per-`loot_type` handling to avoid lower-casing password/hash material).
- `LootManager` has no `load()` that reconstructs `LootItem` objects — confirmed not currently a practical gap since `--resume` doesn't wire vault/loot state back in either.
- `CredentialVault._get_or_create_key()`'s fragility if the on-disk key file itself is corrupted/truncated.

10 new tests added (796 → 806); full suite, ruff, mypy, and bandit all pass.

## [2.4.1] — 2026-07-13

Phase 13 (Engagement Management): audited `core/engagement.py::EngagementManager` and its interaction with `WorkflowOrchestrator.run()`. Pure bug fixes — no new public fields/methods/capabilities — so PATCH per `docs/VERSIONING.md`.

### Fixed

- `WorkflowOrchestrator.run()`: called `self.engagement.complete()` unconditionally at the end of a successful step loop, but `complete()` only accepts `"active"`/`"paused"` source states. Resuming an already-completed or cancelled engagement via `--resume` (pointed at a file this tool itself writes after every run) meant the entire workflow ran against the live target before crashing at that call — and since `_save_workflow_report()` runs immediately after and never executed, the whole run's results were never persisted. Now fails fast with `WorkflowError` before any step executes.
- `EngagementManager.cancel()`: the only lifecycle transition method with no state guard — could be called from any state including `"completed"`, silently overwriting `end_time` and duplicating the cancellation timeline entry. Now raises `EngagementError` from `"completed"`/`"cancelled"` like every sibling method.
- `EngagementManager.load()`: had no exception handling around `json.loads()` or `TimelineEntry(**entry_dict)` reconstruction — a corrupted/hand-edited/partially-written engagement file (reachable via `--resume`) crashed with a raw `JSONDecodeError`/`TypeError` instead of the typed `EngagementError` the method's own docstring already claimed. Also added `status` validation against `ENGAGEMENT_STATUSES` and a non-dict-payload guard.

### Documented (not yet fixed — tracked as follow-ups)

- `EngagementManager.save()` writes `module_results` to disk unencrypted, unlike `CredentialVault`/`LootManager` (default-on encryption since P1-2) — not fixed speculatively without exhaustive verification of what module result dicts actually contain across all 5 modules.

8 new tests added (788 → 796); full suite, ruff, mypy, and bandit all pass.

## [2.4.0] — 2026-07-13

Phase 12 (OPSEC Model): audited `core/opsec_checks.py`/`core/detection_map.py` and all 31 `opsec.check()` call sites against each module's actual tool-invocation surface. Adds new backward-compatible `DETECTION_LEVELS` entries and wires previously-dead `OpsecChecker.warn()` into `check()` (MINOR per `docs/VERSIONING.md`), alongside real gating fixes.

### Fixed

- `core/detection_map.py::is_allowed()`: returned `True` unconditionally for any `opsec_mode` not in `{"stealth","normal","aggressive"}` — every module's `opsec_mode` constructor parameter accepts an unvalidated string (only the CLI's own `argparse choices=` guards the direct CLI path), so a typo'd or programmatic mode silently disabled all noise gating. Now fails closed.
- `modules/ad/collectors/delegation_collector.py`: checked opsec technique `"impacket_delegation"`, which doesn't exist in `DETECTION_LEVELS` (real key: `"impacket_finddelegation"`) — an unknown-technique check always fails closed, so findDelegation.py collection was permanently disabled regardless of `--opsec` mode.
- `modules/ad/collectors/{ldap,smb,dns,kerberos}_collector.py`: had zero `opsec.check()` calls despite `DETECTION_LEVELS` defining specific entries for exactly these operations — every LDAP/SMB/DNS/Kerberos enumeration query ran unconditionally regardless of `--opsec` mode. `--opsec stealth` provided no real protection for the AD module's core enumeration surface. Wired checks into all query methods across the 4 files.
- `kerberos_collector.py::collect_rid_cycling()`: only scaled `max_rid` by `opsec_mode=="aggressive"` but ran the `high`-noise RID cycling technique unconditionally in every mode; now actually blocked outside aggressive mode.

### Added

- Two new `DETECTION_LEVELS` entries: `ldap_password_policy` (low noise) and `nmap_kerberos_detect` (low noise, distinct from the existing high-noise NSE-script `nmap_ad_kerberos` entry).
- `OpsecChecker.warn()` — previously dead code, never called — is now wired into `OpsecChecker.check()` itself, so every existing call site automatically surfaces a heads-up warning when a high/very_high-noise technique is allowed to proceed.

### Documented (not yet fixed — tracked as follow-ups)

- A full correctness audit of the ~25 remaining `opsec.check()` call sites across network/web/api/surface modules, cross-verified against their tool-invocation surface the way AD's collector layer was in this phase.
- No test coverage asserting `OpsecChecker.check()`'s block/allow gate stays consistent with tool wrappers' separate `opsec_mode`-based intensity scaling (a second, independent mechanism).
- Pre-existing "Enable risk policy enforcement by default" P2 item — a related but distinct mechanism, unchanged.

40 new tests added (748 → 788); full suite, ruff, mypy, and bandit all pass.

## [2.3.1] — 2026-07-13

Phase 11 (AD/Web/API Module Quality): audited phase-orchestration logic in all 5 AD, 4 web, and 4 API phase files. Pure bug fixes — no new public fields/methods/capabilities — so PATCH per `docs/VERSIONING.md`.

### Fixed

- `ad/phases/bloodhound_collection.py::_identify_da_paths()`: Kerberoast→DA and AS-REP→DA branches checked group membership by matching readable substrings like `"domain admins"` against `user.member_of`, which holds BloodHound SIDs, never names — the check could never match, so both branches never fired for any target. Now checks membership against `results["da_users"]`, the correctly SID-keyed list `PrivilegeAnalyzer` already builds.
- `api/phases/fuzzing.py::_classify_error_response()`/`_check_for_info_disclosure()`: searched ffuf's whole-batch stdout (the only body-content text available) but reported a match as evidence for one arbitrarily-chosen fuzzed entry's URL — one entry's error text could get misattributed to a different, unrelated entry. Now classifies the batch once per fuzz run and reports a single finding covering every affected entry, explicit that the specific triggering input can't be isolated with current instrumentation.
- `ad/collectors/delegation_collector.py::DelegationCollector.collect()`: hardcoded `result.success = True` regardless of whether any of its three LDAP queries (or findDelegation.py) actually completed — a total collection failure was indistinguishable from a genuinely clean environment. Each query now reports whether it actually ran; `delegation_discovery.py` surfaces a finding and returns early on total failure instead of silently continuing on empty data.
- `web/phases/surface_discovery.py::_run_wafw00f()`: the only tool-invoking method in the file that didn't check `run_result.success` before trusting parsed output — a wafw00f execution failure was indistinguishable from a genuine "no WAF detected" finding.

### Documented (not yet fixed — tracked as follow-ups)

- `results["success"]` is decorative (unconditionally `True`) in 12 of 13 phase files; inert today (no caller reads it) but a latent trap for future code.
- Weak SSRF-confirmation regex signal-to-noise in `web/phases/vulnerability_scanning.py` (already hedged `confidence="low"`).

22 new tests added (726 → 748); full suite, ruff, mypy, and bandit all pass.

## [2.3.0] — 2026-07-13

Phase 10 (Attack-Path Analysis): audited `reconforge/attack_paths/engine.py`, `modules/ad/attack_paths/*.py`'s 6 builders, and `core/attack_workflow.py`. Adds a new backward-compatible dedup mechanism to `AttackWorkflow` and a new `core/version.py` module (MINOR per `docs/VERSIONING.md`), alongside real bug fixes.

### Fixed

- `reconforge/attack_paths/engine.py::_path_impact()`: checked the bare string `"auth_bypass"` where the real finding-type constant is `"auth_bypass_candidate"` — the branch was dead, silently mislabeling every auth-bypass chain's impact.
- `_compatible_findings()`: the cross-parameter cluster allowlist omitted `"auth"`/`"role"`, two canonical clusters flagged as equally high-risk as `id`/`user_identifier` — chains pivoting through an auth/role-parameter correlation could never be generated.
- `_refine_paths()`: refinement could re-append a step identical to an existing one, padding step count and silently lowering the path's exploitability score.
- `_build_graph()`: cluster→endpoint edges were appended without ensuring the endpoint node exists; hardened defensively.
- `modules/ad/phases/passive_recon.py`: `self.acl_path_builder` was constructed but `.build()` was never called — `_generate_workflow()` hand-rolled a partial duplicate of its SMB-relay chain, missing the builder's `ntlmrelayx.py` suggestion. Now calls the real builder.
- `modules/ad/phases/bloodhound_collection.py`: removed a second, genuinely-dead `self.delegation_builder` instantiation (same "constructed, never called" pattern; unlike the ACL case, this one had no data to wire it to — its job is already covered elsewhere in that phase and by the dedicated `delegation_discovery.py` phase).
- `privilege_escalation_paths.py::_build_password_spray()`: replaced a hardcoded literal password (`'Spring2026!'`) in a suggested command with a `passwords.txt` wordlist reference.
- Stale `"Generated by ReconForge v1.0 release"` footer string (vs. actual `2.2.0`), hardcoded independently in 8 report-generating files.

### Added

- `AttackWorkflow.add_attack_path()` now does exact-match dedup by chain name (mirroring `suggest_next()`'s existing pattern), closing 3 real double-fire cases (Kerberoast/AS-REP chains from two phases, "Privileged Account Targeting" hardcoded twice, "SMB Relay Attack" hardcoded twice). New `duplicate_attack_path_count`, surfaced in `to_markdown()`.
- `core/version.py::__version__` — the one runtime-importable version string, wired into all 8 report footers, filling a gap `docs/VERSIONING.md` had explicitly flagged as not yet existing.

### Documented (not yet fixed — tracked as follow-ups)

- Cross-module/cross-phase attack-path chains that are semantically similar but differently *named* aren't caught by the new exact-match dedup (same scoping limit Phase 9 accepted for `FindingsManager`).
- `modules/surface/intelligence/attack_prioritizer.py` remains a third, structurally isolated "attack"-adjacent system.
- Extending the attack-path graph to cover AD/network assets, not just HTTP endpoints, is still open.

33 new tests added (693 → 726); full suite, ruff, mypy, and bandit all pass.

## [2.2.0] — 2026-07-13

Phase 9 (Deduplication/Correlation): `core/findings_manager.py::FindingsManager.add()` had zero identity/dedup check — every call unconditionally appended. Adds a new backward-compatible dedup mechanism and cross-module aggregation (MINOR per `docs/VERSIONING.md`'s "new finding fields"/"new core features" rules), alongside real duplicate-finding bug fixes.

### Fixed

- `network/phases/authentication_checks.py`: SMB null-session testing is host-level, but `ANON_TEST_SERVICES` mapped both port 139 and 445 to the same test — any dual-port SMB host (the overwhelming majority of Windows/Samba targets) got the test run, and a finding recorded, twice.
- `network/parsers/nmap_parser.py::check_anonymous_access()`: a service-name heuristic and NSE script output were checked independently, producing two findings describing the same anonymous-access condition for one port.
- `modules/surface/intelligence/correlation_engine.py::_ingest_http()`: HTTP services were grouped by scheme alone, ignoring port — two distinct HTTP services on different ports of the same host were conflated into one `CorrelatedService`, misattributing their technologies/products/urls to each other.
- `CorrelationEngine._ingest_entry()`: hardcoded `detection_method="port_scan"` for every entry, discarding `ServiceDeduplicator`'s real multi-method tagging — `ConfidenceScorer`'s `multi_detection` signal could never fire for TCP/UDP services, only HTTP.

### Added

- `FindingsManager.add()` now does exact-match fingerprint deduplication (modeled on `core/credential_vault.py::CredentialVault._fingerprint()`'s proven pattern) — a duplicate call returns the first-seen `Finding` instead of creating a second entry. New `duplicate_count` property, surfaced in `to_markdown()`.
- `FindingsManager.ingest(other)` merges another manager's findings through `add()`, so the new dedup applies automatically.
- `WorkflowOrchestrator.findings` — previously instantiated but never used anywhere (dead code) — is now wired into `_run_module()` (mirroring the existing `credential_vault.ingest_from_loot()` pattern) and saved as `findings_<timestamp>.{json,md}` in the workflow's final report output, giving a real cross-module aggregated view for the first time.

### Documented (not yet fixed — tracked as follow-ups)

- Cross-module semantically-similar-but-differently-worded duplicates (e.g. network and ad modules independently reporting SMB-signing status with different description text) aren't caught by the new exact-match dedup.
- `CredentialVault._fingerprint()`'s case-sensitive username/domain matching.
- `LootManager`'s O(n) linear-scan dedup vs. `CredentialVault`'s O(1) approach.
- A `network/phases/port_scanning.py` live-hosts loop edge case.

25 new tests added (668 → 693); full suite, ruff, mypy, and bandit all pass.

## [2.1.0] — 2026-07-13

Phase 8 (Confidence Model): audited `core/findings_manager.py` and ~94 confidence-assignment call sites across all 5 recon modules. Adds a new backward-compatible `confidence_reason` field (MINOR per `docs/VERSIONING.md`'s "new finding fields" rule) alongside several real bug fixes.

### Security / Correctness

- `web/phases/exploit_candidates.py::_run_sqlmap()`: fixed a bare `"injectable" in line_lower` substring match tripping on sqlmap's own NEGATIVE-result phrasing ("does not appear to be injectable"), which fabricated a `severity="critical", confidence="confirmed"` SQL-injection finding for a target sqlmap explicitly reported as not injectable. The most severe bug found in this phase.
- `web/phases/vulnerability_scanning.py`: fixed nuclei-finding confidence being derived FROM severity (`"high" if sev in ("critical","high") else "medium"`), which inverted `_clamp_severity()`'s intended evidence→confidence→severity-cap flow and let any severe-enough finding always escape its own cap. Confidence is now independent of severity.
- `ad/phases/bloodhound_collection.py`: relabeled the Domain-Admin attack-path finding from `confidence="confirmed"` to `"high"` — a BloodHound graph-traversal inference is not an exploited/verified fact per this project's own confidence definitions.

### Added

- `Finding.confidence_reason: str` and a matching `confidence_reason=` parameter on `FindingsManager.add()` and all 5 modules' `add_finding()` wrappers, so callers can record *why* a confidence level was chosen. Populated at the 3 fixed call sites above; broader adoption across ~90 other call sites is a tracked follow-up, not attempted in this phase.
- `FindingsManager.to_markdown()` now includes a "Heuristic Findings" section (previously-dead `get_heuristic_findings()` is now wired in) and shows `confidence_reason` per finding when present.
- `quick_report.md` (network/web/api/surface modules) now shows a visible warning when findings were severity-clamped due to weak confidence — previously such findings could silently vanish from the "Critical & High Findings" headline section with no operator-facing signal.

### Fixed

- `modules/surface/intelligence/confidence_scorer.py::ConfidenceScorer` never emitted the `"heuristic"` tier (weakest confidence level) — a zero-signal service detection was mislabeled `"low"` instead.
- `api/phases/discovery.py` marked every ffuf-discovered endpoint `confidence="confirmed"` unconditionally; aligned with `web/phases/content_enumeration.py`'s status-code-based tiering for the same evidence type.
- Removed dead `core/findings_manager.py::_CONFIDENCE_RANK` constant.

### Documented (not yet fixed — tracked as follow-ups)

- The AD module's wholesale `confidence="confirmed"` usage across ~29 remaining phase/analyzer call sites.
- `confidence_scorer.py`'s surface-module-only scoping, not shared with the other 4 modules.
- A handful of minor within-file confidence inconsistencies (wpscan version vs. plugin inventory; JWT `alg=none` vs. empty signature).
- `core/cve_enricher.py::enrich_references()`'s blocking-network-call-in-hot-loop risk when `RECONFORGE_NVD_LOOKUP=1` is set.

57 new tests added (611 → 668), including full confidence×severity clamp-matrix coverage for `core/findings_manager.py` (previously untested); full suite, ruff, mypy, and bandit all pass.

## [2.0.2] — 2026-07-13

Phase 7 (Parsing/Normalization): a full audit of all 26 `modules/*/parsers/*.py` files, fixing real bugs found in the process. No CLI-facing or config-schema changes — pure correctness/security fixes, released as a PATCH per `docs/VERSIONING.md`.

### Fixed

- `api/parsers/nuclei_parser.py`: a JSONL line with `"info": null` raised an uncaught `AttributeError` and aborted parsing of the entire scan's results (one malformed record killed the whole batch — same class of bug as Phase 6's `output_file=` clobbering). Ported the guard already present in `web/parsers/nuclei_parser.py`.
- `ad/parsers/bloodhound_parser.py`: all 5 `parse_*_json()` methods assumed every JSON list entry was a dict; a malformed non-dict entry raised an uncaught `AttributeError` and aborted the whole file's parse. Added `isinstance` guards.
- `ad/parsers/nmap_parser.py`: the text-mode NSE script-block regex only matched `"| "`-prefixed continuation lines, silently dropping the `"|_"`-prefixed final line — exactly where SMB-signing status commonly appears. Confirmed live-reachable via `ad/collectors/dns_collector.py`'s fallback to text parsing.
- `network/parsers/nmap_parser.py`: added the missing `OSError` to its caught-exceptions tuple (had `FileNotFoundError` but not the broader `OSError`), matching its `ad/` sibling.
- `ad/parsers/nmap_parser.py::parse_xml()`: now preserves the raw XML text in the result's `raw` field even when parsing fails, instead of leaving zero postmortem-debugging signal.
- `api/parsers/nuclei_parser.py`: severity classification now routes through the same shared `normalize_severity()` helper `web/parsers/nuclei_parser.py` already uses for the identical tool, fixing silent fallthrough on `"moderate"`/`"important"`/`"crit"` aliases.
- `network/parsers/smb_parser.py`: ported `ad/parsers/smb_parser.py`'s broader access-denied pattern coverage (`NT_STATUS_ACCOUNT_DISABLED`, bare `ACCESS_DENIED`/`LOGON_FAILURE`), fixing a risk of misclassifying denied SMB access as successful.

### Changed

- Consolidated the triplicated LDIF entry-splitting algorithm: `ad/parsers/ldap_parser.py` and `ad/parsers/delegation_parser.py` had byte-for-byte identical implementations (self-acknowledged in the latter's docstring); extracted into `modules/ad/parsers/ldif_utils.py::split_ldif_entries()`. `network/parsers/ldap_parser.py`'s independent implementation was deliberately left as-is — it preserves case-sensitive attribute names that ~15 call sites in that file depend on, which the shared function's lowercased-key convention would have silently broken.
- Removed 16 unused `typing` imports across parser files (`ruff --select F401 --fix`).
- Corrected `web/parsers/gobuster_parser.py`'s docstring, which claimed DNS-subdomain extraction support its regex can never match.
- Corrected `web/parsers/wpscan_parser.py`'s unreachable `severity: str = "high"` dataclass default to `"low"` (every construction site passes severity explicitly).

### Documented (not yet fixed — tracked as follow-ups)

- Severity/confidence assignment is inconsistent across parsers — no shared evidence-derived-confidence pattern like `reconforge/intelligence/engine.py`'s P1-5 fix.
- Return-type convention (dataclass-with-errors vs. bare dict/list) is ad hoc across the 26 parsers.
- `netexec_parser.py`, `delegation_parser.py`, and `impacket_parser.py` still lack raw/error preservation on parse failure.
- `ad/parsers/impacket_parser.py`'s whitespace-column-splitting heuristic risk on tables with blank optional columns (unconfirmed without a real tool-output sample).

33 new tests added (578 → 611); full suite, ruff, mypy, and bandit all pass.

## [2.0.1] — 2026-07-12

Phase 6 (Tool Adapters): a full audit of all 28 `modules/*/tools/*.py` wrappers, fixing real bugs found in the process. No CLI-facing or config-schema changes — pure correctness/security fixes, released as a PATCH per `docs/VERSIONING.md`.

### Security

- `modules/network/tools/smbclient.py::list_share_contents()`: fixed an unsanitized `path` argument reaching smbclient's `-c` batch-command mini-language, where a `;`-containing `path` could inject additional smbclient commands (batch-language injection, not OS shell injection — `shell=False` throughout). Now validated via `core.runner.validate_arg()`.
- `core/logger.py`: added redaction patterns for three credential formats that previously reached command logs in plaintext — `-w <password>` (ldapsearch/impacket bind password), `-U user%password` (smbclient), and domain-qualified `DOMAIN/username:password` (impacket's bare positional identity string). The identity-string pattern is deliberately scoped to require a domain prefix to avoid false-positive redaction of unrelated `host:port` tokens.

### Fixed

- `ad/tools/nmap.py::dns_all_srv()`: no longer hardcodes `success=True` regardless of the underlying `dig` calls' actual results.
- `Runner.run()`'s `output_file=` parameter was unconditionally overwriting a tool's own output file with captured stdout after the subprocess exits, corrupting output already written via the tool's own `-o`/`--log-json`/`-oJ` flag. Confirmed empirically for `curl_tool.py` (traced downstream to false-positive/false-negative header findings in `modules/web/phases/surface_discovery.py`); fixed across 11 wrappers total (`whatweb.py`, `ffuf.py`, `ffuf_api.py`, `arjun_tool.py`, `wpscan.py`, `wafw00f.py`, `gobuster.py`, `nuclei.py`, `nuclei_api.py`, `httpx_tool.py`, plus `curl_tool.py`).
- Magic returncode literals (`-1`, `-2`) in 8 tool-wrapper files that collided with `core.runner`'s `RC_TIMEOUT`/`RC_TOOL_NOT_FOUND` sentinels — replaced with the correct named constants, adding a new `RC_PRECONDITION_FAILED` for the "no wordlist resolved" case that didn't fit any existing sentinel.
- `bloodhound.py`, `ad/tools/ldapsearch.py`, `netexec.py`, and one method of `advanced_impacket.py`: `self.tool_cfg`/`self._tool_cfg()` was instantiated but never called, so `tools.yaml` timeout overrides were silently ignored.
- `ad/tools/smbclient.py::test_sysvol_access()`/`test_netlogon_access()`: the caller's `timeout` argument was silently discarded instead of forwarded.
- Removed redundant double command-logging in `modules/surface/tools/nmap_stealth.py` and `service_detector.py`.

### Documented (not yet fixed — tracked as follow-ups)

- `validate_arg()` is only called in 4 of 28 tool wrappers (all `modules/api/tools/*`); the other 24, including the highest-traffic nmap variants and every AD credential-bearing wrapper, build commands from unvalidated input.
- `Runner.get_tool_version()` (added in 1.2.0/Phase 4) is still wired into zero of the 28 tool wrapper constructors.
- `modules/api/tools/httpx_tool.py` and `modules/surface/tools/service_detector.py` independently wrap httpx with near-identical flags — a third instance of the per-module tool duplication already assessed (and deliberately left alone) for nmap/ldapsearch/smbclient in 1.2.0.

37 new tests added (541 → 578); full suite, ruff, mypy, and bandit all pass.

## [2.0.0] — 2026-07-12

Phase 5 (Target Validation and Safety): closes the gap where ReconForge would run active scans against any target with zero acknowledgement of authorization, and tightens URL/domain validation that previously let malformed or malicious-looking targets reach the CLI's "validated" modules unchecked.

### Security

- `core/validators.py::validate_url()` now rejects embedded credentials (`user:pass@host`), control characters, newlines/null bytes, and excessively long values, instead of only checking scheme and netloc presence.
- `modules/web/web_module.py` and `modules/api/api_module.py`: `_normalise_url()` was a no-op that just prefixed `http://` onto anything; both now route through `validate_url()` so malformed targets fail fast instead of being silently passed to nikto/ffuf/gobuster/etc.
- `modules/ad/ad_module.py`: the `--domain` flag now validates through `core/validators.py::validate_domain()` instead of accepting any string unchecked.

### Added

- `--authorized-target` and `--lab-mode` CLI flags on all 6 subcommands (`network`, `ad`, `web`, `api`, `workflow`, `surface`).
- `reconforge/cli.py::require_authorization()`: refuses to dispatch any active (non-`--dry-run`) run unless the user has passed `--authorized-target`, `--lab-mode`, or a successfully validated `--enforce-scope`. Wired into `main()` immediately after `enforce_scope_gate()`.

### Breaking

- **Existing scripts/automation that invoke ReconForge without `--dry-run` will now fail** with a clear authorization error unless they add `--authorized-target`, `--lab-mode`, or `--enforce-scope` (with `--scope-file`/`--approval-id`). This is a deliberate, security-motivated behavior change — per `docs/VERSIONING.md`, "existing users must modify their workflow to maintain the same behavior" is the definition of breaking, so this is released as a MAJOR version bump rather than folded into a MINOR/PATCH release. Migration: add one of the three flags above to any existing invocation.

## [1.2.0] — 2026-07-12

Public-release remediation pass: a full architecture/security audit (`docs/ARCHITECTURE_REVIEW.md`) followed by every P0 (release-blocking) and P1 (major quality/security) fix it identified.

### Security

- `core/target_parser.py`: fixed a hostname-validation bypass that accepted any string as a "validated" target, including shell metacharacters and flag-injection payloads.
- `core/runner.py`: `--enforce-scope` is now enforced at every command execution (construction and every `run()` call, not just once at CLI start), and propagated through all 5 modules, `WorkflowOrchestrator`, and auto-handoff to targets discovered mid-run.
- Command logs and session notes now route through the same secret-redaction path as the structured logger; fixed a redaction-ordering bug that let part of a Bearer token through.
- Fixed a scheme-override bug in the Burp MCP adapter that could let a malicious/compromised MCP server redirect `urlopen` to `file://`.
- `core/credential_vault.py`, `core/loot_manager.py`: vault/loot files now written with mode `0600`; saving without encryption now emits an explicit warning; added `RECONFORGE_VAULT_KEY` / `RECONFORGE_LOOT_KEY` env vars to supply the Fernet key out-of-band instead of relying solely on the on-disk key file.
- Switched nmap/AD/surface XML parsing from `xml.etree.ElementTree` to `defusedxml` (XXE hardening).
- Triaged all 76 bandit findings surfaced once CI's bandit target was corrected (previously silently pointed at a deleted file and never actually scanned the package).

### Added

- `LICENSE` (Apache-2.0), `SECURITY.md`, `.gitleaks.toml`, `.github/dependabot.yml`.
- `reconforge/__main__.py` — `python -m reconforge ...` now works without installing.
- `core/exceptions.py`: completed the typed exception hierarchy (`KillSwitchBlockedError`, `PolicyBlockedError`, `InvalidCommandError`) and wired `run_or_raise()`/`check_tool_or_raise()` to actually use it.

### Fixed

- 4 failing tests (root cause: they loaded a top-level `reconforge.py` deleted when the code moved into the `reconforge/` package) and 25 stale `reconforge.py` references across docs/CLI.
- `mcp_validation/run_validation.py`: fixed a real syntax error and a `main()` that parsed CLI args but never called the validator.
- `reconforge/attack_paths/engine.py`: attack paths were marked `validated=True` from any non-erroring HTTP response; now separated into `unreachable` / `reachable` / `corroborated` tiers based on whether the response actually matched the finding type's own signal.
- `reconforge/intelligence/engine.py`: vulnerability-classification confidence is now derived from concrete evidence factors per finding type instead of a fixed literal per rule.
- CI pipeline corrected end to end (mypy/bandit target paths, `ruff check .`, packaging smoke test's `--no-build-isolation` fragility) and given an honest coverage gate (50%, matching real ~52% coverage, replacing a never-true, never-enforced 85% claim).

### Changed

- README repositioned as "An evidence-driven reconnaissance and attack-path analysis framework for authorized penetration testing and Red Team laboratories," with explicit external-dependencies and heuristic-vs-confirmed sections.
- `docs/PROJECT_SCORECARD.md` and `docs/INDEPENDENT_SECURITY_ASSESSMENT_2026-04-13.md` labeled as author self-assessments, not independent reviews.

## [1.1.0] — 2026-04-13

Baseline/professionalization release focused on release alignment, quality gates, packaging, and artifact governance.

### Changed

- Aligned README/docs baseline to current test suite status (`368` passing tests) and bumped documented version to `1.1.0`.
- Added modern Python packaging via `pyproject.toml` and installable CLI entry point (`reconforge`).
- Added formal CI quality gates for linting, type checks, SAST, dependency audit, and coverage-enforced tests.
- Added runtime artifact policy and stopped tracking operational `outputs/` artifacts in version control.

## [1.0.0] — 2026-03-21

Initial stable release. All 348 tests passing.

### Added

#### Command Execution Hardening (Priority 1)
- `core/runner.py`: All subprocess execution uses `list[str]` via `subprocess.run` — zero `shell=True` usage across the entire codebase.
- `validate_arg()` rejects shell metacharacters (`; & | \` $ ( ) { }`) before subprocess execution.
- String commands accepted for backward compatibility with `DeprecationWarning`; split via `shlex.split`.
- `RunResult` dataclass returns stdout, stderr, returncode, duration.
- `run_or_raise()` variant with typed exceptions: `ToolNotFoundError`, `TimeoutError`, `ExecutionError`.

#### Configuration Unification (Priority 2)
- Single-source-of-truth YAML config: `config/tools.yaml` and `config/profiles.yaml`.
- `core/tool_config.py`: Typed accessor for tool entries with `binary`, `mode_args()`, `effective_timeout()`.
- `core/config_loader.py`: YAML loading with caching. No fallback namespaces, no env-var overrides.
- `core/profile_loader.py`: OPSEC profile resolution (stealth / normal / aggressive).
- Migration guide: `docs/MIGRATION_CONFIG_SCHEMA.md`.

#### Findings Model (Priority 3)
- `core/findings_manager.py`: 5-level confidence model (`confirmed` → `high` → `medium` → `low` → `heuristic`).
- Automatic severity clamping: heuristic caps at `low`, low confidence caps at `medium`.
- Clamped findings annotated with original severity in description.
- `core/loot_manager.py`: Credential/hash/token tracking with deduplication and optional Fernet encryption.
- `core/credential_vault.py`: Centralized credential store with deduplication, encryption, export/import.

#### API Hardening (Priority 5)
- `modules/api/`: 4 tools (`ffuf_api`, `httpx_tool`, `arjun_tool`, `nuclei_api`), 4 parsers, 4 phases.
- Phases: discovery, authentication, fuzzing, authorization.
- OpenAPI spec parsing, JWT analysis, authorization boundary testing.

#### Surface Intelligence (Priority 6)
- `modules/surface/intelligence/`: Correlation engine, confidence scorer, deduplicator, service normalizer, service intelligence, attack prioritizer.
- `modules/surface/`: 2 tools, 1 parser, 4 phases (port discovery, service fingerprint, vector correlation, prioritization).

#### AD Modularization (Priority 7)
- `modules/ad/`: 8 tools, 8 parsers, 6 collectors, 5 analyzers, 6 attack path detectors, 5 phases, 6 reporters.
- Extended pipeline: `tools → parsers → collectors → analyzers → attack_paths → phases → reporting → module`.
- Attack path detection: ACL, AS-REP roasting, delegation, GPO abuse, Kerberoasting, privilege escalation.

#### Notes & Reporting (Priority 8)
- `core/notes_manager.py`: Timestamped session notes with categories (phase, finding, command, general).
- `core/output_manager.py`: Structured output directories with engagement report generation.
- `core/attack_workflow.py`: Kill-chain tracking, hypothesis management, next-command suggestions.
- `core/engagement.py`: Full lifecycle (planning → active → paused → completed → cancelled).

#### Documentation (Priority 4)
- 20 Markdown files in `docs/` (5,273 total lines) with PDF exports.
- Module-level READMEs for all 5 modules plus AD architecture deep-dive and surface intelligence guide.
- Complete API reference (`docs/API_REFERENCE.md`, 620 lines).

#### Core Infrastructure
- 5 modules: `network`, `web`, `api`, `surface`, `ad`.
- `core/workflow_orchestrator.py`: Cross-module chaining with conditional branching.
- `core/validators.py`: IP, CIDR, hostname, URL, port validation.
- `core/opsec_checks.py` + `core/detection_map.py`: Technique-level OPSEC gating with noise-level mapping.
- `core/exceptions.py`: Structured hierarchy (`ReconForgeError` → `ConfigError`, `ValidationError`, `ExecutionError`, `ModuleError`, `WorkflowError`).
- `core/logger.py`: Color-coded logging with credential sanitization.
- CLI entry point (`reconforge`) with argparse subcommands per module.

### Known Issues
- `surface` subparser missing `--encrypt-loot` CLI flag (backend supports it; cosmetic-only).
- `smbclient` `ls_cmd` uses f-string interpolation for inner SMB command (not a security risk — passed as single `list[str]` element, no `shell=True`).
