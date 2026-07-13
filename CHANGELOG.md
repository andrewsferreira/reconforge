# Changelog

All notable changes to ReconForge are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (see [docs/VERSIONING.md](docs/VERSIONING.md)).


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
