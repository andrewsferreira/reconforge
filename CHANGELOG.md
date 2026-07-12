# Changelog

All notable changes to ReconForge are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (see [docs/VERSIONING.md](docs/VERSIONING.md)).


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
