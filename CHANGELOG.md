# Changelog

All notable changes to ReconForge are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (see [docs/VERSIONING.md](docs/VERSIONING.md)).


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
- CLI entry point (`reconforge.py`) with argparse subcommands per module.

### Known Issues
- `surface` subparser missing `--encrypt-loot` CLI flag (backend supports it; cosmetic-only).
- `smbclient` `ls_cmd` uses f-string interpolation for inner SMB command (not a security risk — passed as single `list[str]` element, no `shell=True`).
