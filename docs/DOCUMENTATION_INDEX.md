# ReconForge — Documentation Index

> **Navigation guide for all project documentation**
> Last updated: 2026-03-21 · 20 Markdown documents · 16 PDF exports

---

## Quick Links

| Need to… | Go to |
|----------|-------|
| Understand the project | [README.md](#readmemd) |
| Install & set up | [SETUP.md](#setupmd) |
| Run the tool | [USAGE.md](#usagemd) |
| Understand the architecture | [ARCHITECTURE.md](#architecturemd) |
| Configure tools & profiles | [CONFIGURATION.md](#configurationmd) |
| Build a new module/phase | [DEVELOPMENT.md](#developmentmd) + [EXTENDING.md](#extendingmd) |
| Look up a class or method | [API_REFERENCE.md](#api_referencemd) |
| Understand findings/severity | [FINDINGS.md](#findingsmd) + [SEVERITY_CRITERIA.md](#severity_criteriamd) |
| Run multi-module workflows | [WORKFLOW_GUIDE.md](#workflow_guidemd) |
| Integrate Burp MCP provider | [BURP_MCP_INTEGRATION.md](#burp_mcp_integrationmd) |

| Review audit & stabilization | [AUDIT_REPORT.md](#audit_reportmd) + [FINAL_STABILIZATION_REPORT.md](#final_stabilization_reportmd) |

---

## 1. User-Facing Documentation

### README.md
📍 **Location:** [`/README.md`](../README.md)
**Status:** ✅ Complete & current (7 KB)

Project overview, module table (Network/Web/API/Surface/AD/Workflow), architecture summary, quick-start commands, OPSEC modes, output structure, and full project tree. The single entry point for anyone encountering the project for the first time.

---

### SETUP.md
📍 **Location:** [`docs/SETUP.md`](SETUP.md)
**Status:** ✅ Complete (78 lines)

Prerequisites (Python 3.10+), `pip install` instructions, external tool installation (`nmap`, `smbclient`, `ldapsearch`, Impacket), and a dependency table showing required vs. optional packages.

---

### USAGE.md
📍 **Location:** [`docs/USAGE.md`](USAGE.md) · [PDF](USAGE.pdf)
**Status:** ✅ Complete (319 lines)

Full CLI reference for all six subcommands (`network`, `web`, `api`, `surface`, `ad`, `workflow`). Covers common flags (`--target`, `--opsec`, `--phases`, `--dry-run`, `--encrypt-loot`), per-module examples, OPSEC mode behavior, and output interpretation.

---

### WORKFLOW_GUIDE.md
📍 **Location:** [`docs/WORKFLOW_GUIDE.md`](WORKFLOW_GUIDE.md) · [PDF](WORKFLOW_GUIDE.pdf)
**Status:** ✅ Complete (320 lines)

Cross-module workflow orchestration: pipeline definition, `WorkflowContext` data passing, conditional step evaluation, `CredentialVault` sharing, `EngagementManager` lifecycle, and example pipelines (full recon, targeted, stealth).

---

## 2. Architecture & Design

### ARCHITECTURE.md
📍 **Location:** [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) · [PDF](ARCHITECTURE.pdf)
**Status:** ✅ Complete (305 lines)

System-level design: the `tools/ → parsers/ → phases/ → module.py → core/` pipeline, directory structure, core services layer (17 modules), data flow diagrams, security model (no `shell=True`, `validate_arg()`, credential sanitization), and module-specific extensions (Surface `intelligence/`, AD extended pipeline).

---

### MODULES.md
📍 **Location:** [`docs/MODULES.md`](MODULES.md) · [PDF](MODULES.pdf)
**Status:** ✅ Complete (409 lines)

Detailed documentation for all five modules: Network (5 tools, 4 phases), Web (9 tools, 4 phases), API (4 tools, 4 phases), Surface (2 tools, 6 intelligence components, 4 phases), and AD (8 tools, 5 phases with collectors/analyzers/attack paths/reporters). Includes base class signatures, phase lists, and tool inventories.

---

### CONFIGURATION.md
📍 **Location:** [`docs/CONFIGURATION.md`](CONFIGURATION.md) · [PDF](CONFIGURATION.pdf)
**Status:** ✅ Complete (290 lines)

`tools.yaml` schema (binary paths, timeouts, scan profiles, safety settings), `profiles.yaml` schema (OPSEC modes, timing, technique toggles, noise-level gates), `ConfigLoader` API, `ToolConfig` typed accessor, and `ProfileLoader` resolution logic. Single source of truth — no env-var overrides.

---

### FINDINGS.md
📍 **Location:** [`docs/FINDINGS.md`](FINDINGS.md) · [PDF](FINDINGS.pdf)
**Status:** ✅ Complete (208 lines)

The 5-level confidence model (`confirmed` → `heuristic`), 5-level severity scale (`critical` → `info`), automatic severity clamping rules, and `FindingsManager` API. Key concept: heuristic-only detections are auto-capped to `low` severity.

---

### SEVERITY_CRITERIA.md
📍 **Location:** [`docs/SEVERITY_CRITERIA.md`](SEVERITY_CRITERIA.md) · [PDF](SEVERITY_CRITERIA.pdf)
**Status:** ✅ Complete (300 lines)

Detailed evidence requirements for each severity × confidence combination. Defines what constitutes `confirmed` vs. `heuristic` evidence, per-tool classification examples, and the clamping enforcement matrix. Companion to FINDINGS.md.

---

## 3. Developer Documentation

### DEVELOPMENT.md
📍 **Location:** [`docs/DEVELOPMENT.md`](DEVELOPMENT.md) · [PDF](DEVELOPMENT.pdf)
**Status:** ✅ Complete (402 lines)

Project structure overview, step-by-step guides for adding tools/parsers/phases, testing guidelines (pytest, 375 tests), code standards (type hints, docstrings, `list[str]` commands), and the 11-parameter base class constructor contract.

---

### EXTENDING.md
📍 **Location:** [`docs/EXTENDING.md`](EXTENDING.md) · [PDF](EXTENDING.pdf)
**Status:** ✅ Complete (94 lines)

Concise quick-reference for extending the framework: inheriting from module base classes (`NetworkPhaseBase`, `ADPhaseBase`, `WebPhaseBase`), registering phases in orchestrators, and adding new tool wrappers/parsers. Complements DEVELOPMENT.md.

---

### API_REFERENCE.md
📍 **Location:** [`docs/API_REFERENCE.md`](API_REFERENCE.md) · [PDF](API_REFERENCE.pdf)
**Status:** ✅ Complete (620 lines)

Full class/method reference for: `Runner` + `RunResult`, `ConfigLoader`, `ToolConfig`, `ProfileLoader`, `FindingsManager`, `LootManager`, `CredentialVault`, `EngagementManager`, `WorkflowOrchestrator`, `OutputManager`, `NotesManager`, `OpsecChecks`, `Validators`, and all module base classes.

---

### MIGRATION_CONFIG_SCHEMA.md
📍 **Location:** [`docs/MIGRATION_CONFIG_SCHEMA.md`](MIGRATION_CONFIG_SCHEMA.md) · [PDF](MIGRATION_CONFIG_SCHEMA.pdf)
**Status:** ✅ Complete (227 lines)

Migration guide for the `web_tools:` → unified `tools:` namespace consolidation. Before/after YAML examples, `ConfigLoader` changes, and per-file migration checklist. Relevant for anyone working with pre-unification branches.

---

## 4. Audit & Stabilization Reports

### AUDIT_REPORT.md
📍 **Location:** [`docs/AUDIT_REPORT.md`](AUDIT_REPORT.md) · [PDF](AUDIT_REPORT.pdf)
**Status:** ✅ Complete (259 lines)

Comprehensive technical audit from an offensive security perspective. Overall score: **6.5/10**. Covers directory structure, module completeness, config/code sync, test quality, OPSEC enforcement, and findings pipeline. Identifies architectural drift as the central problem and provides prioritized remediation.

---

### COMMAND_REFACTORING_REPORT.md
📍 **Location:** [`docs/COMMAND_REFACTORING_REPORT.md`](COMMAND_REFACTORING_REPORT.md) · [PDF](COMMAND_REFACTORING_REPORT.pdf)
**Status:** ✅ Complete (467 lines)

Documents the Priority-1 refactoring of all 27 tool wrappers from `f"tool ..."` string commands to `["tool", "--flag", arg]` list commands. Before/after metrics, per-file changelog, and `Runner` deprecation-warning behavior.

---

### FINAL_STABILIZATION_REPORT.md
📍 **Location:** [`docs/FINAL_STABILIZATION_REPORT.md`](FINAL_STABILIZATION_REPORT.md) · [PDF](FINAL_STABILIZATION_REPORT.pdf)
**Status:** ✅ Complete (256 lines)

10-point checklist validation confirming framework stability: 375/375 tests passing, no critical blockers, two non-critical issues documented (Surface CLI missing `--encrypt-loot`, minor), and deferred technical debt inventory.

---

### STABILIZATION_CHECK_P9.md
📍 **Location:** [`docs/STABILIZATION_CHECK_P9.md`](STABILIZATION_CHECK_P9.md) · [PDF](STABILIZATION_CHECK_P9.pdf)
**Status:** ✅ Complete (158 lines)

Priority-9 stabilization pass: `tools.yaml` consumption audit. 33 files modified, new `core/tool_config.py` (typed accessor), 78 new tests. Confirms all tool wrappers now read config from `tools.yaml` via `ToolConfig`.

---

## 5. Module Build Summaries

### AD_MODULE_SUMMARY.md
📍 **Location:** [`docs/AD_MODULE_SUMMARY.md`](AD_MODULE_SUMMARY.md)
**Status:** ✅ Complete (89 lines)

AD Advanced Module integration summary: 16 files changed (+3,752 lines), test results for all 5 phases (delegation discovery, Bloodhound collection), bug fix during testing, and 26-file inventory with author attribution.

---

### WEB_MODULE_SUMMARY.md
📍 **Location:** [`docs/WEB_MODULE_SUMMARY.md`](WEB_MODULE_SUMMARY.md)
**Status:** ✅ Complete (90 lines)

Web Module build summary: 26 Python files (3,499 lines), 4 phases, 9 tool wrappers, 7 parsers, phase architecture, and dry-run validation results.

---

### RECONFORGE_MODULE_REPORT.md
📍 **Location:** [`docs/RECONFORGE_MODULE_REPORT.md`](RECONFORGE_MODULE_REPORT.md)
**Status:** ✅ Complete (152 lines)

Early-stage module inventory report (March 17, 2026): 2 modules at that point, 60 Python files, 12,910 LOC, 12 core services, 3 git commits. Historical snapshot of the project's growth.

---

### burp_validation.md
📍 **Location:** [`docs/burp_validation.md`](burp_validation.md)
**Status:** ✅ Complete

Official internal validator runbook for Burp MCP integration. Covers CLI/module/programmatic usage, output fields, readiness semantics (`READY`/`PARTIAL`/`FAILED`), error handling behavior, and practical next steps after successful validation.

---

## 6. Root-Level Stabilization Checks (outside `docs/`)

These files live in the project root, not in `docs/`:

| File | Lines | Description |
|------|-------|-------------|
| [`STABILIZATION_CHECK_P6.md`](../STABILIZATION_CHECK_P6.md) | 275 | Priority 6 — Base class standardization |
| [`STABILIZATION_CHECK_P7.md`](../STABILIZATION_CHECK_P7.md) | 225 | Priority 7 — Profile system wiring |
| [`STABILIZATION_CHECK_P8.md`](../STABILIZATION_CHECK_P8.md) | 245 | Priority 8 — Loot pipeline consolidation |

---

## File Format Summary

| Format | Count | Purpose |
|--------|------:|---------|
| Markdown (`.md`) | 23 | Primary documentation (version-controlled) |
| PDF (`.pdf`) | 16 | Exported snapshots for offline/client distribution |

---

### TERMINOLOGY.md
📍 **Location:** [`docs/TERMINOLOGY.md`](TERMINOLOGY.md)
**Status:** ✅ Complete
**Added:** Phase 6 Quality Pass

Canonical terminology reference for all naming conventions: module names, phase slugs, CLI flags, OPSEC modes, severity/confidence levels, finding types, exception classes, and core components. Single source of truth for consistent naming across all documentation.

---

### DOCUMENTATION_MAP.md
📍 **Location:** [`docs/DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md)
**Status:** ✅ Complete
**Added:** Phase 6 Quality Pass

Canonical source map designating which document is authoritative for each topic. Lists primary and secondary references, historical documents, and cross-reference rules.

---

### PHASE_6_QUALITY_REPORT.md
📍 **Location:** [`docs/PHASE_6_QUALITY_REPORT.md`](PHASE_6_QUALITY_REPORT.md)
**Status:** ✅ Complete (historical)
**Added:** Phase 6 Quality Pass

Summary of the Phase 6 documentation quality pass: files audited, issues found and fixed, terminology standardized, historical documents labeled, and canonical sources designated.

---

## Reading Order for New Contributors

1. **[README.md](../README.md)** — What is ReconForge?
2. **[SETUP.md](SETUP.md)** — Get it running
3. **[USAGE.md](USAGE.md)** — Run your first scan
4. **[ARCHITECTURE.md](ARCHITECTURE.md)** — Understand the design
5. **[MODULES.md](MODULES.md)** — Deep-dive into each module
6. **[CONFIGURATION.md](CONFIGURATION.md)** — Customize tools & profiles
7. **[FINDINGS.md](FINDINGS.md)** — Understand the output
8. **[TERMINOLOGY.md](TERMINOLOGY.md)** — Naming conventions reference
9. **[DEVELOPMENT.md](DEVELOPMENT.md)** — Start contributing
10. **[API_REFERENCE.md](API_REFERENCE.md)** — Class/method lookup

---

*This index is auto-maintained. When adding new documentation, add an entry here.*
