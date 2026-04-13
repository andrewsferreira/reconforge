# ReconForge — Documentation Map & Canonical Source Reference

> **Purpose:** Defines which document is the canonical (authoritative) source for each topic.
> When multiple documents cover the same topic, this map designates the primary source
> and lists secondary references.
> Last updated: 2026-03-21

---

## Canonical Source Assignments

### Architecture & Design

| Topic | Canonical Source | Secondary References |
|-------|-----------------|---------------------|
| System architecture | [ARCHITECTURE.md](ARCHITECTURE.md) | [README.md](../README.md), [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md) |
| Module architecture | [MODULES.md](MODULES.md) | Module-level READMEs (`modules/*/README.md`) |
| AD module internals | [modules/ad/README.md](../modules/ad/README.md) | [AD_MODULE_SUMMARY.md](AD_MODULE_SUMMARY.md), [modules/ad/ARCHITECTURE.md](../modules/ad/ARCHITECTURE.md) |
| Web module internals | [modules/web/README.md](../modules/web/README.md) | [WEB_MODULE_SUMMARY.md](WEB_MODULE_SUMMARY.md) |
| API module internals | [modules/api/README.md](../modules/api/README.md) | [MODULES.md](MODULES.md) |
| Network module internals | [modules/network/README.md](../modules/network/README.md) | [MODULES.md](MODULES.md) |
| Surface module internals | [modules/surface/SURFACE_INTELLIGENCE.md](../modules/surface/SURFACE_INTELLIGENCE.md) | [MODULES.md](MODULES.md) |

### Configuration & Setup

| Topic | Canonical Source | Secondary References |
|-------|-----------------|---------------------|
| Tool & profile configuration | [CONFIGURATION.md](CONFIGURATION.md) | [FAQ.md](FAQ.md), [SETUP.md](SETUP.md) |
| Installation & prerequisites | [SETUP.md](SETUP.md) | [README.md](../README.md) |
| Platform support | [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) | [SETUP.md](SETUP.md) |
| Config schema migration | [MIGRATION_CONFIG_SCHEMA.md](MIGRATION_CONFIG_SCHEMA.md) *(historical)* | [CONFIGURATION.md](CONFIGURATION.md) |

### Usage & Operations

| Topic | Canonical Source | Secondary References |
|-------|-----------------|---------------------|
| CLI reference | [USAGE.md](USAGE.md) | [README.md](../README.md), [FAQ.md](FAQ.md) |
| Workflow orchestration | [WORKFLOW_GUIDE.md](WORKFLOW_GUIDE.md) | [USAGE.md](USAGE.md), [ARCHITECTURE.md](ARCHITECTURE.md) |
| Operational runbooks | [RUNBOOKS.md](RUNBOOKS.md) | [USAGE.md](USAGE.md), [FAQ.md](FAQ.md) |
| Troubleshooting | [FAQ.md](FAQ.md) | [LIMITATIONS.md](LIMITATIONS.md) |

### Findings & Severity

| Topic | Canonical Source | Secondary References |
|-------|-----------------|---------------------|
| Findings system | [FINDINGS.md](FINDINGS.md) | [ARCHITECTURE.md](ARCHITECTURE.md), [EXTENDING.md](EXTENDING.md) |
| Severity criteria & scoring | [SEVERITY_CRITERIA.md](SEVERITY_CRITERIA.md) | [FINDINGS.md](FINDINGS.md) |
| Confidence model & clamping | [FINDINGS.md](FINDINGS.md) | [SEVERITY_CRITERIA.md](SEVERITY_CRITERIA.md), [LIMITATIONS.md](LIMITATIONS.md) |

### Development & Extension

| Topic | Canonical Source | Secondary References |
|-------|-----------------|---------------------|
| Development guidelines | [DEVELOPMENT.md](DEVELOPMENT.md) | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Extension guide | [EXTENDING.md](EXTENDING.md) | [DEVELOPMENT.md](DEVELOPMENT.md), [API_REFERENCE.md](API_REFERENCE.md) |
| API reference (classes/methods) | [API_REFERENCE.md](API_REFERENCE.md) | [EXTENDING.md](EXTENDING.md) |
| Contributing guidelines | [CONTRIBUTING.md](../CONTRIBUTING.md) | [DEVELOPMENT.md](DEVELOPMENT.md) |
| Integration testing | [INTEGRATION_TESTING.md](INTEGRATION_TESTING.md) | [DEVELOPMENT.md](DEVELOPMENT.md) |
| Versioning policy | [VERSIONING.md](VERSIONING.md) | [CHANGELOG.md](../CHANGELOG.md) |

### Terminology & Naming

| Topic | Canonical Source | Secondary References |
|-------|-----------------|---------------------|
| All terminology | [TERMINOLOGY.md](TERMINOLOGY.md) | — |
| Known limitations | [LIMITATIONS.md](LIMITATIONS.md) | [FAQ.md](FAQ.md) |

---

## Historical Documents

These documents are preserved as historical records. They reflect the project state at the time of writing and are **not maintained**.

| Document | Date | Description |
|----------|------|-------------|
| [AUDIT_REPORT.md](AUDIT_REPORT.md) | 2026-03-17 | Comprehensive technical audit |
| [RECONFORGE_MODULE_REPORT.md](RECONFORGE_MODULE_REPORT.md) | 2026-03-17 | Module inventory report |
| [COMMAND_REFACTORING_REPORT.md](COMMAND_REFACTORING_REPORT.md) | 2026-03-20 | Command execution refactoring (Priority 1) |
| [PHASE_1_CONSISTENCY_AUDIT.md](PHASE_1_CONSISTENCY_AUDIT.md) | 2026-03-21 | Documentation consistency audit |
| [PRIORITY_4_COMPLETION_REPORT.md](PRIORITY_4_COMPLETION_REPORT.md) | 2026-03-21 | Documentation completion report |
| [FINAL_STABILIZATION_REPORT.md](FINAL_STABILIZATION_REPORT.md) | 2026-03-21 | Final stabilization validation |
| [MIGRATION_CONFIG_SCHEMA.md](MIGRATION_CONFIG_SCHEMA.md) | 2026-03-21 | Config schema unification guide |
| [STABILIZATION_CHECK_P9.md](STABILIZATION_CHECK_P9.md) | 2026-03-21 | Priority 9 stabilization check |
| [../STABILIZATION_CHECK_P6.md](../STABILIZATION_CHECK_P6.md) | 2026-03-21 | Priority 6 stabilization check |
| [../STABILIZATION_CHECK_P7.md](../STABILIZATION_CHECK_P7.md) | 2026-03-21 | Priority 7 stabilization check |
| [../STABILIZATION_CHECK_P8.md](../STABILIZATION_CHECK_P8.md) | 2026-03-21 | Priority 8 stabilization check |

---

## Module-Level Documentation

| Document | Canonical For |
|----------|--------------|
| [modules/network/README.md](../modules/network/README.md) | Network module tools, phases, parsers |
| [modules/web/README.md](../modules/web/README.md) | Web module tools, phases, parsers |
| [modules/api/README.md](../modules/api/README.md) | API module tools, phases, parsers |
| [modules/api/HARDENING_CHANGELOG.md](../modules/api/HARDENING_CHANGELOG.md) | API module hardening history *(historical)* |
| [modules/ad/README.md](../modules/ad/README.md) | AD module tools, phases, collectors, analyzers |
| [modules/ad/ARCHITECTURE.md](../modules/ad/ARCHITECTURE.md) | AD module architecture details |
| [modules/surface/SURFACE_INTELLIGENCE.md](../modules/surface/SURFACE_INTELLIGENCE.md) | Surface intelligence engine |

---

## Cross-Reference Rules

1. **Do not duplicate detailed explanations.** When a non-canonical document discusses a canonical topic, add a cross-reference: `> See [CANONICAL_DOC.md](CANONICAL_DOC.md) for details.`
2. **Canonical sources are authoritative.** If a secondary reference conflicts with the canonical source, the canonical source is correct.
3. **Historical documents are frozen.** Do not update historical documents to match current state — they reflect the project at a specific point in time.
4. **Module READMEs are canonical for module internals.** `docs/MODULES.md` provides the overview; module-level READMEs provide implementation details.
