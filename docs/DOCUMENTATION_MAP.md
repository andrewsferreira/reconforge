# ReconForge — Canonical Source Map

> Defines which document is the single authoritative source for each topic. When multiple
> documents touch the same subject, this map designates the primary source; everything else
> is a secondary reference and should defer to it, not restate it.

## Canonical Source Assignments

### Architecture & Design

| Topic | Canonical Source | Secondary References |
|-------|-------------------|---------------------|
| System architecture | [ARCHITECTURE.md](ARCHITECTURE.md) | [README.md](../README.md) |
| Module architecture | [MODULES.md](MODULES.md) | Module-level READMEs (`modules/*/README.md`) |
| AD module internals | [modules/ad/README.md](../modules/ad/README.md) | [modules/ad/ARCHITECTURE.md](../modules/ad/ARCHITECTURE.md) |
| Web module internals | [modules/web/README.md](../modules/web/README.md) | — |
| API module internals | [modules/api/README.md](../modules/api/README.md) | [MODULES.md](MODULES.md) |
| Network module internals | [modules/network/README.md](../modules/network/README.md) | [MODULES.md](MODULES.md) |
| Surface module internals | [modules/surface/SURFACE_INTELLIGENCE.md](../modules/surface/SURFACE_INTELLIGENCE.md) | [MODULES.md](MODULES.md) |
| Deterministic decision/correlation engine | [AI_ORCHESTRATION_ARCHITECTURE.md](AI_ORCHESTRATION_ARCHITECTURE.md) | — |

### Configuration & Setup

| Topic | Canonical Source | Secondary References |
|-------|-------------------|---------------------|
| Tool, profile & MCP configuration | [CONFIGURATION.md](CONFIGURATION.md) | [FAQ.md](FAQ.md), [SETUP.md](SETUP.md) |
| Installation & prerequisites | [SETUP.md](SETUP.md) | [README.md](../README.md) |
| Platform support | [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) | [SETUP.md](SETUP.md) |
| Artifact retention & handling | [ARTIFACT_POLICY.md](ARTIFACT_POLICY.md) | — |

### Usage & Operations

| Topic | Canonical Source | Secondary References |
|-------|-------------------|---------------------|
| CLI reference | [USAGE.md](USAGE.md) | [README.md](../README.md), [FAQ.md](FAQ.md) |
| Workflow orchestration | [WORKFLOW_GUIDE.md](WORKFLOW_GUIDE.md) | [USAGE.md](USAGE.md), [ARCHITECTURE.md](ARCHITECTURE.md) |
| Operational runbooks | [RUNBOOKS.md](RUNBOOKS.md) | [USAGE.md](USAGE.md) |
| Troubleshooting | [FAQ.md](FAQ.md) | [LIMITATIONS.md](LIMITATIONS.md) |

### Findings, Severity & Execution Safety

| Topic | Canonical Source | Secondary References |
|-------|-------------------|---------------------|
| Findings system, confidence model, severity clamping | [FINDINGS.md](FINDINGS.md) | [SEVERITY_CRITERIA.md](SEVERITY_CRITERIA.md) |
| Severity scoring criteria | [SEVERITY_CRITERIA.md](SEVERITY_CRITERIA.md) | [FINDINGS.md](FINDINGS.md) |
| Execution authorization (`--authorized-target`/`--lab-mode`/`--enforce-scope`) | [README.md § Safety and Scope](../README.md#execution-model) | [ARCHITECTURE_REVIEW.md](ARCHITECTURE_REVIEW.md) |
| Whole-system threat model | [THREAT_MODEL.md](THREAT_MODEL.md) | — |
| Known limitations & non-goals | [LIMITATIONS.md](LIMITATIONS.md) | [FAQ.md](FAQ.md) |

### MCP Integration

| Topic | Canonical Source | Secondary References |
|-------|-------------------|---------------------|
| MCP client setup, security model, tool/resource reference | [CLAUDE_MCP_INTEGRATION.md](CLAUDE_MCP_INTEGRATION.md) | [THREAT_MODEL.md](THREAT_MODEL.md) |
| MCP execution policy tiers, human-approval flow | [CLAUDE_MCP_INTEGRATION.md § Security model](CLAUDE_MCP_INTEGRATION.md#security-model-summary) | `reconforge/mcp/policy.py`, `reconforge/mcp/approvals.py` (code) |
| MCP design history (why it's built this way) | [CLAUDE_MCP_IMPLEMENTATION_PLAN.md](CLAUDE_MCP_IMPLEMENTATION_PLAN.md) *(historical log — see banner)* | — |
| Burp Suite MCP provider | [BURP_MCP_INTEGRATION.md](BURP_MCP_INTEGRATION.md) | [burp_validation.md](burp_validation.md), [burp_web_lifecycle.md](burp_web_lifecycle.md), [mcp_validation/README.md](../mcp_validation/README.md) |

### Development & Extension

| Topic | Canonical Source | Secondary References |
|-------|-------------------|---------------------|
| Development guidelines | [DEVELOPMENT.md](DEVELOPMENT.md) | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Extension points (new tools/parsers/phases/modules) | [EXTENDING.md](EXTENDING.md) | [DEVELOPMENT.md](DEVELOPMENT.md), [API_REFERENCE.md](API_REFERENCE.md) |
| API reference (classes/methods) | [API_REFERENCE.md](API_REFERENCE.md) | [EXTENDING.md](EXTENDING.md) |
| Contributing guidelines | [CONTRIBUTING.md](../CONTRIBUTING.md) | [DEVELOPMENT.md](DEVELOPMENT.md) |
| Integration testing | [INTEGRATION_TESTING.md](INTEGRATION_TESTING.md) | [DEVELOPMENT.md](DEVELOPMENT.md) |
| Versioning policy | [VERSIONING.md](VERSIONING.md) | [CHANGELOG.md](../CHANGELOG.md) |
| Terminology | [TERMINOLOGY.md](TERMINOLOGY.md) | — |
| Observability, audit events, data contracts | [OBSERVABILITY_AND_CONTRACTS.md](OBSERVABILITY_AND_CONTRACTS.md) | — |

---

## Archived (Historical) Documents

These are frozen point-in-time records — reports, completion snapshots, self-assessments, and a fully-completed migration guide. They are **not maintained** and must not be read as current-state documentation. Each carries its own status banner with the date it describes and a link back to the canonical document for that topic. All live under [`docs/archive/`](archive/).

| Document | Date | Superseded by |
|----------|------|----------------|
| [AD_MODULE_SUMMARY.md](archive/AD_MODULE_SUMMARY.md) | 2026-03-17 | [modules/ad/README.md](../modules/ad/README.md) |
| [WEB_MODULE_SUMMARY.md](archive/WEB_MODULE_SUMMARY.md) | 2026-03-17 | [modules/web/README.md](../modules/web/README.md) |
| [RECONFORGE_MODULE_REPORT.md](archive/RECONFORGE_MODULE_REPORT.md) | 2026-03-17 | [MODULES.md](MODULES.md) |
| [COMMAND_REFACTORING_REPORT.md](archive/COMMAND_REFACTORING_REPORT.md) | 2026-03-20 | [ARCHITECTURE.md](ARCHITECTURE.md) |
| [PRIORITY_4_COMPLETION_REPORT.md](archive/PRIORITY_4_COMPLETION_REPORT.md) | 2026-03-21 | [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md) |
| [FINAL_STABILIZATION_REPORT.md](archive/FINAL_STABILIZATION_REPORT.md) | 2026-03-21 | [ARCHITECTURE_REVIEW.md](ARCHITECTURE_REVIEW.md) |
| [MIGRATION_CONFIG_SCHEMA.md](archive/MIGRATION_CONFIG_SCHEMA.md) | 2026-03-21 | [CONFIGURATION.md](CONFIGURATION.md) |
| [PHASE_6_QUALITY_REPORT.md](archive/PHASE_6_QUALITY_REPORT.md) | 2026-03-21 | [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md) |
| [PROJECT_SCORECARD.md](archive/PROJECT_SCORECARD.md) | 2026-04 (self-assessed) | [ARCHITECTURE_REVIEW.md](ARCHITECTURE_REVIEW.md) |
| [INDEPENDENT_SECURITY_ASSESSMENT_2026-04-13.md](archive/INDEPENDENT_SECURITY_ASSESSMENT_2026-04-13.md) | 2026-04-13 (self-assessed) | [THREAT_MODEL.md](THREAT_MODEL.md) |
| [HTB_JERRY_CAPABILITY_ASSESSMENT.md](archive/HTB_JERRY_CAPABILITY_ASSESSMENT.md) | 2026-04-13 | — (one-off capability check) |
| [HTB_KNIFE_CAPABILITY_ASSESSMENT.md](archive/HTB_KNIFE_CAPABILITY_ASSESSMENT.md) | 2026-04-13 | — (one-off capability check) |
| [modules/api/HARDENING_CHANGELOG.md](../modules/api/HARDENING_CHANGELOG.md) | 2026-03-20 | [modules/api/README.md](../modules/api/README.md) |

Two documents are **continuously-updated audit logs**, not frozen snapshots, and are kept in `docs/` rather than the archive — but the same rule applies: they record engineering history and are not required reading to understand current behavior, which canonical documents state directly.

| Document | Nature |
|----------|--------|
| [ARCHITECTURE_REVIEW.md](ARCHITECTURE_REVIEW.md) | Running phase-by-phase remediation log. Canonical docs may point here for *why* a fix happened; they must not depend on it to explain *current* behavior. |
| [CLAUDE_MCP_IMPLEMENTATION_PLAN.md](CLAUDE_MCP_IMPLEMENTATION_PLAN.md) | Originally a design plan, now a completed-phase log for the MCP server. Current MCP behavior is documented in [CLAUDE_MCP_INTEGRATION.md](CLAUDE_MCP_INTEGRATION.md), not here. |

---

## Cross-Reference Rules

1. **Do not duplicate detailed explanations.** When a non-canonical document discusses a canonical topic, link to the canonical source instead of restating it.
2. **Canonical sources are authoritative.** If a secondary reference conflicts with the canonical source, the canonical source is correct — file it as a bug.
3. **Archived documents are frozen.** Do not update them to match current state; they record what was true on the date in their banner.
4. **Module READMEs are canonical for module internals.** `docs/MODULES.md` gives the cross-module overview; module-level READMEs own the implementation detail.
