# ReconForge — Documentation Index

> **Navigation guide for all project documentation**
> Last updated: 2026-07-14 · 47 Markdown documents (42 in `docs/`, 5 at project root; this index itself is the 47th)
>
> The 29 tracked PDF exports mentioned in earlier versions of this index have
> been removed from git (Phase 24, 2026-07-14) — untracked binary duplicates
> of Markdown sources that added repo weight with no CI/tooling dependency on
> them; see `CHANGELOG.md`.
>
> Every Markdown file in the repository has an entry below (confirmed via a
> full `find`-based inventory cross-check). Two previously-listed files
> (`AUDIT_REPORT.md`, `STABILIZATION_CHECK_P9.md`) no longer exist and are
> kept as struck-through, explicitly-dead entries rather than silently
> removed — see §4 and §8.

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
| Review the current audit / remediation status | [ARCHITECTURE_REVIEW.md](#architecture_reviewmd) |
| Troubleshoot a problem | [FAQ.md](#faqmd) |
| Follow a step-by-step assessment | [RUNBOOKS.md](#runbooksmd) |
| Know what ReconForge doesn't do | [LIMITATIONS.md](#limitationsmd) |
| Report a security issue | [SECURITY.md](#securitymd) |

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
📍 **Location:** [`docs/USAGE.md`](USAGE.md)
**Status:** ✅ Complete (319 lines)

Full CLI reference for all six subcommands (`network`, `web`, `api`, `surface`, `ad`, `workflow`). Covers common flags (`--target`, `--opsec`, `--phases`, `--dry-run`, `--encrypt-loot`), per-module examples, OPSEC mode behavior, and output interpretation.

---

### WORKFLOW_GUIDE.md
📍 **Location:** [`docs/WORKFLOW_GUIDE.md`](WORKFLOW_GUIDE.md)
**Status:** ✅ Complete (320 lines)

Cross-module workflow orchestration: pipeline definition, `WorkflowContext` data passing, conditional step evaluation, `CredentialVault` sharing, `EngagementManager` lifecycle, and example pipelines (full recon, targeted, stealth).

---

### FAQ.md
📍 **Location:** [`docs/FAQ.md`](FAQ.md)
**Status:** ✅ Complete (506 lines)

Practical Q&A troubleshooting guide organized by topic (installation/setup, tool availability, permissions, encryption). Points to the canonical spec docs (`FINDINGS.md`, `CONFIGURATION.md`, `USAGE.md`, `MODULES.md`, `ARCHITECTURE.md`) for anything beyond quick fixes rather than duplicating them.

---

### RUNBOOKS.md
📍 **Location:** [`docs/RUNBOOKS.md`](RUNBOOKS.md)
**Status:** ✅ Complete (532 lines)

Step-by-step operator runbooks for common assessment scenarios (external web app assessment is Runbook 1), each with prerequisites, exact CLI commands, expected output file listings, and guidance on which findings matter. Cross-references `FINDINGS.md`/`SEVERITY_CRITERIA.md`/`MODULES.md` rather than restating them.

---

### SUPPORT_MATRIX.md
📍 **Location:** [`docs/SUPPORT_MATRIX.md`](SUPPORT_MATRIX.md)
**Status:** ✅ Complete (129 lines)

Compatibility reference: supported Python versions (3.10 minimum), OS/platform support tiers (Kali/Parrot fully tested, macOS/Windows-WSL2 partial, no official Docker image), the (intentionally short) Python dependency list, per-module external tool tables with install commands, root/privileged-operation requirements, and explicitly unsupported environments.

---

## 2. Architecture & Design

### ARCHITECTURE.md
📍 **Location:** [`docs/ARCHITECTURE.md`](ARCHITECTURE.md)
**Status:** ✅ Complete (305 lines)

System-level design: the `tools/ → parsers/ → phases/ → module.py → core/` pipeline, directory structure, core services layer (17 modules), data flow diagrams, security model (no `shell=True`, `validate_arg()`, credential sanitization), and module-specific extensions (Surface `intelligence/`, AD extended pipeline).

---

### MODULES.md
📍 **Location:** [`docs/MODULES.md`](MODULES.md)
**Status:** ✅ Complete (409 lines)

Detailed documentation for all five modules: Network (5 tools, 4 phases), Web (9 tools, 4 phases), API (4 tools, 4 phases), Surface (2 tools, 6 intelligence components, 4 phases), and AD (8 tools, 5 phases with collectors/analyzers/attack paths/reporters). Includes base class signatures, phase lists, and tool inventories.

---

### CONFIGURATION.md
📍 **Location:** [`docs/CONFIGURATION.md`](CONFIGURATION.md)
**Status:** ✅ Complete (290 lines)

`tools.yaml` schema (binary paths, timeouts, scan profiles, safety settings), `profiles.yaml` schema (OPSEC modes, timing, technique toggles, noise-level gates), `ConfigLoader` API, `ToolConfig` typed accessor, and `ProfileLoader` resolution logic. Single source of truth — no env-var overrides.

---

### FINDINGS.md
📍 **Location:** [`docs/FINDINGS.md`](FINDINGS.md)
**Status:** ✅ Complete (208 lines)

The 5-level confidence model (`confirmed` → `heuristic`), 5-level severity scale (`critical` → `info`), automatic severity clamping rules, and `FindingsManager` API. Key concept: heuristic-only detections are auto-capped to `low` severity.

---

### SEVERITY_CRITERIA.md
📍 **Location:** [`docs/SEVERITY_CRITERIA.md`](SEVERITY_CRITERIA.md)
**Status:** ✅ Complete (300 lines)

Detailed evidence requirements for each severity × confidence combination. Defines what constitutes `confirmed` vs. `heuristic` evidence, per-tool classification examples, and the clamping enforcement matrix. Companion to FINDINGS.md.

---

### LIMITATIONS.md
📍 **Location:** [`docs/LIMITATIONS.md`](LIMITATIONS.md)
**Status:** ✅ Complete (422 lines)

Honest account of what ReconForge deliberately does not do: not a full exploitation framework (no post-exploitation, no payload/shell handling — the web module's `exploit_candidates` phase is detection-only and opt-in), not a vulnerability scanner (no CVE database, no authenticated/compliance scanning, no CVSS), and not a replacement for manual testing (no business-logic understanding, no creative vulnerability chaining). Also documents the redirect/DNS-resolution scope-enforcement gap for CLI-tool-wrapping modules (added Phase 5). The project's own "what we don't claim" reference — the mirror image of the module/feature docs.

---

### ARTIFACT_POLICY.md
📍 **Location:** [`docs/ARTIFACT_POLICY.md`](ARTIFACT_POLICY.md)
**Status:** ✅ Complete (54 lines)

Policy for runtime output handling: the `outputs/` tree is git-ignored (only synthetic fixtures live in `tests/fixtures/`), storage separation by environment, retention defaults (30/180/365 days for raw/parsed/final artifacts), sensitive-data handling (`--encrypt-loot`, key file permissions, `RECONFORGE_VAULT_KEY`/`RECONFORGE_LOOT_KEY` out-of-band key supply), and auditability guidance for engagement traceability.

---

### OBSERVABILITY_AND_CONTRACTS.md
📍 **Location:** [`docs/OBSERVABILITY_AND_CONTRACTS.md`](OBSERVABILITY_AND_CONTRACTS.md)
**Status:** ✅ Complete (59 lines)

Documents three related capabilities: per-module observability (`execution_id`, structured JSONL logs, per-phase duration/status metadata, `audit.json`), `ConfigLoader`'s layered environment-aware config resolution (base → environment overlay → secret-placeholder resolution via `RECONFORGE_SECRET_PROVIDER`), and versioned data-contract sidecars (`findings.contract.json`, `loot.contract.json`, `results.contract.json`) that preserve backward compatibility with legacy output files while adding a `schema_version`-tagged strict-consumer format.

---

### AI_ORCHESTRATION_ARCHITECTURE.md
📍 **Location:** [`docs/AI_ORCHESTRATION_ARCHITECTURE.md`](AI_ORCHESTRATION_ARCHITECTURE.md)
**Status:** ✅ Complete (49 lines) — corrected Phase 30 (2026-07-14): this entry previously called the layer "proposed" and pointed to the wrong files as "what's actually implemented" (`reconforge/intelligence/engine.py` and `reconforge/attack_paths/engine.py` — neither is this layer; the first is a separate, honestly-self-labeled "deterministic vulnerability classification and correlation engine" for Burp/HTTP traffic, the second is the HTTP-endpoint attack-path graph). The real implementation is `core/ai_orchestration.py::AIOrchestrationLayer`, which is not proposed — it is imported and called from `core/workflow_orchestrator.py` (instantiated at construction, ingests every module's result, and can dynamically queue an extra module step when its confidence score clears a hardcoded 0.65 threshold).

Diagram + narrative for the layer sitting above `WorkflowOrchestrator`: normalizes findings into a host→service→endpoint graph, scores each signal via a fixed weighted formula (severity 35% + exploit-likelihood 30% + reachability 20% + asset-criticality 15%, scaled by a confidence multiplier), and recommends/queues follow-up modules when a fixed per-recommendation-type confidence literal (e.g. 0.93 for HTTP→web, 0.9 for LDAP/Kerberos/SMB→AD) clears the threshold. **Read this document's own terminology carefully**: "AI Orchestration Layer", "Central Intelligence Engine", and "AI Triage" describe a deterministic, rule-based correlation and scoring engine — fixed keyword-set membership checks, a 4-entry hardcoded banner→CVE lookup table, and literal confidence constants written by hand per recommendation type — not a machine-learning model or an LLM. No language-model call exists anywhere in this codebase (confirmed via repo-wide search, Phase 30). See `docs/ARCHITECTURE_REVIEW.md`'s Phase 30 entry for the full investigation.

---

### CLAUDE_MCP_IMPLEMENTATION_PLAN.md
📍 **Location:** [`docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md`](CLAUDE_MCP_IMPLEMENTATION_PLAN.md)
**Status:** 🚧 Phases 1–5, 8, 10 done (13 tools: 12 read-only + 1 controlled-execution, plus structured error codes and the user-facing setup guide); CI recovery + quality-gate scope widening in v2.11.1; Phases 6, 7, 9, 11–15 not started (updated 2026-07-14)

The design for `reconforge/mcp/`, the package that lets Claude Desktop/Claude Code act as an MCP *client* against a ReconForge-hosted MCP *server* (the reverse relationship from `core/adapters/burp/`, where ReconForge is the MCP client). Covers the trust-boundary diagram, the `trusted_metadata`/`untrusted_evidence` response-shape split, the `SAFE_READ_ONLY → PROHIBITED` execution-tier policy table, the human-approval model, representative request/response schemas, and which existing primitives each planned tool reuses rather than duplicates. `reconforge/mcp/server.py` (Phase 2) builds a real `mcp` SDK `Server`, runnable via `reconforge mcp serve`. `reconforge/mcp/tools.py` + `services.py` + `schemas.py` (Phase 3) register all 12 read-only tools. `reconforge/mcp/sanitization.py` (Phase 4) centralizes untrusted-content handling; every response carries a `trust: "server_generated"` marker; a 26-payload adversarial test suite proves injection payloads stay inert. `reconforge/mcp/policy.py` (Phase 5) implements the tier taxonomy, and `reconforge_execute_approved_phase` (Phase 5) is the one tool that can trigger real execution — independently re-verified engagement/scope/confirmation, CREDENTIAL_USE phases (AD delegation/bloodhound) rejected outright, single process-wide execution lock. A real stdio-corruption bug (`ReconLogger` logging to `sys.stdout` unconditionally, breaking the JSON-RPC stream) was found via a genuine subprocess test — not the in-memory transport every other test in this package uses — and fixed in `server.py`. `tools.py` (Phase 8) now surfaces each error's `code` and, for policy denials, `missing_requirements` as `structuredContent` on the MCP error response, instead of only the SDK's generic plain-text fallback.

---

### CLAUDE_MCP_INTEGRATION.md
📍 **Location:** [`docs/CLAUDE_MCP_INTEGRATION.md`](CLAUDE_MCP_INTEGRATION.md)
**Status:** ✅ Complete (Phase 10, 2026-07-14)

The user-facing setup guide, distinct from the implementation plan above (design rationale) — this one is purely "how do I connect a client." Covers the `mcp` extra install (`pip install -e ".[mcp]"`), Claude Desktop's `claude_desktop_config.json` `mcpServers` block, Claude Code's `claude mcp add`, a condensed security-model summary, a table of all 13 tools, a read-only exploration walkthrough, and a step-by-step walkthrough for authorizing real execution (scope YAML → `reconforge workflow --engagement` → the `reconforge_execute_approved_phase` call itself), plus the two most user-relevant known limitations (no credentialed execution, one execution at a time per server process).

---

## 3. Developer Documentation

### DEVELOPMENT.md
📍 **Location:** [`docs/DEVELOPMENT.md`](DEVELOPMENT.md)
**Status:** ✅ Complete (402 lines)

Project structure overview, step-by-step guides for adding tools/parsers/phases, testing guidelines (pytest, 375 tests), code standards (type hints, docstrings, `list[str]` commands), and the 11-parameter base class constructor contract.

---

### EXTENDING.md
📍 **Location:** [`docs/EXTENDING.md`](EXTENDING.md)
**Status:** ✅ Complete (94 lines)

Concise quick-reference for extending the framework: inheriting from module base classes (`NetworkPhaseBase`, `ADPhaseBase`, `WebPhaseBase`), registering phases in orchestrators, and adding new tool wrappers/parsers. Complements DEVELOPMENT.md.

---

### API_REFERENCE.md
📍 **Location:** [`docs/API_REFERENCE.md`](API_REFERENCE.md)
**Status:** ✅ Complete (620 lines)

Full class/method reference for: `Runner` + `RunResult`, `ConfigLoader`, `ToolConfig`, `ProfileLoader`, `FindingsManager`, `LootManager`, `CredentialVault`, `EngagementManager`, `WorkflowOrchestrator`, `OutputManager`, `NotesManager`, `OpsecChecks`, `Validators`, and all module base classes.

---

### MIGRATION_CONFIG_SCHEMA.md
📍 **Location:** [`docs/MIGRATION_CONFIG_SCHEMA.md`](MIGRATION_CONFIG_SCHEMA.md)
**Status:** ✅ Complete (227 lines)

Migration guide for the `web_tools:` → unified `tools:` namespace consolidation. Before/after YAML examples, `ConfigLoader` changes, and per-file migration checklist. Relevant for anyone working with pre-unification branches.

---

### VERSIONING.md
📍 **Location:** [`docs/VERSIONING.md`](VERSIONING.md)
**Status:** ✅ Complete (139 lines)

Semantic Versioning 2.0.0 policy: what counts as MAJOR (breaking CLI/config/output-schema changes, module removal), MINOR (new modules/tools/phases/features, backward-compatible), and PATCH (bug fixes, parser corrections, doc updates). The policy every phase of the `ARCHITECTURE_REVIEW.md` remediation mandate has bumped the version against — consult this before classifying any change.

---

### INTEGRATION_TESTING.md
📍 **Location:** [`docs/INTEGRATION_TESTING.md`](INTEGRATION_TESTING.md)
**Status:** ✅ Complete (718 lines)

How to validate full CLI flows without live targets or installed tools: mock `Runner.run()` (the single choke point every external command passes through) to return canned `RunResult`s, then assert on phase orchestration, OPSEC enforcement, tool command construction, parser handling, finding generation, loot dedup, and output file structure. Covers what to test, why external tools must never run in CI, and worked examples for full end-to-end module flows.

---

## 4. Audit & Stabilization Reports

### ~~AUDIT_REPORT.md~~ (removed)

This file no longer exists in the repository (confirmed absent as of 2026-07-14) but was still listed here as if current, describing a "6.5/10... architectural drift" audit — that role is now filled by `ARCHITECTURE_REVIEW.md` below, the living document that superseded it. Entry kept, struck through, per the same policy applied to the dead `STABILIZATION_CHECK_P9.md` link further down this section.

---

### ARCHITECTURE_REVIEW.md
📍 **Location:** [`docs/ARCHITECTURE_REVIEW.md`](ARCHITECTURE_REVIEW.md)
**Status:** 🔄 Living document — updated after every remediation phase

The project's primary, currently-maintained audit — and the one actually cross-checked against real command execution (`pytest`, `ruff`, `mypy`, `bandit`) rather than documentation claims. Structure: current architecture, strengths, architectural weaknesses, security risks, duplicated components, misleading/unverified claims, untested assumptions, dead code, incomplete/overstated features, P0 release-blocker summary, and a prioritized P1/P2/P3 remediation checklist — each item tracked to resolution with a dated note explaining what changed and why. §4 ("Status of the phased mandate") is a running phase-by-phase log of every remediation pass from Phase 1 onward, including this one. Supersedes the historical `AUDIT_REPORT.md` (removed) and the self-assessed `PROJECT_SCORECARD.md`/`INDEPENDENT_SECURITY_ASSESSMENT_2026-04-13.md` below as the authoritative account of project quality.

---

### PROJECT_SCORECARD.md
📍 **Location:** [`docs/PROJECT_SCORECARD.md`](PROJECT_SCORECARD.md)
**Status:** ⚠️ Author self-assessment (carries its own disclaimer banner)

A self-scored snapshot (9.5/10, dated April 2026) written by the project author, not an independent reviewer — the file's own banner says so explicitly and points readers to `ARCHITECTURE_REVIEW.md` for a claims-cross-checked-against-code audit instead. Covers strong points (modular architecture, quality gates, observability, contract sidecars, autonomy features), remaining gaps, a stage-by-stage evolution narrative, and recommended next priorities. Treat the score as a maintainer's opinion, not validation.

---

### INDEPENDENT_SECURITY_ASSESSMENT_2026-04-13.md
📍 **Location:** [`docs/INDEPENDENT_SECURITY_ASSESSMENT_2026-04-13.md`](INDEPENDENT_SECURITY_ASSESSMENT_2026-04-13.md)
**Status:** ⚠️ Author self-assessment despite the filename (carries its own disclaimer banner), written in Portuguese

Despite its name, this is also a self-assessment by the project author (with AI assistance), not a third-party review — the file's own banner corrects the title and flags that its "383 tests passing" claim didn't match the real count even at the time it was written (445, per the banner). Self-score: 7.8/10. Covers objective strengths/gaps, a per-business-goal readiness diagnosis (bug bounty vs. professional consulting), and a phased remediation roadmap. Same caveat as `PROJECT_SCORECARD.md`: a maintainer's opinion, cross-check against `ARCHITECTURE_REVIEW.md`.

---

### PRIORITY_4_COMPLETION_REPORT.md
📍 **Location:** [`docs/PRIORITY_4_COMPLETION_REPORT.md`](PRIORITY_4_COMPLETION_REPORT.md)
**Status:** 📜 Historical (carries its own "HISTORICAL DOCUMENT" banner, dated 2026-03-21)

A dated snapshot of the "Priority 4: Documentation Completion" pass — an inventory of every doc file that existed at the time (20 `docs/` Markdown files, 6 module-level READMEs, root-level files), with line counts and one-line purposes for each. Explicitly self-labeled as historical and superseded by this index for current documentation state; several files it lists (`AUDIT_REPORT.md`, `STABILIZATION_CHECK_P9.md`, the three root `STABILIZATION_CHECK_P6/P7/P8.md` files) have since been removed from the repository — expected drift for a document that documents itself as a point-in-time snapshot, not a bug.

---

### HTB_JERRY_CAPABILITY_ASSESSMENT.md
📍 **Location:** [`docs/HTB_JERRY_CAPABILITY_ASSESSMENT.md`](HTB_JERRY_CAPABILITY_ASSESSMENT.md)
**Status:** ✅ Complete (46 lines, written in Portuguese, dated 2026-04-13)

A capability assessment asking a narrow, concrete question: can ReconForge autonomously complete the HTB "Jerry" box end-to-end (Tomcat Manager default-credential login → malicious WAR upload → reverse shell)? Verdict: no — the framework covers enumeration and Tomcat fingerprinting well, but has no Tomcat Manager exploitation playbook, no WAR-deploy automation, and no post-compromise executor (self-scored 6.4/10 for this specific scenario). Useful as a concrete, falsifiable capability boundary rather than an abstract claim.

---

### HTB_KNIFE_CAPABILITY_ASSESSMENT.md
📍 **Location:** [`docs/HTB_KNIFE_CAPABILITY_ASSESSMENT.md`](HTB_KNIFE_CAPABILITY_ASSESSMENT.md)
**Status:** ✅ Complete (46 lines, written in Portuguese, dated 2026-04-13)

Same format as the Jerry assessment above, applied to HTB "Knife" (PHP 8.1.0-dev backdoor RCE via a malformed `User-Agent` header → reverse shell → `sudo knife exec` privilege escalation). Verdict: no autonomous end-to-end capability — no native exploit for the PHP dev-build backdoor and no automated privesc executor for the specific `sudo knife` chain (self-scored 6.1/10 for this scenario).

---

### COMMAND_REFACTORING_REPORT.md
📍 **Location:** [`docs/COMMAND_REFACTORING_REPORT.md`](COMMAND_REFACTORING_REPORT.md)
**Status:** ✅ Complete (467 lines)

Documents the Priority-1 refactoring of all 27 tool wrappers from `f"tool ..."` string commands to `["tool", "--flag", arg]` list commands. Before/after metrics, per-file changelog, and `Runner` deprecation-warning behavior.

---

### FINAL_STABILIZATION_REPORT.md
📍 **Location:** [`docs/FINAL_STABILIZATION_REPORT.md`](FINAL_STABILIZATION_REPORT.md)
**Status:** ✅ Complete (256 lines)

10-point checklist validation confirming framework stability: 375/375 tests passing, no critical blockers, two non-critical issues documented (Surface CLI missing `--encrypt-loot`, minor), and deferred technical debt inventory.

---

### ~~STABILIZATION_CHECK_P9.md~~ (removed)

This file no longer exists in the repository (confirmed absent as of 2026-07-13) but was still listed here as if current. Entry kept, struck through, so the historical Priority-9 `tools.yaml` consumption audit it described isn't silently erased from this index's record.

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

## 6. Burp MCP / Intelligence Engine Guides

These five documents cover the Burp MCP-backed HTTP collection, correlation, and attack-path
generation stack (`reconforge/attack_paths/`, `reconforge/intelligence/`, `reconforge/collectors/`,
`reconforge/normalizers/`, `core/adapters/burp/`) — distinct from the recon-module (`network`/`web`/
`api`/`surface`/`ad`) tool/parser/phase architecture covered in §2-§3 above.

### BURP_MCP_INTEGRATION.md
📍 **Location:** [`docs/BURP_MCP_INTEGRATION.md`](BURP_MCP_INTEGRATION.md)
**Status:** ✅ Complete (133 lines)

The integration architecture reference: `core/adapters/burp/` module layout, the safe/enabled Burp tool subset (`send_http1_request`, `send_http2_request`, `get_proxy_http_history[_regex]`), default-blocked tool categories (config-changing, intercept-toggling, scanner/intruder), `BurpMcpConfig` fields, the `mcp_validation/run_validation.py` connectivity/capability check command, the `NormalizedBurpHttpRecord` normalization boundary, and current limitations (tool argument schemas not yet strongly typed).

---

### attack_path_generation.md
📍 **Location:** [`docs/attack_path_generation.md`](attack_path_generation.md)
**Status:** ✅ Complete (69 lines)

Documents `reconforge/attack_paths/engine.py`: how classified findings become candidate multi-step attack paths, each step replayed live and tagged `unreachable`/`reachable`/`corroborated` (never "confirmed exploitation" — that requires authorized-lab validation per `FINDINGS.md`). Covers the 7 engine phases (graph build → primitive mapping → candidate generation → replay/tagging → scoring → refinement → failure analysis), the `reconforge burp attack-paths` CLI command, and `AttackPathReport`/`AttackPath` output structure.

---

### burp_web_lifecycle.md
📍 **Location:** [`docs/burp_web_lifecycle.md`](burp_web_lifecycle.md)
**Status:** ✅ Complete (44 lines)

The `reconforge burp lifecycle-validate` command: validates baseline-request/replay consistency, controlled mutation execution, response classification, session continuity, and gap analysis through a single structured `LifecycleReport` — no raw MCP payloads forwarded, all request-capable actions go through Burp provider methods with upstream scope enforcement.

---

### http_collection.md
📍 **Location:** [`docs/http_collection.md`](http_collection.md)
**Status:** ✅ Complete (77 lines)

The `HttpCollector`/`HttpObservationNormalizer` pipeline that turns Burp provider outputs into a stable, provider-agnostic `HTTPObservation` schema (request/response fields, `evidence_id`, `source_tool`/`source_provider`). Covers the two collection flows (single-request, proxy-history), evidence-ID traceability, the `summarize()` aggregate stats helper, and how to extend the normalizer to a non-Burp provider. Documents a real current limitation: response bodies are stored as base64-prefixed text, not decoded structured data.

---

### vulnerability_intelligence.md
📍 **Location:** [`docs/vulnerability_intelligence.md`](vulnerability_intelligence.md)
**Status:** ✅ Complete (69 lines)

The `reconforge burp intelligence-validate` engine: converts mutated-HTTP behavior into `MutationIntelligence`/`VulnerabilityClassification`/`ParameterProfile`/`CorrelationRelationship`/`PrioritizedFinding` models via deterministic, evidence-backed rules (`IDOR_candidate`, `auth_bypass_candidate`, `reflection_detected`, `enumeration_vector` — explicitly no AI-based tagging). The validation loop runs baseline vs. correlation-enabled passes and flags improvement when correlation yields more or higher-scored findings.

---

## 7. Root-Level Project Files (outside `docs/`)

### AGENTS.md
📍 **Location:** [`../AGENTS.md`](../AGENTS.md)
**Status:** ✅ Complete (339 lines)

The agent operating contract governing this repository's own phased remediation mandate: project mission, core architecture principles (single orchestration authority, adapter-only integrations, policy-first execution, deterministic-by-default behavior, "evidence over narration"), non-negotiable rules, trust boundaries, execution/scope-enforcement rules, coding/architecture/logging/testing/documentation standards, anti-patterns, and the Definition of Done every phase in `ARCHITECTURE_REVIEW.md` §4 is held to.

---

### CHANGELOG.md
📍 **Location:** [`../CHANGELOG.md`](../CHANGELOG.md)
**Status:** 🔄 Living document — updated every release

[Keep a Changelog](https://keepachangelog.com/en/1.1.0/)-formatted release history, one entry per version bump, each classified MAJOR/MINOR/PATCH per `VERSIONING.md`'s policy. Since the Phase 1 remediation mandate began, effectively every phase closes with a version bump and a CHANGELOG entry describing what was fixed/added/documented and why — the terse counterpart to `ARCHITECTURE_REVIEW.md` §4's fuller narrative for the same history.

---

### CONTRIBUTING.md
📍 **Location:** [`../CONTRIBUTING.md`](../CONTRIBUTING.md)
**Status:** ✅ Complete (169 lines)

Contributor guidelines: branch naming (`<type>/<short-description>`), Conventional Commits style, test expectations per change type (new tool wrapper/parser/phase/core component, bug fix), documentation-update expectations, code review checklist (no `shell=True`, `list[str]` commands only, input validation, correct confidence/severity, no secrets), merge policy (squash-merge, ≥1 approval, green CI), and the process for proposing new tools/phases/modules.

---

### SECURITY.md
📍 **Location:** [`../SECURITY.md`](../SECURITY.md)
**Status:** ✅ Complete (42 lines)

Security policy: scope is ReconForge's own code (not the third-party tools it wraps), only the latest `main` release is supported, vulnerabilities should be reported via GitHub's private security-advisory feature rather than a public issue, and a reminder that ReconForge is for authorized testing only — findings *produced by* ReconForge follow the target engagement's own disclosure process, not this repository's.

---

## 8. Root-Level Stabilization Checks (outside `docs/`)

`STABILIZATION_CHECK_P6.md`/`P7.md`/`P8.md` (project root) and
`STABILIZATION_CHECK_P9.md` (`docs/`) were previously listed here but no
longer exist in the repository — removed at some earlier cleanup point
without this index being updated. Confirmed absent as of 2026-07-13.

---

## File Format Summary

| Format | Count | Purpose |
|--------|------:|---------|
| Markdown (`.md`) | 47 (42 in `docs/`, 5 at project root) | Primary documentation (version-controlled). All 46 non-index files have an entry below (this file is the 47th, indexing the others) |
| PDF (`.pdf`) | 0 | Removed from git in Phase 24 (2026-07-14) — were untracked binary duplicates of the Markdown sources above, with no CI or tooling dependency on them |

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

*This index is manually maintained, not auto-generated — it previously claimed otherwise while carrying a 4-month-old snapshot with dead links to deleted files (fixed 2026-07-13) and ~20 real files with no entry at all (fixed 2026-07-14). When adding new documentation, add an entry here — the "Known gap" disclaimer this file carried between those two dates is exactly what happens when that doesn't happen.*
