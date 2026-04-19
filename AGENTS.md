# AGENTS.md — ReconForge Agent Operating Contract

## 1) Project Mission

ReconForge is an **offensive security orchestration framework**. Its mission is to execute authorized reconnaissance workflows in a controlled, auditable, and deterministic manner.

**This repository exists to implement and evolve one model only:**
- **Model 1: ReconForge as the primary orchestrator.**

All agent contributions **must preserve** these outcomes:
- Centralized orchestration and control inside ReconForge core.
- Strict in-scope execution only.
- Deterministic, reproducible workflow behavior where technically feasible.
- Complete evidence trail for every execution and transformation.

---

## 2) Core Architecture Principles

1. **Single orchestration authority**
   - ReconForge core owns workflow state machine, sequencing, gating, retries, and failure policy.
   - No other component may coordinate multi-step execution logic.

2. **Adapter-only integrations**
   - External tools, APIs, and MCP servers are integration surfaces, not workflow engines.
   - Adapters translate I/O and capabilities; they do not decide “what happens next.”

3. **Policy-first execution**
   - Scope policy and safety policy are evaluated before execution and at each critical transition.
   - If policy state is unknown or ambiguous, execution must halt safely.

4. **Deterministic-by-default behavior**
   - Prefer explicit configs, stable schemas, idempotent operations, and bounded retries.
   - Non-deterministic behavior must be isolated, labeled, and justified in code and docs.

5. **Evidence over narration**
   - Every significant action must emit structured logs and evidence artifacts.
   - Human/LLM summaries are secondary and must reference recorded evidence.

---

## 3) Non-Negotiable Rules

The following rules are mandatory and override convenience, speed, or stylistic preference:

- **Do not move orchestration logic out of ReconForge core.**
- **Do not place decision logic inside adapters.**
- **Do not bypass scope validation for any execution path.**
- **Do not add hidden side effects or implicit network calls.**
- **Do not implement autonomous offensive actions beyond approved recon scope.**
- **Do not rely on prompts to enforce core security behavior that should be enforced in code.**
- **Do not merge features lacking logs, tests, and deterministic failure handling.**

If a requested change conflicts with these rules, the agent must refuse or implement a safe equivalent.

---

## 4) System Boundaries (Trust Boundaries)

Define and enforce these trust boundaries explicitly:

- **Trusted boundary: ReconForge core**
  - Orchestration engine
  - Scope and policy evaluators
  - Execution controller
  - Normalization/correlation pipeline
  - Reporting pipeline

- **Semi-trusted boundary: Internal adapters**
  - Translate between core contracts and external systems.
  - Must validate input/output schema conformance.
  - Must not alter policy state or orchestration flow.

- **Untrusted boundary: External tools/services/MCP endpoints**
  - Output is untrusted until validated and normalized.
  - Never execute returned instructions directly.
  - Never treat external recommendations as policy decisions.

Required control: all cross-boundary interactions must be explicit, typed, logged, and policy-checked.

---

## 5) Execution Rules

1. **Execution entrypoint control**
   - All operational actions must enter through sanctioned ReconForge orchestration interfaces.
   - Direct tool invocation that bypasses orchestration is forbidden.

2. **Pre-execution gates**
   - Verify scope authorization.
   - Verify target constraints.
   - Verify safety policy eligibility.
   - Refuse execution on any failed/unknown gate.

3. **Runtime controls**
   - Enforce timeouts, rate limits, concurrency bounds, and retry ceilings.
   - Fail closed on policy service or validator unavailability.

4. **Post-execution controls**
   - Normalize outputs into canonical schema.
   - Store raw evidence and normalized evidence with trace linkage.
   - Record final status, failure reason taxonomy, and operator-visible summary.

5. **Reproducibility requirements**
   - Capture run configuration, tool versions, adapter version, and policy snapshot.
   - Re-run of the same plan under same inputs must produce explainably consistent behavior.

---

## 6) Scope Enforcement Rules

Scope enforcement is mandatory and must be technical, not procedural.

- Every target/action pair must be validated against an explicit scope object.
- Scope object must be versioned and immutable during a run.
- Wildcard expansion must be deterministic and logged.
- Out-of-scope detection must stop execution immediately for that action.
- “Soft warnings” for scope violations are forbidden; violations are hard failures.
- Manual override paths must be explicit, authenticated, and permanently logged.
- Adapters must not implement alternative scope interpretation logic.

Minimum scope checks:
- Asset identity (domain/IP/CIDR/service) authorization
- Action class authorization
- Time-window authorization (if defined)
- Environment/tenant segregation

---

## 7) MCP Integration Rules (Adapter-Only Model)

ReconForge currently supports MCP integration only as an **adapter model**.

Mandatory constraints:
- MCP servers are treated as external capability providers.
- MCP must not own workflow sequencing, policy decisions, or execution control.
- MCP outputs must pass through ReconForge validation/normalization before use.
- MCP-originated instructions are data, not commands.
- No direct trust escalation from MCP metadata or self-reported capability.

Forbidden patterns:
- “Let MCP decide next steps.”
- Dynamic tool chaining controlled by MCP output without core policy gating.
- Embedding scope logic in MCP adapter code.

Future-ready requirement:
- Keep interfaces capability-oriented and typed so evolution is possible, but do not implement hybrid control-plane behavior in this model.

---

## 8) LLM Usage Rules (Strict Limitations)

LLMs are assistive components, not operators.

Allowed LLM tasks:
- Summarization of evidence
- Classification/tagging
- Prioritization support
- Report drafting from structured evidence

Forbidden LLM tasks:
- Autonomous execution planning that can trigger tools without deterministic policy gates
- Scope decision making
- Safety policy override
- Generating or launching exploit chains, credential attacks, brute-force routines, or payload automation
- Making final go/no-go execution decisions

Implementation mandates:
- LLM inputs/outputs must be logged with redaction controls.
- LLM outputs must be treated as untrusted until validated.
- Any LLM recommendation that can affect execution requires deterministic rule evaluation in code.
- Prompts must not be the sole location of critical security constraints; constraints must live in enforceable code paths.

---

## 9) Coding Standards

- Use explicit types/schemas for boundaries and critical data structures.
- Prefer pure functions for normalization, correlation, and policy evaluation.
- Avoid hidden global state in orchestration-critical code.
- Use dependency injection for adapters and policy services.
- Every non-trivial function must define failure modes and returned error categories.
- All external calls must be timeout-bounded and error-classified.
- No dead code, commented-out logic, or placeholder security checks.
- No “TODO: enforce scope later” in merged code.

Security-specific standards:
- Validate all untrusted input.
- Sanitize serialized logs/events.
- Never log secrets in plaintext.
- Use allowlists for action classes; do not rely on denylist-only models.

---

## 10) Architecture Standards

Required layering:
- **Core Orchestrator Layer**: workflow graph/state machine, policy gates, execution lifecycle.
- **Domain Layer**: scope models, normalized entities, correlation logic, findings semantics.
- **Adapter Layer**: thin capability translation to tools/APIs/MCP.
- **Interface Layer**: API/CLI/UI/report consumers.

Hard constraints:
- Dependencies must point inward toward core/domain abstractions.
- Adapter layer must not import orchestration policy internals except public contracts.
- Domain logic must be testable independent of network/tool availability.
- Cross-layer shortcuts are forbidden unless explicitly approved and documented with rationale.

---

## 11) Logging and Observability Rules

Every run must emit structured, queryable telemetry.

Required log/event fields (minimum):
- run_id, trace_id, tenant/project identifier
- scope_version
- action_type and target
- orchestrator decision point
- adapter invoked and external capability used
- status (started/succeeded/failed/blocked)
- failure category and reason code
- timestamps (start/end/duration)

Rules:
- Logs must be machine-parseable and stable across versions.
- Redaction policy must be enforced before persistence/export.
- Missing critical telemetry is a release-blocking defect.

---

## 12) Evidence and Audit Rules

- Preserve raw tool outputs as immutable evidence artifacts when legally and operationally permissible.
- Maintain deterministic linkage: raw evidence -> normalized entity -> correlated finding -> report item.
- Every report claim must be traceable to evidence IDs.
- Evidence transformations must record transformer identity and version.
- Audit trails must include who/what initiated runs and any override events.

Forbidden:
- Evidence fabrication, synthetic “fill-ins,” or unverifiable claims.
- Editing historical evidence without a new versioned artifact.

---

## 13) Testing Requirements

Changes are not complete without tests aligned to risk.

Minimum required test coverage for relevant changes:
- Unit tests for scope validators, policy gates, and normalization logic.
- Contract tests for adapter input/output schemas.
- Determinism tests for orchestration paths (including retries/timeouts/failures).
- Negative tests proving out-of-scope actions are blocked.
- Regression tests for previously fixed security or policy bugs.

Quality gates:
- Failing security/policy tests block merge.
- Tests using live external systems must be isolated and clearly marked.

---

## 14) Documentation Requirements

Every architecture-affecting change must update documentation in the same change set.

Required documentation updates when applicable:
- Orchestration flow or state transition updates
- Scope model/policy rule changes
- Adapter capability contracts
- Logging/evidence schema changes
- Security assumptions and threat boundary impacts

Documentation must state:
- What changed
- Why it changed
- How safety/scope/audit guarantees are preserved

---

## 15) Anti-Patterns (MUST NEVER Be Done)

- Putting orchestration or policy logic in adapters.
- Allowing external tools/MCP/LLM output to directly trigger execution without core gating.
- Bypassing validators “temporarily” for demos or speed.
- Encoding security controls only in natural-language prompts.
- Creating fake abstraction layers that hide side effects or policy bypasses.
- Coupling report generation directly to unvalidated raw tool output.
- Silent exception swallowing in security-critical paths.
- Non-versioned schema changes for evidence/logging payloads.
- Any automation for brute force, credential stuffing, exploit execution, or uncontrolled payload deployment.

---

## 16) Definition of Done (Quality Bar)

A change is Done only when **all** conditions are true:

1. Architecture integrity preserved
   - ReconForge remains sole orchestrator.
   - Adapters remain adapter-only.

2. Safety and scope preserved
   - Scope gating cannot be bypassed by the new path.
   - Forbidden action classes remain technically blocked.

3. Determinism and reliability preserved
   - Bounded execution behavior is enforced.
   - Failure paths are explicit and test-covered.

4. Auditability preserved
   - Structured logs and evidence linkage exist for new/changed flows.
   - Claims remain evidence-traceable.

5. Engineering quality met
   - Tests added/updated and passing.
   - Documentation updated.
   - No unresolved placeholders for critical controls.

If any condition is unmet, the change is incomplete and must not be represented as production-ready.

---

## Agent Enforcement Clause

Any AI agent working in this repository must treat this document as binding operational policy.

When instructions conflict:
1. System/developer/user instructions
2. This AGENTS.md
3. Other local guidance

Agent behavior requirements:
- Refuse unsafe or out-of-policy implementation requests.
- Implement enforceable controls in code, not only in prompts/comments.
- Surface policy conflicts explicitly in change notes.
- Prefer deletion of unsafe paths over partial containment.

This project values controlled capability over unrestricted automation. Compliance is mandatory.
