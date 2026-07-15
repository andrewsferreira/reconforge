# ReconForge — Documentation Index

Start here. This page routes by intent; the full canonical-source table (which document owns which topic) lives in [DOCUMENTATION_MAP.md](DOCUMENTATION_MAP.md).

| I want to… | Go to |
|---|---|
| Understand what ReconForge is | [README.md](../README.md) |
| Install it | [SETUP.md](SETUP.md) |
| Run a safe local demo | [README.md § Local Validation Lab](../README.md#local-validation-lab) |
| Understand the architecture | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Use a specific module | [MODULES.md](MODULES.md), or the module's own README under `modules/<name>/` |
| Configure tools, profiles, or the MCP server | [CONFIGURATION.md](CONFIGURATION.md) |
| Create or run a multi-module workflow | [WORKFLOW_GUIDE.md](WORKFLOW_GUIDE.md) |
| Understand findings, confidence, and severity | [FINDINGS.md](FINDINGS.md), [SEVERITY_CRITERIA.md](SEVERITY_CRITERIA.md) |
| Connect an MCP client (Claude Desktop/Code) | [CLAUDE_MCP_INTEGRATION.md](CLAUDE_MCP_INTEGRATION.md) |
| Understand the threat model and security boundaries | [THREAT_MODEL.md](THREAT_MODEL.md) |
| Contribute or extend the framework | [DEVELOPMENT.md](DEVELOPMENT.md), [EXTENDING.md](EXTENDING.md), [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Look up a class or method | [API_REFERENCE.md](API_REFERENCE.md) |
| Understand current limitations and known gaps | [LIMITATIONS.md](LIMITATIONS.md) |
| Follow a step-by-step assessment scenario | [RUNBOOKS.md](RUNBOOKS.md) |
| Troubleshoot a problem | [FAQ.md](FAQ.md) |
| Report a security issue in ReconForge itself | [SECURITY.md](../SECURITY.md) |

## Reference documents

Topic-specific references not covered above: [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) (platform/tool compatibility), [TERMINOLOGY.md](TERMINOLOGY.md) (naming conventions), [ARTIFACT_POLICY.md](ARTIFACT_POLICY.md) (output/artifact retention), [OBSERVABILITY_AND_CONTRACTS.md](OBSERVABILITY_AND_CONTRACTS.md) (audit events, data contracts), [VERSIONING.md](VERSIONING.md) (semver policy), [INTEGRATION_TESTING.md](INTEGRATION_TESTING.md) (mocked-tool test methodology), [AI_ORCHESTRATION_ARCHITECTURE.md](AI_ORCHESTRATION_ARCHITECTURE.md) (the deterministic cross-module decision engine), [BURP_MCP_INTEGRATION.md](BURP_MCP_INTEGRATION.md) and its adjacent pipeline docs (`burp_validation.md`, `burp_web_lifecycle.md`, `http_collection.md`, `attack_path_generation.md`, `vulnerability_intelligence.md`).

## Canonical sources and engineering history

- **[DOCUMENTATION_MAP.md](DOCUMENTATION_MAP.md)** — which document is authoritative for each topic, and the full list of archived historical documents.
- **[ARCHITECTURE_REVIEW.md](ARCHITECTURE_REVIEW.md)** — the running, phase-by-phase engineering audit log. Useful for *why* a design decision was made; canonical docs above are the source for *current* behavior.
- **[docs/archive/](archive/)** — frozen, dated snapshot reports (build summaries, completion reports, self-assessments). Not maintained; each carries a banner pointing to its current replacement.

## Internal, not user-facing

**[AGENTS.md](../AGENTS.md)** is an operating contract for AI coding agents working in this repository — not end-user or operator documentation.
