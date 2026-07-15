# ReconForge

[![Quality Gates](https://github.com/andrewsferreira/reconforge/actions/workflows/quality-gates.yml/badge.svg)](https://github.com/andrewsferreira/reconforge/actions/workflows/quality-gates.yml)
[![Coverage](https://img.shields.io/badge/coverage-70%25%20floor-yellow.svg)](#testing--quality-gates)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**A modular reconnaissance framework for authorized penetration testing, with a human-gated MCP server for LLM-directed workflows.**

ReconForge treats reconnaissance output as evidence, not conclusions — every finding carries a confidence level, and severity never exceeds what's actually been verified. When an LLM client drives the workflow, execution still requires a human operator's approval, given entirely outside the LLM's own request. This is a framework, not a wrapper around a single scanner.

> **Authorization required.** ReconForge executes real reconnaissance tooling against real targets. Only run it against systems you own or are explicitly authorized to test. See [Execution Model](#execution-model).

## Highlights

- **Evidence-driven findings** — severity structurally clamped to confidence; a heuristic match cannot present as `critical`
- **Human-in-the-loop execution** — an LLM can request a run, never approve one
- **Secure-by-construction execution** — zero `shell=True`; every subprocess call is a validated `list[str]`
- **Modular architecture** — five independent recon modules, one orchestrator, one confidence model
- **Native MCP integration** — 18 schema-driven tools, an execution-tier policy engine, out-of-band approval
- **CI-enforced quality gates** — Ruff, MyPy (232 files), Bandit, pip-audit, 1192 tests, every push

## Architecture

```
Target + Scope
      ↓
Authorization Gate
      ↓
Recon Module   (tools → parsers → phases)
      ↓
Evidence       (confidence-clamped findings)
      ↓
Reports
```

Every module shares one core:

- `runner.py` — secure subprocess execution
- `findings_manager.py` — confidence model, severity clamping
- `ai_orchestration.py` — deterministic cross-module correlation engine
- `workflow_orchestrator.py` — conditional multi-module pipeline
- `credential_vault.py` / `loot_manager.py` — centralized, deduplicated, optionally encrypted
- `engagement.py` — full lifecycle: planning → active → paused → completed

## Modules

| Module | Target | Tools | Phases |
|--------|--------|-------|--------|
| **Network** | IPs, CIDRs, hostnames | nmap, enum4linux, smbclient, ldapsearch, hydra | host_discovery, port_scanning, service_enumeration, authentication_checks |
| **Web** | URLs | whatweb, wafw00f, nikto, gobuster, ffuf, wpscan, nuclei, sqlmap, curl | surface_discovery, content_enumeration, vulnerability_scanning, exploit_candidates |
| **API** | API endpoints | httpx, arjun, ffuf, nuclei | discovery, authentication, fuzzing, authorization |
| **Surface** | IPs, hostnames | nmap (stealth), service_detector | port_discovery, service_fingerprint, vector_correlation, prioritization |
| **AD** | Domain controllers | nmap, enum4linux-ng, Impacket, ldapsearch, smbclient, BloodHound, NetExec | passive_recon, identity_enumeration, configuration_enumeration, delegation_discovery, bloodhound_collection |
| **Workflow** | Any target | All modules | Conditional multi-module pipeline |

None of the tools above ship with ReconForge. Only `nmap` is required for network/AD targets — everything else is optional and gracefully skipped if missing. See [SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md).

## Evidence Model

Confidence scale: `confirmed → high → medium → low → heuristic`. Severity is capped by confidence — a heuristic match can never present as `critical`.

- **Heuristic**: a mutated request to a numeric-ID endpoint returns HTTP 200 with a body that differs from baseline. Logged as `IDOR_candidate`, low/medium confidence — evidence worth checking, not proof.
- **Confirmed**: a human or a dedicated validation step reproduces unauthorized access to another user's identifiable data.

Full rule set and severity-clamping table: [FINDINGS.md](docs/FINDINGS.md).

## Execution Model

- Every active run requires an explicit acknowledgement: `--authorized-target`, `--lab-mode`, or `--enforce-scope` with a `--scope-file`. Omit all three and ReconForge refuses to run.
- `--enforce-scope` checks an explicit allowlist on every command, not just at startup, and propagates to targets discovered mid-run. Matching is exact-string only today — see [ARCHITECTURE_REVIEW.md](docs/ARCHITECTURE_REVIEW.md) for that and other tracked gaps.
- `--dry-run` prints the exact commands ReconForge would run without executing them.
- Intrusive phases (exploit candidates, brute force) require explicit opt-in flags; never run by default.

| OPSEC Mode | Noise | Behavior |
|---|---|---|
| `stealth` | low | Passive techniques, limited ports |
| `normal` | low, medium | Standard engagements |
| `aggressive` | low – very_high | CTF / lab environments |

## Quick Start

```bash
pip install -e ".[dev]"

reconforge network --target 10.10.10.1 --dry-run -v          # no auth flag needed
reconforge network --target 10.10.10.1 --authorized-target   # live run
reconforge workflow --target 10.10.10.1 --auto-handoff --authorized-target
```

`ad`, `web`, `api`, `surface` follow the same shape. Full CLI reference: [USAGE.md](docs/USAGE.md).

## Local Validation Lab

A first-party, pure-stdlib target at [`lab/vulnerable_app.py`](lab/vulnerable_app.py) — no third-party dependencies, loopback-only, deterministic:

```bash
python3 lab/vulnerable_app.py
reconforge web --target http://127.0.0.1:8008 --phases surface,content -v --lab-mode
```

Serves known weaknesses (missing security headers, a reflected query parameter, enumerable admin paths) for the `web`/`api` modules to detect.

## Screenshots

*Not yet captured.*

| Placeholder | Shows |
|---|---|
| `docs/media/terminal-execution.png` | `--dry-run` command construction |
| `docs/media/report-output.png` | Rendered executive report |
| `docs/media/workflow-run.png` | `--auto-handoff` end-to-end run |
| `docs/media/architecture.png` | Module → core → MCP data flow |

## MCP Integration

`reconforge mcp serve` exposes 13 read-only tools and 5 execution tools to an MCP client (Claude Desktop, Claude Code) over stdio — including `reconforge_recommend_next_steps`, a deterministic recommendation of which module hasn't been assessed yet and which findings to prioritize.

Execution never happens on the LLM's say-so:

```
Claude requests execution
      ↓
Policy Engine       (SAFE_READ_ONLY → PROHIBITED tier classification)
      ↓
Pending approval     (awaiting_operator_approval, disk-backed)
      ↓
Human operator approves   (separate CLI process, out-of-band)
      ↓
Execution            (single-use, hash-verified against the approved request)
```

No field in the LLM's own request substitutes for that step. Full model: [CLAUDE_MCP_INTEGRATION.md](docs/CLAUDE_MCP_INTEGRATION.md#security-model-summary), [THREAT_MODEL.md](docs/THREAT_MODEL.md).

```bash
pip install -e ".[mcp]"
reconforge mcp serve
```

## Reporting

```
outputs/<target>/<module>/
├── findings.json / findings.md
├── loot.json
├── session.md
├── commands.log
├── attack_paths.md
└── quick_report.md
```

## Testing & Quality Gates

```bash
python -m pytest   # 1192 tests, ~23s
```

CI (`.github/workflows/quality-gates.yml`) runs on every push: Ruff, MyPy (232 files, zero errors), Bandit, pip-audit, pytest with a 70% coverage floor, and a packaging smoke test. Tests run against mocked tool execution and stored fixtures, not real binaries — see [LIMITATIONS.md](docs/LIMITATIONS.md) for what has and has not been validated against live tools.

## Project Structure

```
reconforge/
├── reconforge/mcp/       # MCP server: 18 tools, schema-driven, approval state machine
├── core/                 # shared services: execution, findings, credentials, orchestration
├── modules/{network,web,api,surface,ad}/
└── tests/                # 1192 tests
```

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, data flow, core services, security model |
| [MODULES.md](docs/MODULES.md) | All 5 modules: tools, parsers, phases |
| [FINDINGS.md](docs/FINDINGS.md) | Confidence model, severity clamping |
| [USAGE.md](docs/USAGE.md) | CLI reference, OPSEC modes |
| [CLAUDE_MCP_INTEGRATION.md](docs/CLAUDE_MCP_INTEGRATION.md) | MCP setup, security model, tool reference |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, trust boundaries, mitigations |
| [DEVELOPMENT.md](docs/DEVELOPMENT.md) | Adding tools/parsers/phases, code standards |
| [LIMITATIONS.md](docs/LIMITATIONS.md) | Current gaps, tracked honestly |

Full index: [docs/DOCUMENTATION_INDEX.md](docs/DOCUMENTATION_INDEX.md).

## Security Model

External tools ReconForge shells out to (nmap, nuclei, sqlmap, etc.) retain their own licenses and are not distributed with this project. Full threat model: [THREAT_MODEL.md](docs/THREAT_MODEL.md). Responsible disclosure: [SECURITY.md](SECURITY.md).

## Limitations

Reconnaissance and evidence-normalization, not an exploitation platform, not a fully autonomous pentest, and not a stealth tool by default. Full list: [LIMITATIONS.md](docs/LIMITATIONS.md). Prioritized remediation plan: [ARCHITECTURE_REVIEW.md](docs/ARCHITECTURE_REVIEW.md).

## License

[Apache License 2.0](LICENSE). Third-party tools ReconForge shells out to are governed by their own licenses.
