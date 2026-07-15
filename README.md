# ReconForge

[![Quality Gates](https://github.com/andrewsferreira/reconforge/actions/workflows/quality-gates.yml/badge.svg)](https://github.com/andrewsferreira/reconforge/actions/workflows/quality-gates.yml)
[![Coverage](https://img.shields.io/badge/coverage-70%25%20floor-yellow.svg)](#testing--quality-gates)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**A reconnaissance platform for authorized penetration testing, built on evidence modeling and policy-gated execution.**

ReconForge normalizes reconnaissance output into confidence-scored evidence instead of raw scanner noise, and treats execution as something to be authorized, not assumed — including when an LLM client is the one asking. Every module shares one orchestration core, and every command that runs is auditable before and after it executes.

> **Authorization required.** ReconForge executes real reconnaissance tooling against real targets. Only run it against systems you own or are explicitly authorized to test. See [Execution Model](#execution-model).

## Highlights

- **Human approval outside the LLM trust boundary** — an MCP client can request execution, never approve it
- **Evidence-first findings** — severity structurally clamped to confidence
- **Secure subprocess execution** — no `shell=True`, every argument validated
- **Modular orchestration** — independent recon modules behind one shared core
- **Schema-driven MCP interface** — typed, validated requests and responses
- **CI-enforced engineering quality** — lint, types, security scan, and tests on every push

## Architecture

```
Target + Scope
      ↓
Authorization Gate
      ↓
Recon Module
      ↓
Evidence
      ↓
Reports
```

Each module follows the same shape — tool adapters, parsers, and phases feeding one shared confidence model — while a single orchestration core handles cross-module correlation and conditional sequencing. Detail: [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Modules

| Module | Target | Capability |
|--------|--------|------------|
| **Network** | IPs, CIDRs, hostnames | Host and service discovery, authenticated checks |
| **Web** | URLs | Content enumeration, vulnerability scanning |
| **API** | Endpoints | Discovery, authentication and authorization testing |
| **Surface** | IPs, hostnames | Passive mapping, attack-vector correlation |
| **AD** | Domain controllers | Identity and delegation enumeration, BloodHound collection |
| **Workflow** | Any target | Conditional multi-module orchestration |

Modules wrap external tools you install yourself — full inventory and install commands in [SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md).

## Evidence Model

Confidence: `confirmed → high → medium → low → heuristic`. Severity is capped by confidence — a heuristic match can never present as `critical`.

- **Heuristic**: a mutated request to a numeric-ID endpoint returns a body that differs from baseline — evidence worth checking, not proof.
- **Confirmed**: a human or a dedicated validation step reproduces unauthorized access to identifiable data.

Full rule set: [FINDINGS.md](docs/FINDINGS.md).

## Execution Model

- Every run requires an explicit acknowledgement — `--authorized-target`, `--lab-mode`, or `--enforce-scope` with a scope file. Omit all three and ReconForge refuses to run.
- `--enforce-scope` validates against an allowlist on every command, not just at startup, including targets discovered mid-run.
- `--dry-run` prints the exact commands without executing them.
- Intrusive phases are opt-in and never run by default.

| OPSEC Mode | Behavior |
|---|---|
| `stealth` | Passive techniques, limited ports |
| `normal` | Standard engagement pace |
| `aggressive` | Full coverage for CTF/lab environments |

## MCP Integration

`reconforge mcp serve` exposes 18 schema-driven tools to an MCP client (Claude Desktop, Claude Code) over stdio. The LLM sits outside the execution trust boundary — it can request a run, never authorize one:

```
Claude requests execution
      ↓
Policy Engine        (execution-tier classification)
      ↓
Pending approval      (disk-backed, awaiting operator)
      ↓
Human operator approves    (separate process, out-of-band)
      ↓
Execution             (single-use, hash-verified)
```

No field in the request substitutes for that approval step. Full model: [CLAUDE_MCP_INTEGRATION.md](docs/CLAUDE_MCP_INTEGRATION.md#security-model-summary), [THREAT_MODEL.md](docs/THREAT_MODEL.md).

```bash
pip install -e ".[mcp]"
reconforge mcp serve
```

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

## Reporting

```
outputs/<target>/<module>/
├── findings.json / findings.md
├── loot.json
├── session.md
├── commands.log
└── quick_report.md
```

## Testing & Quality Gates

```bash
python -m pytest
```

CI (`.github/workflows/quality-gates.yml`) runs Ruff, MyPy, Bandit, and pip-audit on every push, gated by 1192 tests and a 70% coverage floor across the full 232-file package tree. Tests run against mocked tool execution, not real binaries — see [LIMITATIONS.md](docs/LIMITATIONS.md).

## Project Structure

```
reconforge/
├── reconforge/mcp/       # MCP server: schema-driven tools, approval state machine
├── core/                 # shared services: execution, findings, orchestration
├── modules/{network,web,api,surface,ad}/
└── tests/
```

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, data flow, security model |
| [FINDINGS.md](docs/FINDINGS.md) | Confidence model, severity clamping |
| [USAGE.md](docs/USAGE.md) | CLI reference, OPSEC modes |
| [CLAUDE_MCP_INTEGRATION.md](docs/CLAUDE_MCP_INTEGRATION.md) | MCP setup, security model, tool reference |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, trust boundaries, mitigations |
| [LIMITATIONS.md](docs/LIMITATIONS.md) | Current gaps, tracked honestly |

Full index: [docs/DOCUMENTATION_INDEX.md](docs/DOCUMENTATION_INDEX.md).

## Security Model

External tools ReconForge shells out to retain their own licenses and are not distributed with this project. Full threat model: [THREAT_MODEL.md](docs/THREAT_MODEL.md). Responsible disclosure: [SECURITY.md](SECURITY.md).

## Limitations

Reconnaissance and evidence normalization — not an exploitation platform, not autonomous, not a stealth tool by default. Full list and remediation plan: [LIMITATIONS.md](docs/LIMITATIONS.md), [ARCHITECTURE_REVIEW.md](docs/ARCHITECTURE_REVIEW.md).

## License

[Apache License 2.0](LICENSE). Third-party tools ReconForge shells out to are governed by their own licenses.
