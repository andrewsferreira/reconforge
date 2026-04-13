# ReconForge

**Modular Pentest Reconnaissance Framework**

> Author: Andrews Ferreira • Version 1.0 • 348/348 tests passing

ReconForge automates the reconnaissance phase of penetration tests through five specialized modules and a cross-module workflow orchestrator. All commands are executed securely as `list[str]` via `subprocess.run` — **no `shell=True` anywhere in the codebase**.

## Modules

| Module | Target | Tools | Phases |
|--------|--------|-------|--------|
| **Network** | IPs, CIDRs, hostnames | nmap, enum4linux, smbclient, ldapsearch, hydra | host_discovery, port_scanning, service_enumeration, authentication_checks |
| **Web** | URLs | whatweb, wafw00f, nikto, gobuster, ffuf, wpscan, nuclei, sqlmap, curl | surface_discovery, content_enumeration, vulnerability_scanning, exploit_candidates |
| **API** | API endpoints | httpx, arjun, ffuf, nuclei | discovery, authentication, fuzzing, authorization |
| **Surface** | IPs, hostnames | nmap (stealth), service_detector | port_discovery, service_fingerprint, vector_correlation, prioritization |
| **AD** | Domain controllers | nmap, enum4linux-ng, Impacket, ldapsearch, smbclient, BloodHound, NetExec | passive_recon, identity_enumeration, configuration_enumeration, delegation_discovery, bloodhound_collection |
| **Workflow** | Any target | All modules | Conditional multi-module pipeline |

## Architecture

```
tools/ → parsers/ → phases/ → module.py → core/
```

All modules share a common core providing:

- **OPSEC-aware profiles** — stealth / normal / aggressive with noise-level gating
- **Secure execution** — `list[str]` commands, `validate_arg()`, credential sanitization in logs
- **5-level confidence model** — confirmed → high → medium → low → heuristic, with severity clamping
- **Structured output** — findings (JSON/Markdown), loot vault (optional Fernet encryption), session notes
- **Credential vault** — centralized, deduplicated storage shared across modules
- **Engagement tracking** — full lifecycle (planning → active → paused → completed) with pause/resume
- **Workflow orchestration** — conditional multi-module pipelines with automatic data passing
- **Configuration system** — `tools.yaml` + `profiles.yaml` as single source of truth, typed `ToolConfig` accessor

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Network recon
python reconforge.py network --target 10.10.10.1

# AD recon
python reconforge.py ad --target 10.10.10.1 --domain corp.local

# Web recon
python reconforge.py web --target https://example.com

# API recon with authentication
python reconforge.py api --target https://api.example.com --auth-token "Bearer eyJ..."

# Attack surface mapping
python reconforge.py surface --target 10.10.10.1

# Full workflow (conditional: surface → network → ad → web → api)
python reconforge.py workflow --target 10.10.10.1

# Targeted workflow with engagement tracking
python reconforge.py workflow --target 10.10.10.1 --modules network,ad \
    --engagement "Q1 Pentest" --client "Acme Corp" --encrypt-loot

# Stealth mode
python reconforge.py network --target 10.10.10.1 --opsec stealth

# Dry run (show commands without executing)
python reconforge.py network --target 10.10.10.1 --dry-run -v
```

## OPSEC Modes

| Mode | Allowed Noise | Behavior |
|------|--------------|----------|
| `stealth` | low | Minimal noise, passive techniques, limited ports |
| `normal` | low, medium | Balanced for standard engagements |
| `aggressive` | low, medium, high, very_high | Full coverage for CTF/lab environments |

## Output Structure

```
outputs/<target>/<module>/
├── raw/                  # Raw tool output
├── parsed/               # Parsed results
├── findings.json         # Findings (JSON)
├── findings.md           # Findings (Markdown)
├── loot.json             # Discovered loot
├── session.md            # Session notes
├── commands.log          # Command log
├── attack_paths.md       # Attack paths
└── quick_report.md       # Quick report
```

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, data flow, core services, security model |
| [CONFIGURATION.md](docs/CONFIGURATION.md) | tools.yaml, profiles.yaml, ToolConfig, ProfileLoader |
| [MODULES.md](docs/MODULES.md) | All 5 modules: tools, parsers, phases, architecture |
| [FINDINGS.md](docs/FINDINGS.md) | 5-level confidence model, severity clamping, classification |
| [USAGE.md](docs/USAGE.md) | CLI reference, examples, OPSEC modes, output interpretation |
| [DEVELOPMENT.md](docs/DEVELOPMENT.md) | Adding tools/parsers/phases, testing guidelines, code standards |
| [API_REFERENCE.md](docs/API_REFERENCE.md) | Core classes, module classes, data structures |
| [FINAL_STABILIZATION_REPORT.md](docs/FINAL_STABILIZATION_REPORT.md) | Validation results, technical debt, 10-point checklist |

## Testing

```bash
pip install pytest
python -m pytest tests/ -v
# 348 tests, all passing (~3.1s)
```

## Project Structure

```
reconforge/
├── reconforge.py              # CLI entry-point
├── config/
│   ├── tools.yaml             # Tool configuration
│   └── profiles.yaml          # OPSEC profiles
├── core/                      # 17 shared services
│   ├── runner.py              # Secure subprocess execution
│   ├── config_loader.py       # YAML config with caching
│   ├── tool_config.py         # Typed config accessor
│   ├── profile_loader.py      # OPSEC profile resolution
│   ├── findings_manager.py    # 5-level confidence + severity clamping
│   ├── loot_manager.py        # Loot tracking + Fernet encryption
│   ├── credential_vault.py    # Centralized credential store
│   ├── engagement.py          # Engagement lifecycle
│   ├── workflow_orchestrator.py  # Cross-module pipeline
│   ├── attack_workflow.py     # Kill-chain tracking
│   ├── notes_manager.py       # Session notes
│   ├── output_manager.py      # Structured output + reports
│   ├── validators.py          # Input validation
│   ├── opsec_checks.py        # Technique gating
│   ├── detection_map.py       # Noise-level mapping
│   ├── exceptions.py          # Exception hierarchy
│   ├── logger.py              # Logging + credential sanitization
│   └── target_parser.py       # Target parsing
├── modules/
│   ├── network/               # 5 tools, 4 parsers, 4 phases
│   ├── web/                   # 9 tools, 7 parsers, 4 phases
│   ├── api/                   # 4 tools, 4 parsers, 4 phases
│   ├── surface/               # 2 tools, 1 parser, 6 intelligence, 4 phases
│   └── ad/                    # 8 tools, 8 parsers, 6 collectors, 5 analyzers, 6 attack paths, 5 phases, 6 reporters
└── tests/                     # 348 tests (pytest)
```

## License

Internal use — see project documentation for terms.
