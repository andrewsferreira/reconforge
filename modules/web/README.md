# ReconForge — Web Module

**Author:** Andrews Ferreira

---

## Overview

The **Web Module** provides automated web application reconnaissance and vulnerability assessment through a four-phase pipeline. Each phase builds on the findings of the previous one, progressively deepening the analysis from passive fingerprinting to active exploit candidate identification.

The module follows the same architectural patterns as the Network and AD modules: tool wrappers abstract CLI invocations, parsers normalise raw output into structured findings, and phase classes orchestrate tool execution with full OPSEC awareness.

---

## Architecture

```
modules/web/
├── __init__.py              # Exports WebModule
├── base.py                  # WebPhaseBase — abstract base for all phases
├── web_module.py            # WebModule orchestrator (entry point)
├── README.md                # This file
├── phases/
│   ├── __init__.py
│   ├── surface_discovery.py       # Phase 1 — Technology & WAF fingerprinting
│   ├── content_enumeration.py     # Phase 2 — Directory & file discovery
│   ├── vulnerability_scanning.py  # Phase 3 — Automated vuln scanning
│   └── exploit_candidates.py      # Phase 4 — Targeted exploit analysis
├── tools/
│   ├── __init__.py
│   ├── whatweb.py           # WhatWeb wrapper
│   ├── wafw00f.py           # wafw00f wrapper
│   ├── curl_tool.py         # curl wrapper (header grabbing)
│   ├── ffuf.py              # ffuf wrapper
│   ├── gobuster.py          # gobuster wrapper
│   ├── nikto.py             # Nikto wrapper
│   ├── nuclei.py            # Nuclei wrapper
│   ├── wpscan.py            # WPScan wrapper
│   └── sqlmap.py            # sqlmap wrapper
└── parsers/
    ├── __init__.py
    ├── whatweb_parser.py
    ├── wafw00f_parser.py
    ├── nikto_parser.py
    ├── gobuster_parser.py
    ├── ffuf_parser.py
    ├── wpscan_parser.py
    └── nuclei_parser.py
```

---

## Phases

### Phase 1 — Surface Discovery

**Goal:** Build a technology profile of the target without heavy scanning.

| Tool | Technique Key | Noise Level | Purpose |
|------|---------------|-------------|---------|
| WhatWeb | `whatweb_scan` | Low | CMS, frameworks, server headers |
| wafw00f | `wafw00f_detect` | Low | WAF / CDN detection |
| curl | `curl_header_grab` | Low | Raw HTTP header analysis |

**Outputs:** Technology stack, WAF presence, security header audit, server metadata.

### Phase 2 — Content Enumeration

**Goal:** Discover hidden paths, files, and endpoints.

| Tool | Technique Key | Noise Level | Purpose |
|------|---------------|-------------|---------|
| ffuf | `ffuf_dir_scan` | Medium | Fast directory/file fuzzing |
| gobuster | `gobuster_dir_scan` | Medium | Directory brute-force |

**Outputs:** Discovered directories, files, status codes, interesting paths (admin panels, backup files, config files).

### Phase 3 — Vulnerability Scanning

**Goal:** Identify known vulnerabilities across the web application surface.

| Tool | Technique Key | Noise Level | Purpose |
|------|---------------|-------------|---------|
| Nikto | `nikto_scan` | High | Comprehensive web vuln scanner |
| Nuclei | `nuclei_scan` | Medium | Template-based CVE / misconfig detection |

**Outputs:** Vulnerability findings with severity ratings, CVE references, affected URLs.

### Phase 4 — Exploit Candidates

**Goal:** Targeted analysis based on discoveries from previous phases. **Opt-in only.**

| Tool | Technique Key | Noise Level | Purpose |
|------|---------------|-------------|---------|
| WPScan | `wpscan_enum` | High | WordPress plugin/theme/user enumeration |
| sqlmap | `sqlmap_scan` | Very High | SQL injection testing |

**Gating:** Phase 4 tools are gated behind explicit opt-in (`--exploits` flag or config toggle). WPScan only runs if WordPress is detected in Phase 1. sqlmap only runs if injectable parameters are found in Phase 3.

---

## Tool Requirements

All tools must be installed and available on `$PATH`:

```bash
# Core (Phase 1)
apt install whatweb curl
pip install wafw00f

# Enumeration (Phase 2)
# ffuf  — https://github.com/ffuf/ffuf
# gobuster — https://github.com/OJ/gobuster

# Scanning (Phase 3)
# nikto — https://github.com/sullo/nikto
# nuclei — https://github.com/projectdiscovery/nuclei

# Exploit (Phase 4 — optional)
# wpscan — https://github.com/wpscanteam/wpscan
# sqlmap — https://github.com/sqlmapproject/sqlmap
```

Wordlists are resolved via `ConfigLoader` or fall back to common paths:
- `/usr/share/wordlists/dirb/common.txt`
- `/usr/share/seclists/Discovery/Web-Content/common.txt`

---

## Usage

### Programmatic

```python
from modules.web.web_module import WebModule

module = WebModule(
    target="https://example.com",
    config=config_loader,
    output=output_manager,
    findings=findings_manager,
    notes=notes_manager,
    loot=loot_manager,
    opsec=opsec_checker,
    workflow=attack_workflow,
)

module.run(
    phases=[1, 2, 3],       # Run phases 1-3 (default: all four)
    dry_run=False,           # Set True to preview commands without executing
    exploits=False,          # Set True to enable Phase 4 exploit tools
)
```

### Configuration (reconforge.yaml)

```yaml
web:
  threads: 30
  timeout: 120
  wordlist: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
  extensions: "php,html,txt,bak,conf,xml,json"
  user_agent: "Mozilla/5.0 (compatible; ReconForge/1.0)"
  wpscan_api_token: ""
  nuclei_severity: "low,medium,high,critical"
  sqlmap_level: 1
  sqlmap_risk: 1
  exploits_enabled: false
```

---

## OPSEC Considerations

| OPSEC Mode | Allowed Phases | Blocked |
|------------|----------------|---------|
| **stealth** | Phase 1 only (whatweb, wafw00f, curl) | Phases 2–4 |
| **normal** | Phases 1–2, Nuclei from Phase 3 | Nikto, WPScan, sqlmap |
| **aggressive** | All phases and tools | None |

- Phase 1 tools are passive/low-noise and safe for stealth engagements.
- Directory brute-forcing (Phase 2) generates moderate log entries.
- Nikto and WPScan produce distinctive signatures easily flagged by WAFs and SIEMs.
- sqlmap is the noisiest tool — use only when explicitly authorised.

---

## Output Structure

```
output/<target>/
├── web/
│   ├── phase1_surface_discovery/
│   │   ├── whatweb_raw.txt
│   │   ├── wafw00f_raw.txt
│   │   └── headers_raw.txt
│   ├── phase2_content_enumeration/
│   │   ├── ffuf_raw.json
│   │   └── gobuster_raw.txt
│   ├── phase3_vulnerability_scanning/
│   │   ├── nikto_raw.txt
│   │   └── nuclei_raw.json
│   ├── phase4_exploit_candidates/
│   │   ├── wpscan_raw.json
│   │   └── sqlmap_raw.txt
│   ├── web_report.json          # Consolidated JSON report
│   └── web_quick_report.txt     # Human-readable summary
```

---

## Integration Points

- **FindingsManager** — All discoveries (technologies, paths, vulns) are registered as structured findings.
- **LootManager** — Credentials, tokens, and sensitive files found during scanning are saved as loot.
- **AttackWorkflow** — Each phase records its step; Phase 4 suggestions feed into the global attack graph.
- **NotesManager** — Phase start/end timestamps and key events are logged for the engagement notebook.
- **OpsecChecker** — Every tool invocation is checked against the active OPSEC policy before execution.

---

## Extending the Module

To add a new tool:

1. Create a tool wrapper in `tools/` implementing the standard `run(target, **kwargs) -> RunResult` interface.
2. Create a parser in `parsers/` with a `parse(raw_output) -> list[dict]` method.
3. Register the tool in the appropriate phase class.
4. Add a detection level entry in `core/detection_map.py`.
5. Export the new classes from the respective `__init__.py` files.
