# ReconForge Module Documentation

> Version 1.1.0 — Last updated: 2026-04-13

## Module Architecture Pattern

All modules follow the same layered pipeline:

```
tools/ → parsers/ → phases/ → module.py → core/
```

Each module has:
- A **base class** (ABC) defining the phase interface with 11 standard constructor parameters
- **Tool wrappers** that build `list[str]` commands via `Runner`
- **Parsers** that extract structured data from raw tool output
- **Phases** that orchestrate tool execution, parsing, and finding generation
- A **module orchestrator** that sequences phases and manages lifecycle

---

## Network Module (`modules/network/`)

### Overview

Network-level reconnaissance: host discovery, port scanning, service enumeration, and authentication testing.

**Orchestrator:** `NetworkModule` (`network_module.py`)
**Base Class:** `NetworkPhaseBase` (`base.py`)
**CLI Phase Slugs:** `discovery`, `scanning`, `enumeration`, `authentication`

### Tools

| Tool | Wrapper | Description |
|------|---------|-------------|
| nmap | `tools/nmap.py` | Host discovery, port scanning, service/version detection, NSE scripts |
| enum4linux | `tools/enum4linux.py` | SMB/NetBIOS enumeration |
| smbclient | `tools/smbclient.py` | SMB share access and listing |
| ldapsearch | `tools/ldapsearch.py` | LDAP directory enumeration |
| hydra | `tools/hydra.py` | Authentication brute-force testing (**opt-in only**) |

### Parsers

| Parser | Input | Output |
|--------|-------|--------|
| `nmap_parser.py` | nmap stdout/XML | Hosts, ports, services, versions |
| `enum4linux_parser.py` | enum4linux stdout | Users, shares, groups, password policy |
| `smb_parser.py` | smbclient stdout | Shares, permissions, files |
| `ldap_parser.py` | ldapsearch stdout | LDAP entries, attributes |

### Phases

| # | Internal PHASE_NAME | CLI Slug | Key Actions |
|---|---------------------|----------|-------------|
| 1 | `host_discovery` | `discovery` | Ping sweep, ARP scan, live host identification |
| 2 | `port_scanning` | `scanning` | SYN/connect scan, port enumeration, service detection |
| 3 | `service_enumeration` | `enumeration` | SMB enumeration, LDAP queries, deep service analysis |
| 4 | `authentication_checks` | `authentication` | Anonymous access testing, credential testing, hydra brute-force (opt-in) |

### Module-Specific Options

| CLI Flag | Description |
|----------|-------------|
| `--brute-force` | Enable hydra brute-force testing (opt-in) |
| `--phases discovery,scanning` | Run specific phases |

### `run()` Signature

```python
NetworkModule.run(phases: Optional[List[str]] = None, brute_force: bool = False) -> Dict
```

---

## Web Module (`modules/web/`)

### Overview

Web application reconnaissance: technology fingerprinting, content discovery, vulnerability scanning, and exploit candidate identification.

**Orchestrator:** `WebModule` (`web_module.py`)
**Base Class:** `WebPhaseBase` (`base.py`)
**Valid Phases:** `surface`, `content`, `vuln`, `exploit`

### Tools

| Tool | Wrapper | Description |
|------|---------|-------------|
| whatweb | `tools/whatweb.py` | Web technology fingerprinting |
| wafw00f | `tools/wafw00f.py` | WAF detection |
| nikto | `tools/nikto.py` | Web vulnerability scanning |
| gobuster | `tools/gobuster.py` | Directory/file brute-forcing |
| ffuf | `tools/ffuf.py` | Fast web fuzzing |
| wpscan | `tools/wpscan.py` | WordPress security scanning |
| nuclei | `tools/nuclei.py` | Template-based vulnerability scanning |
| sqlmap | `tools/sqlmap.py` | SQL injection detection/exploitation |
| curl_tool | `tools/curl_tool.py` | HTTP request utility |

### Parsers

| Parser | Input | Output |
|--------|-------|--------|
| `gobuster_parser.py` | gobuster stdout | Discovered paths, status codes |
| `ffuf_parser.py` | ffuf JSON | Fuzzed endpoints, responses |
| `nikto_parser.py` | nikto stdout | Vulnerabilities, misconfigurations |
| `nuclei_parser.py` | nuclei JSON | Template matches, CVEs |
| `whatweb_parser.py` | whatweb JSON | Technologies, versions |
| `wafw00f_parser.py` | wafw00f stdout | WAF identification |
| `wpscan_parser.py` | wpscan JSON | WordPress vulnerabilities, plugins |

### Phases

| # | Internal PHASE_NAME | CLI Slug | Key Actions |
|---|---------------------|----------|-------------|
| 1 | `surface_discovery` | `surface` | Technology fingerprinting, WAF detection, SSL testing |
| 2 | `content_enumeration` | `content` | Directory brute-forcing, file discovery, vhost enumeration |
| 3 | `vulnerability_scanning` | `vuln` | Nuclei templates, nikto scans, known CVE checks |
| 4 | `exploit_candidates` | `exploit` | SQLMap testing, exploit identification (**opt-in via phase selection**) |

### `run()` Signature

```python
WebModule.run(phases: Optional[List[str]] = None, opt_in: bool = False) -> Dict
```

The `opt_in` parameter controls whether the `exploit` phase runs. When phases are specified via CLI, including `exploit` in the list automatically sets `opt_in=True`.

---

## API Module (`modules/api/`)

### Overview

API security assessment: endpoint discovery, authentication testing (JWT, OpenAPI), parameter fuzzing, and authorization testing.

**Orchestrator:** `APIModule` (`api_module.py`)
**Base Class:** `APIPhaseBase` (`base.py`)
**Valid Phases:** `discovery`, `authentication`, `fuzzing`, `authorization`

### Tools

| Tool | Wrapper | Description |
|------|---------|-------------|
| httpx | `tools/httpx_tool.py` | Fast HTTP probing and technology detection |
| arjun | `tools/arjun_tool.py` | HTTP parameter discovery |
| ffuf | `tools/ffuf_api.py` | API endpoint fuzzing |
| nuclei | `tools/nuclei_api.py` | API-specific vulnerability templates |

### Parsers

| Parser | Input | Output |
|--------|-------|--------|
| `openapi_parser.py` | OpenAPI 3.x / Swagger 2.x JSON/YAML | Endpoints, parameters, security schemes, `$ref` resolution, JWT detection |
| `arjun_parser.py` | arjun JSON | Discovered parameters |
| `ffuf_parser.py` | ffuf JSON | Fuzzed endpoints, responses |
| `nuclei_parser.py` | nuclei JSON | API vulnerability matches |

### Phases

| # | Phase | Key Actions |
|---|-------|-------------|
| 1 | `discovery` | OpenAPI/Swagger spec detection, endpoint enumeration, httpx probing |
| 2 | `authentication` | JWT analysis via `is_jwt_bearer()`, token testing, auth scheme detection |
| 3 | `fuzzing` | Parameter fuzzing, endpoint fuzzing, error-based detection |
| 4 | `authorization` | IDOR testing, privilege escalation checks, role-based access testing |

### JWT & OpenAPI Features

- **OpenAPI Parser** handles both OpenAPI 3.x and Swagger 2.x with full `$ref` resolution
- **JWT Detection:** `is_jwt_bearer()` identifies Bearer tokens with JWT format in OpenAPI security schemes
- **Authorization Phase** explicitly uses `confidence="heuristic"` + `severity="low"` for pattern-based detections
- **Fuzzing Phase** documents that HTTP 500 alone is classified as `heuristic/info`

### `run()` Signature

```python
APIModule.run(phases: Optional[List[str]] = None, opt_in: bool = False) -> Dict
```

The `opt_in` parameter controls whether the `authorization` phase runs. Including `authorization` in the CLI phases list automatically sets `opt_in=True`.

### Module-Specific Options

| CLI Flag | Description |
|----------|-------------|
| `--auth-token "Bearer eyJ..."` | Bearer/auth token for authenticated requests |
| `--header "X-Api-Key: abc"` | Extra HTTP headers (repeatable) |

---

## Surface Module (`modules/surface/`)

### Overview

Attack surface mapping: correlates ports, services, and URLs into a unified attack surface map with confidence scoring and attack prioritization.

**Orchestrator:** `SurfaceModule` (`surface_module.py`)
**Base Class:** `SurfacePhaseBase` (`base.py`)
**Valid Phases:** `port_discovery`, `service_fingerprint`, `vector_correlation`, `prioritization`

### Architecture (Extended)

```
tools/ → parsers/ → intelligence/ → phases/ → surface_module.py → core/
```

The `intelligence/` layer is unique to the Surface module.

### Tools

| Tool | Wrapper | Description |
|------|---------|-------------|
| nmap (stealth profiles) | `tools/nmap_stealth.py` | Port discovery with OPSEC-aware scan profiles |
| service_detector | `tools/service_detector.py` | HTTP service probing |

### Intelligence Layer (`intelligence/`)

| Component | Description |
|-----------|-------------|
| `correlation_engine.py` | Correlates ports/services/URLs into `CorrelatedService` entries → `AttackSurfaceMap` |
| `confidence_scorer.py` | Multi-signal scoring: port_match (0.25), banner_match (0.25), version_detected (0.20), multi_detection (0.20), http_confirmed (0.10) → labels: confirmed ≥0.80, high ≥0.60, medium ≥0.40, low <0.40 |
| `deduplicator.py` | `ServiceDeduplicator` merges duplicate detections from port scan and version scan phases |
| `service_normalizer.py` | Normalizes service names across tools |
| `service_intelligence.py` | `ServiceIntelligenceDB` — enrichment data (categories, attack contexts, common tools, high-value flags) |
| `attack_prioritizer.py` | Prioritizes attack vectors by risk |

### Phases

| # | Phase | Key Actions |
|---|-------|-------------|
| 1 | `port_discovery` | Stealth/normal/aggressive port scanning |
| 2 | `service_fingerprint` | Version detection, banner grabbing |
| 3 | `vector_correlation` | Links ports/services/URLs into attack surface map |
| 4 | `prioritization` | Ranks attack vectors by risk and confidence |

### `run()` Signature

```python
SurfaceModule.run(phases: Optional[List[str]] = None) -> Dict
```

---

## AD Module (`modules/ad/`)

### Overview

Active Directory reconnaissance: user/group enumeration, misconfiguration analysis, delegation discovery, attack path generation, and structured reporting.

**Orchestrator:** `ADModule` (`ad_module.py`)
**Base Class:** `ADPhaseBase` (`base.py`)
**Valid Phases:** `passive`, `identity`, `configuration`, `delegation`, `bloodhound`

### Architecture (Extended)

```
tools/ → parsers/ → collectors/ → analyzers/ → attack_paths/ → phases/ → reporting/ → ad_module.py → core/
```

No file exceeds ~250 lines. Clean separation across 8 sub-packages.

### Tools (8)

| Tool | Wrapper | Description |
|------|---------|-------------|
| nmap | `tools/nmap.py` | AD service port scanning, LDAP/SMB scripts |
| enum4linux-ng | `tools/enum4linux_ng.py` | Next-gen SMB/MSRPC enumeration |
| Impacket (GetADUsers, GetNPUsers, lookupsid, rpcdump) | `tools/impacket.py` | LDAP user dump, AS-REP roasting, SID brute-force |
| Impacket (findDelegation, GetUserSPNs) | `tools/advanced_impacket.py` | Delegation discovery, Kerberoasting |
| ldapsearch | `tools/ldapsearch.py` | LDAP directory queries |
| smbclient | `tools/smbclient.py` | SMB share enumeration |
| BloodHound | `tools/bloodhound.py` | AD graph data collection |
| NetExec | `tools/netexec.py` | Multi-protocol enumeration |

### Parsers (8)

| Parser | Description |
|--------|-------------|
| `nmap_parser.py` | AD service scan results |
| `enum4linux_ng_parser.py` | enum4linux-ng output |
| `impacket_parser.py` | Impacket tool output |
| `smb_parser.py` | SMB enumeration results |
| `ldap_parser.py` | LDAP query results |
| `bloodhound_parser.py` | BloodHound JSON data |
| `delegation_parser.py` | Delegation configuration data |
| `netexec_parser.py` | NetExec output |

### Collectors (6)

| Collector | Description |
|-----------|-------------|
| `bloodhound_collector.py` | BloodHound data collection |
| `delegation_collector.py` | Delegation configuration collection |
| `dns_collector.py` | DNS record collection |
| `kerberos_collector.py` | Kerberos-specific data collection |
| `ldap_collector.py` | LDAP enumeration |
| `smb_collector.py` | SMB share and session enumeration |

### Analyzers (5)

| Analyzer | Description |
|----------|-------------|
| `misconfiguration_analyzer.py` | AD misconfiguration detection (largest file: ~241 lines) |
| `permission_analyzer.py` | ACL and permission analysis |
| `privilege_analyzer.py` | Privilege escalation path analysis |
| `relationship_analyzer.py` | Trust and group relationship analysis |
| `trust_analyzer.py` | Domain/forest trust analysis |

### Attack Path Generators (6)

| Generator | Description |
|-----------|-------------|
| `acl_paths.py` | ACL-based attack paths |
| `asrep_paths.py` | AS-REP roasting attack paths |
| `delegation_paths.py` | Delegation abuse attack paths |
| `gpo_paths.py` | GPO-based attack paths |
| `kerberoast_paths.py` | Kerberoasting attack paths |
| `privilege_escalation_paths.py` | Privilege escalation chains |

### Reporting (6)

| Reporter | Description |
|----------|-------------|
| `ad_summary_reporter.py` | Overall AD summary |
| `attack_path_reporter.py` | Attack path documentation |
| `attack_surface_reporter.py` | AD attack surface report |
| `high_value_targets_reporter.py` | High-value target identification |
| `remediation_reporter.py` | Remediation recommendations |
| `report_builders.py` | Report assembly utilities |

### Phases (5)

| # | Internal PHASE_NAME | CLI Slug | Key Actions |
|---|---------------------|----------|-------------|
| 1 | `passive_recon` | `passive` | DNS SRV enumeration, anonymous LDAP, SMB null sessions |
| 2 | `identity_enumeration` | `identity` | User/group enumeration, RID cycling, Kerberos user enumeration |
| 3 | `configuration_enumeration` | `configuration` | GPO analysis, trust enumeration, misconfiguration detection |
| 4 | `delegation_discovery` | `delegation` | Unconstrained/constrained/RBCD delegation detection |
| 5 | `bloodhound_collection` | `bloodhound` | BloodHound data collection and graph analysis |

### Module-Specific Options

| CLI Flag | Description |
|----------|-------------|
| `--domain corp.local` | AD domain name |
| `-u / --username` | Username for authenticated enumeration |
| `-p / --password` | Password for authenticated enumeration |
| `--dc-ip` | Domain Controller IP (if different from target) |

### `run()` Signature

```python
ADModule.run(phases: Optional[List[str]] = None) -> Dict
```

---

## Workflow Orchestrator

The `WorkflowOrchestrator` (`core/workflow_orchestrator.py`) chains modules together:

### Pre-built Pipelines

**Full Recon** (`WorkflowOrchestrator.full_recon()`):
```
surface → network → ad (conditional) → web (conditional) → api (conditional)
```

**Targeted** (`WorkflowOrchestrator.targeted()`):
```
Runs specified modules sequentially without conditions.
```

### Conditional Branching

| Module | Condition |
|--------|-----------|
| `surface` | Always runs if targets exist |
| `network` | Always runs (no condition) |
| `ad` | Runs if LDAP, Kerberos, SMB, MSRPC, or domain detected |
| `web` | Runs if HTTP/HTTPS service or URL detected |
| `api` | Runs if HTTP/HTTPS service or URL detected |

### Shared Context

The `WorkflowContext` data bus carries discovered data between steps:
- `live_hosts`, `open_ports`, `services`, `domains`, `urls`
- Populated via `_extract_context_from_result()` after each module completes
- `CredentialVault` automatically shares credentials across modules

### CLI Usage

```bash
# Full recon (conditional branching)
python reconforge.py workflow --target 10.10.10.1

# Targeted modules
python reconforge.py workflow --target 10.10.10.1 --modules network,ad,web

# With engagement tracking
python reconforge.py workflow --target 10.10.10.1 --engagement "Q1 Pentest" --client "Acme"

# Resume a paused engagement
python reconforge.py workflow --target 10.10.10.1 --resume /path/to/engagement.json
```

---

*Module documentation validated: 2026-03-21 — 375/375 tests passing*
