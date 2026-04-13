# ReconForge Network Module

## Overview

The Network module provides comprehensive network reconnaissance through a
four-phase kill chain approach. Designed for pentesters working in HTB, THM,
OSCP labs, and authorized engagements.

**Author:** Andrews Ferreira

## Architecture

```
modules/network/
├── network_module.py          # Main orchestrator
├── phases/
│   ├── host_discovery.py      # Phase 1: Find live hosts
│   ├── port_scanning.py       # Phase 2: Enumerate ports/services
│   ├── service_enumeration.py # Phase 3: Deep dive into services
│   └── authentication_checks.py # Phase 4: Test credentials
├── parsers/
│   ├── nmap_parser.py         # Parse nmap XML/text output
│   ├── enum4linux_parser.py   # Parse enum4linux output
│   ├── smb_parser.py          # Parse smbclient output
│   └── ldap_parser.py         # Parse ldapsearch output
├── tools/
│   ├── nmap.py                # Nmap wrapper
│   ├── enum4linux.py          # Enum4linux wrapper
│   ├── smbclient.py           # SMBClient wrapper
│   ├── ldapsearch.py          # LDAPSearch wrapper
│   └── hydra.py               # Hydra wrapper (opt-in only)
└── README.md
```

## Phases

### Phase 1: Host Discovery
- **Purpose:** Identify live hosts on the network
- **Tools:** nmap (-sn ping sweep)
- **Output:** List of live IPs with hostnames
- **OPSEC:** Low noise (ICMP/ARP)

### Phase 2: Port Scanning
- **Purpose:** Enumerate open ports and basic service info
- **Tools:** nmap (-sS SYN scan, -sV version detection)
- **Output:** Open ports, services, known vulns
- **OPSEC:** Medium noise (SYN packets)

### Phase 3: Service Enumeration
- **Purpose:** Deep dive into interesting services (SMB, LDAP)
- **Tools:** enum4linux, smbclient, ldapsearch, nmap NSE scripts
- **Output:** Users, shares, groups, password policies, domain info
- **OPSEC:** Medium-High noise (multiple protocol queries)

### Phase 4: Authentication Checks
- **Purpose:** Test for anonymous access and weak credentials
- **Tools:** smbclient (passive), hydra (active, opt-in)
- **Output:** Anonymous access findings, default credentials
- **OPSEC:** Passive checks are low noise; hydra is VERY HIGH

## Tool Requirements

| Tool | Required | Install Command |
|------|----------|-----------------|
| nmap | **Yes** | `sudo apt install -y nmap` |
| enum4linux | No | `sudo apt install -y enum4linux` |
| smbclient | No | `sudo apt install -y smbclient` |
| ldapsearch | No | `sudo apt install -y ldap-utils` |
| hydra | No | `sudo apt install -y hydra` |

## Usage Examples

### Python API

```python
from modules.network import NetworkModule

# Full scan of a single target
module = NetworkModule(target="10.10.10.1")
results = module.run()

# Stealth scan
module = NetworkModule(target="10.10.10.1", opsec_mode="stealth")
results = module.run()

# Aggressive scan with brute-force (lab environment)
module = NetworkModule(target="10.10.10.1", opsec_mode="aggressive")
results = module.run(brute_force=True)

# Run specific phases only
results = module.run(phases=["discovery", "scanning"])

# Network range scan
module = NetworkModule(target="10.10.10.0/24")
results = module.run()

# Dry run (shows commands without executing)
module = NetworkModule(target="10.10.10.1", dry_run=True)
results = module.run()
```

### CLI (when integrated with reconforge CLI)

```bash
# Full scan
python reconforge.py network --target 10.10.10.1

# Stealth mode
python reconforge.py network --target 10.10.10.1 --opsec stealth

# Aggressive with brute-force
python reconforge.py network --target 10.10.10.1 --opsec aggressive --brute-force

# Specific phases
python reconforge.py network --target 10.10.10.1 --phases discovery,scanning

# Verbose output
python reconforge.py network --target 10.10.10.1 -v
```

## Output Structure

```
outputs/<target>/network/
├── raw/                    # Raw tool output files
│   ├── ping_sweep.xml
│   ├── syn_scan.xml
│   ├── version_scan.xml
│   ├── enum4linux_full.txt
│   ├── smbclient_shares.txt
│   └── ldap_rootdse.txt
├── parsed/                 # Structured parsed data
│   ├── port_scan_results.json
│   ├── service_enum_results.json
│   └── auth_check_results.json
├── findings.json           # All findings (machine-readable)
├── findings.md             # All findings (human-readable)
├── session.md              # Session notes with timeline
├── attack_paths.md         # Identified attack vectors
├── quick_report.md         # Executive summary
├── loot.json               # All loot (creds, hashes, shares, users)
└── commands.log            # All executed commands with timestamps
```

## OPSEC Considerations

### Stealth Mode
- Only low-noise techniques allowed
- Limited port range (common ports only)
- No version detection or script scanning
- No enum4linux or active enumeration
- Suitable for red team engagements

### Normal Mode (Default)
- Low and medium noise techniques
- Full port range with SYN scan
- Version detection enabled
- enum4linux and smbclient allowed
- Suitable for standard pentests

### Aggressive Mode
- All techniques allowed
- Script scanning and UDP scanning enabled
- Full service enumeration
- Suitable for CTF/lab environments
- **Hydra still requires explicit opt-in**

### Hydra / Brute-Force
- **Always opt-in only** regardless of OPSEC mode
- Rate-limited to 4 parallel tasks
- 3-second delay between connections
- Tests common default credentials only
- Can trigger account lockouts and IDS alerts
- Only use against authorized targets

## Findings Model

Each finding includes:
- **ID:** Unique identifier
- **Type:** vulnerability, misconfiguration, exposure, credential
- **Severity:** critical, high, medium, low, info
- **Confidence:** confirmed, high, medium, low
- **Target:** IP:port or hostname
- **Description:** Clear description of the finding
- **Evidence:** Supporting evidence
- **Recommendation:** Remediation advice
- **References:** Related CVEs or URLs

## Loot Tracking

The module extracts and stores:
- **Credentials:** username:password pairs
- **Hashes:** NTLM, NTLMv2, etc.
- **Users:** Enumerated usernames with domain
- **Shares:** Accessible SMB shares with permissions
- **Services:** Vulnerable service versions
- **Config:** Base DNs, naming contexts, domain info

## Attack Workflow

The module tracks:
- Current phase and hypothesis
- Each command with justification
- Alternative approaches considered
- Identified attack paths with risk levels
- Suggested next commands
- Rabbit holes avoided

## Troubleshooting

### nmap requires root for SYN scan
```bash
# Run with sudo or use connect scan
sudo python reconforge.py network --target 10.10.10.1
# Or the module will fall back to -sT connect scan
```

### enum4linux not found
```bash
sudo apt install -y enum4linux
# Or install enum4linux-ng (Python 3)
pip install enum4linux-ng
```

### ldapsearch connection refused
- Verify LDAP is running on the target (port 389/636)
- Try: `ldapsearch -x -H ldap://<target> -s base`
- Check if SSL/TLS is required (use ldaps://)

### Permission denied errors
- Ensure you have sudo/root access for SYN scans
- The module will skip unavailable tools gracefully

### Scan taking too long
- Use stealth mode for limited port range
- Specify specific phases: `--phases discovery,scanning`
- Increase timeout: `--timeout 1200`
