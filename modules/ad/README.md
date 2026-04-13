# ReconForge AD Module — Active Directory Reconnaissance

**Author:** Andrews Ferreira  
**Version:** 1.0  
**Module:** `ad`

---

## Overview

The AD Module provides automated, OPSEC-aware Active Directory reconnaissance following a structured five-phase kill chain. It integrates eight specialized tools with intelligent parsing, finding generation, loot extraction, and attack path recommendation.

### AD Recon Kill Chain

```
Phase 1: Passive Recon          Phase 2: Identity Enum         Phase 3: Config Enum
├── AD service scan             ├── LDAP user enum             ├── Password policy
├── DNS SRV enumeration         ├── LDAP group enum            ├── Trust relationships
├── LDAP anonymous bind         ├── LDAP computer enum         ├── GPO enumeration
├── SMB null session            ├── SPN discovery              ├── Share enumeration
├── Kerberos detection          ├── AS-REP roastable users     ├── DC enumeration
└── RootDSE extraction          ├── RID cycling                └── Attack path generation
                                └── enum4linux-ng integration

Phase 4: Delegation Discovery   Phase 5: Bloodhound Collection
├── Unconstrained delegation    ├── bloodhound-python collection
├── Constrained delegation      ├── NetExec Bloodhound mode
├── RBCD enumeration            ├── Node & relationship analysis
├── Impacket findDelegation     └── Attack path graph generation
└── MachineAccountQuota query
```

## Quick Start

```bash
# Basic unauthenticated scan
python reconforge.py ad --target 10.10.10.1 --domain corp.local

# Authenticated scan with credentials
python reconforge.py ad --target 10.10.10.1 --domain corp.local -u jsmith -p 'P@ssw0rd'

# Stealth mode — passive phase only
python reconforge.py ad --target 10.10.10.1 --domain corp.local --opsec stealth

# Aggressive mode — all phases, maximum coverage
python reconforge.py ad --target 10.10.10.1 --domain corp.local --opsec aggressive

# Specific phases only
python reconforge.py ad --target 10.10.10.1 --domain corp.local --phases passive,identity

# Delegation discovery only
python reconforge.py ad --target 10.10.10.1 --domain corp.local -u jsmith -p 'P@ssw0rd' --phases delegation

# Bloodhound collection (requires credentials)
python reconforge.py ad --target 10.10.10.1 --domain corp.local -u jsmith -p 'P@ssw0rd' --phases bloodhound

# Full advanced scan — all five phases
python reconforge.py ad --target 10.10.10.1 --domain corp.local -u jsmith -p 'P@ssw0rd' --opsec aggressive

# Dry-run (show commands without execution)
python reconforge.py ad --target 10.10.10.1 --domain corp.local --dry-run -v
```

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target DC IP or hostname (required) | — |
| `--domain` | AD domain name (e.g. `corp.local`) | Auto-discover |
| `--opsec` | OPSEC mode: `stealth`, `normal`, `aggressive` | `normal` |
| `--phases` | Comma-separated: `passive`, `identity`, `configuration`, `delegation`, `bloodhound` | All |
| `-u, --username` | Username for authenticated enumeration | — |
| `-p, --password` | Password for authenticated enumeration | — |
| `--dc-ip` | Domain Controller IP (if different from target) | Same as target |
| `-o, --output` | Output base directory | `outputs` |
| `-v, --verbose` | Enable verbose/debug logging | Off |
| `--dry-run` | Show commands without executing | Off |
| `--timeout` | Default command timeout (seconds) | 600 |

## Tool Requirements

| Tool | Required | Install | Purpose |
|------|----------|---------|---------|
| **nmap** | Yes | `apt install nmap` | AD service scan, NSE scripts, DNS SRV |
| **ldapsearch** | Yes | `apt install ldap-utils` | LDAP queries, anonymous bind, user/group/GPO enum |
| **smbclient** | No | `apt install smbclient` | Null session, share enumeration |
| **enum4linux-ng** | No | `pip install enum4linux-ng` | Full AD SMB/RPC enumeration |
| **impacket** | No | `pip install impacket` | GetADUsers, GetNPUsers, lookupsid, rpcdump, findDelegation, GetUserSPNs |
| **bloodhound-python** | No | `pip install bloodhound` | AD graph data collection for Bloodhound |
| **netexec** | No | `pipx install netexec` | Network execution tool (SMB/LDAP enum, Bloodhound collection) |

Install all tools at once:
```bash
sudo apt install -y nmap ldap-utils smbclient
pip install enum4linux-ng impacket bloodhound
pipx install netexec
```

## Phase Details

### Phase 1: Passive Reconnaissance

Low-noise discovery of AD services and anonymous access vectors.

| Technique | Detection Level | Description |
|-----------|----------------|-------------|
| AD service scan | Medium | Nmap version scan on AD ports (53,88,135,139,389,445,636,...) |
| DNS SRV enumeration | Low | Query `_ldap._tcp`, `_kerberos._tcp`, `_gc._tcp` records |
| LDAP anonymous bind | Low | Test if anonymous LDAP queries are allowed |
| SMB null session | Low | Test if null session share listing works |
| Kerberos detection | Low | Verify Kerberos KDC availability on port 88 |
| RootDSE extraction | Low | Extract domain naming context, forest info, DC capabilities |

### Phase 2: Identity Enumeration

Enumerate domain principals (users, groups, computers) and identify attack targets.

| Technique | Detection Level | Description |
|-----------|----------------|-------------|
| LDAP user enum | Medium | Full user dump via LDAP (SAM, UPN, last logon, flags) |
| LDAP group enum | Medium | Group dump with member resolution |
| LDAP computer enum | Medium | Computer object enumeration (OS, version) |
| SPN discovery | Medium | Find Kerberoastable service accounts |
| AS-REP users | Medium | Identify accounts without Kerberos pre-auth |
| RID cycling | High | Brute-force RIDs to enumerate users/groups |
| enum4linux-ng | Medium | Comprehensive SMB/RPC user/group/share enum |

### Phase 3: Configuration Enumeration

Extract domain configuration and generate attack paths.

| Technique | Detection Level | Description |
|-----------|----------------|-------------|
| Password policy | Low–Medium | Extract domain password policy (min length, lockout, complexity) |
| Trust enumeration | Medium | Discover inter-domain and inter-forest trusts |
| GPO enumeration | Medium | List Group Policy Objects |
| Share enumeration | Low–Medium | Enumerate accessible SMB shares |
| DC enumeration | Low | Identify all domain controllers |
| SYSVOL/NETLOGON access | Medium | Test access to critical AD shares |

### Phase 4: Delegation Discovery

Enumerate Kerberos delegation configurations to identify privilege escalation paths.

| Technique | Detection Level | Description |
|-----------|----------------|-------------|
| Unconstrained delegation query | Medium | LDAP query for `TRUSTED_FOR_DELEGATION` flag on accounts |
| Constrained delegation query | Medium | LDAP query for `msDS-AllowedToDelegateTo` attribute |
| RBCD query | Medium | LDAP query for `msDS-AllowedToActOnBehalfOfOtherIdentity` |
| Impacket findDelegation | Medium | Automated delegation discovery via Impacket |
| MachineAccountQuota query | Low | Query `ms-DS-MachineAccountQuota` for RBCD abuse potential |
| NetExec LDAP enum | Medium | NetExec LDAP-based delegation enumeration |

**Findings generated:**
- Unconstrained delegation on non-DC computer accounts (HIGH)
- Constrained delegation with protocol transition (MEDIUM)
- RBCD configurations allowing impersonation (HIGH)
- MachineAccountQuota > 0 enabling RBCD abuse (MEDIUM)

**Attack paths:**
- **Unconstrained Delegation Abuse** — Compromise delegated host → extract TGTs → impersonate any user
- **Constrained Delegation Abuse** — S4U2Self/S4U2Proxy → access target service as any user
- **RBCD Abuse** — Create machine account → configure RBCD → S4U2Proxy to target

### Phase 5: Bloodhound Collection

Collect AD graph data for comprehensive attack path analysis using Bloodhound.

| Technique | Detection Level | Description |
|-----------|----------------|-------------|
| bloodhound-python DCOnly | High | Collect users, groups, computers, ACLs from DC only |
| bloodhound-python All | Very High | Full collection including sessions, local groups |
| bloodhound-python Stealth | High | DC-only collection with DNS over TCP |
| NetExec Bloodhound | High | NetExec LDAP-based Bloodhound data collection |

**Findings generated:**
- Bloodhound collection completed with node/relationship counts (INFO)
- High-value targets identified from graph analysis (HIGH)
- Shortest attack paths to Domain Admin (CRITICAL)

**Output files:**
- Bloodhound JSON files (importable into Bloodhound CE/Legacy)
- Node count summaries (users, computers, groups, GPOs, OUs)
- High-value path analysis report

## OPSEC Considerations

### Stealth Mode (`--opsec stealth`)
- **Phase 1 only** (passive reconnaissance)
- Only low-noise techniques: anonymous LDAP, DNS SRV, null session tests
- No Nmap scripts, no enum4linux-ng, no Impacket tools
- Minimal log footprint on target DC

### Normal Mode (`--opsec normal`)
- Phases 1–4 enabled (passive, identity, configuration, delegation)
- Low and medium noise techniques allowed
- LDAP queries, enum4linux-ng, Impacket GetADUsers/GetNPUsers/findDelegation
- RID cycling disabled (high noise)
- Bloodhound collection disabled (high noise)

### Aggressive Mode (`--opsec aggressive`)
- All five phases enabled including delegation and Bloodhound collection
- All techniques enabled including RID cycling
- Nmap AD script suite, Kerberos enumeration
- Full enum4linux-ng enumeration, Bloodhound All collection
- NetExec SMB/LDAP/Bloodhound enumeration
- Suitable for CTF/lab environments only

## Output Structure

```
outputs/<target>/ad/
├── raw/                    # Raw tool output files
│   ├── nmap_ad_*.xml
│   ├── ldap_*.txt
│   ├── smb_*.txt
│   ├── enum4linux_ng_*.txt
│   ├── impacket_*.txt
│   ├── bloodhound_*.json
│   └── netexec_*.txt
├── parsed/                 # Parsed structured data
│   ├── *.json
│   └── *.md
├── findings.json           # All findings (machine-readable)
├── findings.md             # All findings (human-readable)
├── quick_report.md         # Executive summary
├── ad_summary.md           # AD-specific intelligence summary
├── attack_paths.md         # Identified attack paths and workflows
├── session.md              # Session notes and timeline
├── commands.log            # All executed commands
├── loot.json               # Extracted credentials, users, shares, services
└── results.json            # Complete scan results
```

## Attack Paths Detected

The module automatically identifies and documents attack paths including:

- **Kerberoasting** — SPN accounts found → request TGS → offline crack
- **AS-REP Roasting** — No pre-auth accounts → request AS-REP → offline crack
- **Null Session Exploitation** — Anonymous access → user/share enumeration
- **Password Spray** — Weak policy + user list → targeted spray
- **Trust Abuse** — Inter-domain trusts → lateral movement
- **GPO Abuse** — Misconfigured GPOs → privilege escalation
- **Share Exploitation** — Sensitive share access → data exfiltration
- **Unconstrained Delegation** — Compromised host → TGT extraction → domain compromise
- **Constrained Delegation** — S4U2Self/S4U2Proxy → service impersonation
- **RBCD Abuse** — Machine account creation → RBCD write → service impersonation
- **Bloodhound Graph Paths** — Shortest paths to Domain Admin via ACL/group chains

## Programmatic Usage

```python
from modules.ad.ad_module import ADModule

# Initialize
module = ADModule(
    target="10.10.10.1",
    domain="corp.local",
    username="jsmith",
    password="P@ssw0rd",
    dc_ip="10.10.10.1",
    opsec_mode="normal",
    verbose=True,
)

# Run all phases
results = module.run()

# Run specific phases
results = module.run(phases=["passive", "identity"])

# Run delegation and bloodhound phases
results = module.run(phases=["delegation", "bloodhound"])

# Access results
identity = results["phases"].get("identity", {})
print(f"Users: {identity.get('user_count', 0)}")
print(f"Kerberoastable: {identity.get('spn_count', 0)}")
print(f"AS-REP roastable: {identity.get('asrep_count', 0)}")

# Access delegation results
delegation = results["phases"].get("delegation", {})
print(f"Unconstrained: {len(delegation.get('unconstrained_delegation', []))}")
print(f"Constrained: {len(delegation.get('constrained_delegation', []))}")
print(f"RBCD: {len(delegation.get('rbcd', []))}")

# Access bloodhound results
bh = results["phases"].get("bloodhound", {})
print(f"Collection method: {bh.get('collection_method', 'N/A')}")
print(f"Files collected: {bh.get('files_collected', 0)}")
```

## Troubleshooting

### Common Issues

**"Tool not found: impacket"**
```bash
pip install impacket
# Verify: which GetADUsers.py || which impacket-GetADUsers
```

**"Tool not found: enum4linux-ng"**
```bash
pip install enum4linux-ng
# Verify: which enum4linux-ng
```

**"No domain discovered"**
- Provide `--domain` explicitly if auto-discovery fails
- Ensure DNS is configured to resolve the DC
- Try: `nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>`

**"LDAP anonymous bind denied"**
- Modern DCs often block anonymous LDAP — use `-u`/`-p` for credentials
- The module gracefully falls back to other techniques

**Timeout errors**
- Increase timeout: `--timeout 1200`
- Run specific phases: `--phases passive`

**"Tool not found: bloodhound-python"**
```bash
pip install bloodhound
# Verify: which bloodhound-python || python -c "import bloodhound"
```

**"Tool not found: netexec"**
```bash
pipx install netexec
# Verify: which netexec || which nxc
# Legacy fallback: which crackmapexec
```

**"Bloodhound collection requires credentials"**
- Phase 5 requires authenticated access — provide `-u`/`-p` flags
- Bloodhound cannot run with anonymous or null session access

**"Bloodhound collection timeout"**
- Large domains can exceed the default 600s timeout
- Increase timeout: `--timeout 1200`
- Use DCOnly collection (default) instead of All: less data, faster completion
- In stealth mode, Bloodhound uses `--dns-tcp` which is slower

**"NetExec connection refused"**
- Ensure SMB (445) or LDAP (389) ports are accessible
- NetExec requires valid credentials for most enumeration modes
- Check firewall rules between attacker and target DC

---

*ReconForge AD Module v1.0 — Author: Andrews Ferreira*
