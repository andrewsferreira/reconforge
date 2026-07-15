> **⚠️ HISTORICAL DOCUMENT**
> This is a historical record of Module Inventory Report completed on 2026-03-17.
> It reflects the state of the project at that time and is preserved for reference.
> For current documentation, see [DOCUMENTATION_INDEX.md](../DOCUMENTATION_INDEX.md).

# ReconForge Framework — Module Inventory Report

**Generated:** March 17, 2026  
**Repository:** `/home/ubuntu/reconforge`  
**Git Commits:** 3

---

## Framework Overview

| Metric | Value |
|---|---|
| **Total Modules** | 2 |
| **Total Python Files** | 60 |
| **Total Lines of Code** | 12,910 |
| **Core Services** | 12 |
| **Configuration Files** | 2 (YAML) |
| **Git Commits** | 3 |

---

## Git History

| Commit | Description |
|---|---|
| `fd8fc39` | feat: Add AD Advanced Module — Delegation and Bloodhound |
| `9b43902` | feat: Add AD Module — Active Directory reconnaissance |
| `ffce38e` | feat: Complete Network module for ReconForge framework |

---

## Module Completion Status

| Module | Phases | Tools | Parsers | Orchestrator | README | Status |
|---|:---:|:---:|:---:|:---:|:---:|---|
| **network** | 4 | 5 | 4 | ✓ | ✓ | ✅ Complete |
| **ad** | 5 | 8 | 8 | ✓ | ✓ | ✅ Complete |

---

## Module 1: `network` — Network Reconnaissance

**Python files:** 18 · **Lines of code:** 3,590 · **Orchestrator:** `network_module.py`

### Phases (4)
| Phase | Description |
|---|---|
| `host_discovery` | Discover live hosts on the target network |
| `port_scanning` | Scan for open ports on discovered hosts |
| `service_enumeration` | Enumerate services running on open ports |
| `authentication_checks` | Check for weak/default authentication |

### Tools (5)
| Tool | Purpose |
|---|---|
| `nmap` | Host discovery, port scanning, service detection |
| `enum4linux` | SMB/NetBIOS enumeration |
| `ldapsearch` | LDAP directory queries |
| `smbclient` | SMB share enumeration and access |
| `hydra` | Brute-force authentication testing |

### Parsers (4)
| Parser | Parses output from |
|---|---|
| `nmap_parser` | Nmap scan results |
| `enum4linux_parser` | Enum4linux output |
| `ldap_parser` | LDAP query results |
| `smb_parser` | SMB client output |

---

## Module 2: `ad` — Active Directory Reconnaissance

**Python files:** 26 · **Lines of code:** 8,249 · **Orchestrator:** `ad_module.py`

### Phases (5)
| Phase | Description |
|---|---|
| `passive_recon` | Passive information gathering against AD |
| `identity_enumeration` | Enumerate users, groups, and identities |
| `configuration_enumeration` | Enumerate AD configuration and policies |
| `delegation_discovery` | Discover Kerberos delegation settings |
| `bloodhound_collection` | Collect data for BloodHound graph analysis |

### Tools (8)
| Tool | Purpose |
|---|---|
| `nmap` | Network scanning for AD services |
| `ldapsearch` | LDAP queries against domain controllers |
| `enum4linux_ng` | Next-gen SMB/NetBIOS enumeration |
| `smbclient` | SMB share access and enumeration |
| `impacket` | Impacket suite (secretsdump, GetNPUsers, etc.) |
| `advanced_impacket` | Advanced Impacket techniques |
| `netexec` | Network execution and credential testing |
| `bloodhound` | BloodHound data collection (SharpHound) |

### Parsers (8)
| Parser | Parses output from |
|---|---|
| `nmap_parser` | Nmap scan results |
| `ldap_parser` | LDAP query results |
| `enum4linux_ng_parser` | Enum4linux-ng output |
| `smb_parser` | SMB client output |
| `impacket_parser` | Impacket tool output |
| `netexec_parser` | NetExec output |
| `bloodhound_parser` | BloodHound collection data |
| `delegation_parser` | Kerberos delegation findings |

---

## Core Services (12)

| Service | Role |
|---|---|
| `runner` | Command execution engine |
| `config_loader` | YAML configuration loading |
| `target_parser` | Target specification parsing |
| `output_manager` | Report and output generation |
| `findings_manager` | Vulnerability/finding tracking |
| `loot_manager` | Credential and loot storage |
| `notes_manager` | Operator notes and annotations |
| `logger` | Structured logging |
| `opsec_checks` | Operational security validation |
| `detection_map` | Detection risk mapping |
| `attack_workflow` | Attack chain orchestration |
| `utils` | Shared utility functions |

---

## Configuration Files

| File | Purpose |
|---|---|
| `config/tools.yaml` | Tool paths and default arguments |
| `config/profiles.yaml` | Scan profiles (stealth, normal, aggressive) |

---

## CLI Integration

Both modules are registered in `reconforge` via argparse subparsers:

```
reconforge network  →  Network reconnaissance module
reconforge ad       →  Active Directory reconnaissance module
```

---

## Summary

The ReconForge framework currently has **2 fully complete modules** (Network and AD), backed by **12 core services**, totaling **~12,900 lines of Python** across **60 files**. Both modules follow a consistent architecture: **phases** define the reconnaissance workflow, **tools** wrap external binaries, **parsers** normalize output, and an **orchestrator** ties everything together. Each module includes documentation and is wired into the main CLI.
