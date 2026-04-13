# ReconForge Configuration Guide

> Version 1.1.0 — Last updated: 2026-04-13

## Overview

ReconForge uses two YAML configuration files as the single source of truth:

| File | Purpose |
|------|---------|
| `config/tools.yaml` | Tool binary paths, default arguments, timeouts, scan profiles, safety settings |
| `config/profiles.yaml` | OPSEC-aware scan profiles with timing, technique toggles, and noise-level gates |

There are no fallback namespaces, no environment variable overrides, and no hardcoded config overrides. The YAML files are authoritative.

## tools.yaml

### Structure

Each tool entry lives under the top-level `tools:` key:

```yaml
tools:
  nmap:
    binary: nmap
    description: "Network mapper - host discovery, port scanning, service enumeration"
    required: true
    default_timeout: 600
    install_cmd: "sudo apt install -y nmap"
    scan_profiles:
      ping_sweep:
        args: "-sn"
        timeout: 120
        detection: low
      syn_scan:
        args: "-sS --open"
        timeout: 600
        detection: medium
        requires_root: true
      version_scan:
        args: "-sV --version-intensity 5"
        timeout: 600
        detection: medium
```

### Top-Level Tool Fields

| Field | Type | Description |
|-------|------|-------------|
| `binary` | string | Primary binary name (e.g., `nmap`) |
| `alt_binary` | string | Alternative binary name (e.g., `impacket-GetADUsers`) |
| `description` | string | Human-readable tool description |
| `required` | bool | Whether the tool is required for the module |
| `default_timeout` | int | Default timeout in seconds |
| `install_cmd` | string | Installation command |
| `detection` | string | Top-level detection/noise level |
| `opt_in_only` | bool | Requires explicit user opt-in (e.g., `hydra`) |
| `warning` | string | Safety warning displayed when tool is used |

### Mode / Scan Profile Fields

Tools define either `modes:` or `scan_profiles:` (both are treated identically by `ToolConfig`):

| Field | Type | Description |
|-------|------|-------------|
| `args` | string | Raw argument string for this mode |
| `timeout` | int | Mode-specific timeout override |
| `detection` | string | Noise level: `low`, `medium`, `high`, `very_high` |
| `requires_root` | bool | Whether the mode requires root privileges |

### Safety Block (hydra example)

```yaml
  hydra:
    binary: hydra
    opt_in_only: true
    warning: "Brute-force testing can trigger lockouts and IDS alerts"
    safety:
      max_tasks: 4
      wait_time: 3
      max_attempts_per_account: 10
```

### Collection Methods (bloodhound example)

```yaml
  bloodhound_python:
    binary: bloodhound-python
    collection_methods:
      all:
        args: "-c All"
        timeout: 900
      default:
        args: "-c DCOnly"
        timeout: 300
      stealth:
        args: "-c DCOnly --dns-tcp"
        timeout: 300
```

### Currently Configured Tools

**Network Module:** `nmap`, `enum4linux`, `smbclient`, `ldapsearch`, `hydra`

**AD Module:** `enum4linux_ng`, `impacket_getadusers`, `impacket_getnpusers`, `impacket_lookupsid`, `impacket_rpcdump`, `nmap_ad`, `bloodhound_python`, `netexec`, `impacket_finddelegation`, `impacket_getuserspns`

**Web Module:** `whatweb`, `wafw00f`, `nikto`, `gobuster`, `ffuf`, `wpscan`, `nuclei`, `sqlmap`, `testssl`

**API Module:** `httpx`, `arjun`, `ffuf_api`, `nuclei_api`

**Surface Module:** `nmap_surface`, `httpx_surface`

---

## profiles.yaml

### Structure

Each profile lives under the top-level `profiles:` key:

```yaml
profiles:
  stealth:
    description: "Minimal noise - avoid detection"
    opsec_mode: stealth
    timing:
      nmap_timing: T2
      scan_delay: "500ms"
      max_retries: 1
    scanning:
      port_range: "21,22,23,25,53,80,88,..."
      scan_type: syn
      version_detection: false
    enumeration:
      enum4linux: false
      smb_scripts: false
    authentication:
      brute_force: false
      anonymous_checks: true
    allowed_noise_levels:
      - low
```

### Base Profiles

| Profile | OPSEC Mode | Noise Levels | Description |
|---------|------------|--------------|-------------|
| `stealth` | stealth | low | Minimal noise — avoid detection |
| `normal` | normal | low, medium | Balanced — standard engagement |
| `aggressive` | aggressive | low, medium, high, very_high | Maximum coverage — CTF/Lab |
| `ctf` | aggressive | low, medium, high, very_high | CTF optimized — fast and comprehensive |

### Module-Specific Profiles

Each module has dedicated profile variants that override the base profile with module-specific settings:

**AD:** `stealth_ad`, `normal_ad`, `aggressive_ad`
**Surface:** `stealth_surface`, `normal_surface`, `aggressive_surface`
**API:** `stealth_api`, `normal_api`, `aggressive_api`
**Web:** `stealth_web`, `normal_web`, `aggressive_web`

Example — `stealth_ad` restricts phases and disables noisy techniques:

```yaml
  stealth_ad:
    description: "AD recon - minimal noise, anonymous/passive only"
    opsec_mode: stealth
    timing:
      nmap_timing: T2
      scan_delay: "500ms"
    ad:
      phases:
        - passive
      anonymous_only: true
      ldap_queries: true
      smb_null_session: true
      rid_cycling: false
      enum4linux_ng: false
      impacket: false
    allowed_noise_levels:
      - low
```

### Profile Resolution Order

When `ProfileLoader` is initialized with `(config, opsec_mode, module)`, it resolves:

1. **Module-specific variant** (most specific): `{base_mode}_{module}` (e.g., `stealth_ad`)
2. **Exact match**: `opsec_mode` as-is
3. **Base mode**: via canonical mapping (`stealth`, `normal`, `aggressive`)
4. **Empty dict**: all defaults

---

## ToolConfig Accessor

The `ToolConfig` class provides typed access to tool YAML configuration inside tool wrappers:

```python
from core.tool_config import ToolConfig

class GobusterTool:
    def __init__(self, runner, logger, output_dir, opsec_mode="normal", config=None):
        self.tool_cfg = ToolConfig(config, "gobuster")

    def dir_scan(self, target, timeout=600):
        # Timeout resolution: mode-specific → tool default → caller default
        effective_timeout = self.tool_cfg.mode_timeout("dir", timeout)
        threads = self.tool_cfg.mode_value("dir", "threads", 50)
        args = self.tool_cfg.mode_args("dir", default="dir -t 50")
```

### Timeout Resolution Hierarchy

```
mode-specific timeout → tool default_timeout → caller default
```

`ToolConfig.effective_timeout(mode, caller_default)` resolves this chain automatically.

### Backward Compatibility

`ToolConfig(None, "tool")` returns caller-supplied defaults for every accessor — providing full backward compatibility for tools not yet consuming configuration.

### Key Methods

| Method | Description |
|--------|-------------|
| `binary` | Primary binary name |
| `alt_binary` | Alternative binary name |
| `required` | Whether tool is required |
| `default_timeout` | Top-level timeout from YAML |
| `has_config` | Whether a non-empty YAML entry was loaded |
| `mode_timeout(mode, default)` | Timeout for a named mode |
| `mode_args(mode, default)` | Argument string for a mode |
| `mode_detection(mode, default)` | Detection level for a mode |
| `mode_value(mode, key, default)` | Arbitrary key from a mode entry |
| `mode_requires_root(mode)` | Whether a scan profile requires root |
| `safety(key, default)` | Read from the `safety:` block |
| `collection(method, key, default)` | Read from `collection_methods` |
| `get(dotted_key, default)` | Dot-notation generic getter |
| `effective_timeout(mode, caller_default)` | Unified timeout resolution |

---

## ProfileLoader

The `ProfileLoader` class resolves and queries OPSEC profiles:

```python
from core.profile_loader import ProfileLoader

loader = ProfileLoader(config_loader, opsec_mode="stealth", module="ad")

# Access timing
timing = loader.timing              # {"nmap_timing": "T2", "scan_delay": "500ms", ...}
nmap_t = loader.nmap_timing         # "T2"

# Check noise levels
allowed = loader.allowed_noise      # ["low"]

# Check technique toggles
can_rid = loader.is_technique_enabled("rid_cycling")  # False for stealth_ad

# Get enabled phases
phases = loader.enabled_phases()    # ["passive"] for stealth_ad

# Deep access
anon = loader.get("ad.anonymous_only", default=False)  # True for stealth_ad
```

### Key Properties

| Property / Method | Description |
|-------------------|-------------|
| `profile_data` | Full resolved profile dict |
| `opsec_mode` | Effective OPSEC mode string |
| `timing` | Timing configuration dict |
| `allowed_noise` | List of allowed noise levels |
| `nmap_timing` | nmap `-T` value (e.g., `T2`) |
| `scan_delay` | nmap `--scan-delay` value |
| `max_retries` | nmap `--max-retries` value |
| `section(key)` | Top-level section of the profile |
| `get(dotted_key, default)` | Deep dot-notation access |
| `is_technique_enabled(technique)` | Check technique toggle |
| `enabled_phases()` | Profile-restricted phase list (or None) |

---

*Configuration system validated: 2026-03-21 — 375/375 tests passing*
