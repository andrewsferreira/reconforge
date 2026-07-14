# ReconForge Configuration Guide

> Version 1.2.0 — Last updated: 2026-07-14

## Overview

ReconForge uses two YAML configuration files as the single source of truth:

| File | Purpose |
|------|---------|
| `config/tools.yaml` | Tool binary paths, default arguments, timeouts, scan profiles, safety settings |
| `config/profiles.yaml` | OPSEC-aware scan profiles with timing, technique toggles, and noise-level gates |

There are no fallback namespaces or hardcoded config overrides for these two files — they are authoritative for tool/profile settings. Several cross-cutting behaviors (secrets backend selection, a kill switch, encryption key overrides, an optional risk-approval gate) are controlled by environment variables instead, since they're either security-sensitive (keys should not have to live in a YAML file) or need to be settable without editing a checked-in config file — see [Environment Variables](#environment-variables) below.

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

## Environment Variables

All of these are optional and off/empty by default — a fresh checkout with no environment variables set behaves the same as it always has. None of them live in `tools.yaml`/`profiles.yaml` because each is either security-sensitive (a key shouldn't have to live in a checked-in-adjacent file) or needs to be flippable without editing a file (an emergency stop).

| Variable | Default | Effect |
|----------|---------|--------|
| `RECONFORGE_KILL_SWITCH` | unset | Set to `1` to make every `Runner.run()` call refuse to execute (`core/runner.py::_kill_switch_active()`). An emergency global stop — checked before every single command, not just once at startup. |
| `RECONFORGE_KILL_SWITCH_FILE` | unset | Path to a sentinel file; if its contents (trimmed, lowercased) are one of `1`/`true`/`on`/`stop`/`blocked`, has the same effect as `RECONFORGE_KILL_SWITCH=1`. Useful when you want to flip the switch from another process/script without touching the running one's environment. |
| `RECONFORGE_POLICY_ENFORCE` | unset (disabled) | Set to `1` to enable `core/risk_policy.py::RiskPolicyEngine` — a second, independent approval-tier gate on top of the `--opsec` noise model. When enabled, every command is classified `low`/`medium`/`high` by a keyword match (`sqlmap`/`hydra`/`netexec` → high; `nuclei`/`nikto`/`ffuf`/`wpscan`/`enum4linux`/`impacket` → medium; everything else → low) and blocked unless `RECONFORGE_APPROVAL_TIER` is at least that tier. **Off by default deliberately, not by oversight**: this project's primary safety model is `--opsec` (stealth/normal/aggressive noise gating, on by default, CLI-flag-driven) plus explicit per-feature opt-in flags (`--brute-force` for hydra, `--authorized-target`/`--lab-mode`/`--enforce-scope` for authorization). Enabling this by default would silently block core, already-safety-gated AD-module functionality (`impacket`/`enum4linux` classified "medium") behind an undocumented env var instead of a discoverable CLI flag — a worse default, not a safer one. It exists for environments that want a *third*, coarser-grained layer (e.g. a blanket "nothing above medium risk without a human setting an env var first" policy for compliance reasons) on top of the two mechanisms above, not as a replacement for either. |
| `RECONFORGE_APPROVAL_TIER` | `low` | The approval tier granted when `RECONFORGE_POLICY_ENFORCE=1` — one of `low`/`medium`/`high`. Has no effect unless enforcement is also enabled. |
| `RECONFORGE_LOOT_KEY` | unset | Base64 urlsafe Fernet key for `core/loot_manager.py`'s encryption, taking precedence over the on-disk key file. Keeps the key off disk entirely — recommended if the loot file itself may leave this machine. |
| `RECONFORGE_VAULT_KEY` | unset | Same as `RECONFORGE_LOOT_KEY`, for `core/credential_vault.py`. |
| `RECONFORGE_NVD_LOOKUP` | unset (disabled) | Set to `1` to let `core/cve_enricher.py` make live NVD API lookups for CPE strings found in findings (rate-limited, cached — see `docs/ARCHITECTURE_REVIEW.md`'s Phase 20 entry). Off by default since it's a live network call from inside `FindingsManager.add()`, called in tight per-finding loops. |
| `RECONFORGE_ENV` | `dev` | Selects which `config/environments/<name>.yaml` overlay `ConfigLoader` merges on top of `tools.yaml`/`profiles.yaml`. |
| `RECONFORGE_SECRET_PROVIDER` | `env` | Backend for `core/secrets_manager.py::SecretManager` — one of `env`, `file`, `aws_secretsmanager` (needs `boto3`), `vault` (HashiCorp Vault KV v2). |
| `RECONFORGE_SECRETS_FILE` | unset | Path to the JSON key/value file, when `RECONFORGE_SECRET_PROVIDER=file`. |

Not covered above: the Burp MCP integration (`core/adapters/burp/`, `reconforge/entrypoints/burp_validation.py`) reads its own `BURP_MCP_URL`/`BURP_MCP_BASE_URL` and related variables — see `docs/BURP_MCP_INTEGRATION.md` for that subsystem, which is a distinct integration surface from the recon-module configuration this guide covers.

---

*Configuration system last reviewed: 2026-07-14, 878/878 tests passing — see `docs/ARCHITECTURE_REVIEW.md` for the current, continuously-updated audit trail rather than treating this stamp as authoritative going forward.*
