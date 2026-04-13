# ReconForge Support Matrix

> **See also:** [SETUP.md](SETUP.md) for installation, [MODULES.md](MODULES.md) for module details.


> Version 1.1.0 — Last updated: 2026-04-13

---

## Python Versions

| Version | Status | Notes |
|---------|--------|-------|
| 3.10 | ✅ Supported (minimum) | `match` statements not used; `dataclass` features require 3.10+ |
| 3.11 | ✅ Tested | Primary development and CI target |
| 3.12 | ✅ Supported | Compatible; no deprecated API usage |
| 3.13+ | ⚠️ Untested | Expected to work; not yet validated |
| 3.9 and below | ❌ Unsupported | Uses `list[str]` type hints (PEP 585), `dataclass(slots=True)`, `|` union syntax |

---

## Operating Systems / Platforms

| Platform | Status | Notes |
|----------|--------|-------|
| Kali Linux (latest) | ✅ Tested | Recommended. Most external tools pre-installed. |
| Parrot OS | ✅ Supported | Similar tool availability to Kali. |
| Ubuntu 22.04+ | ✅ Supported | Tools available via `apt` / `pip` / `go install`. |
| Debian 12+ | ✅ Supported | Same package availability as Ubuntu. |
| Arch Linux | ⚠️ Untested | Tools available via `pacman` / AUR; expected to work. |
| macOS | ⚠️ Partial | Python core works. Some tools (`nmap`, `enum4linux`) available via Homebrew. `hydra`, `smbclient` require manual setup. Root-requiring scans (`-sS`, `-sU`) need `sudo`. |
| Windows / WSL2 | ⚠️ Partial | WSL2 with Kali/Ubuntu image works. Native Windows unsupported — `subprocess.run` assumes POSIX tool paths. |
| Docker | ✅ Supported | Run in any Linux-based container with tools installed. No official Dockerfile yet. |

---

## Python Dependencies

| Package | Required | Version | Purpose |
|---------|----------|---------|---------|
| `pyyaml` | ✅ Yes | ≥ 6.0 | YAML config loading (`config_loader.py`) |
| `cryptography` | ❌ Optional | ≥ 41.0 | Fernet encryption for loot vault (`--encrypt-loot`) |
| `pytest` | ❌ Dev only | ≥ 7.0 | Test runner |
| `pytest-cov` | ❌ Dev only | ≥ 4.0 | Coverage reporting |

No other Python packages are required. The framework is intentionally dependency-light.

---

## External Tools by Module

Missing tools are detected at runtime and their features are gracefully skipped. No tool absence causes a crash.

### Network Module

| Tool | Required | Install | Purpose |
|------|----------|---------|---------|
| `nmap` | ✅ | `sudo apt install nmap` | Host discovery, port scanning, NSE scripts |
| `enum4linux` | ❌ | `sudo apt install enum4linux` | SMB/NetBIOS enumeration |
| `smbclient` | ❌ | `sudo apt install smbclient` | SMB share access |
| `ldapsearch` | ❌ | `sudo apt install ldap-utils` | LDAP queries |
| `hydra` | ❌ | `sudo apt install hydra` | Brute-force (opt-in only, requires `--brute-force` flag) |

### Web Module

| Tool | Required | Install | Purpose |
|------|----------|---------|---------|
| `gobuster` | ❌ | `go install github.com/OJ/gobuster/v3@latest` | Directory/file brute-forcing |
| `ffuf` | ❌ | `go install github.com/ffuf/ffuf/v2@latest` | Content discovery, fuzzing |
| `nikto` | ❌ | `sudo apt install nikto` | Web vulnerability scanning |
| `nuclei` | ❌ | `go install github.com/projectdiscovery/nuclei/v3@latest` | Template-based vuln scanning |
| `whatweb` | ❌ | `sudo apt install whatweb` | Technology fingerprinting |
| `wafw00f` | ❌ | `pip install wafw00f` | WAF detection |
| `wpscan` | ❌ | `gem install wpscan` | WordPress enumeration |
| `sqlmap` | ❌ | `sudo apt install sqlmap` | SQL injection detection (opt-in) |
| `curl` | ❌ | Pre-installed on most systems | HTTP probing |

### API Module

| Tool | Required | Install | Purpose |
|------|----------|---------|---------|
| `ffuf` | ❌ | `go install github.com/ffuf/ffuf/v2@latest` | API endpoint fuzzing |
| `httpx` | ❌ | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` | HTTP probing and tech detection |
| `arjun` | ❌ | `pip install arjun` | Hidden parameter discovery |
| `nuclei` | ❌ | `go install github.com/projectdiscovery/nuclei/v3@latest` | API-specific vulnerability templates |

### Surface Module

| Tool | Required | Install | Purpose |
|------|----------|---------|---------|
| `nmap` | ✅ | `sudo apt install nmap` | Stealth port discovery |

### AD Module

| Tool | Required | Install | Purpose |
|------|----------|---------|---------|
| `nmap` | ✅ | `sudo apt install nmap` | AD service detection |
| `enum4linux-ng` | ❌ | `pip install enum4linux-ng` | Modern SMB/RPC enumeration |
| `impacket` | ❌ | `pip install impacket` | GetADUsers, GetNPUsers, lookupsid, rpcdump |
| `ldapsearch` | ❌ | `sudo apt install ldap-utils` | LDAP queries |
| `smbclient` | ❌ | `sudo apt install smbclient` | Share enumeration |
| `bloodhound-python` | ❌ | `pip install bloodhound` | BloodHound data collection |
| `netexec` | ❌ | `pip install netexec` | Multi-protocol enumeration |

---

## Root / Privileged Operations

Some operations require root or `CAP_NET_RAW`:

| Operation | Why | Workaround |
|-----------|-----|------------|
| `nmap -sS` (SYN scan) | Raw socket access | Use `-sT` (connect scan) as non-root |
| `nmap -sU` (UDP scan) | Raw socket access | None — requires root |
| `nmap -O` (OS detection) | Raw socket access | Skip OS detection as non-root |

ReconForge does not escalate privileges itself. Run with `sudo` when root-requiring profiles are needed.

---

## Known Unsupported Environments

| Environment | Reason |
|-------------|--------|
| Python < 3.10 | Modern type hint syntax, dataclass features |
| Native Windows (no WSL) | POSIX subprocess assumptions, tool path resolution |
| Alpine Linux (musl) | Some pip packages (`cryptography`) require build toolchain; fixable but untested |
| Restricted shells / containers without `subprocess` | Framework relies entirely on `subprocess.run` for tool execution |
| Air-gapped without pre-installed tools | No auto-download of external binaries; tools must be pre-installed |
