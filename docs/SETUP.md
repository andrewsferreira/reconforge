# ReconForge Setup Guide

> **See also:** [USAGE.md](USAGE.md) for CLI reference, [CONFIGURATION.md](CONFIGURATION.md) for tool/profile configuration.


## Prerequisites

* **Python 3.10+**
* **pip** (or pipx)
* A Linux environment (Kali, Parrot, Ubuntu) is recommended.

## Quick Install

```bash
# Clone the repo
git clone <repo-url> reconforge && cd reconforge

# Install Python dependencies
pip install -r requirements.txt

# (Optional) Install external recon tools
sudo apt install -y nmap smbclient ldap-utils
pip install enum4linux-ng impacket
```

## Python Dependencies

| Package | Required | Purpose |
|---------|----------|---------|
| `pyyaml` | ✅ | YAML config loading |
| `cryptography` | ❌ | Optional Fernet encryption for loot (`--encrypt-loot`) |
| `pytest` | ❌ | Running the test suite |
| `pytest-cov` | ❌ | Coverage reporting |

## External Tools

ReconForge wraps the following tools.  Missing tools are detected at
runtime and their features are gracefully skipped.

### Network Module
| Tool | Install | Purpose |
|------|---------|---------|
| nmap | `sudo apt install nmap` | Host discovery, port scanning, NSE scripts |
| enum4linux | `sudo apt install enum4linux` | SMB/NetBIOS enumeration |
| smbclient | `sudo apt install smbclient` | SMB share access |
| ldapsearch | `sudo apt install ldap-utils` | LDAP queries |
| hydra | `sudo apt install hydra` | Brute-force (opt-in) |

### AD Module
| Tool | Install | Purpose |
|------|---------|---------|
| enum4linux-ng | `pip install enum4linux-ng` | Modern SMB/RPC enum |
| impacket | `pip install impacket` | GetADUsers, GetNPUsers, lookupsid, rpcdump |
| nmap | `sudo apt install nmap` | AD service detection |
| ldapsearch | `sudo apt install ldap-utils` | LDAP queries |
| smbclient | `sudo apt install smbclient` | Share enumeration |

### Web Module
| Tool | Install | Purpose |
|------|---------|---------|
| ffuf | `go install github.com/ffuf/ffuf/v2@latest` | Content discovery |
| nikto | `sudo apt install nikto` | Web vulnerability scanner |
| whatweb | `sudo apt install whatweb` | Technology fingerprinting |

## Running Tests

```bash
pip install pytest pytest-cov
python -m pytest tests/ -v
python -m pytest tests/ --cov=core --cov=modules --cov-report=term-missing
```

## Configuration

All YAML config lives in `config/`:

* **tools.yaml** — tool binaries, default args, timeouts.
* **profiles.yaml** — OPSEC scan profiles (stealth / normal / aggressive).

Override the config directory with `--config-dir` or by passing
`config_dir=` to the module constructor.
