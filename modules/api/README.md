# ReconForge API Module

**Author:** Andrews Ferreira

## Overview

The API module provides automated reconnaissance and security assessment for
REST/JSON APIs. It follows a four-phase kill chain designed to systematically
discover, test, and assess API security posture.

## Phases

### Phase 1: Discovery
- HTTP probing with **httpx** (status, headers, technology)
- OpenAPI/Swagger specification detection and parsing
- Endpoint enumeration with **ffuf** (common API paths)
- API version detection and base path identification

### Phase 2: Authentication
- Auth mechanism analysis from OpenAPI specs (Bearer, API key, OAuth2, Basic)
- Auth endpoint testing (login, token, register)
- JWT analysis (algorithm detection, `alg=none` vulnerability)
- **Nuclei** authentication template scanning

### Phase 3: Fuzzing
- Hidden parameter discovery with **Arjun**
- Parameter fuzzing with **ffuf** (common API params, injection payloads)
- Sensitive parameter detection (password, token, secret, key patterns)

### Phase 4: Authorization (opt-in)
- BOLA/IDOR pattern detection (numeric ID manipulation)
- **Nuclei** authorization template scanning
- Access control checks (admin paths, role escalation)
- Rate limiting assessment

## Tools

| Tool    | Purpose                           | Detection Level |
|---------|-----------------------------------|-----------------|
| httpx   | HTTP probing & tech detection     | Low             |
| ffuf    | Endpoint/parameter fuzzing        | Medium          |
| Arjun   | Hidden parameter discovery        | Medium          |
| Nuclei  | Template-based vulnerability scan | Medium          |

## Usage

### CLI

```bash
# Basic scan (phases 1-3)
reconforge api --target https://api.example.com/v1

# Stealth mode
reconforge api --target https://api.example.com --opsec stealth

# Full scan including authorization testing
reconforge api --target https://api.example.com --phases discovery,authentication,fuzzing,authorization

# With authentication
reconforge api --target https://api.example.com --auth-token "Bearer eyJ..."

# Custom headers
reconforge api --target https://api.example.com --header "X-Api-Key: abc123" --header "X-Custom: value"
```

### Python API

```python
from modules.api.api_module import APIModule

module = APIModule(
    target="https://api.example.com/v1",
    opsec_mode="normal",
    auth_token="Bearer eyJhbG...",
    headers=["X-Api-Key: abc123"],
)
results = module.run()
```

## OPSEC Profiles

| Profile    | Phases                                          | Notes                        |
|------------|------------------------------------------------|------------------------------|
| stealth    | discovery                                       | Passive probing only         |
| normal     | discovery, authentication, fuzzing              | Balanced approach            |
| aggressive | discovery, authentication, fuzzing, authorization | Full coverage incl. authz   |

## Output Structure

```
outputs/<target>/api/
├── raw/           # Raw tool output (JSON, JSONL)
├── parsed/        # Parsed and normalised results
├── findings.json  # All findings in structured format
├── findings.md    # Human-readable findings
├── report.md      # Executive summary
├── session.md     # Session notes and timeline
├── attack_paths.md# Identified attack chains
├── commands.log   # All executed commands
└── loot.json      # Extracted credentials and tokens
```

## Detection Map

All techniques have OPSEC-aware detection levels:

| Technique              | Noise Level | Description                         |
|-----------------------|-------------|-------------------------------------|
| httpx_api_probe       | low         | HTTP probe with httpx               |
| api_spec_detection    | low         | OpenAPI/Swagger spec detection      |
| ffuf_api_scan         | medium      | FFUF API endpoint enumeration       |
| ffuf_api_fuzz         | medium      | FFUF parameter fuzzing              |
| arjun_param_discovery | medium      | Arjun hidden parameter discovery    |
| nuclei_api_scan       | medium      | Nuclei API template scan            |
| api_auth_testing      | medium      | Authentication mechanism testing    |
| api_authz_testing     | high        | Authorization/BOLA testing          |
| api_rate_limit_check  | low         | Rate limiting assessment            |
