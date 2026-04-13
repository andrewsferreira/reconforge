# API Module Hardening — PRIORITY 5 Changelog

**Author:** Andrews Ferreira  
**Date:** 2026-03-20  
**Scope:** `modules/api/parsers/*`, `modules/api/phases/*`, `modules/api/api_module.py`

---

## Executive Summary

PRIORITY 5 transforms the API module from a pattern-heavy, heuristic-driven scanner
into a technically robust, evidence-based API reconnaissance engine.  Every phase
now requires stronger proof before reporting, the OpenAPI parser handles real-world
specs properly, and JWT analysis provides deep, actionable intelligence.

---

## 1. OpenAPI Parser (`parsers/openapi_parser.py`)

### BEFORE
- Only extracted `parameters` from path operations
- No `$ref` resolution — `$ref: '#/components/schemas/User'` was ignored
- Security schemes extracted without OAuth2 flow details
- No support for `requestBody` (OpenAPI 3.x)
- No support for composed schemas (`oneOf`, `anyOf`, `allOf`)
- No error reporting for malformed specs
- Single flat `OpenApiEndpoint` dataclass

### AFTER
- **Full `$ref` resolution**: Recursive resolver handles `#/components/schemas/*`,
  `#/components/parameters/*`, `#/components/requestBodies/*`, `#/definitions/*`
  (Swagger 2.x), with circular reference detection and depth limit (20)
- **`requestBody` parsing**: Extracts content types, resolved schemas, required
  fields, and examples.  Swagger 2.x `body` parameters auto-converted
- **Complex schema support**: `oneOf`, `anyOf`, `allOf` composition; nested
  objects; arrays with item types; enum values; format hints
- **OAuth2 flow extraction**: Authorization URLs, token URLs, scopes per flow
  (implicit, authorizationCode, clientCredentials, password)
- **Rich data classes**: `ResolvedSchema`, `OpenApiParameter`, `OpenApiRequestBody`,
  `OpenApiEndpoint` (with `all_parameter_names`, `accepts_input`, `to_dict`)
- **Robust error handling**: `parse_errors` and `parse_warnings` lists on
  `OpenApiSpec` — parser never raises, always returns a result
- **Backward compatible**: `OpenApiSpec.authenticated_endpoints`,
  `unauthenticated_endpoints`, `by_tag` still work
- **New properties**: `endpoints_with_body`, `deprecated_endpoints`,
  `input_endpoints`, `endpoint_count`, `summary()`

### Example
```python
parser = OpenApiParser()
spec = parser.parse(Path("petstore.json"))

# $ref resolved
for ep in spec.endpoints:
    print(ep.path, ep.method, ep.all_parameter_names)
    if ep.request_body:
        print("  Body fields:", ep.request_body.fields)
        print("  Content types:", ep.request_body.content_types)

# Auth schemes with OAuth2 details
for scheme in spec.auth_schemes:
    print(scheme.name, scheme.auth_type)
    if scheme.oauth_flows:
        print("  Flows:", scheme.oauth_flows)

# Errors/warnings
if spec.parse_errors:
    print("Errors:", spec.parse_errors)
```

---

## 2. Authentication Phase (`phases/authentication.py`)

### BEFORE
- JWT analysis: decoded header, checked `alg=none` and `HS256`
- No payload claims extraction
- No expiration checks
- No `kid`/`jku`/`x5u` header analysis
- Limited OpenAPI auth scheme analysis
- No OAuth2 flow-specific checks

### AFTER
- **Deep JWT claims extraction**: `sub`, `iss`, `exp`, `aud`, `iat`, `nbf`, `jti`,
  scope/scp, roles/groups/permissions, custom claim count
- **JWT misconfiguration checks**:
  - Missing `exp` claim → medium severity (token never expires)
  - Expired token detection with age calculation
  - Excessively long token lifetime (>24h) → low severity
  - Missing `iss` / `aud` claims → info (reduced validation surface)
  - Sensitive data in payload (`password`, `secret`, etc.) → high severity
  - Empty/trivial signature → high severity
- **Header attack vector analysis**:
  - `kid` parameter injection indicators (SQL injection, path traversal)
  - `jku` / `x5u` header SSRF potential
- **Enhanced OpenAPI auth analysis**:
  - OAuth2 implicit flow deprecation warning
  - Bearer format (JWT) detection
  - OpenID Connect URL extraction
- **Smarter unauthenticated endpoint check**: Now requires both sensitive
  keyword match AND `accepts_input` (parameters or request body), reducing
  noise from `/health` and `/status` endpoints
- **HS256 remains info-only** (unchanged from PRIORITY 3)

### JWT Output Example (BEFORE → AFTER)
```
# BEFORE
JWT header: alg=HS256   → info: "JWT uses symmetric algorithm"

# AFTER
JWT header: alg=HS256   → info: "JWT uses symmetric algorithm"
JWT claims: sub=user123, iss=api.example.com, exp=1742515200
  → info: "JWT lacks 'aud' claim"
  → medium: "JWT has long expiration: ~720 hours"
JWT header: kid=key-001
  → info: "JWT header contains 'kid' parameter: key-001"
     Recommendation: "Test for kid injection: SQL injection in kid value..."
```

---

## 3. Authorization Phase (`phases/authorization.py`)

### BEFORE
- Flat `IDOR_PATTERNS` list of parameter names
- URL substring matching for IDOR-prone paths
- All matches reported at `low`/`heuristic`
- No scoring — every match got the same treatment
- No specific test case generation

### AFTER
- **Scoring-based IDOR detection**: Multiple structural signals scored independently:
  - Resource path structure (`/users/{id}`) → 0.3–0.5
  - HTTP method weight (DELETE: 0.4, PUT/PATCH: 0.3, POST: 0.2, GET: 0.1)
  - Numeric/UUID path segment detection → 0.3
  - Endpoint accessibility (HTTP 200) → 0.1
- **Configurable threshold**: Only candidates with score ≥ 0.4 are reported
  (eliminates low-signal noise)
- **Parameter scoring reduced**: Parameter names alone only contribute 0.2;
  need additional signal (mutating method) to reach threshold
- **Per-candidate test cases**: Generated with specific steps for each
  IDOR candidate (different steps for GET vs PUT vs DELETE)
- **Response-based auth patterns**: Detects inconsistent response sizes
  across same-path endpoints (possible partial data exposure)
- **Normalised path grouping**: Groups endpoints by path pattern for analysis
- **Helper methods**: `_looks_like_id()` detects numeric, UUID, hex,
  and slug-with-digits patterns

### Noise Reduction Example
```
# BEFORE: 15 IDOR findings from parameter names like "id", "name", "type"
# AFTER:  3 scored candidates above threshold
  - DELETE /users/{id}  (score: 0.8, signals: path_pattern, mutating_method)
  - PUT /accounts/{id}  (score: 0.7, signals: path_pattern, mutating_method)
  - GET /profiles/12345 (score: 0.5, signals: id_in_path, accessible:200)
```

---

## 4. Fuzzing Phase (`phases/fuzzing.py`)

### BEFORE
- HTTP 500 → `low`/`heuristic` finding (no content analysis)
- No response body inspection
- No error fingerprinting
- Same treatment for SQL errors and generic 500s

### AFTER
- **Error fingerprint library**: 50+ regex patterns across 5 categories:
  - SQL injection: MySQL, PostgreSQL, Oracle, MSSQL, SQLite patterns
  - Stack traces: Python, Java, .NET, PHP frameworks
  - Command injection: `/etc/passwd`, `uid=`, Windows paths
  - Template injection: Jinja2, FreeMarker, SSTI indicators
  - Information disclosure: DEBUG=True, connection strings, config exposure
- **Evidence-based classification**: Each HTTP 500 is classified:
  - SQL error detected → `high` severity, `high` confidence
  - Command execution evidence → `critical` severity, `high` confidence
  - Stack trace exposed → `medium` severity, `high` confidence
  - Template injection → `high` severity, `medium` confidence
  - Generic 500 (no evidence) → `low` severity, `heuristic` confidence
- **200 response analysis**: Checks for information disclosure in
  non-error responses (debug mode, config leaks)
- **Rich evidence strings**: Include specific regex match, input word,
  response size, and status code

### Classification Example
```
# BEFORE
HTTP 500 with input "' OR 1=1--" → low/heuristic: "Server error triggered"

# AFTER
HTTP 500 with input "' OR 1=1--" → high/high: "Potential SQL injection"
  Evidence: "SQL error pattern detected: Warning: mysqli_query()...
            Status: HTTP 500, Input: \"' OR 1=1--\", Response size: 2048 bytes"
```

---

## 5. Discovery Phase (`phases/discovery.py`)

### BEFORE
- Detected spec URLs but didn't parse them
- `spec_data` key not populated in results
- No endpoint enrichment from specs

### AFTER
- **Spec parsing integration**: Discovered specs are parsed through enhanced
  OpenApiParser with full `$ref` resolution
- **`spec_data` populated**: Downstream phases receive a complete `OpenApiSpec`
  object with resolved schemas, requestBodies, and auth schemes
- **Endpoint enrichment**: Endpoints from parsed spec added to discovery
  results (with `source: "openapi_spec"` tag)
- **Deprecated endpoint reporting**: Spec-declared deprecated endpoints flagged
- **Spec summary in results**: Quick summary dict with counts

---

## 6. API Module Orchestrator (`api_module.py`)

### Changes
- `spec_data` now properly passed from Phase 1 → Phase 2 (authentication)
- `discovered_params` from Phase 3 (fuzzing) passed to Phase 4 (authorization)
- `spec_data` passed to Phase 4 for structural analysis

---

## Acceptance Criteria Verification

| Criterion | Status |
|-----------|--------|
| OpenAPI parser handles `requestBody` | ✅ Full parsing with content type + schema |
| OpenAPI parser resolves `$ref` | ✅ Recursive resolver with circular detection |
| API findings require stronger validation | ✅ Evidence-based scoring replaces flat patterns |
| Reduced noise in results | ✅ IDOR threshold scoring, fingerprint-based fuzzing |
| Better technical depth in analysis | ✅ JWT claims, OAuth2 flows, error fingerprints |
| Clear documentation of improvements | ✅ This file |

---

## Files Modified

| File | Change Type |
|------|-------------|
| `modules/api/parsers/openapi_parser.py` | **Rewritten** — $ref resolver, requestBody, schemas |
| `modules/api/phases/authentication.py` | **Rewritten** — JWT deep analysis, OAuth2 checks |
| `modules/api/phases/authorization.py` | **Rewritten** — scoring-based IDOR, test cases |
| `modules/api/phases/fuzzing.py` | **Rewritten** — error fingerprints, content analysis |
| `modules/api/phases/discovery.py` | **Enhanced** — spec parsing, endpoint enrichment |
| `modules/api/api_module.py` | **Updated** — proper spec_data/params passing |

---

*Generated by ReconForge PRIORITY 5 hardening — 2026-03-20*
