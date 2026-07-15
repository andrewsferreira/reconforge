"""ReconForge OpenAPI/Swagger Parser - Parse API specifications.

Author: Andrews Ferreira

PRIORITY 5 hardened parser with:
- Full $ref resolution for components/schemas
- requestBody parsing (not just parameters)
- Proper security scheme extraction (OAuth2 flows, scopes)
- Complex nested schema support (oneOf, anyOf, allOf, arrays)
- OpenAPI 3.x full support + Swagger 2.x backwards compat
- Robust error handling for malformed specs

Extracts:
- API endpoints with methods, parameters, and request bodies
- Authentication schemes (apiKey, http, oauth2, openIdConnect)
- Parameter definitions with resolved types
- Schema information with nested structure
- Server/base URL details
- Response schemas
"""

import json
import logging
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("reconforge.openapi_parser")


# ── Data Classes ────────────────────────────────────────────────────


@dataclass
class ResolvedSchema:
    """A fully resolved schema from $ref traversal."""
    schema_type: str = ""          # object, array, string, integer, etc.
    properties: dict[str, Any] = field(default_factory=dict)
    required_fields: list[str] = field(default_factory=list)
    items_type: str = ""           # For array types
    enum_values: list[Any] = field(default_factory=list)
    format_hint: str = ""          # date-time, email, uri, uuid, etc.
    description: str = ""
    example: Any = None
    composition: str = ""          # oneOf, anyOf, allOf
    composition_schemas: list["ResolvedSchema"] = field(default_factory=list)
    nullable: bool = False
    raw: dict = field(default_factory=dict)

    @property
    def is_complex(self) -> bool:
        """Whether this schema has nested structure."""
        return bool(self.properties or self.composition_schemas)

    @property
    def field_names(self) -> list[str]:
        """All property/field names (including from composed schemas)."""
        names = list(self.properties.keys())
        for sub in self.composition_schemas:
            names.extend(sub.field_names)
        return names


@dataclass
class OpenApiParameter:
    """A single API parameter (query, path, header, cookie, or body field)."""
    name: str = ""
    location: str = ""       # query, path, header, cookie, body
    required: bool = False
    param_type: str = ""     # string, integer, boolean, object, array
    format_hint: str = ""    # date-time, email, uuid, etc.
    description: str = ""
    example: Any = None
    enum_values: list[Any] = field(default_factory=list)
    schema: ResolvedSchema | None = None


@dataclass
class OpenApiRequestBody:
    """A parsed requestBody definition."""
    required: bool = False
    content_types: list[str] = field(default_factory=list)
    schema: ResolvedSchema | None = None
    description: str = ""
    examples: dict[str, Any] = field(default_factory=dict)

    @property
    def fields(self) -> list[str]:
        """Extract field names from request body schema."""
        if self.schema:
            return self.schema.field_names
        return []


@dataclass
class OpenApiEndpoint:
    """A single API endpoint from OpenAPI spec."""
    path: str = ""
    method: str = ""
    summary: str = ""
    description: str = ""
    operation_id: str = ""
    parameters: list[OpenApiParameter] = field(default_factory=list)
    request_body: OpenApiRequestBody | None = None
    security: list[dict] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    responses: dict[str, Any] = field(default_factory=dict)
    requires_auth: bool = False
    deprecated: bool = False

    @property
    def all_parameter_names(self) -> list[str]:
        """All parameter names including request body fields."""
        names = [p.name for p in self.parameters]
        if self.request_body and self.request_body.schema:
            names.extend(self.request_body.schema.field_names)
        return names

    @property
    def accepts_input(self) -> bool:
        """Whether this endpoint accepts any user input."""
        return bool(self.parameters or self.request_body)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict for backward compatibility."""
        # Flatten parameters for legacy consumers
        params = []
        for p in self.parameters:
            params.append({
                "name": p.name,
                "in": p.location,
                "required": p.required,
                "type": p.param_type,
                "format": p.format_hint,
                "description": p.description,
            })
        if self.request_body and self.request_body.schema:
            for fname in self.request_body.schema.field_names:
                params.append({
                    "name": fname,
                    "in": "body",
                    "required": fname in (self.request_body.schema.required_fields or []),
                    "type": self.request_body.schema.properties.get(fname, {}).get("type", ""),
                })
        return {
            "path": self.path,
            "method": self.method,
            "summary": self.summary,
            "operation_id": self.operation_id,
            "parameters": params,
            "has_request_body": self.request_body is not None,
            "requires_auth": self.requires_auth,
            "deprecated": self.deprecated,
            "tags": self.tags,
        }


@dataclass
class OpenApiAuthScheme:
    """Authentication scheme from OpenAPI spec."""
    name: str = ""
    auth_type: str = ""       # apiKey, http, oauth2, openIdConnect
    scheme: str = ""          # bearer, basic, etc.
    location: str = ""        # header, query, cookie
    param_name: str = ""      # e.g., "Authorization", "X-API-Key"
    bearer_format: str = ""   # JWT, opaque, etc.
    # OAuth2 specifics
    oauth_flows: dict[str, Any] = field(default_factory=dict)
    openid_connect_url: str = ""

    @property
    def is_jwt_bearer(self) -> bool:
        """Whether this scheme likely uses JWT."""
        return (
            self.auth_type == "http"
            and self.scheme == "bearer"
            and self.bearer_format.lower() in ("jwt", "")
        )

    @property
    def is_api_key_in_query(self) -> bool:
        """API key passed as query parameter (weak practice)."""
        return self.auth_type == "apiKey" and self.location == "query"


@dataclass
class OpenApiSpec:
    """Parsed OpenAPI specification."""
    title: str = ""
    version: str = ""
    spec_version: str = ""       # "openapi_3.0.3" or "swagger_2.0"
    description: str = ""
    servers: list[str] = field(default_factory=list)
    endpoints: list[OpenApiEndpoint] = field(default_factory=list)
    auth_schemes: list[OpenApiAuthScheme] = field(default_factory=list)
    global_security: list[dict] = field(default_factory=list)
    raw_spec: dict = field(default_factory=dict)
    parse_errors: list[str] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)

    @property
    def by_tag(self) -> dict[str, list[OpenApiEndpoint]]:
        groups: dict[str, list[OpenApiEndpoint]] = {}
        for ep in self.endpoints:
            for tag in (ep.tags or ["untagged"]):
                groups.setdefault(tag, []).append(ep)
        return groups

    @property
    def authenticated_endpoints(self) -> list[OpenApiEndpoint]:
        return [ep for ep in self.endpoints if ep.requires_auth]

    @property
    def unauthenticated_endpoints(self) -> list[OpenApiEndpoint]:
        return [ep for ep in self.endpoints if not ep.requires_auth]

    @property
    def endpoints_with_body(self) -> list[OpenApiEndpoint]:
        """Endpoints that accept a request body."""
        return [ep for ep in self.endpoints if ep.request_body is not None]

    @property
    def deprecated_endpoints(self) -> list[OpenApiEndpoint]:
        return [ep for ep in self.endpoints if ep.deprecated]

    @property
    def input_endpoints(self) -> list[OpenApiEndpoint]:
        """Endpoints accepting any user input (params or body)."""
        return [ep for ep in self.endpoints if ep.accepts_input]

    @property
    def endpoint_count(self) -> int:
        return len(self.endpoints)

    def summary(self) -> dict[str, Any]:
        """Generate a compact summary of the spec."""
        return {
            "title": self.title,
            "version": self.version,
            "spec_version": self.spec_version,
            "endpoint_count": self.endpoint_count,
            "auth_schemes": len(self.auth_schemes),
            "authenticated": len(self.authenticated_endpoints),
            "unauthenticated": len(self.unauthenticated_endpoints),
            "with_body": len(self.endpoints_with_body),
            "deprecated": len(self.deprecated_endpoints),
            "servers": self.servers,
            "parse_errors": len(self.parse_errors),
            "parse_warnings": len(self.parse_warnings),
        }


# ── $ref Resolver ───────────────────────────────────────────────────


class RefResolver:
    """Resolve JSON $ref pointers within an OpenAPI spec.

    Handles:
    - #/components/schemas/...
    - #/components/parameters/...
    - #/components/requestBodies/...
    - #/components/responses/...
    - #/definitions/... (Swagger 2.x)
    - Circular reference detection
    """

    MAX_DEPTH = 20  # Guard against infinite recursion

    def __init__(self, spec: dict) -> None:
        self._spec = spec
        self._cache: dict[str, Any] = {}
        self._resolving: set[str] = set()  # Circular ref guard

    def resolve(self, obj: Any, depth: int = 0) -> Any:
        """Recursively resolve $ref pointers in *obj*.

        Returns a deep-copied, fully resolved object.  Circular references
        are replaced with ``{"$circular_ref": "<pointer>"}`` to avoid
        infinite loops.
        """
        if depth > self.MAX_DEPTH:
            return obj

        if isinstance(obj, dict):
            if "$ref" in obj:
                return self._resolve_ref(obj["$ref"], depth)
            return {k: self.resolve(v, depth) for k, v in obj.items()}

        if isinstance(obj, list):
            return [self.resolve(item, depth) for item in obj]

        return obj

    def _resolve_ref(self, ref: str, depth: int) -> Any:
        """Resolve a single $ref pointer string."""
        if ref in self._cache:
            return deepcopy(self._cache[ref])

        if ref in self._resolving:
            # Circular reference detected
            return {"$circular_ref": ref}

        self._resolving.add(ref)
        try:
            target = self._lookup(ref)
            if target is None:
                return {"$unresolved_ref": ref}

            resolved = self.resolve(deepcopy(target), depth + 1)
            self._cache[ref] = resolved
            return deepcopy(resolved)
        finally:
            self._resolving.discard(ref)

    def _lookup(self, ref: str) -> Any | None:
        """Walk the spec tree following a JSON pointer."""
        if not ref.startswith("#/"):
            # External refs not supported
            return None

        parts = ref[2:].split("/")
        node: Any = self._spec
        for part in parts:
            # JSON pointer escaping
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(node, dict):
                node = node.get(part)
            elif isinstance(node, list):
                try:
                    node = node[int(part)]
                except (ValueError, IndexError):
                    return None
            else:
                return None
            if node is None:
                return None
        return node


# ── Main Parser ─────────────────────────────────────────────────────


class OpenApiParser:
    """Parse OpenAPI/Swagger specification files.

    PRIORITY 5 hardened:
    - Full $ref resolution
    - requestBody support
    - Complex schema handling (oneOf/anyOf/allOf)
    - Proper security scheme extraction
    - Robust error handling
    """

    # Valid HTTP methods in OpenAPI
    HTTP_METHODS = frozenset({
        "get", "post", "put", "delete", "patch", "options", "head", "trace",
    })

    def parse(self, spec_path: Path) -> OpenApiSpec:
        """Parse an OpenAPI/Swagger spec file (JSON or YAML).

        Args:
            spec_path: Path to spec file.

        Returns:
            OpenApiSpec with parsed data (never raises, errors in parse_errors).
        """
        result = OpenApiSpec()

        if not spec_path.is_file():
            result.parse_errors.append(f"Spec file not found: {spec_path}")
            return result

        try:
            raw = spec_path.read_text(encoding="utf-8")
        except OSError as exc:
            result.parse_errors.append(f"Cannot read spec file: {exc}")
            return result

        data = self._load_content(raw, spec_path.suffix, result)
        if data is None:
            return result

        result.raw_spec = data
        return self._parse_spec(data, result)

    def parse_dict(self, data: dict) -> OpenApiSpec:
        """Parse an OpenAPI spec from a dictionary.

        Args:
            data: Parsed spec as a dict.

        Returns:
            OpenApiSpec with parsed data.
        """
        if not isinstance(data, dict):
            result = OpenApiSpec()
            result.parse_errors.append("Spec data is not a dictionary")
            return result
        result = OpenApiSpec(raw_spec=data)
        return self._parse_spec(data, result)

    def parse_raw(self, raw_text: str, file_type: str = "json") -> OpenApiSpec:
        """Parse raw text content as an OpenAPI spec.

        Args:
            raw_text: Raw spec content.
            file_type: "json" or "yaml".

        Returns:
            OpenApiSpec with parsed data.
        """
        result = OpenApiSpec()
        suffix = f".{file_type}"
        data = self._load_content(raw_text, suffix, result)
        if data is None:
            return result
        result.raw_spec = data
        return self._parse_spec(data, result)

    # ── Internal parsing ────────────────────────────────────────────

    def _load_content(self, raw: str, suffix: str, result: OpenApiSpec) -> dict | None:
        """Load raw text into a dict (JSON or YAML)."""
        try:
            if suffix in (".yaml", ".yml"):
                try:
                    import yaml
                    data = yaml.safe_load(raw)
                except ImportError:
                    result.parse_errors.append("PyYAML not installed; cannot parse YAML specs")
                    return None
                except yaml.YAMLError as exc:
                    result.parse_errors.append(f"YAML parse error: {exc}")
                    return None
            else:
                data = json.loads(raw)
        except json.JSONDecodeError as exc:
            result.parse_errors.append(f"JSON parse error: {exc}")
            return None

        if not isinstance(data, dict):
            result.parse_errors.append("Parsed content is not a JSON object")
            return None

        return data

    def _parse_spec(self, data: dict, result: OpenApiSpec) -> OpenApiSpec:
        """Internal spec parsing logic with full $ref resolution."""

        # Detect spec type
        result.spec_version = self.detect_spec_type(data)

        # Initialise $ref resolver
        resolver = RefResolver(data)

        # ── Info ────────────────────────────────────────────────────
        info = data.get("info", {})
        if not isinstance(info, dict):
            result.parse_warnings.append("'info' is not a dict")
            info = {}
        result.title = str(info.get("title", ""))
        result.version = str(info.get("version", ""))
        result.description = str(info.get("description", ""))

        # ── Servers ─────────────────────────────────────────────────
        self._parse_servers(data, result)

        # ── Security schemes ────────────────────────────────────────
        self._parse_security_schemes(data, resolver, result)

        # ── Global security requirement ─────────────────────────────
        global_security = data.get("security", [])
        if isinstance(global_security, list):
            result.global_security = global_security
        else:
            result.parse_warnings.append("'security' is not an array")
            global_security = []

        # ── Endpoints ───────────────────────────────────────────────
        self._parse_paths(data, resolver, global_security, result)

        return result

    def _parse_servers(self, data: dict, result: OpenApiSpec) -> None:
        """Parse servers (3.x) or host (2.x)."""
        if "servers" in data:
            servers = data.get("servers", [])
            if isinstance(servers, list):
                for s in servers:
                    if isinstance(s, dict):
                        url = s.get("url", "")
                        if url:
                            result.servers.append(str(url))
                    elif isinstance(s, str):
                        result.servers.append(s)
            else:
                result.parse_warnings.append("'servers' is not an array")
        elif "host" in data:
            scheme = (data.get("schemes", ["https"]) or ["https"])[0]
            base_path = data.get("basePath", "")
            result.servers = [f"{scheme}://{data['host']}{base_path}"]

    def _parse_security_schemes(self, data: dict, resolver: RefResolver,
                                 result: OpenApiSpec) -> None:
        """Extract security schemes from components or securityDefinitions."""
        security_defs = (
            data.get("components", {}).get("securitySchemes", {})
            or data.get("securityDefinitions", {})
        )
        if not isinstance(security_defs, dict):
            return

        for name, scheme_data in security_defs.items():
            if not isinstance(scheme_data, dict):
                result.parse_warnings.append(
                    f"Security scheme '{name}' is not a dict"
                )
                continue

            # Resolve $refs in scheme data
            scheme_data = resolver.resolve(scheme_data)
            if not isinstance(scheme_data, dict):
                continue

            auth_type = str(scheme_data.get("type", ""))

            # Extract OAuth2 flows
            oauth_flows: dict[str, Any] = {}
            if auth_type == "oauth2":
                flows_raw = scheme_data.get("flows", scheme_data.get("flow", {}))
                if isinstance(flows_raw, dict):
                    for flow_name, flow_data in flows_raw.items():
                        if isinstance(flow_data, dict):
                            oauth_flows[flow_name] = {
                                "authorizationUrl": flow_data.get("authorizationUrl", ""),
                                "tokenUrl": flow_data.get("tokenUrl", ""),
                                "refreshUrl": flow_data.get("refreshUrl", ""),
                                "scopes": flow_data.get("scopes", {}),
                            }
                elif isinstance(flows_raw, str):
                    # Swagger 2.x style
                    oauth_flows[flows_raw] = {
                        "authorizationUrl": scheme_data.get("authorizationUrl", ""),
                        "tokenUrl": scheme_data.get("tokenUrl", ""),
                        "scopes": scheme_data.get("scopes", {}),
                    }

            scheme = OpenApiAuthScheme(
                name=name,
                auth_type=auth_type,
                scheme=str(scheme_data.get("scheme", "")),
                location=str(scheme_data.get("in", "")),
                param_name=str(scheme_data.get("name", "")),
                bearer_format=str(scheme_data.get("bearerFormat", "")),
                oauth_flows=oauth_flows,
                openid_connect_url=str(scheme_data.get("openIdConnectUrl", "")),
            )
            result.auth_schemes.append(scheme)

    def _parse_paths(self, data: dict, resolver: RefResolver,
                      global_security: list, result: OpenApiSpec) -> None:
        """Parse all path items and operations."""
        paths = data.get("paths", {})
        if not isinstance(paths, dict):
            result.parse_warnings.append("'paths' is not a dict")
            return

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            # Path-level parameters (inherited by all operations)
            path_params_raw = path_item.get("parameters", [])
            path_params = self._parse_parameters(path_params_raw, resolver, result)

            for method, operation in path_item.items():
                method_lower = method.lower()
                if method_lower not in self.HTTP_METHODS:
                    continue
                if not isinstance(operation, dict):
                    continue

                try:
                    endpoint = self._parse_operation(
                        path, method_lower, operation, path_params,
                        global_security, resolver, result,
                    )
                    result.endpoints.append(endpoint)
                except Exception as exc:
                    result.parse_warnings.append(
                        f"Error parsing {method.upper()} {path}: {exc}"
                    )

    def _parse_operation(
        self, path: str, method: str, operation: dict,
        path_params: list[OpenApiParameter],
        global_security: list, resolver: RefResolver,
        result: OpenApiSpec,
    ) -> OpenApiEndpoint:
        """Parse a single operation (method on a path)."""

        # ── Security ────────────────────────────────────────────────
        op_security = operation.get("security")
        if op_security is None:
            # Inherit global security
            effective_security = global_security
        elif op_security == []:
            # Explicitly no security
            effective_security = []
        else:
            effective_security = op_security if isinstance(op_security, list) else []

        requires_auth = bool(effective_security)

        # ── Parameters ──────────────────────────────────────────────
        op_params_raw = operation.get("parameters", [])
        op_params = self._parse_parameters(op_params_raw, resolver, result)

        # Merge path-level params (operation params override by name+location)
        merged_params = self._merge_parameters(path_params, op_params)

        # ── Request body (OpenAPI 3.x) ──────────────────────────────
        request_body = None
        rb_raw = operation.get("requestBody")
        if rb_raw:
            request_body = self._parse_request_body(rb_raw, resolver, result)

        # Swagger 2.x: body parameters
        if request_body is None:
            body_params = [p for p in merged_params if p.location == "body"]
            if body_params:
                # Convert Swagger 2.x body param to requestBody
                bp = body_params[0]
                request_body = OpenApiRequestBody(
                    required=bp.required,
                    content_types=["application/json"],
                    schema=bp.schema,
                    description=bp.description,
                )
                # Remove body params from the param list
                merged_params = [p for p in merged_params if p.location != "body"]

        # ── Responses ───────────────────────────────────────────────
        responses_raw = operation.get("responses", {})
        responses = {}
        if isinstance(responses_raw, dict):
            for status_code, resp_data in responses_raw.items():
                if isinstance(resp_data, dict):
                    resp_resolved = resolver.resolve(resp_data)
                    responses[str(status_code)] = {
                        "description": resp_resolved.get("description", "") if isinstance(resp_resolved, dict) else "",
                    }

        return OpenApiEndpoint(
            path=path,
            method=method.upper(),
            summary=str(operation.get("summary", "")),
            description=str(operation.get("description", "")),
            operation_id=str(operation.get("operationId", "")),
            parameters=merged_params,
            request_body=request_body,
            security=effective_security if isinstance(effective_security, list) else [],
            tags=operation.get("tags", []) if isinstance(operation.get("tags"), list) else [],
            responses=responses,
            requires_auth=requires_auth,
            deprecated=bool(operation.get("deprecated", False)),
        )

    def _parse_parameters(self, params_raw: Any, resolver: RefResolver,
                           result: OpenApiSpec) -> list[OpenApiParameter]:
        """Parse a list of parameter objects, resolving $refs."""
        if not isinstance(params_raw, list):
            return []

        params: list[OpenApiParameter] = []
        for p_raw in params_raw:
            if not isinstance(p_raw, dict):
                continue

            # Resolve $ref
            p = resolver.resolve(p_raw)
            if not isinstance(p, dict):
                continue

            # Extract schema
            schema_raw = p.get("schema", {})
            resolved_schema = None
            if isinstance(schema_raw, dict):
                resolved_schema_data = resolver.resolve(schema_raw)
                if isinstance(resolved_schema_data, dict):
                    resolved_schema = self._build_schema(resolved_schema_data, resolver)

            param_type = ""
            format_hint = ""
            if resolved_schema:
                param_type = resolved_schema.schema_type
                format_hint = resolved_schema.format_hint
            elif isinstance(schema_raw, dict):
                param_type = str(schema_raw.get("type", ""))
                format_hint = str(schema_raw.get("format", ""))

            # Swagger 2.x: type directly on param
            if not param_type:
                param_type = str(p.get("type", ""))
                format_hint = format_hint or str(p.get("format", ""))

            params.append(OpenApiParameter(
                name=str(p.get("name", "")),
                location=str(p.get("in", "")),
                required=bool(p.get("required", False)),
                param_type=param_type,
                format_hint=format_hint,
                description=str(p.get("description", "")),
                example=p.get("example"),
                enum_values=p.get("enum", []) if isinstance(p.get("enum"), list) else [],
                schema=resolved_schema,
            ))

        return params

    def _parse_request_body(self, rb_raw: Any, resolver: RefResolver,
                             result: OpenApiSpec) -> OpenApiRequestBody | None:
        """Parse an OpenAPI 3.x requestBody."""
        if not isinstance(rb_raw, dict):
            return None

        # Resolve $ref on the requestBody itself
        rb = resolver.resolve(rb_raw)
        if not isinstance(rb, dict):
            return None

        content = rb.get("content", {})
        if not isinstance(content, dict):
            result.parse_warnings.append("requestBody.content is not a dict")
            return None

        content_types = list(content.keys())
        schema: ResolvedSchema | None = None
        examples: dict[str, Any] = {}

        # Prefer application/json, then first available
        preferred = ["application/json", "application/xml", "multipart/form-data"]
        chosen_ct = None
        for ct in preferred:
            if ct in content:
                chosen_ct = ct
                break
        if chosen_ct is None and content_types:
            chosen_ct = content_types[0]

        if chosen_ct and isinstance(content.get(chosen_ct), dict):
            media_type = content[chosen_ct]
            schema_raw = media_type.get("schema", {})
            if isinstance(schema_raw, dict):
                resolved_data = resolver.resolve(schema_raw)
                if isinstance(resolved_data, dict):
                    schema = self._build_schema(resolved_data, resolver)

            # Extract examples
            if "example" in media_type:
                examples["default"] = media_type["example"]
            if "examples" in media_type and isinstance(media_type["examples"], dict):
                for ex_name, ex_data in media_type["examples"].items():
                    if isinstance(ex_data, dict):
                        examples[ex_name] = ex_data.get("value", ex_data)

        return OpenApiRequestBody(
            required=bool(rb.get("required", False)),
            content_types=content_types,
            schema=schema,
            description=str(rb.get("description", "")),
            examples=examples,
        )

    def _build_schema(self, schema_data: dict, resolver: RefResolver,
                       depth: int = 0) -> ResolvedSchema:
        """Build a ResolvedSchema from a (resolved) schema dict.

        Handles object, array, primitive, and composition (oneOf/anyOf/allOf).
        """
        if depth > RefResolver.MAX_DEPTH:
            return ResolvedSchema(raw=schema_data)

        schema_type = str(schema_data.get("type", ""))
        nullable = bool(schema_data.get("nullable", False))

        # ── Composition schemas ─────────────────────────────────────
        composition = ""
        composition_schemas: list[ResolvedSchema] = []
        for comp_key in ("oneOf", "anyOf", "allOf"):
            comp_list = schema_data.get(comp_key)
            if isinstance(comp_list, list):
                composition = comp_key
                for sub_raw in comp_list:
                    if isinstance(sub_raw, dict):
                        sub_resolved = resolver.resolve(sub_raw)
                        if isinstance(sub_resolved, dict):
                            composition_schemas.append(
                                self._build_schema(sub_resolved, resolver, depth + 1)
                            )
                break

        # ── Object properties ───────────────────────────────────────
        properties: dict[str, Any] = {}
        required_fields: list[str] = []

        if schema_type == "object" or "properties" in schema_data:
            schema_type = schema_type or "object"
            props_raw = schema_data.get("properties", {})
            if isinstance(props_raw, dict):
                for prop_name, prop_schema in props_raw.items():
                    if isinstance(prop_schema, dict):
                        prop_resolved = resolver.resolve(prop_schema)
                        if isinstance(prop_resolved, dict):
                            properties[prop_name] = {
                                "type": prop_resolved.get("type", ""),
                                "format": prop_resolved.get("format", ""),
                                "description": prop_resolved.get("description", ""),
                                "enum": prop_resolved.get("enum", []),
                                "nullable": prop_resolved.get("nullable", False),
                            }

            required_raw = schema_data.get("required", [])
            if isinstance(required_raw, list):
                required_fields = [str(r) for r in required_raw]

        # Also gather properties from allOf composition
        if composition == "allOf":
            for sub_schema in composition_schemas:
                properties.update(sub_schema.properties)
                required_fields.extend(sub_schema.required_fields)

        # ── Array items ─────────────────────────────────────────────
        items_type = ""
        if schema_type == "array":
            items_raw = schema_data.get("items", {})
            if isinstance(items_raw, dict):
                items_resolved = resolver.resolve(items_raw)
                if isinstance(items_resolved, dict):
                    items_type = str(items_resolved.get("type", "object"))

        return ResolvedSchema(
            schema_type=schema_type,
            properties=properties,
            required_fields=required_fields,
            items_type=items_type,
            enum_values=schema_data.get("enum", []) if isinstance(schema_data.get("enum"), list) else [],
            format_hint=str(schema_data.get("format", "")),
            description=str(schema_data.get("description", "")),
            example=schema_data.get("example"),
            composition=composition,
            composition_schemas=composition_schemas,
            nullable=nullable,
            raw=schema_data,
        )

    @staticmethod
    def _merge_parameters(path_params: list[OpenApiParameter],
                           op_params: list[OpenApiParameter]) -> list[OpenApiParameter]:
        """Merge path-level and operation-level parameters.

        Operation params override path params when they share
        the same ``(name, location)`` key.
        """
        key_fn = lambda p: (p.name, p.location)
        merged: dict[tuple[str, str], OpenApiParameter] = {}
        for p in path_params:
            merged[key_fn(p)] = p
        for p in op_params:
            merged[key_fn(p)] = p
        return list(merged.values())

    @staticmethod
    def detect_spec_type(data: dict) -> str:
        """Detect if spec is OpenAPI 3.x or Swagger 2.x."""
        if "openapi" in data:
            return f"openapi_{data['openapi']}"
        if "swagger" in data:
            return f"swagger_{data['swagger']}"
        return "unknown"
