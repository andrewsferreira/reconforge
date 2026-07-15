"""PRIORITY 5 – OpenAPI Parser hardening tests.

Tests:
- $ref resolution (components/schemas, parameters, requestBodies)
- requestBody parsing with content types
- Circular $ref detection
- Security scheme extraction (apiKey, bearer, OAuth2)
- Composed schemas (oneOf, anyOf, allOf)
- Swagger 2.x backwards compatibility
- Malformed spec error handling
- Complex nested schemas
"""

import json
import sys
import tempfile
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.api.parsers.openapi_parser import (
    OpenApiParser,
)


def test_ref_resolution_basic():
    """Test basic $ref resolution for components/schemas."""
    spec_data = {
        "openapi": "3.0.3",
        "info": {"title": "Test", "version": "1.0"},
        "paths": {
            "/users": {
                "post": {
                    "summary": "Create user",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/User"}
                            }
                        }
                    },
                    "responses": {"201": {"description": "Created"}}
                }
            }
        },
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "required": ["name", "email"],
                    "properties": {
                        "name": {"type": "string"},
                        "email": {"type": "string", "format": "email"},
                        "age": {"type": "integer"},
                    }
                }
            }
        }
    }

    parser = OpenApiParser()
    result = parser.parse_dict(spec_data)

    assert result.endpoint_count == 1, f"Expected 1 endpoint, got {result.endpoint_count}"
    ep = result.endpoints[0]
    assert ep.path == "/users"
    assert ep.method == "POST"
    assert ep.request_body is not None, "requestBody should be parsed"
    assert "application/json" in ep.request_body.content_types
    assert ep.request_body.schema is not None
    assert "name" in ep.request_body.schema.properties
    assert "email" in ep.request_body.schema.properties
    assert "name" in ep.request_body.schema.required_fields
    assert ep.request_body.schema.schema_type == "object"
    print("✅ test_ref_resolution_basic PASSED")


def test_ref_resolution_nested():
    """Test nested $ref resolution (schema referencing another schema)."""
    spec_data = {
        "openapi": "3.0.3",
        "info": {"title": "Test", "version": "1.0"},
        "paths": {
            "/orders": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Order"}
                            }
                        }
                    },
                    "responses": {"201": {"description": "Created"}}
                }
            }
        },
        "components": {
            "schemas": {
                "Order": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "customer": {"$ref": "#/components/schemas/Customer"},
                    }
                },
                "Customer": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "email": {"type": "string"},
                    }
                }
            }
        }
    }

    parser = OpenApiParser()
    result = parser.parse_dict(spec_data)
    ep = result.endpoints[0]
    assert ep.request_body is not None
    schema = ep.request_body.schema
    assert "id" in schema.properties
    assert "customer" in schema.properties
    print("✅ test_ref_resolution_nested PASSED")


def test_circular_ref_detection():
    """Test circular $ref doesn't cause infinite recursion."""
    spec_data = {
        "openapi": "3.0.3",
        "info": {"title": "Test", "version": "1.0"},
        "paths": {
            "/nodes": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "OK",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Node"}
                                }
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "Node": {
                    "type": "object",
                    "properties": {
                        "value": {"type": "string"},
                        "children": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/Node"}
                        }
                    }
                }
            }
        }
    }

    parser = OpenApiParser()
    result = parser.parse_dict(spec_data)
    assert result.endpoint_count == 1
    assert not result.parse_errors, f"Unexpected errors: {result.parse_errors}"
    print("✅ test_circular_ref_detection PASSED")


def test_security_schemes_oauth2():
    """Test OAuth2 security scheme extraction with flows."""
    spec_data = {
        "openapi": "3.0.3",
        "info": {"title": "Test", "version": "1.0"},
        "paths": {},
        "components": {
            "securitySchemes": {
                "oauth2": {
                    "type": "oauth2",
                    "flows": {
                        "authorizationCode": {
                            "authorizationUrl": "https://auth.example.com/authorize",
                            "tokenUrl": "https://auth.example.com/token",
                            "scopes": {
                                "read": "Read access",
                                "write": "Write access",
                            }
                        },
                        "implicit": {
                            "authorizationUrl": "https://auth.example.com/authorize",
                            "scopes": {"read": "Read"}
                        }
                    }
                },
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                },
                "apiKey": {
                    "type": "apiKey",
                    "in": "query",
                    "name": "api_key",
                }
            }
        }
    }

    parser = OpenApiParser()
    result = parser.parse_dict(spec_data)

    assert len(result.auth_schemes) == 3
    oauth = next(s for s in result.auth_schemes if s.name == "oauth2")
    assert oauth.auth_type == "oauth2"
    assert "authorizationCode" in oauth.oauth_flows
    assert "implicit" in oauth.oauth_flows
    assert oauth.oauth_flows["authorizationCode"]["tokenUrl"] == "https://auth.example.com/token"

    bearer = next(s for s in result.auth_schemes if s.name == "bearerAuth")
    assert bearer.is_jwt_bearer
    assert bearer.bearer_format == "JWT"

    apikey = next(s for s in result.auth_schemes if s.name == "apiKey")
    assert apikey.is_api_key_in_query
    assert apikey.param_name == "api_key"
    print("✅ test_security_schemes_oauth2 PASSED")


def test_allof_composition():
    """Test allOf schema composition."""
    spec_data = {
        "openapi": "3.0.3",
        "info": {"title": "Test", "version": "1.0"},
        "paths": {
            "/pets": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "allOf": [
                                        {"$ref": "#/components/schemas/BaseAnimal"},
                                        {
                                            "type": "object",
                                            "properties": {
                                                "breed": {"type": "string"}
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    },
                    "responses": {"201": {"description": "Created"}}
                }
            }
        },
        "components": {
            "schemas": {
                "BaseAnimal": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": {"type": "string"},
                        "species": {"type": "string"},
                    }
                }
            }
        }
    }

    parser = OpenApiParser()
    result = parser.parse_dict(spec_data)
    ep = result.endpoints[0]
    assert ep.request_body is not None
    schema = ep.request_body.schema
    # allOf merges properties from all sub-schemas
    all_fields = schema.field_names
    assert "name" in all_fields, f"'name' not in {all_fields}"
    assert "breed" in all_fields, f"'breed' not in {all_fields}"
    print("✅ test_allof_composition PASSED")


def test_swagger_2x_compat():
    """Test Swagger 2.x backwards compatibility."""
    spec_data = {
        "swagger": "2.0",
        "info": {"title": "Legacy API", "version": "1.0"},
        "host": "api.example.com",
        "basePath": "/v1",
        "schemes": ["https"],
        "securityDefinitions": {
            "apiKey": {
                "type": "apiKey",
                "name": "X-API-Key",
                "in": "header",
            }
        },
        "paths": {
            "/users": {
                "get": {
                    "summary": "List users",
                    "parameters": [
                        {"name": "limit", "in": "query", "type": "integer"},
                        {"name": "offset", "in": "query", "type": "integer"},
                    ],
                    "responses": {"200": {"description": "OK"}}
                }
            }
        }
    }

    parser = OpenApiParser()
    result = parser.parse_dict(spec_data)

    assert result.spec_version == "swagger_2.0"
    assert "https://api.example.com/v1" in result.servers
    assert len(result.auth_schemes) == 1
    assert result.auth_schemes[0].param_name == "X-API-Key"
    assert result.endpoint_count == 1
    ep = result.endpoints[0]
    assert len(ep.parameters) == 2
    assert ep.parameters[0].name == "limit"
    assert ep.parameters[0].param_type == "integer"
    print("✅ test_swagger_2x_compat PASSED")


def test_request_body_multiple_content_types():
    """Test requestBody with multiple content types."""
    spec_data = {
        "openapi": "3.0.3",
        "info": {"title": "Test", "version": "1.0"},
        "paths": {
            "/upload": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"data": {"type": "string"}}
                                }
                            },
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"file": {"type": "string", "format": "binary"}}
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "OK"}}
                }
            }
        }
    }

    parser = OpenApiParser()
    result = parser.parse_dict(spec_data)
    ep = result.endpoints[0]
    assert ep.request_body is not None
    assert ep.request_body.required is True
    assert len(ep.request_body.content_types) == 2
    assert "application/json" in ep.request_body.content_types
    assert "multipart/form-data" in ep.request_body.content_types
    print("✅ test_request_body_multiple_content_types PASSED")


def test_malformed_spec_handling():
    """Test parser doesn't crash on malformed specs."""
    parser = OpenApiParser()

    # Empty dict
    result = parser.parse_dict({})
    assert result.endpoint_count == 0

    # Non-dict
    result = parser.parse_dict("not a dict")
    assert len(result.parse_errors) > 0

    # Missing paths
    result = parser.parse_dict({"openapi": "3.0.3", "info": {"title": "T", "version": "1"}})
    assert result.endpoint_count == 0
    assert not result.parse_errors

    # Invalid path item
    result = parser.parse_dict({
        "openapi": "3.0.3",
        "info": {"title": "T", "version": "1"},
        "paths": {"/foo": "not a dict"}
    })
    assert result.endpoint_count == 0

    print("✅ test_malformed_spec_handling PASSED")


def test_parameter_ref_resolution():
    """Test $ref resolution for parameters."""
    spec_data = {
        "openapi": "3.0.3",
        "info": {"title": "Test", "version": "1.0"},
        "paths": {
            "/items/{itemId}": {
                "get": {
                    "parameters": [
                        {"$ref": "#/components/parameters/ItemId"}
                    ],
                    "responses": {"200": {"description": "OK"}}
                }
            }
        },
        "components": {
            "parameters": {
                "ItemId": {
                    "name": "itemId",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string", "format": "uuid"},
                }
            }
        }
    }

    parser = OpenApiParser()
    result = parser.parse_dict(spec_data)
    ep = result.endpoints[0]
    assert len(ep.parameters) == 1
    param = ep.parameters[0]
    assert param.name == "itemId"
    assert param.location == "path"
    assert param.required is True
    assert param.param_type == "string"
    assert param.format_hint == "uuid"
    print("✅ test_parameter_ref_resolution PASSED")


def test_endpoint_properties():
    """Test endpoint convenience properties."""
    spec_data = {
        "openapi": "3.0.3",
        "info": {"title": "Test", "version": "1.0"},
        "security": [{"bearerAuth": []}],
        "paths": {
            "/public": {
                "get": {
                    "security": [],
                    "responses": {"200": {"description": "OK"}}
                }
            },
            "/private": {
                "post": {
                    "deprecated": True,
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"type": "object", "properties": {"x": {"type": "string"}}}
                            }
                        }
                    },
                    "responses": {"200": {"description": "OK"}}
                }
            }
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"}
            }
        }
    }

    parser = OpenApiParser()
    result = parser.parse_dict(spec_data)

    assert len(result.unauthenticated_endpoints) == 1
    assert result.unauthenticated_endpoints[0].path == "/public"

    assert len(result.authenticated_endpoints) == 1
    assert result.authenticated_endpoints[0].path == "/private"

    assert len(result.deprecated_endpoints) == 1
    assert result.deprecated_endpoints[0].deprecated is True

    assert len(result.endpoints_with_body) == 1
    assert result.endpoints_with_body[0].path == "/private"

    assert len(result.input_endpoints) == 1  # /private has body
    print("✅ test_endpoint_properties PASSED")


def test_spec_summary():
    """Test spec summary generation."""
    spec_data = {
        "openapi": "3.0.3",
        "info": {"title": "My API", "version": "2.0"},
        "servers": [{"url": "https://api.example.com"}],
        "paths": {
            "/a": {"get": {"responses": {"200": {"description": "OK"}}}},
            "/b": {"post": {"responses": {"200": {"description": "OK"}}}},
        }
    }

    parser = OpenApiParser()
    result = parser.parse_dict(spec_data)
    summary = result.summary()

    assert summary["title"] == "My API"
    assert summary["version"] == "2.0"
    assert summary["endpoint_count"] == 2
    assert summary["servers"] == ["https://api.example.com"]
    print("✅ test_spec_summary PASSED")


def test_file_parsing():
    """Test parsing from JSON file."""
    spec_data = {
        "openapi": "3.0.3",
        "info": {"title": "File Test", "version": "1.0"},
        "paths": {
            "/test": {
                "get": {
                    "parameters": [
                        {"name": "q", "in": "query", "schema": {"type": "string"}}
                    ],
                    "responses": {"200": {"description": "OK"}}
                }
            }
        }
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(spec_data, f)
        f.flush()
        path = Path(f.name)

    parser = OpenApiParser()
    result = parser.parse(path)
    assert result.endpoint_count == 1
    assert result.endpoints[0].parameters[0].name == "q"
    path.unlink()
    print("✅ test_file_parsing PASSED")


if __name__ == "__main__":
    test_ref_resolution_basic()
    test_ref_resolution_nested()
    test_circular_ref_detection()
    test_security_schemes_oauth2()
    test_allof_composition()
    test_swagger_2x_compat()
    test_request_body_multiple_content_types()
    test_malformed_spec_handling()
    test_parameter_ref_resolution()
    test_endpoint_properties()
    test_spec_summary()
    test_file_parsing()
    print("\n🎉 All PRIORITY 5 OpenAPI parser tests PASSED!")
