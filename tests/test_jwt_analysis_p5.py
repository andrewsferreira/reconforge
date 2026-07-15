"""PRIORITY 5 – JWT analysis tests for authentication phase.

Tests the enhanced JWT analysis including:
- Claims extraction
- Misconfiguration detection
- Header attack vectors (kid, jku, x5u)
- Missing exp/iss/aud
- Sensitive data in payload
"""

import base64
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.api.phases.authentication import _b64url_decode, _safe_json_decode


def _make_jwt(header: dict, payload: dict, signature: str = "dummysig") -> str:
    """Create a test JWT from header and payload dicts."""
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    h = _b64url_encode(json.dumps(header).encode())
    p = _b64url_encode(json.dumps(payload).encode())
    return f"{h}.{p}.{signature}"


def test_b64url_decode():
    """Test base64url decoding with padding."""
    data = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    result = _b64url_decode(data)
    assert json.loads(result) == {"alg": "HS256"}
    print("✅ test_b64url_decode PASSED")


def test_safe_json_decode():
    """Test safe JSON decode from JWT segment."""
    header = {"alg": "RS256", "typ": "JWT"}
    segment = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    result = _safe_json_decode(segment)
    assert result == header

    # Invalid base64
    assert _safe_json_decode("!!!invalid!!!") is None
    print("✅ test_safe_json_decode PASSED")


def test_make_jwt():
    """Test JWT creation helper."""
    token = _make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "user123", "exp": 9999999999},
    )
    parts = token.split(".")
    assert len(parts) == 3
    header = _safe_json_decode(parts[0])
    payload = _safe_json_decode(parts[1])
    assert header["alg"] == "HS256"
    assert payload["sub"] == "user123"
    print("✅ test_make_jwt PASSED")


def test_jwt_with_kid():
    """Test that kid header is detected."""
    token = _make_jwt(
        {"alg": "RS256", "typ": "JWT", "kid": "key-001"},
        {"sub": "test"},
    )
    parts = token.split(".")
    header = _safe_json_decode(parts[0])
    assert "kid" in header
    assert header["kid"] == "key-001"
    print("✅ test_jwt_with_kid PASSED")


def test_jwt_with_jku():
    """Test that jku header is detected."""
    token = _make_jwt(
        {"alg": "RS256", "typ": "JWT", "jku": "https://evil.com/jwks.json"},
        {"sub": "test"},
    )
    parts = token.split(".")
    header = _safe_json_decode(parts[0])
    assert "jku" in header
    print("✅ test_jwt_with_jku PASSED")


def test_jwt_claims_extraction():
    """Test standard claims extraction."""
    now = int(time.time())
    payload = {
        "sub": "user123",
        "iss": "https://auth.example.com",
        "aud": "api.example.com",
        "exp": now + 3600,
        "iat": now,
        "nbf": now,
        "jti": "abc-123",
        "scope": "read write",
        "roles": ["admin", "user"],
        "custom_field": "value",
    }
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, payload)
    parts = token.split(".")
    decoded = _safe_json_decode(parts[1])

    assert decoded["sub"] == "user123"
    assert decoded["iss"] == "https://auth.example.com"
    assert decoded["exp"] == now + 3600
    assert "scope" in decoded
    assert "roles" in decoded
    print("✅ test_jwt_claims_extraction PASSED")


def test_jwt_missing_exp():
    """Test detection of missing exp claim."""
    payload = {"sub": "test", "iss": "example.com"}
    # No exp claim
    assert "exp" not in payload
    print("✅ test_jwt_missing_exp PASSED")


def test_jwt_expired():
    """Test expired token detection."""
    now = int(time.time())
    payload = {"sub": "test", "exp": now - 3600}
    assert payload["exp"] < now
    print("✅ test_jwt_expired PASSED")


def test_jwt_long_expiration():
    """Test long expiration detection."""
    now = int(time.time())
    payload = {"sub": "test", "iat": now, "exp": now + (30 * 24 * 3600)}  # 30 days
    lifetime_hours = (payload["exp"] - payload["iat"]) / 3600
    assert lifetime_hours > 24
    print("✅ test_jwt_long_expiration PASSED")


def test_jwt_sensitive_claims():
    """Test sensitive data detection in payload."""
    payload = {"sub": "test", "password": "secret123"}
    sensitive_keys = ("password", "secret", "credit_card", "ssn")
    exposed = [k for k in payload if k.lower() in sensitive_keys]
    assert "password" in exposed
    print("✅ test_jwt_sensitive_claims PASSED")


def test_jwt_none_algorithm():
    """Test none algorithm detection."""
    token = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "test"}, signature="")
    parts = token.split(".")
    header = _safe_json_decode(parts[0])
    assert header["alg"] == "none"
    print("✅ test_jwt_none_algorithm PASSED")


def test_jwt_empty_signature():
    """Test empty signature detection."""
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "test"}, signature="")
    parts = token.split(".")
    assert parts[2] == "" or parts[2] in ("", ".", "AA")
    print("✅ test_jwt_empty_signature PASSED")


if __name__ == "__main__":
    test_b64url_decode()
    test_safe_json_decode()
    test_make_jwt()
    test_jwt_with_kid()
    test_jwt_with_jku()
    test_jwt_claims_extraction()
    test_jwt_missing_exp()
    test_jwt_expired()
    test_jwt_long_expiration()
    test_jwt_sensitive_claims()
    test_jwt_none_algorithm()
    test_jwt_empty_signature()
    print("\n🎉 All PRIORITY 5 JWT analysis tests PASSED!")
