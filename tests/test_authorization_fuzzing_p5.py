"""PRIORITY 5 – Authorization scoring and fuzzing fingerprint tests."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.api.phases.authorization import (
    _IDOR_REPORT_THRESHOLD,
    _METHOD_SCORES,
    _RESOURCE_PATH_PATTERNS,
    AuthorizationPhase,
)
from modules.api.phases.fuzzing import (
    _COMMAND_INJECTION_PATTERNS,
    _SQL_ERROR_PATTERNS,
    _STACK_TRACE_PATTERNS,
)


def test_idor_scoring_high_risk():
    """High-risk IDOR: DELETE /users/{id} should exceed threshold."""
    score = 0.0
    url = "/users/123"
    method = "DELETE"

    for pattern, pscore in _RESOURCE_PATH_PATTERNS.items():
        if pattern.lower() in url.lower():
            score += pscore
            break

    score += _METHOD_SCORES.get(method, 0.1)

    # ID in path
    last_seg = url.rstrip("/").split("/")[-1]
    if last_seg.isdigit():
        score += 0.3

    assert score >= _IDOR_REPORT_THRESHOLD, f"Score {score} should be >= {_IDOR_REPORT_THRESHOLD}"
    print(f"✅ test_idor_scoring_high_risk PASSED (score={score:.2f})")


def test_idor_scoring_low_risk():
    """Low-risk: GET /health should NOT exceed threshold."""
    score = 0.0
    url = "/health"
    method = "GET"

    for pattern, pscore in _RESOURCE_PATH_PATTERNS.items():
        if pattern.lower() in url.lower():
            score += pscore
            break

    score += _METHOD_SCORES.get(method, 0.1)

    last_seg = url.rstrip("/").split("/")[-1]
    if last_seg.isdigit():
        score += 0.3

    assert score < _IDOR_REPORT_THRESHOLD, f"Score {score} should be < {_IDOR_REPORT_THRESHOLD}"
    print(f"✅ test_idor_scoring_low_risk PASSED (score={score:.2f})")


def test_looks_like_id():
    """Test ID detection patterns."""
    assert AuthorizationPhase._looks_like_id("123")
    assert AuthorizationPhase._looks_like_id("550e8400-e29b-41d4-a716-446655440000")  # UUID
    assert AuthorizationPhase._looks_like_id("507f1f77bcf86cd799439011")  # MongoDB ObjectId
    assert not AuthorizationPhase._looks_like_id("users")
    assert not AuthorizationPhase._looks_like_id("api")
    assert not AuthorizationPhase._looks_like_id("")
    print("✅ test_looks_like_id PASSED")


def test_sql_error_patterns():
    """Test SQL error fingerprint detection."""
    test_cases = [
        ("Warning: mysqli_query()", True),
        ("PostgreSQL ERROR: syntax error at", True),
        ("ORA-12345: TNS error", True),
        ("SQLSTATE[42000]", True),
        ("Normal response body", False),
        ("200 OK", False),
    ]
    for text, expected in test_cases:
        matched = any(p.search(text) for p in _SQL_ERROR_PATTERNS)
        assert matched == expected, f"SQL pattern match for '{text}': got {matched}, expected {expected}"
    print("✅ test_sql_error_patterns PASSED")


def test_stack_trace_patterns():
    """Test stack trace fingerprint detection."""
    test_cases = [
        ("Traceback (most recent call last):", True),
        ('at com.example.App(App.java:42)', True),
        ('File "/app/main.py", line 10, in main', True),
        ("Everything is fine", False),
    ]
    for text, expected in test_cases:
        matched = any(p.search(text) for p in _STACK_TRACE_PATTERNS)
        assert matched == expected, f"Stack trace match for '{text}': got {matched}, expected {expected}"
    print("✅ test_stack_trace_patterns PASSED")


def test_command_injection_patterns():
    """Test command injection fingerprint detection."""
    test_cases = [
        ("root:x:0:0:root:/root:/bin/bash", True),
        ("uid=0(root) gid=0(root)", True),
        ("Normal API response", False),
    ]
    for text, expected in test_cases:
        matched = any(p.search(text) for p in _COMMAND_INJECTION_PATTERNS)
        assert matched == expected, f"Command injection match for '{text}': got {matched}, expected {expected}"
    print("✅ test_command_injection_patterns PASSED")


def test_normalize_path():
    """Test URL path normalization for grouping."""
    assert AuthorizationPhase._normalize_path("https://api.example.com/users/123") == "/users/{id}"
    assert AuthorizationPhase._normalize_path("https://api.example.com/users") == "/users"
    print("✅ test_normalize_path PASSED")


if __name__ == "__main__":
    test_idor_scoring_high_risk()
    test_idor_scoring_low_risk()
    test_looks_like_id()
    test_sql_error_patterns()
    test_stack_trace_patterns()
    test_command_injection_patterns()
    test_normalize_path()
    print("\n🎉 All PRIORITY 5 authorization/fuzzing tests PASSED!")