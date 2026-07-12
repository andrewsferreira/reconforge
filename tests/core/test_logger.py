"""Tests for core.logger – sanitize_log."""

import pytest

from core.logger import sanitize_log, ReconLogger


# ── sanitize_log ──────────────────────────────────────────────────

def test_redact_password_equals():
    msg = "login password=SuperSecret123"
    result = sanitize_log(msg)
    assert "SuperSecret123" not in result
    assert "REDACTED" in result


def test_redact_password_colon():
    msg = "password: mypass"
    result = sanitize_log(msg)
    assert "mypass" not in result


def test_redact_p_flag():
    msg = "rpcclient -U user -p password123 10.10.10.1"
    result = sanitize_log(msg)
    assert "password123" not in result


def test_redact_api_key():
    msg = "API_KEY=sk_live_abcdef12345"
    result = sanitize_log(msg)
    assert "sk_live_abcdef12345" not in result


def test_redact_bearer_token():
    msg = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdefghij"
    result = sanitize_log(msg)
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdefghij" not in result
    assert "Bearer ***REDACTED***" in result


def test_redact_ntlm_hash():
    msg = "Got hash: aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42"
    result = sanitize_log(msg)
    assert "aad3b435b51404ee" not in result
    assert "HASH_REDACTED" in result


def test_clean_message_unchanged():
    msg = "Scanning port 80 on 10.10.10.1"
    assert sanitize_log(msg) == msg


def test_redact_authorization_header_bearer_token():
    """Regression test: the generic 'authorization=<value>' pattern used to
    run before the Bearer-token pattern, so its \\S+ only consumed the
    literal word "Bearer" and left the actual token in
    "Authorization: Bearer <token>" unredacted. Patterns are now ordered so
    this can't happen."""
    msg = "curl -H 'Authorization: Bearer abcdEFGH12345678ijklMNOP' http://x"
    result = sanitize_log(msg)
    assert "abcdEFGH12345678ijklMNOP" not in result
    assert "REDACTED" in result
    # Exactly one redaction marker — not the double "***REDACTED*** ***REDACTED***"
    # artifact from the generic pattern re-matching the word "Bearer" itself.
    assert result.count("REDACTED") == 1


# ── Phase 4: expanded redaction coverage ──────────────────────────

def test_redact_private_key_block():
    msg = (
        "id_rsa contents:\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAtest\nmore==\n"
        "-----END RSA PRIVATE KEY-----\ndone"
    )
    result = sanitize_log(msg)
    assert "MIIEowIBAAKCAQEAtest" not in result
    assert "PRIVATE_KEY_REDACTED" in result
    assert "done" in result  # content outside the block is preserved


def test_redact_negotiate_kerberos_ticket():
    msg = "curl -H 'Authorization: Negotiate YIIFvQYJKoZIhvcSAQICAQBuggWuMIIFqg=='"
    result = sanitize_log(msg)
    assert "YIIFvQYJKoZIhvcSAQICAQBuggWuMIIFqg==" not in result
    assert result.count("REDACTED") == 1


def test_redact_cookie_header():
    msg = "Cookie: session=abc123def456; other=1"
    result = sanitize_log(msg)
    assert "abc123def456" not in result
    assert "REDACTED" in result


def test_redact_set_cookie_header():
    msg = "Set-Cookie: sessionid=deadbeef1234; Path=/; HttpOnly"
    result = sanitize_log(msg)
    assert "deadbeef1234" not in result
    assert "Path=/" in result  # non-sensitive attributes preserved


def test_redact_aws_access_key_id():
    msg = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    result = sanitize_log(msg)
    assert "AKIAIOSFODNN7EXAMPLE" not in result


def test_redact_aws_secret_access_key():
    msg = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    result = sanitize_log(msg)
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in result


def test_redact_gcp_api_key():
    msg = "key=AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"
    result = sanitize_log(msg)
    assert "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY" not in result


def test_redact_azure_account_key():
    msg = "AccountKey=abcd1234EXAMPLEKEY==;EndpointSuffix=core.windows.net"
    result = sanitize_log(msg)
    assert "abcd1234EXAMPLEKEY==" not in result
    assert "core.windows.net" in result


def test_redact_postgres_connection_string():
    msg = "postgres://admin:SuperSecret123@db.example.com:5432/mydb"
    result = sanitize_log(msg)
    assert "SuperSecret123" not in result
    assert "admin" not in result
    assert "db.example.com:5432/mydb" in result  # host/db not sensitive, kept for debugging


def test_redact_mongodb_connection_string():
    msg = "mongodb+srv://user:p4ss@cluster0.mongodb.net/test"
    result = sanitize_log(msg)
    assert "p4ss" not in result


def test_redact_mysql_connection_string():
    msg = "mysql://root:toor@127.0.0.1:3306/app"
    result = sanitize_log(msg)
    assert "toor" not in result


# ── ReconLogger basic ─────────────────────────────────────────────

def test_logger_creates(tmp_path):
    logger = ReconLogger(name="test", log_dir=tmp_path, verbose=True)
    logger.info("hello")
    log_files = list(tmp_path.glob("*.log"))
    assert len(log_files) == 1
