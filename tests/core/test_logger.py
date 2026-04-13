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


# ── ReconLogger basic ─────────────────────────────────────────────

def test_logger_creates(tmp_path):
    logger = ReconLogger(name="test", log_dir=tmp_path, verbose=True)
    logger.info("hello")
    log_files = list(tmp_path.glob("*.log"))
    assert len(log_files) == 1
