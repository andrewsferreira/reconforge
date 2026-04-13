"""Tests for core.secrets_manager."""

import json

from core.secrets_manager import SecretManager


def test_env_provider_reads_env(monkeypatch):
    monkeypatch.setenv("RF_TEST_SECRET", "abc123")
    sm = SecretManager(provider="env")
    assert sm.get("RF_TEST_SECRET") == "abc123"


def test_file_provider_reads_json(tmp_path):
    secret_file = tmp_path / "secrets.json"
    secret_file.write_text(json.dumps({"api_key": "k-1"}))
    sm = SecretManager(provider="file", file_path=str(secret_file))
    assert sm.get("api_key") == "k-1"


def test_unknown_provider_falls_back_to_env(monkeypatch):
    monkeypatch.setenv("FALLBACK_KEY", "fallback")
    sm = SecretManager(provider="unknown")
    assert sm.get("FALLBACK_KEY") == "fallback"
