"""Tests for modules.api.api_module – APIModule."""

import pytest

from modules.api.api_module import APIModule


def test_module_name():
    assert APIModule.MODULE_NAME == "api"


def test_valid_phases():
    assert set(APIModule.VALID_PHASES) == {
        "discovery", "authentication", "fuzzing", "authorization"
    }


def test_normalise_url_adds_scheme():
    assert APIModule._normalise_url("example.com/api") == "http://example.com/api"


def test_normalise_url_strips_trailing_slash():
    assert APIModule._normalise_url("http://example.com/api/") == "http://example.com/api"


def test_normalise_url_preserves_https():
    assert APIModule._normalise_url("https://api.example.com") == "https://api.example.com"


def test_instantiation_dry_run(tmp_path):
    """Module can be instantiated in dry-run mode without errors."""
    module = APIModule(
        target="http://127.0.0.1:8080/api/v1",
        output_base=str(tmp_path / "outputs"),
        dry_run=True,
        verbose=False,
    )
    assert module.target_url == "http://127.0.0.1:8080/api/v1"
    assert module.opsec_mode == "normal"


def test_instantiation_with_headers(tmp_path):
    module = APIModule(
        target="http://127.0.0.1/api",
        output_base=str(tmp_path / "outputs"),
        dry_run=True,
        headers=["X-Api-Key: abc123"],
        auth_token="Bearer test",
    )
    assert module.headers == ["X-Api-Key: abc123"]
    assert module.auth_token == "Bearer test"


def test_check_tools_returns_dict(tmp_path):
    module = APIModule(
        target="http://127.0.0.1/api",
        output_base=str(tmp_path / "outputs"),
        dry_run=True,
    )
    result = module._check_tools()
    assert isinstance(result, dict)
    assert "ffuf" in result
    assert "arjun" in result
    assert "nuclei" in result
    assert "httpx" in result
