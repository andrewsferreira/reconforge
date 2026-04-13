"""Tests for core.runner – Runner, quote_args, validate_arg."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from core.runner import Runner, RunResult, quote_args, validate_arg


# ── quote_args / validate_arg ─────────────────────────────────────

def test_quote_args_simple():
    assert quote_args("hello", "world") == "hello world"


def test_quote_args_special_chars():
    result = quote_args("hello world", "it's")
    assert "hello world" in result
    assert "it" in result


def test_validate_arg_clean():
    assert validate_arg("10.10.10.1") == "10.10.10.1"


def test_validate_arg_rejects_semicolon():
    with pytest.raises(ValueError, match="unsafe"):
        validate_arg("127.0.0.1; rm -rf /")


def test_validate_arg_rejects_pipe():
    with pytest.raises(ValueError, match="unsafe"):
        validate_arg("foo | bar")


def test_validate_arg_rejects_backtick():
    with pytest.raises(ValueError, match="unsafe"):
        validate_arg("foo`whoami`")


# ── Runner ────────────────────────────────────────────────────────

@pytest.fixture
def runner():
    logger = MagicMock()
    return Runner(logger=logger, timeout=5, dry_run=False)


@pytest.fixture
def dry_runner():
    logger = MagicMock()
    return Runner(logger=logger, timeout=5, dry_run=True)


def test_dry_run_returns_success(dry_runner):
    result = dry_runner.run("echo hello")
    assert result.success is True
    assert result.returncode == 0


def test_run_echo(runner):
    result = runner.run("echo hello")
    assert result.success is True
    assert "hello" in result.stdout


def test_run_list_form(runner):
    result = runner.run(["echo", "hello", "world"])
    assert result.success is True
    assert "hello world" in result.stdout


def test_run_missing_tool(runner):
    result = runner.run("nonexistent_tool_xyz123")
    assert result.success is False
    assert result.returncode == -2


def test_run_timeout(runner):
    result = runner.run("sleep 60", timeout=1)
    assert result.success is False
    assert "Timeout" in result.stderr


def test_run_output_file(runner, tmp_path):
    out = tmp_path / "out.txt"
    result = runner.run("echo file_content", output_file=out)
    assert result.success is True
    assert out.read_text().strip() == "file_content"


def test_check_tool_exists(runner):
    assert runner.check_tool("echo") is True


def test_check_tool_missing(runner):
    assert runner.check_tool("nonexistent_tool_xyz123") is False


def test_command_log(runner):
    runner.run("echo a")
    runner.run("echo b")
    log = runner.get_command_log()
    assert len(log) == 2


def test_kill_switch_blocks_execution(runner, monkeypatch):
    monkeypatch.setenv("RECONFORGE_KILL_SWITCH", "1")
    result = runner.run(["echo", "hello"])
    assert result.success is False
    assert result.returncode == -5
    assert "kill-switch" in result.stderr.lower()


def test_policy_engine_blocks_high_risk_without_approval(runner, monkeypatch):
    monkeypatch.setenv("RECONFORGE_POLICY_ENFORCE", "1")
    monkeypatch.setenv("RECONFORGE_APPROVAL_TIER", "low")
    result = runner.run(["sqlmap", "-u", "https://example.com", "--os-shell"])
    assert result.success is False
    assert result.returncode == -6
    assert "policy blocked" in result.stderr.lower()
