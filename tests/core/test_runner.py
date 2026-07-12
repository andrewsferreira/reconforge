"""Tests for core.runner – Runner, quote_args, validate_arg."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from core.exceptions import ExecutionError
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


def test_run_malformed_string_command_returns_graceful_result(runner):
    """shlex.split() raises ValueError on malformed string commands (e.g. an
    unterminated quote) — this must produce a failed RunResult, not an
    uncaught exception, same as any other execution failure mode."""
    with pytest.warns(DeprecationWarning):
        result = runner.run('echo "unterminated')
    assert result.success is False
    assert result.returncode == -4


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


def test_command_log_redacts_password(runner):
    """The persisted command log must never carry a plaintext secret through,
    even though the console/JSONL logger already redacts separately."""
    runner.run(["smbclient", "-U", "admin", "-p", "SuperSecret123", "//10.10.10.1/share"])
    log = runner.get_command_log()
    assert len(log) == 1
    assert "SuperSecret123" not in log[0]
    assert "REDACTED" in log[0]


def test_run_result_command_redacts_password(runner):
    """RunResult.command (returned to every caller, including anything that
    persists it downstream) must be redacted, not just the logger output."""
    result = runner.run(["curl", "-H", "Authorization: Bearer abcdEFGH12345678ijklMNOP", "http://x"])
    assert "abcdEFGH12345678ijklMNOP" not in result.command
    assert "REDACTED" in result.command


def test_save_command_log_writes_redacted_content(runner, tmp_path):
    runner.run(["hydra", "-l", "admin", "-p", "hunter2hunter2", "ssh://10.10.10.1"])
    out = tmp_path / "commands.log"
    runner.save_command_log(out)
    content = out.read_text()
    assert "hunter2hunter2" not in content
    assert "REDACTED" in content


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


# ── Scope enforcement ────────────────────────────────────────────────

def _make_scope(allowed_targets, approval_id="APPROVAL-1", expired=False):
    from datetime import datetime, timedelta, timezone

    from core.authorization_gate import ScopeAuthorization

    valid_until = datetime.now(timezone.utc) + timedelta(hours=-1 if expired else 1)
    return ScopeAuthorization(
        allowed_targets=allowed_targets,
        approval_id=approval_id,
        valid_until=valid_until,
    )


def test_no_scope_configured_allows_execution():
    logger = MagicMock()
    runner = Runner(logger=logger, timeout=5, dry_run=True, target="10.10.10.1")
    result = runner.run(["echo", "hello"])
    assert result.success is True


def test_target_in_scope_allows_construction_and_execution():
    logger = MagicMock()
    scope = _make_scope(["10.10.10.1"])
    runner = Runner(
        logger=logger, timeout=5, dry_run=True,
        target="10.10.10.1", scope=scope, approval_id="APPROVAL-1",
    )
    result = runner.run(["echo", "hello"])
    assert result.success is True


def test_target_out_of_scope_blocks_construction():
    from core.exceptions import ScopeViolationError

    logger = MagicMock()
    scope = _make_scope(["10.10.10.1"])
    with pytest.raises(ScopeViolationError):
        Runner(
            logger=logger, timeout=5, dry_run=True,
            target="10.10.10.99", scope=scope, approval_id="APPROVAL-1",
        )


def test_wrong_approval_id_blocks_construction():
    from core.exceptions import ScopeViolationError

    logger = MagicMock()
    scope = _make_scope(["10.10.10.1"])
    with pytest.raises(ScopeViolationError):
        Runner(
            logger=logger, timeout=5, dry_run=True,
            target="10.10.10.1", scope=scope, approval_id="WRONG-ID",
        )


def test_expired_scope_blocks_execution_mid_run():
    """A scope that was valid at construction but expires before run() must
    still block — this covers approvals expiring during a long-running scan."""
    from core.exceptions import ScopeViolationError

    logger = MagicMock()
    scope = _make_scope(["10.10.10.1"])
    runner = Runner(
        logger=logger, timeout=5, dry_run=True,
        target="10.10.10.1", scope=scope, approval_id="APPROVAL-1",
    )
    # Simulate the approval expiring after construction but before execution.
    scope.valid_until = scope.valid_until.replace(year=2000)
    with pytest.raises(ScopeViolationError):
        runner.run(["echo", "hello"])


# ── run_or_raise() / check_tool_or_raise() ───────────────────────────
#
# These typed-exception entry points previously had zero test coverage
# (and zero real call sites) — see docs/ARCHITECTURE_REVIEW.md P1.

def test_run_or_raise_returns_result_on_success(runner):
    result = runner.run_or_raise(["echo", "hello"])
    assert result.success is True


def test_run_or_raise_raises_tool_not_found(runner):
    from core.exceptions import ToolNotFoundError

    with pytest.raises(ToolNotFoundError):
        runner.run_or_raise(["nonexistent_tool_xyz123"])


def test_run_or_raise_raises_timeout(runner):
    from core.exceptions import TimeoutError as ReconTimeoutError

    with pytest.raises(ReconTimeoutError):
        runner.run_or_raise(["sleep", "60"], timeout=1)


def test_run_or_raise_raises_kill_switch_blocked(runner, monkeypatch):
    from core.exceptions import KillSwitchBlockedError

    monkeypatch.setenv("RECONFORGE_KILL_SWITCH", "1")
    with pytest.raises(KillSwitchBlockedError):
        runner.run_or_raise(["echo", "hello"])


def test_run_or_raise_raises_policy_blocked(runner, monkeypatch):
    from core.exceptions import PolicyBlockedError

    monkeypatch.setenv("RECONFORGE_POLICY_ENFORCE", "1")
    monkeypatch.setenv("RECONFORGE_APPROVAL_TIER", "low")
    with pytest.raises(PolicyBlockedError):
        runner.run_or_raise(["sqlmap", "-u", "https://example.com", "--os-shell"])


def test_run_or_raise_raises_invalid_command(runner):
    from core.exceptions import InvalidCommandError

    with pytest.raises(InvalidCommandError):
        # Unbalanced quote — shlex.split raises ValueError on this string
        # command (deprecated string form; still supported for back-compat).
        with pytest.warns(DeprecationWarning):
            runner.run_or_raise('echo "unterminated')


def test_run_or_raise_raises_generic_execution_error_on_nonzero_exit(runner):
    with pytest.raises(ExecutionError):
        runner.run_or_raise(["false"])


def test_check_tool_or_raise_returns_true_for_present_tool(runner):
    assert runner.check_tool_or_raise("echo") is True


def test_check_tool_or_raise_raises_for_missing_tool(runner):
    from core.exceptions import ToolNotFoundError

    with pytest.raises(ToolNotFoundError):
        runner.check_tool_or_raise("nonexistent_tool_xyz123")


# ── Environment allowlist ────────────────────────────────────────────

def test_child_process_does_not_inherit_arbitrary_secrets(runner, monkeypatch):
    """A secret set in ReconForge's own environment (e.g. a vault key) must
    not be handed to every external tool by default — only an explicit
    allowlist of safe variables is passed through."""
    monkeypatch.setenv("RECONFORGE_VAULT_KEY", "super-secret-fernet-key")
    monkeypatch.setenv("SOME_RANDOM_API_TOKEN", "should-not-leak")
    result = runner.run(["env"])
    assert "RECONFORGE_VAULT_KEY" not in result.stdout
    assert "super-secret-fernet-key" not in result.stdout
    assert "SOME_RANDOM_API_TOKEN" not in result.stdout


def test_child_process_inherits_path(runner):
    result = runner.run(["env"])
    assert "PATH=" in result.stdout


def test_extra_env_is_additive_not_a_full_replacement(runner):
    """env= adds a variable on top of the safe default env; it does not
    replace it (PATH must still be present so the child can find tools)."""
    result = runner.run(["env"], env={"CUSTOM_VAR": "custom_value"})
    assert "PATH=" in result.stdout
    assert "CUSTOM_VAR=custom_value" in result.stdout


# ── Working directory control ────────────────────────────────────────

def test_cwd_controls_subprocess_working_directory(runner, tmp_path):
    (tmp_path / "marker_file.txt").write_text("x")
    result = runner.run(["ls"], cwd=tmp_path)
    assert "marker_file.txt" in result.stdout


# ── Output size limits ───────────────────────────────────────────────

def test_output_is_truncated_beyond_max_output_bytes():
    logger = MagicMock()
    runner = Runner(logger=logger, timeout=5, dry_run=False, max_output_bytes=100)
    result = runner.run(["python3", "-c", "print('A' * 1000)"])
    assert len(result.stdout) < 1000
    assert "truncated" in result.stdout


def test_output_under_cap_is_not_modified():
    logger = MagicMock()
    runner = Runner(logger=logger, timeout=5, dry_run=False, max_output_bytes=1000)
    result = runner.run(["echo", "hello"])
    assert result.stdout.strip() == "hello"
    assert "truncated" not in result.stdout


def test_max_output_bytes_zero_disables_truncation():
    logger = MagicMock()
    runner = Runner(logger=logger, timeout=5, dry_run=False, max_output_bytes=0)
    result = runner.run(["python3", "-c", "print('B' * 1000)"])
    assert len(result.stdout) > 1000
    assert "truncated" not in result.stdout


def test_output_file_receives_full_untruncated_content(tmp_path):
    """output_file is raw evidence and must never be truncated, even when
    the in-memory RunResult is capped."""
    logger = MagicMock()
    runner = Runner(logger=logger, timeout=5, dry_run=False, max_output_bytes=100)
    out = tmp_path / "raw.txt"
    result = runner.run(["python3", "-c", "print('C' * 1000)"], output_file=out)
    assert len(out.read_text()) > 1000
    assert len(result.stdout) < 1000
