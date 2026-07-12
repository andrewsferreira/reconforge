"""Phase 6-C: ADNmapTool.dns_all_srv must not hardcode success=True."""

from pathlib import Path
from unittest.mock import MagicMock

from core.runner import RunResult
from modules.ad.tools.nmap import ADNmapTool


def _make_tool(tmp_path: Path, results):
    runner = MagicMock()
    runner.run.side_effect = results
    logger = MagicMock()
    return ADNmapTool(runner=runner, logger=logger, output_dir=tmp_path)


def _dig_result(success: bool, returncode: int, stderr: str = "") -> RunResult:
    return RunResult(
        command="dig", returncode=returncode, stdout="", stderr=stderr,
        duration=0.1, success=success,
    )


def test_dns_all_srv_success_when_all_dig_calls_succeed(tmp_path):
    tool = _make_tool(tmp_path, [_dig_result(True, 0) for _ in range(4)])
    result = tool.dns_all_srv("corp.local", "10.10.10.1")
    assert result.success is True
    assert result.returncode == 0


def test_dns_all_srv_fails_when_one_dig_call_fails(tmp_path):
    results = [_dig_result(True, 0), _dig_result(False, 9, "connection timed out"),
               _dig_result(True, 0), _dig_result(True, 0)]
    tool = _make_tool(tmp_path, results)
    result = tool.dns_all_srv("corp.local", "10.10.10.1")
    assert result.success is False
    assert result.returncode == 9
    assert "connection timed out" in result.stderr


def test_dns_all_srv_fails_when_all_dig_calls_fail(tmp_path):
    results = [_dig_result(False, 9, "no response") for _ in range(4)]
    tool = _make_tool(tmp_path, results)
    result = tool.dns_all_srv("corp.local", "10.10.10.1")
    assert result.success is False
    assert result.returncode == 9
