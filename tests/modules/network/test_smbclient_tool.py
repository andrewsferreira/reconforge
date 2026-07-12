"""Phase 6-A: SmbclientTool.list_share_contents must reject batch-command injection via path."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from core.exceptions import InvalidToolArgumentError
from modules.network.tools.smbclient import SmbclientTool


def _make_tool(tmp_path: Path) -> SmbclientTool:
    runner = MagicMock()
    runner.run.return_value = MagicMock(success=True)
    logger = MagicMock()
    return SmbclientTool(runner=runner, logger=logger, output_dir=tmp_path)


def test_list_share_contents_rejects_semicolon_injection(tmp_path):
    tool = _make_tool(tmp_path)
    with pytest.raises(InvalidToolArgumentError):
        tool.list_share_contents("10.10.10.1", "share", path="foo; rm -rf /")


def test_list_share_contents_rejects_pipe_injection(tmp_path):
    tool = _make_tool(tmp_path)
    with pytest.raises(InvalidToolArgumentError):
        tool.list_share_contents("10.10.10.1", "share", path="foo | del *")


def test_list_share_contents_accepts_clean_path(tmp_path):
    tool = _make_tool(tmp_path)
    result = tool.list_share_contents("10.10.10.1", "share", path="Documents/reports")
    assert result.success is True


def test_list_share_contents_accepts_empty_path(tmp_path):
    tool = _make_tool(tmp_path)
    result = tool.list_share_contents("10.10.10.1", "share", path="")
    assert result.success is True
