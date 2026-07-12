"""Phase 6-F/6-G: ADSmbclientTool must read timeouts from ToolConfig and
forward the caller's timeout through test_sysvol_access/test_netlogon_access."""

from unittest.mock import MagicMock

from modules.ad.tools.smbclient import ADSmbclientTool


def _make_tool(tmp_path, config=None):
    runner = MagicMock()
    runner.run.return_value = MagicMock(success=True)
    return ADSmbclientTool(runner=runner, logger=MagicMock(), output_dir=tmp_path, config=config), runner


def test_test_sysvol_access_forwards_timeout(tmp_path):
    tool, runner = _make_tool(tmp_path)
    tool.test_sysvol_access("10.10.10.1", timeout=99)
    assert runner.run.call_args.kwargs["timeout"] == 99


def test_test_netlogon_access_forwards_timeout(tmp_path):
    tool, runner = _make_tool(tmp_path)
    tool.test_netlogon_access("10.10.10.1", timeout=77)
    assert runner.run.call_args.kwargs["timeout"] == 77


def test_effective_timeout_reads_tool_config_default(tmp_path):
    """When tools.yaml provides a default_timeout for smbclient, it must
    override the caller's fallback default — proving self.tool_cfg is
    actually consulted, not dead code."""
    config = MagicMock()
    config.get_tool_config.return_value = {"default_timeout": 123}
    tool, runner = _make_tool(tmp_path, config=config)

    tool.null_session_list("10.10.10.1", timeout=60)

    assert runner.run.call_args.kwargs["timeout"] == 123
