"""Phase 6-F: self.tool_cfg/_tool_cfg() must actually be consulted for
timeouts — bloodhound.py, ad/tools/ldapsearch.py, netexec.py, and one
method of advanced_impacket.py previously instantiated a ToolConfig but
never called it, silently ignoring tools.yaml overrides despite each
docstring claiming timeouts are config-driven.
"""

from unittest.mock import MagicMock

from modules.ad.tools.bloodhound import BloodhoundTool
from modules.ad.tools.ldapsearch import ADLdapsearchTool
from modules.ad.tools.netexec import NetexecTool
from modules.ad.tools.advanced_impacket import AdvancedImpacketTool


def _config_with_timeout(value: int) -> MagicMock:
    config = MagicMock()
    config.get_tool_config.return_value = {"default_timeout": value}
    return config


def test_bloodhound_collect_all_reads_tool_config(tmp_path):
    runner = MagicMock()
    runner.run.return_value = MagicMock(success=True)
    runner.check_tool.return_value = True
    tool = BloodhoundTool(runner=runner, logger=MagicMock(), output_dir=tmp_path,
                           config=_config_with_timeout(555))

    tool.collect_all("corp.local", "user", "pass", timeout=600)

    assert runner.run.call_args.kwargs["timeout"] == 555


def test_ad_ldapsearch_anonymous_bind_reads_tool_config(tmp_path):
    runner = MagicMock()
    runner.run.return_value = MagicMock(success=True)
    tool = ADLdapsearchTool(runner=runner, logger=MagicMock(), output_dir=tmp_path,
                             config=_config_with_timeout(444))

    tool.anonymous_bind_test("10.10.10.1")

    assert runner.run.call_args.kwargs["timeout"] == 444


def test_netexec_smb_enum_reads_tool_config(tmp_path):
    runner = MagicMock()
    runner.run.return_value = MagicMock(success=True)
    runner.check_tool.return_value = True
    tool = NetexecTool(runner=runner, logger=MagicMock(), output_dir=tmp_path,
                        config=_config_with_timeout(333))

    tool.smb_enum("10.10.10.1")

    assert runner.run.call_args.kwargs["timeout"] == 333


def test_advanced_impacket_machine_account_quota_reads_tool_config(tmp_path):
    runner = MagicMock()
    runner.run.return_value = MagicMock(success=True)
    tool = AdvancedImpacketTool(runner=runner, logger=MagicMock(), output_dir=tmp_path,
                                 config=_config_with_timeout(222))

    tool.get_machine_account_quota("10.10.10.1", "corp.local")

    assert runner.run.call_args.kwargs["timeout"] == 222
