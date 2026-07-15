"""Phase 6-E: synthetic RunResults must use core.runner's named RC_*
sentinels instead of magic literals that collide with unrelated meanings
(-1 == RC_TIMEOUT, -2 == RC_TOOL_NOT_FOUND).
"""

from unittest.mock import MagicMock

from core.runner import RC_POLICY_BLOCKED, RC_PRECONDITION_FAILED, RC_TOOL_NOT_FOUND
from modules.ad.tools.netexec import NetexecTool
from modules.network.tools.hydra import HydraTool
from modules.web.tools.ffuf import FfufTool


def test_hydra_unauthorized_uses_policy_blocked(tmp_path):
    runner = MagicMock()
    hydra = HydraTool(runner=runner, logger=MagicMock(), output_dir=tmp_path, authorized=False)

    result = hydra.test_default_creds("10.10.10.1", "ssh")

    assert result.returncode == RC_POLICY_BLOCKED
    assert result.success is False
    runner.run.assert_not_called()


def test_netexec_missing_binary_uses_tool_not_found(tmp_path):
    runner = MagicMock()
    runner.check_tool.return_value = False
    netexec = NetexecTool(runner=runner, logger=MagicMock(), output_dir=tmp_path)

    result = netexec.smb_enum("10.10.10.1")

    assert result.returncode == RC_TOOL_NOT_FOUND
    assert result.success is False


def test_ffuf_missing_wordlist_uses_precondition_failed(tmp_path):
    runner = MagicMock()
    ffuf = FfufTool(runner=runner, logger=MagicMock(), output_dir=tmp_path)
    ffuf.DEFAULT_WORDLISTS = []  # force "no wordlist" branch

    result = ffuf.dir_scan("http://example.com", wordlist="/nonexistent/wordlist.txt")

    assert result.returncode == RC_PRECONDITION_FAILED
    assert result.success is False
    runner.run.assert_not_called()
