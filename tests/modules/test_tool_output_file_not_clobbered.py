"""Phase 6-H: tool wrappers that pass their own -o/-oJ/--log-json flag must
not also pass output_file= to Runner.run() — Runner.run() unconditionally
overwrites output_file with captured stdout after the process exits, which
corrupts (or empties) the file the tool already wrote itself. Confirmed
empirically for curl (tests/modules/web/test_curl_tool_output_file.py);
the rest are locked in here via mock assertions since those tool binaries
are not installed in this environment.
"""

from unittest.mock import MagicMock

import pytest

from modules.web.tools.whatweb import WhatwebTool
from modules.web.tools.ffuf import FfufTool
from modules.web.tools.gobuster import GobusterTool
from modules.web.tools.wpscan import WpscanTool
from modules.web.tools.wafw00f import Wafw00fTool
from modules.web.tools.nuclei import NucleiTool
from modules.api.tools.ffuf_api import FfufApiTool
from modules.api.tools.nuclei_api import NucleiApiTool
from modules.api.tools.httpx_tool import HttpxTool
from modules.api.tools.arjun_tool import ArjunTool


def _runner():
    runner = MagicMock()
    runner.run.return_value = MagicMock(success=True)
    return runner


@pytest.mark.parametrize("factory,method,args", [
    (lambda r, o: WhatwebTool(runner=r, logger=MagicMock(), output_dir=o), "scan", ("http://example.com",)),
    (lambda r, o: FfufTool(runner=r, logger=MagicMock(), output_dir=o), "dir_scan", ("http://example.com", "/etc/hosts")),
    (lambda r, o: FfufTool(runner=r, logger=MagicMock(), output_dir=o), "vhost_scan", ("http://example.com", "/etc/hosts")),
    (lambda r, o: GobusterTool(runner=r, logger=MagicMock(), output_dir=o), "dir_scan", ("http://example.com", "/etc/hosts")),
    (lambda r, o: GobusterTool(runner=r, logger=MagicMock(), output_dir=o), "dns_scan", ("example.com", "/etc/hosts")),
    (lambda r, o: WpscanTool(runner=r, logger=MagicMock(), output_dir=o), "scan", ("http://example.com",)),
    (lambda r, o: Wafw00fTool(runner=r, logger=MagicMock(), output_dir=o), "detect", ("http://example.com",)),
    (lambda r, o: NucleiTool(runner=r, logger=MagicMock(), output_dir=o), "scan", ("http://example.com",)),
    (lambda r, o: FfufApiTool(runner=r, logger=MagicMock(), output_dir=o), "endpoint_scan", ("http://example.com", "/etc/hosts")),
    (lambda r, o: FfufApiTool(runner=r, logger=MagicMock(), output_dir=o), "param_fuzz", ("http://example.com", "/etc/hosts")),
    (lambda r, o: NucleiApiTool(runner=r, logger=MagicMock(), output_dir=o), "api_scan", ("http://example.com",)),
    (lambda r, o: HttpxTool(runner=r, logger=MagicMock(), output_dir=o), "probe", ("http://example.com",)),
    (lambda r, o: ArjunTool(runner=r, logger=MagicMock(), output_dir=o), "discover_params", ("http://example.com",)),
    (lambda r, o: ArjunTool(runner=r, logger=MagicMock(), output_dir=o), "discover_params_json_body", ("http://example.com",)),
])
def test_runner_run_not_called_with_output_file(tmp_path, factory, method, args):
    runner = _runner()
    tool = factory(runner, tmp_path)
    getattr(tool, method)(*args)

    assert runner.run.called
    _, kwargs = runner.run.call_args
    assert "output_file" not in kwargs or kwargs["output_file"] is None
