"""Tests for PRIORITY 9 — tools.yaml consumption via ToolConfig.

Validates that:
1. ToolConfig correctly reads tools.yaml data (timeouts, modes, safety).
2. ToolConfig with None config returns caller defaults (backward compat).
3. ConfigLoader.tool_config() convenience method works.
4. All 25 tool wrappers have tool_cfg attribute when config is provided.
5. Mode timeout resolution: mode-specific → default_timeout → caller default.
6. Safety settings (hydra), collection methods (bloodhound).
7. Generic dot-notation getter.
8. All 5 orchestrators pass config to tool constructors.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from core.config_loader import ConfigLoader
from core.tool_config import ToolConfig


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def config_dir():
    return str(Path(__file__).resolve().parent.parent / "config")


@pytest.fixture
def config(config_dir):
    return ConfigLoader(config_dir=config_dir)


@pytest.fixture
def nmap_cfg(config):
    return ToolConfig(config, "nmap")


@pytest.fixture
def hydra_cfg(config):
    return ToolConfig(config, "hydra")


@pytest.fixture
def bloodhound_cfg(config):
    return ToolConfig(config, "bloodhound_python")


@pytest.fixture
def gobuster_cfg(config):
    return ToolConfig(config, "gobuster")


@pytest.fixture
def none_cfg():
    return ToolConfig(None, "nmap")


# ---------------------------------------------------------------------------
# 1. ToolConfig top-level properties
# ---------------------------------------------------------------------------

class TestToolConfigProperties:
    def test_binary(self, nmap_cfg):
        assert nmap_cfg.binary == "nmap"

    def test_alt_binary(self, bloodhound_cfg):
        assert bloodhound_cfg.alt_binary == "bloodhound.py"

    def test_required(self, nmap_cfg, hydra_cfg):
        assert nmap_cfg.required is True
        assert hydra_cfg.required is False

    def test_default_timeout(self, nmap_cfg):
        assert nmap_cfg.default_timeout == 600

    def test_description(self, nmap_cfg):
        assert "Network mapper" in nmap_cfg.description

    def test_detection(self, hydra_cfg):
        # hydra has no top-level detection → default "medium"
        assert hydra_cfg.detection == "medium"

    def test_opt_in_only(self, hydra_cfg, nmap_cfg):
        assert hydra_cfg.opt_in_only is True
        assert nmap_cfg.opt_in_only is False

    def test_has_config(self, nmap_cfg, none_cfg):
        assert nmap_cfg.has_config is True
        assert none_cfg.has_config is False


# ---------------------------------------------------------------------------
# 2. Backward compatibility (None config)
# ---------------------------------------------------------------------------

class TestBackwardCompat:
    def test_binary_empty(self, none_cfg):
        assert none_cfg.binary == ""

    def test_default_timeout_zero(self, none_cfg):
        assert none_cfg.default_timeout == 0

    def test_mode_timeout_returns_caller_default(self, none_cfg):
        assert none_cfg.mode_timeout("syn_scan", 999) == 999

    def test_mode_args_returns_default(self, none_cfg):
        assert none_cfg.mode_args("dir", "--fallback") == "--fallback"

    def test_effective_timeout_returns_caller_default(self, none_cfg):
        assert none_cfg.effective_timeout("dir", 500) == 500
        assert none_cfg.effective_timeout(None, 500) == 500

    def test_safety_returns_default(self, none_cfg):
        assert none_cfg.safety("max_tasks", 16) == 16

    def test_collection_returns_default(self, none_cfg):
        assert none_cfg.collection("all", "timeout", 999) == 999

    def test_get_returns_default(self, none_cfg):
        assert none_cfg.get("modes.dir.timeout", 777) == 777


# ---------------------------------------------------------------------------
# 3. ConfigLoader.tool_config() convenience method
# ---------------------------------------------------------------------------

class TestConfigLoaderConvenience:
    def test_returns_tool_config_instance(self, config):
        tc = config.tool_config("gobuster")
        assert isinstance(tc, ToolConfig)
        assert tc.has_config is True

    def test_unknown_tool_returns_empty(self, config):
        tc = config.tool_config("nonexistent_tool_xyz")
        assert tc.has_config is False

    def test_equivalent_to_manual(self, config):
        tc_conv = config.tool_config("hydra")
        tc_manual = ToolConfig(config, "hydra")
        assert tc_conv.default_timeout == tc_manual.default_timeout
        assert tc_conv.opt_in_only == tc_manual.opt_in_only


# ---------------------------------------------------------------------------
# 4. Mode timeout resolution
# ---------------------------------------------------------------------------

class TestModeTimeout:
    def test_mode_specific_timeout(self, nmap_cfg):
        # ping_sweep has timeout: 120
        assert nmap_cfg.mode_timeout("ping_sweep", 9999) == 120

    def test_fallback_to_default_timeout(self, nmap_cfg):
        # nonexistent mode → default_timeout 600
        assert nmap_cfg.mode_timeout("nonexistent_mode", 9999) == 600

    def test_fallback_to_caller_default(self, none_cfg):
        # no config at all → caller default
        assert none_cfg.mode_timeout("syn_scan", 1234) == 1234

    def test_scan_profile_timeout(self, nmap_cfg):
        # nmap uses scan_profiles, not modes
        assert nmap_cfg.mode_timeout("script_scan", 100) == 900
        assert nmap_cfg.mode_timeout("aggressive_scan", 100) == 1200

    def test_effective_timeout_with_mode(self, nmap_cfg):
        assert nmap_cfg.effective_timeout("ping_sweep", 9999) == 120

    def test_effective_timeout_no_mode(self, nmap_cfg):
        # No mode → default_timeout 600
        assert nmap_cfg.effective_timeout(None, 9999) == 600


# ---------------------------------------------------------------------------
# 5. Mode args and detection
# ---------------------------------------------------------------------------

class TestModeArgs:
    def test_mode_args(self, gobuster_cfg):
        assert "dir" in gobuster_cfg.mode_args("dir")

    def test_mode_detection(self, nmap_cfg):
        assert nmap_cfg.mode_detection("ping_sweep") == "low"
        assert nmap_cfg.mode_detection("connect_scan") == "high"

    def test_mode_value(self, nmap_cfg):
        assert nmap_cfg.mode_value("syn_scan", "requires_root") is True
        assert nmap_cfg.mode_value("ping_sweep", "requires_root") is None

    def test_mode_requires_root(self, nmap_cfg):
        assert nmap_cfg.mode_requires_root("syn_scan") is True
        assert nmap_cfg.mode_requires_root("ping_sweep") is False


# ---------------------------------------------------------------------------
# 6. Safety settings (hydra)
# ---------------------------------------------------------------------------

class TestSafetySettings:
    def test_max_tasks(self, hydra_cfg):
        assert hydra_cfg.safety("max_tasks") == 4

    def test_wait_time(self, hydra_cfg):
        assert hydra_cfg.safety("wait_time") == 3

    def test_max_attempts(self, hydra_cfg):
        assert hydra_cfg.safety("max_attempts_per_account") == 10

    def test_missing_key(self, hydra_cfg):
        assert hydra_cfg.safety("nonexistent", 42) == 42


# ---------------------------------------------------------------------------
# 7. Collection methods (bloodhound)
# ---------------------------------------------------------------------------

class TestCollectionMethods:
    def test_all_method(self, bloodhound_cfg):
        assert bloodhound_cfg.collection("all", "args") == "-c All"
        assert bloodhound_cfg.collection("all", "timeout") == 900

    def test_stealth_method(self, bloodhound_cfg):
        assert "DCOnly" in bloodhound_cfg.collection("stealth", "args")

    def test_missing_method(self, bloodhound_cfg):
        assert bloodhound_cfg.collection("nope", "args", "default") == "default"


# ---------------------------------------------------------------------------
# 8. Generic dot-notation getter
# ---------------------------------------------------------------------------

class TestGenericGetter:
    def test_nested_key(self, hydra_cfg):
        assert hydra_cfg.get("safety.max_tasks") == 4

    def test_top_level_key(self, nmap_cfg):
        assert nmap_cfg.get("binary") == "nmap"

    def test_missing_key(self, nmap_cfg):
        assert nmap_cfg.get("nonexistent.deep.path", "fallback") == "fallback"


# ---------------------------------------------------------------------------
# 9. Tool wrapper integration — all 25 wrappers accept config
# ---------------------------------------------------------------------------

class TestToolWrapperIntegration:
    """Verify all tool wrappers store tool_cfg when config is provided."""

    @pytest.fixture
    def mock_deps(self):
        runner = MagicMock()
        runner.run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        logger = MagicMock()
        output_dir = "/tmp/test_output"
        return runner, logger, output_dir

    @pytest.fixture
    def mock_config(self, config):
        return config

    # -- Web module tools --

    def test_gobuster_has_tool_cfg(self, mock_deps, mock_config):
        from modules.web.tools.gobuster import GobusterTool
        tool = GobusterTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")
        assert isinstance(tool.tool_cfg, ToolConfig)

    def test_nikto_has_tool_cfg(self, mock_deps, mock_config):
        from modules.web.tools.nikto import NiktoTool
        tool = NiktoTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_ffuf_has_tool_cfg(self, mock_deps, mock_config):
        from modules.web.tools.ffuf import FfufTool
        tool = FfufTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_whatweb_has_tool_cfg(self, mock_deps, mock_config):
        from modules.web.tools.whatweb import WhatwebTool
        tool = WhatwebTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_wafw00f_has_tool_cfg(self, mock_deps, mock_config):
        from modules.web.tools.wafw00f import Wafw00fTool
        tool = Wafw00fTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_wpscan_has_tool_cfg(self, mock_deps, mock_config):
        from modules.web.tools.wpscan import WpscanTool
        tool = WpscanTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_sqlmap_has_tool_cfg(self, mock_deps, mock_config):
        from modules.web.tools.sqlmap import SqlmapTool
        tool = SqlmapTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_nuclei_has_tool_cfg(self, mock_deps, mock_config):
        from modules.web.tools.nuclei import NucleiTool
        tool = NucleiTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_curl_has_tool_cfg(self, mock_deps, mock_config):
        from modules.web.tools.curl_tool import CurlTool
        tool = CurlTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    # -- Network module tools --

    def test_nmap_net_has_tool_cfg(self, mock_deps, mock_config):
        from modules.network.tools.nmap import NmapTool
        tool = NmapTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_enum4linux_has_tool_cfg(self, mock_deps, mock_config):
        from modules.network.tools.enum4linux import Enum4linuxTool
        tool = Enum4linuxTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_smbclient_net_has_tool_cfg(self, mock_deps, mock_config):
        from modules.network.tools.smbclient import SmbclientTool
        tool = SmbclientTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_ldapsearch_net_has_tool_cfg(self, mock_deps, mock_config):
        from modules.network.tools.ldapsearch import LdapsearchTool
        tool = LdapsearchTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_hydra_has_tool_cfg(self, mock_deps, mock_config):
        from modules.network.tools.hydra import HydraTool
        tool = HydraTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    # -- API module tools --

    def test_ffuf_api_has_tool_cfg(self, mock_deps, mock_config):
        from modules.api.tools.ffuf_api import FfufApiTool
        tool = FfufApiTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_httpx_has_tool_cfg(self, mock_deps, mock_config):
        from modules.api.tools.httpx_tool import HttpxTool
        tool = HttpxTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_arjun_has_tool_cfg(self, mock_deps, mock_config):
        from modules.api.tools.arjun_tool import ArjunTool
        tool = ArjunTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_nuclei_api_has_tool_cfg(self, mock_deps, mock_config):
        from modules.api.tools.nuclei_api import NucleiApiTool
        tool = NucleiApiTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    # -- AD module tools --

    def test_nmap_ad_has_tool_cfg(self, mock_deps, mock_config):
        from modules.ad.tools.nmap import ADNmapTool
        tool = ADNmapTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_enum4linux_ng_has_tool_cfg(self, mock_deps, mock_config):
        from modules.ad.tools.enum4linux_ng import Enum4linuxNgTool
        tool = Enum4linuxNgTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_ldapsearch_ad_has_tool_cfg(self, mock_deps, mock_config):
        from modules.ad.tools.ldapsearch import ADLdapsearchTool
        tool = ADLdapsearchTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_smbclient_ad_has_tool_cfg(self, mock_deps, mock_config):
        from modules.ad.tools.smbclient import ADSmbclientTool
        tool = ADSmbclientTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_impacket_has_tool_cfg(self, mock_deps, mock_config):
        from modules.ad.tools.impacket import ImpacketTool
        tool = ImpacketTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "_config")  # impacket stores config as _config

    def test_advanced_impacket_has_tool_cfg(self, mock_deps, mock_config):
        from modules.ad.tools.advanced_impacket import AdvancedImpacketTool
        tool = AdvancedImpacketTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "_config")

    def test_bloodhound_has_tool_cfg(self, mock_deps, mock_config):
        from modules.ad.tools.bloodhound import BloodhoundTool
        tool = BloodhoundTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_netexec_has_tool_cfg(self, mock_deps, mock_config):
        from modules.ad.tools.netexec import NetexecTool
        tool = NetexecTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    # -- Surface module tools --

    def test_nmap_stealth_has_tool_cfg(self, mock_deps, mock_config):
        from modules.surface.tools.nmap_stealth import NmapStealthTool
        tool = NmapStealthTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")

    def test_service_detector_has_tool_cfg(self, mock_deps, mock_config):
        from modules.surface.tools.service_detector import ServiceDetectorTool
        tool = ServiceDetectorTool(*mock_deps, config=mock_config)
        assert hasattr(tool, "tool_cfg")


# ---------------------------------------------------------------------------
# 10. Without config — backward compat for all wrappers
# ---------------------------------------------------------------------------

class TestToolWrapperNoConfig:
    """Verify all tool wrappers work without config (backward compat)."""

    @pytest.fixture
    def mock_deps(self):
        runner = MagicMock()
        runner.run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        logger = MagicMock()
        output_dir = "/tmp/test_output"
        return runner, logger, output_dir

    def test_gobuster_no_config(self, mock_deps):
        from modules.web.tools.gobuster import GobusterTool
        tool = GobusterTool(*mock_deps)
        assert hasattr(tool, "tool_cfg")
        assert tool.tool_cfg.has_config is False

    def test_nmap_no_config(self, mock_deps):
        from modules.network.tools.nmap import NmapTool
        tool = NmapTool(*mock_deps)
        assert tool.tool_cfg.has_config is False

    def test_hydra_no_config(self, mock_deps):
        from modules.network.tools.hydra import HydraTool
        tool = HydraTool(*mock_deps)
        assert tool.tool_cfg.has_config is False

    def test_nmap_ad_no_config(self, mock_deps):
        from modules.ad.tools.nmap import ADNmapTool
        tool = ADNmapTool(*mock_deps)
        assert tool.tool_cfg.has_config is False

    def test_nmap_stealth_no_config(self, mock_deps):
        from modules.surface.tools.nmap_stealth import NmapStealthTool
        tool = NmapStealthTool(*mock_deps)
        assert tool.tool_cfg.has_config is False

    def test_ffuf_api_no_config(self, mock_deps):
        from modules.api.tools.ffuf_api import FfufApiTool
        tool = FfufApiTool(*mock_deps)
        assert tool.tool_cfg.has_config is False


# ---------------------------------------------------------------------------
# 11. ToolConfig __repr__
# ---------------------------------------------------------------------------

class TestToolConfigRepr:
    def test_repr_loaded(self, nmap_cfg):
        r = repr(nmap_cfg)
        assert "nmap" in r
        assert "loaded" in r

    def test_repr_empty(self, none_cfg):
        r = repr(none_cfg)
        assert "empty" in r


# ---------------------------------------------------------------------------
# 12. Cross-tool YAML key isolation
# ---------------------------------------------------------------------------

class TestToolKeyIsolation:
    """nmap, nmap_ad, nmap_surface must load different configs."""

    def test_nmap_vs_nmap_ad(self, config):
        nmap = ToolConfig(config, "nmap")
        nmap_ad = ToolConfig(config, "nmap_ad")
        # nmap has scan_profiles.ping_sweep; nmap_ad does not
        assert nmap.mode_timeout("ping_sweep", 0) == 120
        assert nmap_ad.mode_timeout("ping_sweep", 0) == 600  # falls to default

    def test_nmap_surface(self, config):
        tc = ToolConfig(config, "nmap_surface")
        assert tc.mode_timeout("stealth_syn", 0) == 900
        # nmap_surface has no ping_sweep
        assert tc.mode_timeout("ping_sweep", 0) == 600  # falls to default

    def test_ffuf_vs_ffuf_api(self, config):
        ffuf = ToolConfig(config, "ffuf")
        ffuf_api = ToolConfig(config, "ffuf_api")
        assert ffuf.default_timeout == 300
        assert ffuf_api.default_timeout == 300
        # Different mode arg strings
        assert ffuf.mode_args("stealth") != ffuf_api.mode_args("stealth")
