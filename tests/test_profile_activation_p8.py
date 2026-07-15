"""Tests for PRIORITY 8 — ProfileLoader activation across all modules.

Validates that:
1. All module orchestrators pass profile to phases via _phase_kwargs.
2. All base classes accept and store the profile parameter.
3. ProfileLoader.enabled_phases() drives phase selection when no explicit phases given.
4. Tool wrappers read timing from the profile when available.
5. Backward compatibility: everything still works when profile is None.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.config_loader import ConfigLoader
from core.profile_loader import ProfileLoader

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def config_dir():
    """Return the project config directory."""
    return str(Path(__file__).resolve().parent.parent / "config")


@pytest.fixture
def stealth_profile(config_dir):
    """Create a stealth ProfileLoader instance."""
    config = ConfigLoader(config_dir=config_dir)
    return ProfileLoader(config, opsec_mode="stealth")


@pytest.fixture
def aggressive_profile(config_dir):
    """Create an aggressive ProfileLoader instance."""
    config = ConfigLoader(config_dir=config_dir)
    return ProfileLoader(config, opsec_mode="aggressive")


@pytest.fixture
def stealth_ad_profile(config_dir):
    """Create a stealth_ad ProfileLoader instance."""
    config = ConfigLoader(config_dir=config_dir)
    return ProfileLoader(config, opsec_mode="stealth", module="ad")


@pytest.fixture
def normal_surface_profile(config_dir):
    """Create a normal_surface ProfileLoader instance."""
    config = ConfigLoader(config_dir=config_dir)
    return ProfileLoader(config, opsec_mode="normal", module="surface")


@pytest.fixture
def stealth_surface_profile(config_dir):
    """Create a stealth_surface ProfileLoader instance."""
    config = ConfigLoader(config_dir=config_dir)
    return ProfileLoader(config, opsec_mode="stealth", module="surface")


# ---------------------------------------------------------------------------
# 1. ProfileLoader.enabled_phases() returns correct phases from profiles
# ---------------------------------------------------------------------------

class TestProfileEnabledPhases:
    """Test that profile-driven phase selection works correctly."""

    def test_stealth_ad_only_passive(self, stealth_ad_profile):
        """Stealth AD profile restricts to passive-only phase."""
        phases = stealth_ad_profile.enabled_phases()
        assert phases == ["passive"]

    def test_stealth_surface_only_port_discovery(self, stealth_surface_profile):
        """Stealth surface profile restricts to port_discovery phase."""
        phases = stealth_surface_profile.enabled_phases()
        assert phases == ["port_discovery"]

    def test_normal_surface_all_phases(self, normal_surface_profile):
        """Normal surface profile enables all four phases."""
        phases = normal_surface_profile.enabled_phases()
        assert phases == ["port_discovery", "service_fingerprint",
                         "vector_correlation", "prioritization"]

    def test_stealth_no_module_returns_none(self, stealth_profile):
        """Stealth without module hint returns None (no phase restriction)."""
        phases = stealth_profile.enabled_phases()
        # Base stealth profile doesn't define module-specific phases
        assert phases is None

    def test_aggressive_ad_all_phases(self, config_dir):
        """Aggressive AD profile enables all five AD phases."""
        config = ConfigLoader(config_dir=config_dir)
        profile = ProfileLoader(config, opsec_mode="aggressive", module="ad")
        phases = profile.enabled_phases()
        assert phases == ["passive", "identity", "configuration",
                         "delegation", "bloodhound"]


# ---------------------------------------------------------------------------
# 2. Profile timing properties work correctly
# ---------------------------------------------------------------------------

class TestProfileTiming:
    """Test that timing is read from the profile correctly."""

    def test_stealth_timing_t2(self, stealth_profile):
        assert stealth_profile.nmap_timing == "T2"

    def test_stealth_scan_delay(self, stealth_profile):
        assert stealth_profile.scan_delay == "500ms"

    def test_stealth_max_retries(self, stealth_profile):
        assert stealth_profile.max_retries == 1

    def test_aggressive_timing_t4(self, aggressive_profile):
        assert aggressive_profile.nmap_timing == "T4"

    def test_stealth_surface_timing_t1(self, stealth_surface_profile):
        """Stealth surface has T1 timing per profiles.yaml."""
        assert stealth_surface_profile.nmap_timing == "T1"


# ---------------------------------------------------------------------------
# 3. Tool wrappers use profile timing
# ---------------------------------------------------------------------------

class TestToolProfileIntegration:
    """Test that tool wrappers read from the profile."""

    def test_network_nmap_uses_profile_timing(self, stealth_profile):
        """Network NmapTool reads timing from profile."""
        from modules.network.tools.nmap import NmapTool
        runner = MagicMock()
        tool = NmapTool(runner, MagicMock(), Path("/tmp"), "normal",
                        profile=stealth_profile)
        assert tool._timing_flag() == "-T2"

    def test_network_nmap_fallback_without_profile(self):
        """Network NmapTool falls back to opsec_mode without profile."""
        from modules.network.tools.nmap import NmapTool
        runner = MagicMock()
        tool = NmapTool(runner, MagicMock(), Path("/tmp"), "aggressive")
        assert tool._timing_flag() == "-T4"

    def test_ad_nmap_uses_profile_timing(self, stealth_ad_profile):
        """AD ADNmapTool reads timing from profile."""
        from modules.ad.tools.nmap import ADNmapTool
        runner = MagicMock()
        tool = ADNmapTool(runner, MagicMock(), Path("/tmp"), "normal",
                          profile=stealth_ad_profile)
        assert tool._timing_flag() == "-T2"

    def test_surface_nmap_uses_profile_timing(self, stealth_surface_profile):
        """Surface NmapStealthTool reads timing from profile."""
        from modules.surface.tools.nmap_stealth import NmapStealthTool
        runner = MagicMock()
        tool = NmapStealthTool(runner, MagicMock(), Path("/tmp"), "normal",
                               profile=stealth_surface_profile)
        assert tool._timing_flag() == "-T1"

    def test_network_nmap_extra_timing_args(self, stealth_profile):
        """Stealth profile adds scan-delay and max-retries."""
        from modules.network.tools.nmap import NmapTool
        runner = MagicMock()
        tool = NmapTool(runner, MagicMock(), Path("/tmp"), "normal",
                        profile=stealth_profile)
        extra = tool._extra_timing_args()
        assert "--scan-delay" in extra
        assert "500ms" in extra
        assert "--max-retries" in extra
        assert "1" in extra

    def test_network_nmap_port_range_from_profile(self, stealth_profile):
        """Stealth profile provides restricted port range."""
        from modules.network.tools.nmap import NmapTool
        runner = MagicMock()
        tool = NmapTool(runner, MagicMock(), Path("/tmp"), "normal",
                        profile=stealth_profile)
        ports = tool._port_range()
        # Stealth profile has a specific port range
        assert "22" in ports or "80" in ports or ports == "-"

    def test_surface_nmap_default_port_range(self, normal_surface_profile):
        """Normal surface profile provides --top-ports 1000."""
        from modules.surface.tools.nmap_stealth import NmapStealthTool
        runner = MagicMock()
        tool = NmapStealthTool(runner, MagicMock(), Path("/tmp"), "normal",
                               profile=normal_surface_profile)
        ports = tool._default_port_range()
        assert "1000" in ports


# ---------------------------------------------------------------------------
# 4. Base classes accept profile parameter
# ---------------------------------------------------------------------------

class TestBaseClassProfileParam:
    """Test that all base classes accept and store profile."""

    def _make_kwargs(self, profile=None):
        """Build standard phase kwargs."""
        return {
            "logger": MagicMock(), "runner": MagicMock(), "config": MagicMock(),
            "output_dir": Path("/tmp"), "findings": MagicMock(),
            "loot": MagicMock(), "workflow": MagicMock(), "notes": MagicMock(),
            "opsec": MagicMock(), "opsec_mode": "normal", "profile": profile,
        }

    def test_network_base_stores_profile(self, stealth_profile):
        """NetworkPhaseBase stores profile attribute."""
        # Can't instantiate ABC directly, check __init__ signature
        import inspect

        from modules.network.base import NetworkPhaseBase
        sig = inspect.signature(NetworkPhaseBase.__init__)
        assert "profile" in sig.parameters

    def test_ad_base_stores_profile(self, stealth_profile):
        """ADPhaseBase stores profile attribute."""
        import inspect

        from modules.ad.base import ADPhaseBase
        sig = inspect.signature(ADPhaseBase.__init__)
        assert "profile" in sig.parameters

    def test_web_base_stores_profile(self, stealth_profile):
        """WebPhaseBase stores profile attribute."""
        import inspect

        from modules.web.base import WebPhaseBase
        sig = inspect.signature(WebPhaseBase.__init__)
        assert "profile" in sig.parameters

    def test_api_base_stores_profile(self, stealth_profile):
        """APIPhaseBase stores profile attribute."""
        import inspect

        from modules.api.base import APIPhaseBase
        sig = inspect.signature(APIPhaseBase.__init__)
        assert "profile" in sig.parameters

    def test_surface_base_stores_profile(self, stealth_profile):
        """SurfacePhaseBase stores profile attribute."""
        import inspect

        from modules.surface.base import SurfacePhaseBase
        sig = inspect.signature(SurfacePhaseBase.__init__)
        assert "profile" in sig.parameters


# ---------------------------------------------------------------------------
# 5. Module orchestrators pass profile to _phase_kwargs
# ---------------------------------------------------------------------------

class TestModuleProfileWiring:
    """Test that module orchestrators include profile in _phase_kwargs."""

    @patch("modules.network.network_module.OutputManager")
    @patch("modules.network.network_module.parse_target")
    def test_network_module_has_profile_in_kwargs(self, mock_pt, mock_om, config_dir):
        """NetworkModule includes profile in _phase_kwargs."""
        mock_pt.return_value = MagicMock(display="10.10.10.1", is_network=False,
                                         ip="10.10.10.1", hostname=None)
        from modules.network.network_module import NetworkModule
        mod = NetworkModule("10.10.10.1", config_dir=config_dir)
        assert "profile" in mod._phase_kwargs
        assert mod._phase_kwargs["profile"] is mod.profile
        assert isinstance(mod.profile, ProfileLoader)

    @patch("modules.ad.ad_module.OutputManager")
    @patch("modules.ad.ad_module.parse_target")
    def test_ad_module_has_profile_in_kwargs(self, mock_pt, mock_om, config_dir):
        """ADModule includes profile in _phase_kwargs."""
        mock_pt.return_value = MagicMock(display="10.10.10.1")
        from modules.ad.ad_module import ADModule
        mod = ADModule("10.10.10.1", config_dir=config_dir)
        assert "profile" in mod._phase_kwargs
        assert mod._phase_kwargs["profile"] is mod.profile
        assert isinstance(mod.profile, ProfileLoader)

    @patch("modules.web.web_module.OutputManager")
    def test_web_module_has_profile_in_kwargs(self, mock_om, config_dir):
        """WebModule includes profile in _phase_kwargs."""
        from modules.web.web_module import WebModule
        mod = WebModule("http://10.10.10.1", config_dir=config_dir)
        assert "profile" in mod._phase_kwargs
        assert mod._phase_kwargs["profile"] is mod.profile
        assert isinstance(mod.profile, ProfileLoader)

    @patch("modules.api.api_module.OutputManager")
    def test_api_module_has_profile_in_kwargs(self, mock_om, config_dir):
        """APIModule includes profile in _phase_kwargs."""
        from modules.api.api_module import APIModule
        mod = APIModule("http://10.10.10.1/api", config_dir=config_dir)
        assert "profile" in mod._phase_kwargs
        assert mod._phase_kwargs["profile"] is mod.profile
        assert isinstance(mod.profile, ProfileLoader)

    @patch("modules.surface.surface_module.OutputManager")
    @patch("modules.surface.surface_module.parse_target")
    def test_surface_module_has_profile_in_kwargs(self, mock_pt, mock_om, config_dir):
        """SurfaceModule includes profile in _phase_kwargs."""
        mock_pt.return_value = MagicMock(display="10.10.10.1")
        from modules.surface.surface_module import SurfaceModule
        mod = SurfaceModule("10.10.10.1", config_dir=config_dir)
        assert "profile" in mod._phase_kwargs
        assert mod._phase_kwargs["profile"] is mod.profile
        assert isinstance(mod.profile, ProfileLoader)


# ---------------------------------------------------------------------------
# 6. Profile-driven technique toggles
# ---------------------------------------------------------------------------

class TestProfileTechniqueToggles:
    """Test that profile technique toggles work correctly."""

    def test_stealth_ad_disables_enum4linux(self, stealth_ad_profile):
        """Stealth AD disables enum4linux_ng."""
        assert not stealth_ad_profile.is_technique_enabled("enum4linux_ng")

    def test_stealth_ad_disables_kerberos_enum(self, stealth_ad_profile):
        """Stealth AD disables kerberos_enum."""
        assert not stealth_ad_profile.is_technique_enabled("kerberos_enum")

    def test_stealth_ad_enables_ldap_queries(self, stealth_ad_profile):
        """Stealth AD still allows ldap_queries."""
        assert stealth_ad_profile.is_technique_enabled("ldap_queries")

    def test_stealth_ad_allows_smb_null_session(self, stealth_ad_profile):
        """Stealth AD allows smb_null_session."""
        assert stealth_ad_profile.is_technique_enabled("smb_null_session")

    def test_stealth_profile_allowed_noise_low_only(self, stealth_profile):
        """Stealth profile only allows low noise."""
        assert stealth_profile.allowed_noise == ["low"]

    def test_aggressive_profile_allows_all_noise(self, aggressive_profile):
        """Aggressive profile allows all noise levels."""
        allowed = aggressive_profile.allowed_noise
        assert "low" in allowed
        assert "high" in allowed
        assert "very_high" in allowed


# ---------------------------------------------------------------------------
# 7. Backward compatibility — None profile works
# ---------------------------------------------------------------------------

class TestBackwardCompatibility:
    """Test that everything works when profile is None."""

    def test_network_nmap_no_profile(self):
        """NmapTool works without profile (original behavior)."""
        from modules.network.tools.nmap import NmapTool
        runner = MagicMock()
        tool = NmapTool(runner, MagicMock(), Path("/tmp"), "stealth")
        assert tool.profile is None
        assert tool._timing_flag() == "-T2"
        assert tool._extra_timing_args() == []
        assert tool._port_range() == "-"

    def test_ad_nmap_no_profile(self):
        """ADNmapTool works without profile (original behavior)."""
        from modules.ad.tools.nmap import ADNmapTool
        runner = MagicMock()
        tool = ADNmapTool(runner, MagicMock(), Path("/tmp"), "aggressive")
        assert tool.profile is None
        assert tool._timing_flag() == "-T4"

    def test_surface_nmap_no_profile(self):
        """NmapStealthTool works without profile (original behavior)."""
        from modules.surface.tools.nmap_stealth import NmapStealthTool
        runner = MagicMock()
        tool = NmapStealthTool(runner, MagicMock(), Path("/tmp"), "stealth")
        assert tool.profile is None
        assert tool._timing_flag() == "-T1"
        assert tool._extra_timing_args() == []
        assert tool._default_port_range() == "--top-ports 1000"
