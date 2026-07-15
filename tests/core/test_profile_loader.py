"""Tests for core.profile_loader – ProfileLoader."""


from core.config_loader import ConfigLoader
from core.profile_loader import ProfileLoader


def test_resolve_exact_name(config_dir):
    loader = ProfileLoader(ConfigLoader(config_dir=config_dir), opsec_mode="stealth")
    assert loader.opsec_mode == "stealth"


def test_timing_defaults(config_dir):
    loader = ProfileLoader(ConfigLoader(config_dir=config_dir), opsec_mode="stealth")
    timing = loader.timing
    assert timing["nmap_timing"] == "T2"
    assert timing["max_retries"] == 1


def test_nmap_timing_property(config_dir):
    loader = ProfileLoader(ConfigLoader(config_dir=config_dir), opsec_mode="aggressive")
    assert loader.nmap_timing.startswith("T")


def test_allowed_noise(config_dir):
    loader = ProfileLoader(ConfigLoader(config_dir=config_dir), opsec_mode="stealth")
    assert loader.allowed_noise == ["low"]


def test_module_specific_resolution(config_dir):
    """stealth_web used directly should resolve to stealth_web profile."""
    loader = ProfileLoader(
        ConfigLoader(config_dir=config_dir),
        opsec_mode="stealth_web",
    )
    # stealth_web has nmap_timing T1
    assert loader.timing["nmap_timing"] == "T1"


def test_enabled_phases_from_module(config_dir):
    loader = ProfileLoader(
        ConfigLoader(config_dir=config_dir),
        opsec_mode="stealth_web",
        module="web",
    )
    phases = loader.enabled_phases()
    assert phases == ["surface"]


def test_enabled_phases_none_when_not_set(config_dir):
    loader = ProfileLoader(ConfigLoader(config_dir=config_dir), opsec_mode="normal")
    assert loader.enabled_phases() is None


def test_get_dotted_key(config_dir):
    loader = ProfileLoader(ConfigLoader(config_dir=config_dir), opsec_mode="normal")
    val = loader.get("timing.nmap_timing")
    assert val == "T3"


def test_get_missing_key(config_dir):
    loader = ProfileLoader(ConfigLoader(config_dir=config_dir), opsec_mode="normal")
    assert loader.get("nonexistent.key", default="fallback") == "fallback"


def test_is_technique_enabled_default(config_dir):
    loader = ProfileLoader(ConfigLoader(config_dir=config_dir), opsec_mode="normal")
    assert loader.is_technique_enabled("nmap") is True  # default


def test_fallback_unknown_mode(config_dir):
    """Unknown opsec mode should not crash — returns defaults."""
    loader = ProfileLoader(ConfigLoader(config_dir=config_dir), opsec_mode="unknown_mode")
    assert loader.opsec_mode == "unknown_mode"
    assert loader.nmap_timing == "T3"  # default
