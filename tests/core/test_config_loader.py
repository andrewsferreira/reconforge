"""Tests for core.config_loader – ConfigLoader."""



from core.config_loader import ConfigLoader


def test_load_tools(config_dir):
    loader = ConfigLoader(config_dir=config_dir)
    data = loader.load("tools")
    assert "tools" in data
    # Unified schema: no separate web_tools key
    assert "web_tools" not in data


def test_get_tool_config_network(config_dir):
    """Network tool reachable via unified get_tool_config."""
    loader = ConfigLoader(config_dir=config_dir)
    nmap = loader.get_tool_config("nmap")
    assert nmap["binary"] == "nmap"


def test_get_tool_config_web(config_dir):
    """Web tool reachable via unified get_tool_config (same namespace)."""
    loader = ConfigLoader(config_dir=config_dir)
    ffuf = loader.get_tool_config("ffuf")
    assert ffuf["binary"] == "ffuf"


def test_get_tool_config_missing(config_dir):
    loader = ConfigLoader(config_dir=config_dir)
    result = loader.get_tool_config("nonexistent")
    assert result == {}


def test_get_profile(config_dir):
    loader = ConfigLoader(config_dir=config_dir)
    profile = loader.get_profile("stealth")
    assert profile["opsec_mode"] == "stealth"


def test_get_dotted_key(config_dir):
    loader = ConfigLoader(config_dir=config_dir)
    binary = loader.get("tools", "tools.nmap.binary")
    assert binary == "nmap"


def test_load_caching(config_dir):
    loader = ConfigLoader(config_dir=config_dir)
    a = loader.load("tools")
    b = loader.load("tools")
    assert a is b  # same reference — cached


def test_load_missing_file(config_dir):
    loader = ConfigLoader(config_dir=config_dir)
    assert loader.load("no_such_config") == {}
