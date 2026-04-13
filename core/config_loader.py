"""ReconForge Config Loader - YAML configuration management."""

import yaml
from pathlib import Path
from typing import Any, Dict, Optional


class ConfigLoader:
    """Load and manage YAML configuration files."""

    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = Path(config_dir) if config_dir else Path(__file__).parent.parent / "config"
        self._cache: Dict[str, dict] = {}

    def load(self, name: str) -> dict:
        """Load a config file by name (without extension)."""
        if name in self._cache:
            return self._cache[name]

        for ext in (".yaml", ".yml"):
            path = self.config_dir / f"{name}{ext}"
            if path.exists():
                with open(path) as f:
                    data = yaml.safe_load(f) or {}
                self._cache[name] = data
                return data

        return {}

    def get_tool_config(self, tool_name: str) -> dict:
        """Get configuration for a specific tool.

        All tools live under the single ``tools`` top-level key in
        *tools.yaml*.  No fallback namespaces – the config file is
        the authoritative source of truth.
        """
        data = self.load("tools")
        return data.get("tools", {}).get(tool_name, {})

    def get_profile(self, profile_name: str) -> dict:
        """Get a scan profile configuration."""
        profiles = self.load("profiles")
        return profiles.get("profiles", {}).get(profile_name, {})

    def tool_config(self, tool_name: str) -> "ToolConfig":
        """Return a :class:`ToolConfig` accessor for *tool_name*.

        This is a thin convenience wrapper around :pymethod:`get_tool_config`
        that returns a typed helper object instead of a raw dict.
        """
        from core.tool_config import ToolConfig
        return ToolConfig(self, tool_name)

    def get(self, name: str, key: str, default: Any = None) -> Any:
        """Get a specific key from a config file."""
        data = self.load(name)
        keys = key.split(".")
        for k in keys:
            if isinstance(data, dict):
                data = data.get(k, default)
            else:
                return default
        return data
