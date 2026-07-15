"""ReconForge Config Loader - YAML configuration management."""

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from core.secrets_manager import SecretManager

if TYPE_CHECKING:
    from core.tool_config import ToolConfig


class ConfigLoader:
    """Load and manage YAML configuration files."""

    def __init__(self, config_dir: str | Path | None = None, environment: str | None = None):
        self.config_dir = Path(config_dir) if config_dir else Path(__file__).parent.parent / "config"
        self._cache: dict[str, dict] = {}
        self.environment = (environment or os.getenv("RECONFORGE_ENV") or "dev").strip().lower()
        self._env_dir = self.config_dir / "environments"
        self._secrets = self._build_secret_manager()

    def _build_secret_manager(self) -> SecretManager:
        provider = os.getenv("RECONFORGE_SECRET_PROVIDER", "env").strip().lower() or "env"
        file_path = os.getenv("RECONFORGE_SECRETS_FILE", "").strip()
        return SecretManager(provider=provider, file_path=file_path)

    @staticmethod
    def _merge_dicts(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        merged = dict(base)
        for k, v in override.items():
            if isinstance(v, dict) and isinstance(merged.get(k), dict):
                merged[k] = ConfigLoader._merge_dicts(merged[k], v)
            else:
                merged[k] = v
        return merged

    def _load_env_overrides(self) -> dict:
        if not self.environment:
            return {}
        for ext in (".yaml", ".yml"):
            p = self._env_dir / f"{self.environment}{ext}"
            if p.exists():
                with open(p) as f:
                    return yaml.safe_load(f) or {}
        return {}

    def _resolve_secrets(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: self._resolve_secrets(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._resolve_secrets(v) for v in obj]
        if isinstance(obj, str) and obj.startswith("${secret:") and obj.endswith("}"):
            key = obj[len("${secret:"):-1].strip()
            return self._secrets.get(key, "")
        return obj

    def load(self, name: str) -> dict:
        """Load a config file by name (without extension)."""
        if name in self._cache:
            return self._cache[name]

        for ext in (".yaml", ".yml"):
            path = self.config_dir / f"{name}{ext}"
            if path.exists():
                with open(path) as f:
                    data = yaml.safe_load(f) or {}
                env_data = self._load_env_overrides()
                override = env_data.get(name, {}) if isinstance(env_data, dict) else {}
                merged = self._merge_dicts(data, override if isinstance(override, dict) else {})
                resolved = self._resolve_secrets(merged)
                self._cache[name] = resolved
                return resolved

        self._cache[name] = {}
        return self._cache[name]

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
