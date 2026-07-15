"""ReconForge ToolConfig — Typed accessor for tools.yaml configuration.

Provides a clean API for tool wrappers to read their YAML configuration
(timeouts, mode-specific arguments, safety settings) with **fallback to
current hardcoded defaults**, ensuring full backward compatibility.

Usage inside a tool wrapper::

    from core.tool_config import ToolConfig

    class GobusterTool:
        def __init__(self, runner, logger, output_dir, opsec_mode="normal",
                     config=None):
            self.tool_cfg = ToolConfig(config, "gobuster")
            # ...

        def dir_scan(self, target, timeout=600):
            effective_timeout = self.tool_cfg.mode_timeout("dir", timeout)
            threads = self.tool_cfg.mode_value("dir", "threads",
                                               self._threads())
            # ...

Author: Andrews Ferreira
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.config_loader import ConfigLoader


class ToolConfig:
    """Typed accessor for a single tool's ``tools.yaml`` configuration.

    Parameters
    ----------
    config : ConfigLoader | None
        A :class:`ConfigLoader` instance.  When *None*, every accessor
        returns its caller-supplied default — providing full backward
        compatibility for tool wrappers that don't yet receive a config.
    tool_name : str
        The key under ``tools:`` in *tools.yaml* (e.g. ``"gobuster"``).
    """

    def __init__(self, config: ConfigLoader | None, tool_name: str) -> None:
        self._tool_name = tool_name
        if config is not None:
            self._data: dict[str, Any] = config.get_tool_config(tool_name)
        else:
            self._data = {}

    # ------------------------------------------------------------------
    # Top-level properties
    # ------------------------------------------------------------------

    @property
    def binary(self) -> str:
        """Primary binary name (e.g. ``nmap``)."""
        return self._data.get("binary", "")

    @property
    def alt_binary(self) -> str:
        """Alternative binary name (e.g. ``impacket-GetADUsers``)."""
        return self._data.get("alt_binary", "")

    @property
    def required(self) -> bool:
        """Whether the tool is required for the module to operate."""
        return bool(self._data.get("required", False))

    @property
    def default_timeout(self) -> int:
        """Top-level ``default_timeout`` from the YAML entry."""
        return int(self._data.get("default_timeout", 0))

    @property
    def description(self) -> str:
        return self._data.get("description", "")

    @property
    def detection(self) -> str:
        """Top-level detection level (if present)."""
        return self._data.get("detection", "medium")

    @property
    def opt_in_only(self) -> bool:
        return bool(self._data.get("opt_in_only", False))

    @property
    def has_config(self) -> bool:
        """True when a non-empty YAML entry was loaded."""
        return bool(self._data)

    # ------------------------------------------------------------------
    # Mode / scan_profile helpers
    # ------------------------------------------------------------------

    def _modes(self) -> dict[str, Any]:
        """Return the ``modes`` or ``scan_profiles`` mapping."""
        return self._data.get("modes", self._data.get("scan_profiles", {}))

    def mode_timeout(self, mode: str, default: int) -> int:
        """Timeout for a named mode/scan_profile.

        Falls back to the top-level ``default_timeout``, then to the
        caller-supplied *default*.
        """
        modes = self._modes()
        mode_data = modes.get(mode, {})
        if "timeout" in mode_data:
            return int(mode_data["timeout"])
        if self.default_timeout:
            return self.default_timeout
        return default

    def mode_args(self, mode: str, default: str = "") -> str:
        """Raw argument string for a named mode (e.g. ``"-a 3"``)."""
        modes = self._modes()
        return modes.get(mode, {}).get("args", default)

    def mode_detection(self, mode: str, default: str = "medium") -> str:
        """Detection level for a named mode."""
        modes = self._modes()
        return modes.get(mode, {}).get("detection", default)

    def mode_value(self, mode: str, key: str, default: Any = None) -> Any:
        """Arbitrary key from a mode/scan_profile entry."""
        modes = self._modes()
        return modes.get(mode, {}).get(key, default)

    def mode_requires_root(self, mode: str) -> bool:
        """Whether a scan profile requires root."""
        modes = self._modes()
        return bool(modes.get(mode, {}).get("requires_root", False))

    # ------------------------------------------------------------------
    # Safety settings (e.g. hydra)
    # ------------------------------------------------------------------

    def safety(self, key: str, default: Any = None) -> Any:
        """Read a key from the ``safety:`` block."""
        return self._data.get("safety", {}).get(key, default)

    # ------------------------------------------------------------------
    # Collection methods (e.g. bloodhound)
    # ------------------------------------------------------------------

    def collection(self, method: str, key: str, default: Any = None) -> Any:
        """Read a key from ``collection_methods.<method>``."""
        methods = self._data.get("collection_methods", {})
        return methods.get(method, {}).get(key, default)

    # ------------------------------------------------------------------
    # Generic getter
    # ------------------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        """Dot-notation getter (e.g. ``"safety.max_tasks"``)."""
        data: Any = self._data
        for part in key.split("."):
            if isinstance(data, dict):
                data = data.get(part)
                if data is None:
                    return default
            else:
                return default
        return data

    # ------------------------------------------------------------------
    # Convenience: resolve effective timeout for a method call
    # ------------------------------------------------------------------

    def effective_timeout(self, mode: str | None, caller_default: int) -> int:
        """Resolve timeout: mode-specific → tool default → caller default."""
        if mode:
            return self.mode_timeout(mode, caller_default)
        if self.default_timeout:
            return self.default_timeout
        return caller_default

    # ------------------------------------------------------------------
    # Representation
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        status = "loaded" if self._data else "empty"
        return f"<ToolConfig tool={self._tool_name!r} {status}>"
