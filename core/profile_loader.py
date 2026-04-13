"""ReconForge Profile Loader - Apply OPSEC-aware profiles to module configs.

Reads ``profiles.yaml`` and resolves the active profile so that every module
can query timing, allowed techniques, noise levels, and tool toggles without
hard-coding OPSEC conditionals.

Author: Andrews Ferreira
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.config_loader import ConfigLoader


# ── Defaults used when no profile matches ──────────────────────────
_DEFAULT_TIMING = {
    "nmap_timing": "T3",
    "scan_delay": "0",
    "max_retries": 2,
}

_DEFAULT_ALLOWED_NOISE = ["low", "medium"]

# Map simple opsec_mode strings to canonical profile names
_MODE_TO_PROFILE: Dict[str, str] = {
    "stealth": "stealth",
    "normal": "normal",
    "aggressive": "aggressive",
}


class ProfileLoader:
    """Load and query OPSEC scan profiles.

    Usage::

        loader = ProfileLoader(config_loader, opsec_mode="stealth")
        timing = loader.timing            # {"nmap_timing": "T2", ...}
        allowed = loader.allowed_noise     # ["low"]
        threads = loader.get("web.options.threads", default=10)
    """

    def __init__(
        self,
        config: ConfigLoader,
        opsec_mode: str = "normal",
        module: str = "",
    ) -> None:
        """Initialise the profile loader.

        Args:
            config: A :class:`ConfigLoader` instance (shared across the run).
            opsec_mode: One of ``stealth``, ``normal``, ``aggressive``
                        **or** a full profile slug from *profiles.yaml*
                        (e.g. ``stealth_ad``, ``normal_web``).
            module: Optional module hint (``network``, ``ad``, ``web``).
                    When given, the loader will first try
                    ``{opsec_mode}_{module}`` before falling back to the
                    base profile.
        """
        self._config = config
        self._opsec_mode = opsec_mode
        self._module = module
        self._profile: Dict[str, Any] = self._resolve(opsec_mode, module)

    # ── Public API ──────────────────────────────────────────────────

    @property
    def profile_data(self) -> Dict[str, Any]:
        """Return the full resolved profile dict."""
        return dict(self._profile)

    @property
    def opsec_mode(self) -> str:
        """Effective OPSEC mode string (stealth / normal / aggressive)."""
        return self._profile.get("opsec_mode", self._opsec_mode)

    @property
    def timing(self) -> Dict[str, Any]:
        """Timing configuration (nmap_timing, scan_delay, max_retries)."""
        return {**_DEFAULT_TIMING, **self._profile.get("timing", {})}

    @property
    def allowed_noise(self) -> List[str]:
        """Noise levels allowed by the current profile."""
        return self._profile.get("allowed_noise_levels", _DEFAULT_ALLOWED_NOISE)

    @property
    def nmap_timing(self) -> str:
        """Shortcut: nmap ``-T`` value (e.g. ``T2``)."""
        t = self.timing.get("nmap_timing", "T3")
        # Accept both "T3" and "3"
        return t if t.startswith("T") else f"T{t}"

    @property
    def scan_delay(self) -> str:
        """Shortcut: nmap ``--scan-delay`` value."""
        return self.timing.get("scan_delay", "0")

    @property
    def max_retries(self) -> int:
        """Shortcut: nmap ``--max-retries`` value."""
        return int(self.timing.get("max_retries", 2))

    # ── Section access ──────────────────────────────────────────────

    def section(self, key: str) -> Dict[str, Any]:
        """Return a top-level section of the profile.

        Example::

            loader.section("scanning")  # {"port_range": "-", ...}
            loader.section("ad")        # {"phases": [...], ...}
        """
        return dict(self._profile.get(key, {}))

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Deep-get using dot notation (``ad.phases``, ``web.options.threads``).

        Args:
            dotted_key: Dot-separated path into the profile dict.
            default: Fallback when any segment is missing.
        """
        node: Any = self._profile
        for part in dotted_key.split("."):
            if isinstance(node, dict):
                node = node.get(part)
            else:
                return default
            if node is None:
                return default
        return node

    def is_technique_enabled(self, technique: str) -> bool:
        """Check whether a profile-level technique toggle is on.

        Searches inside the module-specific section first, then the
        top-level profile keys.  Defaults to ``True`` (enabled) if the
        key is not present at all — the :class:`OpsecChecker` will still
        gate the action by noise level.
        """
        # Module-specific section (e.g. profile["ad"]["rid_cycling"])
        mod_section = self._profile.get(self._module, {})
        if isinstance(mod_section, dict) and technique in mod_section:
            return bool(mod_section[technique])

        # Top-level (e.g. profile["enumeration"]["enum4linux"])
        for section in self._profile.values():
            if isinstance(section, dict) and technique in section:
                return bool(section[technique])

        return True  # default: allowed

    def enabled_phases(self) -> Optional[List[str]]:
        """Return the list of phases enabled by the profile, or *None*
        if the profile does not restrict phases (let the module decide)."""
        mod_section = self._profile.get(self._module, {})
        if isinstance(mod_section, dict) and "phases" in mod_section:
            return list(mod_section["phases"])
        return None

    # ── Resolution logic ────────────────────────────────────────────

    def _resolve(self, opsec_mode: str, module: str) -> Dict[str, Any]:
        """Find the best-matching profile in *profiles.yaml*.

        Resolution order (most specific → least specific):
        1. Module-specific  (``{base_mode}_{module}``, e.g. ``stealth_ad``)
        2. Exact name  (``opsec_mode`` used as-is, e.g. ``stealth``)
        3. Base mode via canonical mapping  (``_MODE_TO_PROFILE``)
        4. Empty dict  (all defaults)

        When a *module* hint is provided, module-specific profiles take
        priority over generic base profiles.  This ensures that
        ``ProfileLoader(config, "stealth", module="ad")`` resolves to
        ``stealth_ad`` (with AD-specific phase restrictions and technique
        toggles) rather than the generic ``stealth`` profile.
        """
        base_mode = _MODE_TO_PROFILE.get(opsec_mode, opsec_mode)

        # 1. Module-specific variant (most specific)
        if module:
            candidate = f"{base_mode}_{module}"
            profile = self._config.get_profile(candidate)
            if profile:
                return profile

        # 2. Exact match
        profile = self._config.get_profile(opsec_mode)
        if profile:
            return profile

        # 3. Base mode
        if base_mode != opsec_mode:
            profile = self._config.get_profile(base_mode)
            if profile:
                return profile

        # 4. Fallback
        return {"opsec_mode": opsec_mode}
