"""Provider router for foundational orchestrator flows."""

from __future__ import annotations

from typing import Dict

from core.adapters.base_adapter import ProviderAdapter


class ModuleRouter:
    """Registry-based router for provider adapters."""

    def __init__(self):
        self._providers: Dict[str, ProviderAdapter] = {}

    def register(self, provider: str, adapter: ProviderAdapter) -> None:
        key = provider.strip().lower()
        if not key:
            raise ValueError("provider key cannot be empty")
        self._providers[key] = adapter

    def get(self, provider: str) -> ProviderAdapter:
        key = provider.strip().lower()
        if key not in self._providers:
            raise ValueError(f"provider not registered: {provider}")
        return self._providers[key]

    def has(self, provider: str) -> bool:
        return provider.strip().lower() in self._providers
