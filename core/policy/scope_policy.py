"""Scope and safety policy primitives for orchestrated execution.

This module introduces strict, testable policy enforcement foundations while
remaining compatible with existing CLI/module flows.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatch
from typing import Iterable, Set
from urllib.parse import urlparse

from core.schemas.contracts import ActionClass, ExecutionMode, ExecutionRequest

_ALLOWED_ACTIONS_BY_MODE: dict[ExecutionMode, Set[ActionClass]] = {
    "safe": {"discovery", "enumeration", "fingerprinting", "enrichment", "correlation", "reporting"},
    "standard": {"discovery", "enumeration", "fingerprinting", "enrichment", "correlation", "reporting"},
    "extended": {"discovery", "enumeration", "fingerprinting", "enrichment", "correlation", "reporting"},
}


@dataclass(frozen=True)
class ScopePolicy:
    """Immutable scope snapshot used during execution."""

    scope_id: str
    approval_id: str
    valid_until: datetime
    allowed_domains: tuple[str, ...] = ()
    allowed_subdomains: tuple[str, ...] = ()
    allowed_cidrs: tuple[str, ...] = ()
    explicit_allow_targets: tuple[str, ...] = ()
    explicit_denylist: tuple[str, ...] = ()
    mode_restrictions: tuple[ExecutionMode, ...] = ("safe", "standard", "extended")
    dry_run_only: bool = False

    @classmethod
    def from_mapping(cls, data: dict) -> "ScopePolicy":
        valid_until_raw = str(data.get("valid_until", "")).strip()
        if not valid_until_raw:
            raise ValueError("Scope policy missing valid_until")
        valid_until = _parse_iso_datetime(valid_until_raw)

        return cls(
            scope_id=str(data.get("scope_id", "scope-default")).strip() or "scope-default",
            approval_id=str(data.get("approval_id", "")).strip(),
            valid_until=valid_until,
            allowed_domains=_as_tuple(data.get("allowed_domains", [])),
            allowed_subdomains=_as_tuple(data.get("allowed_subdomains", [])),
            allowed_cidrs=_as_tuple(data.get("allowed_cidrs", [])),
            explicit_allow_targets=_as_tuple(data.get("allowed_targets", [])),
            explicit_denylist=_as_tuple(data.get("denylist", [])),
            mode_restrictions=_as_mode_tuple(data.get("mode_restrictions", ["safe", "standard", "extended"])),
            dry_run_only=bool(data.get("dry_run_only", False)),
        )


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str = ""


class ScopeValidator:
    """Deterministic scope + safety validator."""

    def validate(self, request: ExecutionRequest, policy: ScopePolicy) -> ScopeDecision:
        if not policy.approval_id:
            return ScopeDecision(False, "scope policy missing approval_id")

        now = datetime.now(timezone.utc)
        if now > policy.valid_until:
            return ScopeDecision(False, f"scope expired at {policy.valid_until.isoformat()}")

        if request.mode not in policy.mode_restrictions:
            return ScopeDecision(False, f"mode '{request.mode}' not allowed by scope")

        if policy.dry_run_only and not request.dry_run:
            return ScopeDecision(False, "scope is dry-run only")

        if request.action_class not in _ALLOWED_ACTIONS_BY_MODE[request.mode]:
            return ScopeDecision(False, f"action class '{request.action_class}' not allowed in mode '{request.mode}'")

        target = _canonical_target(request.target.value)
        if self._is_denied(target, policy.explicit_denylist):
            return ScopeDecision(False, f"target '{target}' denied by denylist")

        if self._is_explicitly_allowed(target, policy.explicit_allow_targets):
            return ScopeDecision(True, "target explicitly allowed")

        if self._matches_domain(target, policy.allowed_domains):
            return ScopeDecision(True, "target allowed by domain policy")

        if self._matches_subdomain(target, policy.allowed_subdomains):
            return ScopeDecision(True, "target allowed by subdomain policy")

        if self._matches_cidr(target, policy.allowed_cidrs):
            return ScopeDecision(True, "target allowed by cidr policy")

        return ScopeDecision(False, f"target '{target}' outside authorized scope")

    @staticmethod
    def _is_denied(target: str, denylist: Iterable[str]) -> bool:
        return any(fnmatch(target, rule.strip()) for rule in denylist if rule.strip())

    @staticmethod
    def _is_explicitly_allowed(target: str, allowed: Iterable[str]) -> bool:
        return any(target == item.strip() for item in allowed if item.strip())

    @staticmethod
    def _matches_domain(target: str, domains: Iterable[str]) -> bool:
        hostname = _extract_hostname(target)
        if not hostname:
            return False
        return any(hostname == domain or hostname.endswith(f".{domain}") for domain in domains if domain)

    @staticmethod
    def _matches_subdomain(target: str, subdomains: Iterable[str]) -> bool:
        hostname = _extract_hostname(target)
        if not hostname:
            return False
        return any(hostname == sub or hostname.endswith(f".{sub}") for sub in subdomains if sub)

    @staticmethod
    def _matches_cidr(target: str, cidrs: Iterable[str]) -> bool:
        ip_text = _extract_ip(target)
        if not ip_text:
            return False
        ip = ipaddress.ip_address(ip_text)
        for cidr in cidrs:
            cidr = cidr.strip()
            if not cidr:
                continue
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        return False


def _canonical_target(raw: str) -> str:
    return raw.strip().lower()


def _extract_hostname(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return (urlparse(target).hostname or "").lower()
    if ":" in target and target.count(":") == 1 and not _is_ip(target):
        return target.split(":", 1)[0].lower()
    if _is_ip(target) or "/" in target:
        return ""
    return target.lower()


def _extract_ip(target: str) -> str:
    if target.startswith(("http://", "https://")):
        host = (urlparse(target).hostname or "").strip("[]")
        return host if _is_ip(host) else ""
    text = target.strip("[]")
    if _is_ip(text):
        return text
    return ""


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _parse_iso_datetime(value: str) -> datetime:
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _as_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item).strip().lower() for item in value if str(item).strip())


def _as_mode_tuple(value: object) -> tuple[ExecutionMode, ...]:
    if not isinstance(value, list):
        return ("safe",)
    modes: list[ExecutionMode] = []
    allowed = {"safe", "standard", "extended"}
    for item in value:
        txt = str(item).strip().lower()
        if txt in allowed:
            modes.append(txt)  # type: ignore[arg-type]
    return tuple(modes) if modes else ("safe",)
