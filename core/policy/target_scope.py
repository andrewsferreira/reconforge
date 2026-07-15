"""Reusable domain-scope validator for provider request targets."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class DomainScopePolicy:
    """Domain-based scope policy for request-capable operations."""

    allowed_domains: tuple[str, ...] = field(default_factory=tuple)
    denied_domains: tuple[str, ...] = field(default_factory=tuple)
    allow_subdomains: bool = False

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> DomainScopePolicy:
        return cls(
            allowed_domains=_normalize_domains(data.get("allowed_domains", [])),
            denied_domains=_normalize_domains(data.get("denied_domains", [])),
            allow_subdomains=bool(data.get("allow_subdomains", False)),
        )


@dataclass(frozen=True)
class DomainScopeDecision:
    """Structured scope decision for auditability and caller handling."""

    target: str
    host: str
    normalized_host: str
    in_scope: bool
    decision: str
    matched_rule: str
    reason: str
    source_policy_type: str
    subdomain_match_used: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DomainScopeValidator:
    """Deterministic allow/deny validator for URL/domain targets."""

    POLICY_TYPE = "domain_allow_deny"

    def validate_target(self, target: str, policy: DomainScopePolicy) -> DomainScopeDecision:
        parsed_host = _extract_host(target)
        if not parsed_host:
            decision = DomainScopeDecision(
                target=str(target),
                host="",
                normalized_host="",
                in_scope=False,
                decision="blocked",
                matched_rule="",
                reason="malformed_target",
                source_policy_type=self.POLICY_TYPE,
                subdomain_match_used=False,
            )
            self._log_decision(decision)
            return decision

        normalized_host = parsed_host.lower().strip(".")

        deny_match, deny_subdomain_used = _match_domain(normalized_host, policy.denied_domains, policy.allow_subdomains)
        if deny_match:
            decision = DomainScopeDecision(
                target=str(target),
                host=parsed_host,
                normalized_host=normalized_host,
                in_scope=False,
                decision="blocked",
                matched_rule=deny_match,
                reason="explicitly_denied",
                source_policy_type=self.POLICY_TYPE,
                subdomain_match_used=deny_subdomain_used,
            )
            self._log_decision(decision)
            return decision

        allow_match, allow_subdomain_used = _match_domain(
            normalized_host, policy.allowed_domains, policy.allow_subdomains
        )
        if allow_match:
            decision = DomainScopeDecision(
                target=str(target),
                host=parsed_host,
                normalized_host=normalized_host,
                in_scope=True,
                decision="allowed",
                matched_rule=allow_match,
                reason="target_in_allowed_scope",
                source_policy_type=self.POLICY_TYPE,
                subdomain_match_used=allow_subdomain_used,
            )
            self._log_decision(decision)
            return decision

        decision = DomainScopeDecision(
            target=str(target),
            host=parsed_host,
            normalized_host=normalized_host,
            in_scope=False,
            decision="blocked",
            matched_rule="",
            reason="target_not_in_allowed_scope",
            source_policy_type=self.POLICY_TYPE,
            subdomain_match_used=False,
        )
        self._log_decision(decision)
        return decision

    @staticmethod
    def _log_decision(decision: DomainScopeDecision) -> None:
        LOGGER.info(json.dumps({"event": "scope_validation_decision", **decision.to_dict()}))


def _normalize_domains(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    normalized = [str(item).strip().lower().strip(".") for item in value if str(item).strip()]
    return tuple(normalized)


def _extract_host(target: str) -> str:
    text = str(target or "").strip()
    if not text:
        return ""

    parsed = urlparse(text)
    if parsed.scheme and parsed.netloc:
        return (parsed.hostname or "").strip()

    # Accept plain host/domain input if explicitly provided.
    parsed_guess = urlparse(f"https://{text}")
    host = (parsed_guess.hostname or "").strip()
    if host and "." in host and " " not in host:
        return host

    return ""


def _match_domain(host: str, domains: tuple[str, ...], allow_subdomains: bool) -> tuple[str, bool]:
    for rule in domains:
        if host == rule:
            return rule, False
    if allow_subdomains:
        for rule in domains:
            if host.endswith(f".{rule}"):
                return rule, True
    return "", False
