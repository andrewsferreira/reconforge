"""Risk policy engine for high-impact command execution controls (E3)."""

from __future__ import annotations

import os
import shlex
from collections.abc import Sequence
from dataclasses import dataclass

_TIER_RANK = {"low": 0, "medium": 1, "high": 2}


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str = ""


class RiskPolicyEngine:
    """Classify command risk and enforce approval tiers."""

    @staticmethod
    def classify_risk(command: Sequence[str]) -> str:
        cmd = " ".join(shlex.quote(str(x)).lower() for x in command)
        if any(k in cmd for k in ("sqlmap", "--os-shell", "--sql-shell", "hydra", "netexec")):
            return "high"
        if any(k in cmd for k in ("nuclei", "nikto", "ffuf", "wpscan", "enum4linux", "impacket")):
            return "medium"
        return "low"

    @classmethod
    def check(cls, command: Sequence[str]) -> PolicyDecision:
        """Enforce approval policy when RECONFORGE_POLICY_ENFORCE=1."""
        if os.getenv("RECONFORGE_POLICY_ENFORCE", "").strip() != "1":
            return PolicyDecision(allowed=True)

        required = cls.classify_risk(command)
        provided = os.getenv("RECONFORGE_APPROVAL_TIER", "low").strip().lower()
        if provided not in _TIER_RANK:
            provided = "low"
        if _TIER_RANK[provided] < _TIER_RANK[required]:
            return PolicyDecision(
                allowed=False,
                reason=(
                    f"Policy blocked command risk '{required}' "
                    f"with approval tier '{provided}'"
                ),
            )
        return PolicyDecision(allowed=True)
