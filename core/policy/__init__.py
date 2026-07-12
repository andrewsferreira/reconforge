"""Policy primitives for scope and safety enforcement.

DomainScopeValidator/DomainScopePolicy (target_scope.py) is the real,
wired scope check used by core.adapters.burp.provider.BurpMcpProvider
for every HTTP request the Burp/intelligence/attack-paths subsystem
issues. It is a different mechanism from core.authorization_gate's
ScopeAuthorization, which gates the five recon modules' subprocess
execution via core.runner.Runner — see docs/ARCHITECTURE_REVIEW.md for
why these remain separate rather than consolidated (they gate different
resource types: outbound HTTP requests vs. subprocess tool execution).
"""

from core.policy.target_scope import DomainScopeDecision, DomainScopePolicy, DomainScopeValidator

__all__ = [
    "DomainScopeDecision",
    "DomainScopePolicy",
    "DomainScopeValidator",
]
