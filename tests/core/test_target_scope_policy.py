from core.policy.target_scope import DomainScopePolicy, DomainScopeValidator


def _validator() -> DomainScopeValidator:
    return DomainScopeValidator()


def test_exact_allowed_domain_passes():
    policy = DomainScopePolicy(allowed_domains=("example.com",), denied_domains=(), allow_subdomains=False)
    decision = _validator().validate_target("https://example.com/", policy)

    assert decision.in_scope is True
    assert decision.decision == "allowed"
    assert decision.matched_rule == "example.com"


def test_exact_denied_domain_blocks():
    policy = DomainScopePolicy(allowed_domains=("example.com",), denied_domains=("example.com",), allow_subdomains=True)
    decision = _validator().validate_target("https://example.com/", policy)

    assert decision.in_scope is False
    assert decision.reason == "explicitly_denied"


def test_subdomain_allowed_when_enabled():
    policy = DomainScopePolicy(allowed_domains=("example.com",), denied_domains=(), allow_subdomains=True)
    decision = _validator().validate_target("https://api.example.com/", policy)

    assert decision.in_scope is True
    assert decision.subdomain_match_used is True


def test_subdomain_blocked_when_disabled():
    policy = DomainScopePolicy(allowed_domains=("example.com",), denied_domains=(), allow_subdomains=False)
    decision = _validator().validate_target("https://api.example.com/", policy)

    assert decision.in_scope is False
    assert decision.reason == "target_not_in_allowed_scope"


def test_deny_precedence_over_allow():
    policy = DomainScopePolicy(allowed_domains=("example.com",), denied_domains=("api.example.com",), allow_subdomains=True)
    decision = _validator().validate_target("https://api.example.com/", policy)

    assert decision.in_scope is False
    assert decision.reason == "explicitly_denied"
    assert decision.matched_rule == "api.example.com"


def test_unknown_domain_blocks():
    policy = DomainScopePolicy(allowed_domains=("example.com",), denied_domains=(), allow_subdomains=True)
    decision = _validator().validate_target("https://unknown.com/", policy)

    assert decision.in_scope is False
    assert decision.reason == "target_not_in_allowed_scope"


def test_malformed_url_blocks():
    policy = DomainScopePolicy(allowed_domains=("example.com",), denied_domains=(), allow_subdomains=True)
    decision = _validator().validate_target("not-a-valid-url", policy)

    assert decision.in_scope is False
    assert decision.reason == "malformed_target"
