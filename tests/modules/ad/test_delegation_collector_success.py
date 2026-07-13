"""Phase 11-C: DelegationCollector.collect() hardcoded result.success = True
regardless of whether any of its LDAP queries / findDelegation.py actually
ran. A total collection failure (ldapsearch unavailable, opsec-blocked,
missing base DN, or every LDAP bind rejected) was indistinguishable from a
genuinely clean environment with zero delegations configured. Fixed to
track whether at least one query actually completed.
"""

from pathlib import Path
from types import SimpleNamespace

from modules.ad.collectors.delegation_collector import DelegationCollector


def _make_collector(**overrides) -> DelegationCollector:
    collector = DelegationCollector.__new__(DelegationCollector)
    collector.output_dir = Path("/tmp")
    collector.opsec = SimpleNamespace(check=lambda *a, **k: True)
    collector.ldapsearch = SimpleNamespace(
        is_available=lambda: True,
        _bind_args=lambda *a, **k: "-x -H ldap://10.10.10.1",
        runner=SimpleNamespace(run=lambda *a, **k: SimpleNamespace(success=True, stdout="")),
    )
    collector.advanced_impacket = SimpleNamespace(
        is_available=lambda *a, **k: False,
        find_delegation=lambda **k: SimpleNamespace(success=False, stdout=""),
        get_machine_account_quota=lambda **k: SimpleNamespace(success=False, stdout=""),
    )
    collector.delegation_parser = SimpleNamespace(
        parse_unconstrained=lambda stdout: [],
        parse_constrained=lambda stdout: [],
        parse_rbcd=lambda stdout: [],
        parse_find_delegation=lambda stdout: {},
    )
    for key, value in overrides.items():
        setattr(collector, key, value)
    return collector


def test_successful_ldap_queries_yield_success_true():
    collector = _make_collector()

    result = collector.collect(target="10.10.10.1", domain="corp.local",
                                username="alice", password="pass")

    assert result.success is True
    assert result.errors == []


def test_ldapsearch_unavailable_yields_success_false():
    collector = _make_collector(
        ldapsearch=SimpleNamespace(
            is_available=lambda: False,
            _bind_args=lambda *a, **k: "",
            runner=SimpleNamespace(run=lambda *a, **k: SimpleNamespace(success=False, stdout="")),
        ),
    )

    result = collector.collect(target="10.10.10.1", domain="corp.local",
                                username="alice", password="pass")

    assert result.success is False
    assert result.errors


def test_all_ldap_runs_failing_yields_success_false_not_clean_environment():
    """Regression: previously this scenario reported success=True with
    empty delegation lists, indistinguishable from a real clean scan."""
    collector = _make_collector(
        ldapsearch=SimpleNamespace(
            is_available=lambda: True,
            _bind_args=lambda *a, **k: "-x -H ldap://10.10.10.1",
            runner=SimpleNamespace(run=lambda *a, **k: SimpleNamespace(success=False, stdout="")),
        ),
    )

    result = collector.collect(target="10.10.10.1", domain="corp.local",
                                username="alice", password="pass")

    assert result.success is False
    assert result.data["unconstrained"] == []
    assert result.data["constrained"] == []
    assert result.data["rbcd"] == []


def test_opsec_block_yields_success_false():
    collector = _make_collector(opsec=SimpleNamespace(check=lambda *a, **k: False))

    result = collector.collect(target="10.10.10.1", domain="corp.local",
                                username="alice", password="pass")

    assert result.success is False


def test_find_delegation_checks_the_correctly_named_opsec_technique():
    """Phase 12-B regression: _run_find_delegation() checked the opsec
    technique name "impacket_delegation", which has no entry in
    core/detection_map.py (the real key is "impacket_finddelegation") —
    an unknown-technique check always fails closed, so findDelegation.py
    collection was permanently blocked regardless of opsec mode."""
    checked_names = []
    collector = _make_collector(
        opsec=SimpleNamespace(check=lambda name: checked_names.append(name) or True),
        advanced_impacket=SimpleNamespace(
            is_available=lambda *a, **k: True,
            find_delegation=lambda **k: SimpleNamespace(success=True, stdout=""),
            get_machine_account_quota=lambda **k: SimpleNamespace(success=False, stdout=""),
        ),
    )

    collector.collect(target="10.10.10.1", domain="corp.local",
                       username="alice", password="pass")

    assert "impacket_finddelegation" in checked_names
    assert "impacket_delegation" not in checked_names


def test_find_delegation_alone_can_satisfy_success():
    """If the LDAP queries are blocked but findDelegation.py runs fine,
    that's still real data collection, not a total failure."""
    collector = _make_collector(
        ldapsearch=SimpleNamespace(
            is_available=lambda: False,
            _bind_args=lambda *a, **k: "",
            runner=SimpleNamespace(run=lambda *a, **k: SimpleNamespace(success=False, stdout="")),
        ),
        advanced_impacket=SimpleNamespace(
            is_available=lambda *a, **k: True,
            find_delegation=lambda **k: SimpleNamespace(success=True, stdout=""),
            get_machine_account_quota=lambda **k: SimpleNamespace(success=False, stdout=""),
        ),
    )

    result = collector.collect(target="10.10.10.1", domain="corp.local",
                                username="alice", password="pass")

    assert result.success is True
