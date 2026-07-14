"""Phase 12: core/opsec_checks.py and core/detection_map.py had zero test
coverage before this phase, despite being the mechanism that's supposed to
prevent noisy/detectable actions from running without deliberate operator
opt-in across all 5 recon modules.
"""

from types import SimpleNamespace

from core.detection_map import DETECTION_LEVELS, get_detection_level, is_allowed
from core.opsec_checks import OpsecChecker


# ── is_allowed() mode/noise matrix ──────────────────────────────────

def test_stealth_mode_allows_only_low_noise():
    assert is_allowed("nmap_ping_sweep", "stealth") is True  # low
    assert is_allowed("nmap_version_scan", "stealth") is False  # medium
    assert is_allowed("nmap_connect_scan", "stealth") is False  # high
    assert is_allowed("nmap_aggressive", "stealth") is False  # very_high


def test_normal_mode_allows_low_and_medium():
    assert is_allowed("nmap_ping_sweep", "normal") is True  # low
    assert is_allowed("nmap_version_scan", "normal") is True  # medium
    assert is_allowed("nmap_connect_scan", "normal") is False  # high
    assert is_allowed("nmap_aggressive", "normal") is False  # very_high


def test_aggressive_mode_allows_everything_up_to_very_high():
    assert is_allowed("nmap_ping_sweep", "aggressive") is True
    assert is_allowed("nmap_version_scan", "aggressive") is True
    assert is_allowed("nmap_connect_scan", "aggressive") is True
    assert is_allowed("nmap_aggressive", "aggressive") is True


def test_unknown_technique_is_blocked_in_every_recognized_mode():
    """A technique with no DETECTION_LEVELS entry defaults to "unknown"
    noise, which isn't in any mode's allowlist — fails closed."""
    assert is_allowed("totally_made_up_technique", "stealth") is False
    assert is_allowed("totally_made_up_technique", "normal") is False
    assert is_allowed("totally_made_up_technique", "aggressive") is False


def test_unrecognized_opsec_mode_fails_closed():
    """Phase 12-A regression: an unrecognized mode string (typo, or a
    programmatic caller bypassing the CLI's argparse choices= validation —
    every module's opsec_mode constructor parameter accepts an unvalidated
    string) previously fell through to `return True`, silently allowing
    every action including very_high-noise ones. Must deny instead."""
    assert is_allowed("nmap_aggressive", "Stealth") is False  # capitalization typo
    assert is_allowed("nmap_aggressive", "") is False
    assert is_allowed("nmap_aggressive", "yolo") is False
    assert is_allowed("nmap_ping_sweep", "yolo") is False  # even low-noise techniques


def test_every_detection_level_entry_has_noise_and_description():
    for technique, level in DETECTION_LEVELS.items():
        assert "noise" in level, technique
        assert "description" in level, technique
        assert level["noise"] in ("low", "medium", "high", "very_high"), technique


def test_get_detection_level_returns_none_for_unknown_technique():
    assert get_detection_level("not_a_real_technique") is None


def test_impacket_finddelegation_entry_exists():
    """Phase 12-B regression: modules/ad/collectors/delegation_collector.py
    checked "impacket_delegation" (no such entry) instead of the real
    "impacket_finddelegation" key, permanently blocking that collection
    method regardless of opsec mode."""
    assert get_detection_level("impacket_finddelegation") is not None
    assert get_detection_level("impacket_delegation") is None


def test_ldap_password_policy_entry_exists():
    level = get_detection_level("ldap_password_policy")
    assert level is not None
    assert level["noise"] == "low"


def test_nmap_kerberos_detect_entry_exists_and_is_lower_noise_than_nse_scripts():
    detect = get_detection_level("nmap_kerberos_detect")
    scripts = get_detection_level("nmap_ad_kerberos")
    assert detect is not None
    assert detect["noise"] == "low"
    assert scripts["noise"] == "high"


def test_nmap_syn_scan_is_low_noise_and_allowed_in_stealth_mode():
    """Phase 25 regression: nmap_syn_scan was misclassified "medium" noise,
    which is_allowed() denies in stealth mode — despite this technique's
    own description ("SYN stealth scan") and despite
    modules/network/phases/port_scanning.py and
    modules/surface/phases/port_discovery.py both gating their entire
    scan on this exact technique with no lower-noise fallback. The result:
    `--opsec stealth` silently produced zero port-scan results in both
    modules, the one mode an operator picks specifically to still get
    results while staying quiet. Reclassified to "low"."""
    level = get_detection_level("nmap_syn_scan")
    assert level is not None
    assert level["noise"] == "low"
    assert is_allowed("nmap_syn_scan", "stealth") is True


# ── OpsecChecker.check() ────────────────────────────────────────────

def test_check_returns_true_for_allowed_technique():
    checker = OpsecChecker(mode="normal")
    assert checker.check("nmap_syn_scan") is True


def test_check_returns_false_for_blocked_technique():
    checker = OpsecChecker(mode="stealth")
    assert checker.check("nmap_connect_scan") is False


def test_check_logs_warning_when_blocked():
    warnings = []
    logger = SimpleNamespace(warning=lambda msg: warnings.append(msg))
    checker = OpsecChecker(mode="stealth", logger=logger)

    checker.check("nmap_connect_scan")

    assert len(warnings) == 1
    assert "BLOCKED" in warnings[0]


def test_check_logs_warn_message_when_allowed_but_high_noise():
    """Phase 12-H: warn() was previously dead code — check() now surfaces
    it automatically for every existing call site when a high/very_high
    noise technique is allowed to proceed (not blocked)."""
    warnings = []
    logger = SimpleNamespace(warning=lambda msg: warnings.append(msg))
    checker = OpsecChecker(mode="aggressive", logger=logger)

    checker.check("nmap_aggressive")  # very_high noise, allowed in aggressive

    assert len(warnings) == 1
    assert "detection risk" in warnings[0]


def test_check_does_not_warn_for_low_noise_allowed_technique():
    warnings = []
    logger = SimpleNamespace(warning=lambda msg: warnings.append(msg))
    checker = OpsecChecker(mode="normal", logger=logger)

    checker.check("nmap_ping_sweep")  # low noise

    assert warnings == []


def test_check_without_logger_does_not_raise():
    checker = OpsecChecker(mode="stealth", logger=None)
    assert checker.check("nmap_connect_scan") is False


# ── OpsecChecker.warn() ──────────────────────────────────────────────

def test_warn_returns_none_for_low_noise_technique():
    checker = OpsecChecker(mode="aggressive")
    assert checker.warn("nmap_ping_sweep") is None


def test_warn_returns_message_for_high_noise_technique():
    checker = OpsecChecker(mode="aggressive")
    msg = checker.warn("nmap_connect_scan")
    assert msg is not None
    assert "Full TCP connect scan" in msg


def test_warn_returns_message_for_very_high_noise_technique():
    checker = OpsecChecker(mode="aggressive")
    msg = checker.warn("hydra_brute")
    assert msg is not None


def test_warn_returns_none_for_unknown_technique():
    checker = OpsecChecker(mode="aggressive")
    assert checker.warn("not_a_real_technique") is None


# ── set_mode() ───────────────────────────────────────────────────────

def test_set_mode_changes_subsequent_checks():
    checker = OpsecChecker(mode="stealth")
    assert checker.check("nmap_version_scan") is False  # medium, blocked in stealth

    checker.set_mode("normal")

    assert checker.check("nmap_version_scan") is True  # medium, allowed in normal
