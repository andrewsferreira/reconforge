"""Phase 11-B: modules/api/phases/fuzzing.py's error/info-disclosure
classification searched ffuf's whole-batch stdout per fuzzed entry and
reported a match as "evidence" for that specific entry's URL — but ffuf's
JSON output format captures no per-result response body, so the match
could have come from any entry in the batch, not necessarily the one it
got attributed to. Fixed to classify the batch text once per fuzz run and
report a single finding covering every 500/200-with-disclosure entry,
honest that the specific triggering input couldn't be isolated.
"""

from types import SimpleNamespace

from core.findings_manager import FindingsManager
from modules.api.phases.fuzzing import FuzzingPhase


def _make_phase() -> FuzzingPhase:
    phase = FuzzingPhase.__new__(FuzzingPhase)
    phase.PHASE_NAME = "fuzzing"
    phase.findings = FindingsManager()
    phase.tools_used = []
    phase.logger = SimpleNamespace(info=lambda *a, **k: None, warning=lambda *a, **k: None)
    return phase


def _entry(url="https://api.local/x", status=500, input_word="a", length=0):
    return SimpleNamespace(url=url, status=status, input_word=input_word,
                            length=length, content_type="")


def test_classify_error_response_no_longer_takes_a_per_entry_arg():
    """The old signature was (entry, full_output) — classification is now
    batch-scoped only, with no entry parameter to accidentally misuse."""
    phase = _make_phase()
    result = phase._classify_error_response("SQLSTATE[42000]: some error")
    assert result["type"] == "sql_injection"


def test_batch_classification_produces_one_finding_not_one_per_entry():
    phase = _make_phase()
    entries = [
        _entry(url="https://api.local/a?FUZZ=1", input_word="1"),
        _entry(url="https://api.local/a?FUZZ=2", input_word="2"),
        _entry(url="https://api.local/a?FUZZ=3", input_word="3"),
    ]
    classification = phase._classify_error_response("SQLSTATE[42000]: syntax error")

    count = phase._report_classified_error(
        "https://api.local/a?FUZZ=test", entries, classification, {
            "error_fingerprints": [], "injection_findings": [],
        },
    )

    assert count == 1
    findings = phase.findings.get_all()
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_finding_target_is_fuzz_url_not_an_arbitrary_entry_url():
    """Regression: the finding must be scoped to the endpoint under test,
    not to one entry.url chosen essentially at random from the batch."""
    phase = _make_phase()
    entries = [_entry(url="https://api.local/a?FUZZ=2", input_word="2")]
    classification = phase._classify_error_response("SQLSTATE[42000]: syntax error")

    phase._report_classified_error(
        "https://api.local/a?FUZZ=test", entries, classification, {
            "error_fingerprints": [], "injection_findings": [],
        },
    )

    findings = phase.findings.get_all()
    assert findings[0].target == "https://api.local/a?FUZZ=test"


def test_evidence_text_discloses_attribution_uncertainty():
    phase = _make_phase()
    entries = [_entry(input_word="payload1"), _entry(input_word="payload2")]
    classification = phase._classify_error_response("Traceback (most recent call last):")

    phase._report_classified_error(
        "https://api.local/a?FUZZ=test", entries, classification, {
            "error_fingerprints": [], "injection_findings": [],
        },
    )

    findings = phase.findings.get_all()
    assert "could not be isolated" in findings[0].evidence


def test_generic_error_with_no_batch_evidence_stays_heuristic():
    phase = _make_phase()
    entries = [_entry(input_word="1")]
    classification = phase._classify_error_response("ordinary 500 page, nothing special")

    phase._report_classified_error(
        "https://api.local/a?FUZZ=test", entries, classification, {
            "error_fingerprints": [], "injection_findings": [],
        },
    )

    findings = phase.findings.get_all()
    assert findings[0].confidence == "heuristic"
    assert findings[0].severity == "low"


def test_info_disclosure_check_is_batch_scoped():
    """_check_for_info_disclosure() no longer takes a per-entry arg — same
    misattribution class of bug as the error-response classifier."""
    phase = _make_phase()
    assert phase._check_for_info_disclosure("DEBUG = True") is True
    assert phase._check_for_info_disclosure("ordinary response") is False
