"""Regression test for scripts/check_doc_counters.py.

Enforces at the normal test-suite level (not just CI) that no current
documentation file states an MCP tool/resource count that disagrees with
what reconforge/mcp/tools.py and resources.py actually register — the
stale-counter class of bug documented in docs/DOCUMENTATION_MAP.md.
"""

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "check_doc_counters", REPO_ROOT / "scripts" / "check_doc_counters.py"
)
assert _SPEC is not None and _SPEC.loader is not None
check_doc_counters = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(check_doc_counters)


def test_no_stale_mcp_tool_or_resource_counters():
    problems = check_doc_counters.find_stale_counters()
    assert problems == [], f"{len(problems)} stale documentation counter(s) found: " + "; ".join(problems)


def test_registered_tool_count_matches_known_value():
    # Pinned so a genuine tool addition/removal is a deliberate, visible
    # change to this test rather than a silent drift in what "current" means.
    assert check_doc_counters._registered_tool_count() == 18


def test_registered_resource_count_matches_known_value():
    assert check_doc_counters._registered_resource_count() == 7


def test_find_stale_counters_detects_a_wrong_claim(tmp_path):
    md_file = tmp_path / "doc.md"
    md_file.write_text("The MCP server exposes 99 tools total.\n")
    problems = check_doc_counters.find_stale_counters(files=[md_file])
    assert len(problems) == 1
    assert "claims 99 tools" in problems[0]


def test_find_stale_counters_ignores_non_mcp_tool_counts(tmp_path):
    md_file = tmp_path / "doc.md"
    md_file.write_text("The network module wraps 5 tools across 4 phases.\n")
    assert check_doc_counters.find_stale_counters(files=[md_file]) == []


def test_find_stale_counters_accepts_a_correct_claim(tmp_path):
    md_file = tmp_path / "doc.md"
    md_file.write_text("reconforge mcp serve exposes 18 tools over stdio.\n")
    assert check_doc_counters.find_stale_counters(files=[md_file]) == []
