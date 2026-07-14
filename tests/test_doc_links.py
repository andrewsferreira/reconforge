"""Regression test for scripts/check_doc_links.py.

Enforces at the normal test-suite level (not just CI) that no internal
Markdown link in the repository points at a nonexistent file — the class
of bug found and hand-fixed twice already in this project's history.
"""

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "check_doc_links", REPO_ROOT / "scripts" / "check_doc_links.py"
)
assert _SPEC is not None and _SPEC.loader is not None
check_doc_links = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(check_doc_links)


def test_no_broken_internal_markdown_links():
    broken = check_doc_links.find_broken_links()
    assert broken == [], (
        f"{len(broken)} broken internal Markdown link(s) found: "
        + ", ".join(f"{f.relative_to(REPO_ROOT)} -> {t}" for f, t in broken)
    )


def test_is_external_or_anchor_skips_external_and_anchor_links():
    assert check_doc_links._is_external_or_anchor("https://example.com")
    assert check_doc_links._is_external_or_anchor("http://example.com")
    assert check_doc_links._is_external_or_anchor("mailto:a@example.com")
    assert check_doc_links._is_external_or_anchor("#section")
    assert check_doc_links._is_external_or_anchor("")
    assert not check_doc_links._is_external_or_anchor("README.md")


def test_find_broken_links_detects_dead_relative_link(tmp_path):
    md_file = tmp_path / "doc.md"
    md_file.write_text("See [missing](NOPE.md) for details.")
    broken = check_doc_links.find_broken_links(files=[md_file])
    assert broken == [(md_file, "NOPE.md")]


def test_find_broken_links_accepts_existing_relative_link(tmp_path):
    (tmp_path / "TARGET.md").write_text("# Target")
    md_file = tmp_path / "doc.md"
    md_file.write_text("See [target](TARGET.md) for details.")
    broken = check_doc_links.find_broken_links(files=[md_file])
    assert broken == []
