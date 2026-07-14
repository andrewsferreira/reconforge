#!/usr/bin/env python3
"""Verify every internal Markdown link in the repo resolves to a real file.

Catches the class of bug found and hand-fixed twice already in this
project's history: dead cross-references left in docs after the files
they pointed to were deleted or renamed. This script is the automated
check that replaces that manual discovery going forward.

Scope is `git ls-files '*.md'` so it automatically respects .gitignore
(no need to hand-maintain an exclude list for outputs/, caches, venvs).
External links (http/https/mailto) and pure in-page anchors (#section)
are intentionally not checked — only internal file references.
"""
from __future__ import annotations

import re
import shutil
import subprocess  # nosec B404 - dev/CI tooling script, not part of the runtime execution layer
import sys
from pathlib import Path

_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")

REPO_ROOT = Path(__file__).resolve().parent.parent


def _tracked_markdown_files() -> list[Path]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git executable not found on PATH")
    result = subprocess.run(  # nosec B603 - absolute path, fixed argv, no shell
        [git, "ls-files", "*.md"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [REPO_ROOT / line for line in result.stdout.splitlines() if line]


def _is_external_or_anchor(target: str) -> bool:
    return not target or target.startswith(("http://", "https://", "mailto:", "#"))


def find_broken_links(files: list[Path] | None = None) -> list[tuple[Path, str]]:
    """Return (file, broken_target) pairs for every dead internal link found."""
    broken: list[tuple[Path, str]] = []
    for md_file in files if files is not None else _tracked_markdown_files():
        text = md_file.read_text(encoding="utf-8", errors="replace")
        for match in _LINK_RE.finditer(text):
            target_raw = match.group(1).strip()
            # Drop a trailing markdown link title, e.g. (path "title")
            target = target_raw.split()[0] if target_raw.split() else target_raw
            if _is_external_or_anchor(target):
                continue
            path_part = target.split("#", 1)[0].strip()
            if not path_part:
                continue
            resolved = (md_file.parent / path_part).resolve()
            if not resolved.exists():
                broken.append((md_file, target_raw))
    return broken


def main() -> int:
    files = _tracked_markdown_files()
    broken = find_broken_links(files)
    if not broken:
        print(f"OK - checked {len(files)} tracked Markdown files, no broken internal links.")
        return 0

    print(f"Found {len(broken)} broken internal link(s):\n")
    for md_file, target in broken:
        print(f"  {md_file.relative_to(REPO_ROOT)}: -> {target}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
