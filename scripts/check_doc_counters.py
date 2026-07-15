#!/usr/bin/env python3
"""Verify hardcoded MCP tool/resource counts in current documentation match
the registered implementation.

Scope is deliberately narrow: this checks the one class of stale counter
that's bitten this project's docs repeatedly (see docs/DOCUMENTATION_MAP.md
and the Historical Documents it links) — an MCP tool count copy-pasted into
a doc and never updated after a new tool shipped. It does not attempt to
validate every number in every document; test counts, file counts, and line
counts are excluded on purpose (they change on nearly every commit and
belong in exactly one place — see CHANGELOG.md / README.md's Testing
section — not hardcoded into reference docs this script would then have to
re-verify on every run).

Historical documents (docs/archive/, docs/ARCHITECTURE_REVIEW.md,
docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md, CHANGELOG.md) are excluded from
scanning: their counts are frozen point-in-time records by design, not
claims about current state — see each file's own status banner.
"""
from __future__ import annotations

import re
import shutil
import subprocess  # nosec B404 - dev/CI tooling script, not part of the runtime execution layer
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_EXCLUDED_PREFIXES = (
    "docs/archive/",
    "docs/ARCHITECTURE_REVIEW.md",
    "docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md",
    "CHANGELOG.md",
)

# Matches "18 tools", "13 of 18 tools", "18-tool", "17 tools:" etc. — the
# count is always the number immediately preceding the word "tool(s)". Per-
# module tool-wrapper counts ("5 tools, 4 phases" for the network module)
# use the same phrase shape, so a match only counts as an MCP tool-count
# claim when "MCP" also appears somewhere on the same line.
_MCP_LINE_RE = re.compile(r"\bMCP\b", re.IGNORECASE)
_TOOL_COUNT_RE = re.compile(r"(\d+)[\s-]tools?\b")
_RESOURCE_COUNT_RE = re.compile(r"(\d+)\s+read-only\s+(?:MCP\s+)?resources?\b")


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


def _registered_tool_count() -> int:
    text = (REPO_ROOT / "reconforge" / "mcp" / "tools.py").read_text(encoding="utf-8")
    return len(set(re.findall(r'"(reconforge_[a-z_]+)":\s*\(', text)))


def _registered_resource_count() -> int:
    text = (REPO_ROOT / "reconforge" / "mcp" / "resources.py").read_text(encoding="utf-8")
    doc_uris = set(re.findall(r'"(reconforge://docs/[a-z-]+)":', text))
    other_uris = set(re.findall(r'_([A-Z_]+)_URI = "(reconforge://[a-z]+)"', text))
    return len(doc_uris) + len(other_uris)


def find_stale_counters(files: list[Path] | None = None) -> list[str]:
    """Return one message per doc:line whose stated tool/resource count
    disagrees with the registered implementation."""
    real_tools = _registered_tool_count()
    real_resources = _registered_resource_count()
    problems: list[str] = []

    for md_file in files if files is not None else _tracked_markdown_files():
        try:
            rel = md_file.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            # Not under REPO_ROOT (e.g. a synthetic file under pytest's
            # tmp_path in tests) -- can't be one of the excluded repo
            # paths, so there's nothing to exclude it against.
            rel = md_file.as_posix()
        else:
            if any(rel == p or rel.startswith(p) for p in _EXCLUDED_PREFIXES):
                continue
        for lineno, line in enumerate(md_file.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if not _MCP_LINE_RE.search(line):
                continue
            for match in _TOOL_COUNT_RE.finditer(line):
                claimed = int(match.group(1))
                if claimed != real_tools:
                    problems.append(
                        f"{rel}:{lineno}: claims {claimed} tools, "
                        f"reconforge/mcp/tools.py registers {real_tools}"
                    )
            for match in _RESOURCE_COUNT_RE.finditer(line):
                claimed = int(match.group(1))
                if claimed != real_resources:
                    problems.append(
                        f"{rel}:{lineno}: claims {claimed} read-only resources, "
                        f"reconforge/mcp/resources.py registers {real_resources}"
                    )
    return problems


def main() -> int:
    problems = find_stale_counters()
    if not problems:
        print(
            f"OK - MCP tool/resource counts in current documentation match the "
            f"registered implementation ({_registered_tool_count()} tools, "
            f"{_registered_resource_count()} resources)."
        )
        return 0

    print(f"Found {len(problems)} stale documentation counter(s):\n")
    for problem in problems:
        print(f"  {problem}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
