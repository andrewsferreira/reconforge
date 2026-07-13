"""Phase 10-H: report footers previously hardcoded a stale "v1.0 release"
string independently of pyproject.toml's actual version — core.version
is the single runtime-importable copy report generators use instead."""

import re
from pathlib import Path

from core.version import __version__


def test_version_matches_pyproject_toml():
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    text = pyproject.read_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match, "pyproject.toml has no [project] version field"
    assert __version__ == match.group(1)
