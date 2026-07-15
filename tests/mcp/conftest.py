"""Shared fixtures for tests/mcp/.

Autouse, function-scoped isolation for reconforge/mcp/approvals.py's
disk-backed storage. Without this, every test in this package would
share the same real ``.reconforge/mcp_approvals/`` directory relative
to wherever pytest happens to be invoked from — defeating tmp_path
isolation between tests, and potentially colliding with a real local
``reconforge mcp serve`` invocation's approval requests on the same
machine.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_mcp_approvals_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from reconforge.mcp import approvals

    approvals_dir = tmp_path / "mcp_approvals"

    def _fake_approvals_dir() -> Path:
        approvals_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        return approvals_dir

    monkeypatch.setattr(approvals, "_approvals_dir", _fake_approvals_dir)
    return approvals_dir
