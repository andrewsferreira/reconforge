from pathlib import Path

import pytest

from core.authorization_gate import ScopeAuthorization


def test_scope_authorization_happy_path(tmp_path: Path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        """
allowed_targets:
  - 10.10.10.1
approval_id: APP-123
valid_until: 2099-01-01T00:00:00Z
""".strip()
    )

    auth = ScopeAuthorization.from_file(scope)
    auth.assert_authorized("10.10.10.1", "APP-123")


def test_scope_authorization_blocks_wrong_target(tmp_path: Path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        """
allowed_targets:
  - 10.10.10.1
approval_id: APP-123
valid_until: 2099-01-01T00:00:00Z
""".strip()
    )

    auth = ScopeAuthorization.from_file(scope)
    with pytest.raises(ValueError, match="not present in allowed_targets"):
        auth.assert_authorized("10.10.10.2", "APP-123")


def test_scope_authorization_blocks_expired(tmp_path: Path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        """
allowed_targets:
  - 10.10.10.1
approval_id: APP-123
valid_until: 2020-01-01T00:00:00Z
""".strip()
    )

    auth = ScopeAuthorization.from_file(scope)
    with pytest.raises(ValueError, match="expired"):
        auth.assert_authorized("10.10.10.1", "APP-123")
