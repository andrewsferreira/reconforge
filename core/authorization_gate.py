"""Execution authorization gate for active security testing.

E1 objective: add scope and approval checks before active execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml


@dataclass
class ScopeAuthorization:
    """Parsed authorization document used to gate execution."""

    allowed_targets: list[str]
    approval_id: str
    valid_until: datetime

    @classmethod
    def from_file(cls, path: str | Path) -> ScopeAuthorization:
        p = Path(path)
        if not p.exists():
            raise ValueError(f"Scope file not found: {p}")

        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError("Scope file must be a YAML/JSON object")

        allowed_targets = data.get("allowed_targets", [])
        approval_id = str(data.get("approval_id", "")).strip()
        valid_until_raw = str(data.get("valid_until", "")).strip()

        if not isinstance(allowed_targets, list) or not allowed_targets:
            raise ValueError("Scope file must contain non-empty 'allowed_targets'")
        if not approval_id:
            raise ValueError("Scope file must contain 'approval_id'")
        if not valid_until_raw:
            raise ValueError("Scope file must contain 'valid_until' (ISO-8601)")

        valid_until = _parse_iso_datetime(valid_until_raw)
        return cls(
            allowed_targets=[str(t).strip() for t in allowed_targets if str(t).strip()],
            approval_id=approval_id,
            valid_until=valid_until,
        )

    def assert_authorized(self, target: str, provided_approval_id: str) -> None:
        if not provided_approval_id:
            raise ValueError("Missing --approval-id")
        if provided_approval_id.strip() != self.approval_id:
            raise ValueError("Provided --approval-id does not match scope approval")
        if target not in self.allowed_targets:
            raise ValueError(f"Target '{target}' is not present in allowed_targets")
        if datetime.now(timezone.utc) > self.valid_until:
            raise ValueError(
                f"Scope approval expired at {self.valid_until.isoformat()}"
            )


def _parse_iso_datetime(value: str) -> datetime:
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"Invalid ISO-8601 datetime for valid_until: {value}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
