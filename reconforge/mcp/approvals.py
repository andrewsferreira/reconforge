"""Out-of-band human approval for MCP-triggered execution.

The security property this module exists to provide: **Claude cannot
approve its own execution request.** `reconforge_request_execution`
(the only MCP-reachable entry point into this module) does exactly one
thing — it writes a new :class:`ApprovalRequest` to disk in
``awaiting_operator_approval`` state and returns its id. Nothing in the
MCP tool surface can move a request out of that state. The only way a
request becomes ``approved`` is a human running
``reconforge mcp approvals approve <request_id>`` — a separate process,
a separate CLI invocation, entirely outside the MCP protocol an LLM
client speaks. This mirrors why an MCP request field like
``explicit_confirmation: true`` was never real proof of anything: the
model can supply any argument it likes, so the *channel* the approval
travels over is what has to be untouchable by MCP, not the shape of a
boolean field.

An approval is:
  - **bound** to a canonical SHA-256 hash of the exact operation it
    approves (engagement, normalized target, module, phase, opsec
    profile, tier, scope reference) — anything that would change what
    actually runs invalidates it, because nothing about an existing
    request can be mutated in place; a changed operation is a new
    request with a new hash;
  - **single-use** — consumption claims an OS-level exclusive marker
    file (``open(..., "x")``), which is atomic even across the two
    separate processes (the MCP server and the operator's CLI
    invocation) that touch this directory;
  - **expiring** — checked independently at approval time and at
    consumption time, since an approval granted moments before its
    deadline can still expire before anything actually runs.

Storage is plain JSON files under ``mcp.approvals_dir``
(``config/mcp.yaml``), one per request, deliberately outside any
MCP-request-suppliable path (see docs/CLAUDE_MCP_INTEGRATION.md's
security model) — there is no tool in this package that lets an MCP
client name, read, or write to this directory.
"""

from __future__ import annotations

import contextlib
import getpass
import hashlib
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from core.config_loader import ConfigLoader
from reconforge.mcp.errors import (
    ApprovalExpiredError,
    ApprovalNotApprovedError,
    ApprovalNotFoundError,
    ApprovalRequestMismatchError,
    ApprovalStateError,
)

ApprovalStatus = Literal[
    "awaiting_operator_approval",
    "approved",
    "denied",
    "expired",
    "consumed",
    "revoked",
]

_TERMINAL_STATUSES: frozenset[ApprovalStatus] = frozenset(
    {"denied", "expired", "consumed", "revoked"}
)

# How long a mutating operation (approve/deny/revoke/consume) waits to
# acquire a request's exclusive lock file before giving up. Operator-driven
# operations are not a hot path; a human running two `approvals approve`
# commands against the same id within a few hundred milliseconds of each
# other is the only realistic contention case this guards.
_LOCK_RETRY_INTERVAL_S = 0.02
_LOCK_TIMEOUT_S = 2.0


@dataclass
class ApprovalRequest:
    """A single pending-or-resolved out-of-band approval request.

    Every field needed to actually run the approved operation is stored
    here at creation time — ``reconforge_execute_approved_phase``/
    ``reconforge_start_execution`` take *only* a ``request_id`` and read
    everything else back from this record, so there is nothing left for
    an MCP request to supply (and therefore nothing left to tamper with)
    once a request has been created.
    """

    request_id: str
    engagement_id: str
    target: str
    normalized_target: str
    module: str
    phase: str
    opsec_profile: str
    tier: str
    scope_reference: str
    output_base: str
    domain: str
    scope_file: str | None
    approval_id: str | None
    timeout: int
    request_hash: str
    status: ApprovalStatus
    created_at: str
    expires_at: str
    approved_at: str | None = None
    approved_by: str | None = None
    denial_reason: str | None = None
    consumed_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ApprovalRequest:
        return cls(**data)

    def is_expired(self, *, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return now > _parse_iso(self.expires_at)


def canonical_request_hash(
    *,
    engagement_id: str,
    normalized_target: str,
    module: str,
    phase: str,
    opsec_profile: str,
    tier: str,
    scope_reference: str,
) -> str:
    """Deterministic hash of exactly the fields that define *what
    operation* is being approved. Deliberately excludes execution
    mechanics (output_base, timeout) — those don't change what runs
    against what, only where results land or how long it may take."""
    payload = {
        "engagement_id": engagement_id,
        "target": normalized_target,
        "module": module,
        "phase": phase,
        "opsec_profile": opsec_profile,
        "tier": tier,
        "scope_reference": scope_reference,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _parse_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _approvals_dir() -> Path:
    raw = ConfigLoader().load("mcp").get("mcp", {}).get("approvals_dir", ".reconforge/mcp_approvals")
    directory = Path(raw)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    return directory


def _approval_ttl_minutes() -> int:
    return int(ConfigLoader().load("mcp").get("mcp", {}).get("approval_ttl_minutes", 30))


def _request_path(request_id: str, directory: Path | None = None) -> Path:
    return (directory or _approvals_dir()) / f"{request_id}.json"


def _consumed_marker_path(request_id: str, directory: Path | None = None) -> Path:
    return (directory or _approvals_dir()) / f"{request_id}.consumed"


def _lock_path(request_id: str, directory: Path | None = None) -> Path:
    return (directory or _approvals_dir()) / f"{request_id}.lock"


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    tmp_path = path.with_suffix(path.suffix + f".tmp{os.getpid()}")
    tmp_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)


class _RequestLock:
    """A short-lived, cross-process exclusive lock for one request_id,
    implemented with ``O_CREAT | O_EXCL`` (atomic even across the MCP
    server process and a separate ``reconforge mcp approvals`` CLI
    invocation) rather than a threading primitive, which would only
    ever protect against contention within one process."""

    def __init__(self, request_id: str, directory: Path) -> None:
        self._path = _lock_path(request_id, directory)

    def __enter__(self) -> _RequestLock:
        deadline = time.monotonic() + _LOCK_TIMEOUT_S
        while True:
            try:
                fd = os.open(str(self._path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
                return self
            except FileExistsError:
                if time.monotonic() >= deadline:
                    raise ApprovalStateError(
                        "Timed out waiting for another operation on this approval request to finish."
                    ) from None
                time.sleep(_LOCK_RETRY_INTERVAL_S)

    def __exit__(self, *exc_info: object) -> None:
        with contextlib.suppress(OSError):
            self._path.unlink(missing_ok=True)


def create_request(
    *,
    engagement_id: str,
    target: str,
    normalized_target: str,
    module: str,
    phase: str,
    opsec_profile: str,
    tier: str,
    scope_reference: str,
    output_base: str,
    domain: str,
    scope_file: str | None,
    approval_id: str | None,
    timeout: int,
) -> ApprovalRequest:
    """Create a new pending request in ``awaiting_operator_approval``
    state. This is the *only* function this module exposes that an MCP
    tool handler may call — approve/deny/revoke are for the CLI only.
    """
    directory = _approvals_dir()
    request_id = str(uuid.uuid4())
    created = _now()
    expires = created + timedelta(minutes=_approval_ttl_minutes())
    request_hash = canonical_request_hash(
        engagement_id=engagement_id,
        normalized_target=normalized_target,
        module=module,
        phase=phase,
        opsec_profile=opsec_profile,
        tier=tier,
        scope_reference=scope_reference,
    )
    record = ApprovalRequest(
        request_id=request_id,
        engagement_id=engagement_id,
        target=target,
        normalized_target=normalized_target,
        module=module,
        phase=phase,
        opsec_profile=opsec_profile,
        tier=tier,
        scope_reference=scope_reference,
        output_base=output_base,
        domain=domain,
        scope_file=scope_file,
        approval_id=approval_id,
        timeout=timeout,
        request_hash=request_hash,
        status="awaiting_operator_approval",
        created_at=created.isoformat(),
        expires_at=expires.isoformat(),
    )
    _atomic_write_json(_request_path(request_id, directory), record.to_dict())
    return record


def get_request(request_id: str) -> ApprovalRequest:
    path = _request_path(request_id)
    if not path.is_file():
        raise ApprovalNotFoundError(f"No approval request found for id '{request_id}'.")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return ApprovalRequest.from_dict(data)
    except (json.JSONDecodeError, TypeError, KeyError) as exc:
        raise ApprovalNotFoundError(f"Approval request '{request_id}' is unreadable: {exc}") from exc


def list_requests() -> list[ApprovalRequest]:
    directory = _approvals_dir()
    requests: list[ApprovalRequest] = []
    for path in sorted(directory.glob("*.json")):
        try:
            requests.append(ApprovalRequest.from_dict(json.loads(path.read_text(encoding="utf-8"))))
        except (json.JSONDecodeError, TypeError, KeyError):
            continue  # skip unreadable/corrupt records, don't fail the whole listing
    requests.sort(key=lambda r: r.created_at)
    return requests


def _expire_if_due(record: ApprovalRequest, directory: Path) -> ApprovalRequest:
    if record.status not in _TERMINAL_STATUSES and record.is_expired():
        record.status = "expired"
        _atomic_write_json(_request_path(record.request_id, directory), record.to_dict())
    return record


def approve(request_id: str, *, approved_by: str | None = None) -> ApprovalRequest:
    """Operator-only. Never called from any MCP tool handler."""
    directory = _approvals_dir()
    with _RequestLock(request_id, directory):
        record = get_request(request_id)
        record = _expire_if_due(record, directory)
        if record.status == "expired":
            raise ApprovalExpiredError(f"Approval request '{request_id}' expired at {record.expires_at}.")
        if record.status != "awaiting_operator_approval":
            raise ApprovalStateError(
                f"Cannot approve request '{request_id}': status is '{record.status}', "
                "not 'awaiting_operator_approval'."
            )
        record.status = "approved"
        record.approved_at = _now().isoformat()
        record.approved_by = approved_by or _local_operator_identity()
        _atomic_write_json(_request_path(request_id, directory), record.to_dict())
        return record


def deny(request_id: str, *, reason: str | None = None) -> ApprovalRequest:
    """Operator-only. Never called from any MCP tool handler."""
    directory = _approvals_dir()
    with _RequestLock(request_id, directory):
        record = get_request(request_id)
        record = _expire_if_due(record, directory)
        if record.status == "expired":
            raise ApprovalExpiredError(f"Approval request '{request_id}' expired at {record.expires_at}.")
        if record.status != "awaiting_operator_approval":
            raise ApprovalStateError(
                f"Cannot deny request '{request_id}': status is '{record.status}', "
                "not 'awaiting_operator_approval'."
            )
        record.status = "denied"
        record.denial_reason = reason or "Denied by operator."
        _atomic_write_json(_request_path(request_id, directory), record.to_dict())
        return record


def revoke(request_id: str) -> ApprovalRequest:
    """Operator-only. Revokes a request that was approved but not yet
    consumed — e.g. the operator changes their mind after approving but
    before Claude/the MCP client acts on it. A request that has already
    been consumed cannot be revoked (the execution already happened)."""
    directory = _approvals_dir()
    with _RequestLock(request_id, directory):
        record = get_request(request_id)
        if record.status != "approved":
            raise ApprovalStateError(
                f"Cannot revoke request '{request_id}': status is '{record.status}', not 'approved'."
            )
        record.status = "revoked"
        _atomic_write_json(_request_path(request_id, directory), record.to_dict())
        return record


def consume_if_approved(request_id: str, *, expected_hash: str) -> ApprovalRequest:
    """The only path by which MCP-triggered execution may proceed.

    Raises unless the request is genuinely ``approved``, unexpired, and
    its stored hash matches *expected_hash* (recomputed by the caller
    from the request's own stored canonical fields — a mismatch means
    on-disk tampering or corruption, not a normal condition). On
    success, atomically claims the request via an exclusive marker file
    so a second, concurrent caller for the same request_id always loses
    — there is no window in which two executions can both believe they
    consumed the same approval.
    """
    directory = _approvals_dir()
    record = get_request(request_id)
    record = _expire_if_due(record, directory)

    if record.status == "expired":
        raise ApprovalExpiredError(f"Approval request '{request_id}' expired at {record.expires_at}.")
    if record.status != "approved":
        raise ApprovalNotApprovedError(
            f"Approval request '{request_id}' is not approved (status: '{record.status}').",
            status=record.status,
        )
    if record.request_hash != expected_hash:
        raise ApprovalRequestMismatchError(
            f"Approval request '{request_id}' hash mismatch — refusing to execute."
        )

    marker = _consumed_marker_path(request_id, directory)
    try:
        fd = os.open(str(marker), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
    except FileExistsError:
        raise ApprovalStateError(
            f"Approval request '{request_id}' was already consumed by another execution."
        ) from None

    with _RequestLock(request_id, directory):
        record = get_request(request_id)
        record.status = "consumed"
        record.consumed_at = _now().isoformat()
        _atomic_write_json(_request_path(request_id, directory), record.to_dict())
    return record


def _local_operator_identity() -> str | None:
    try:
        return getpass.getuser()
    except Exception:
        return None
