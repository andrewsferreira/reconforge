"""In-memory execution job registry, layered on top of
``services.py::execute_approved_phase``'s synchronous execution path.

Why this exists: a real module phase can run for minutes (a full nmap
scan of a large range, a nuclei run against many endpoints), which can
exceed how long an MCP client is willing to block on a single tool-call
response. ``reconforge_start_execution`` runs the exact same
authorization path as the synchronous ``reconforge_execute_approved_phase``
tool (``services.py::_consume_and_authorize`` — see that function's
docstring) before returning, so a bad or unauthorized request fails
immediately, not after a job was already created; only the actual
module execution moves to a background thread. Both tools share
``services.py::_EXECUTION_LOCK``, so "one execution at a time on this
server process" holds regardless of which tool started it. Both also
consume the same out-of-band-approved request exactly once
(``reconforge/mcp/approvals.py::consume_if_approved``) — there is no
weaker path into execution via the job model.

No cancellation: ``core/runner.py``'s subprocess execution has no
cooperative-cancellation hook, so a running job cannot actually be
stopped mid-flight. Rather than expose a ``cancel`` tool that only
works in the sub-millisecond window between job creation and the
worker thread starting (i.e., in practice never, for the case anyone
would actually want it), this is documented as a known limitation
instead of built as a tool that mostly doesn't do what its name
implies.

Job state lives only in this process's memory — no persistence across
restarts — matching every other in-memory assumption already made in
this package (one server process per Claude session). Nothing expires
or gets cleaned up; for a short-lived session this doesn't matter, and
building an eviction policy for a problem that hasn't been observed
would be exactly the kind of premature abstraction this project avoids
elsewhere.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from reconforge.mcp.errors import ExecutionConflictError, JobNotFoundError, MCPServiceError
from reconforge.mcp.schemas import ExecuteApprovedPhaseResponse

JobStatus = Literal["pending", "running", "completed", "failed"]


@dataclass
class ExecutionJob:
    job_id: str
    status: JobStatus
    module: str
    phase: str
    target: str
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    result: ExecuteApprovedPhaseResponse | None = None
    error: str | None = None
    error_code: str | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)


_JOBS: dict[str, ExecutionJob] = {}
_JOBS_REGISTRY_LOCK = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def start_execution(request_id: str) -> ExecutionJob:
    """Acquire the execution lock synchronously first (so a busy server
    rejects the call immediately, before the referenced approval is ever
    touched — a lock conflict must never burn a genuinely valid,
    operator-approved request; see ``services.py::execute_approved_phase``'s
    identical ordering and its comment for why), then authorize —
    including atomically consuming the approval
    (``services.py::_consume_and_authorize``) — before creating any job.
    A second call with the same ``request_id`` always fails once the
    approval is consumed, whether or not the lock was ever the reason.
    """
    from reconforge.mcp import services

    if not services._EXECUTION_LOCK.acquire(blocking=False):
        raise ExecutionConflictError("Another execution is already in progress on this server process.")
    try:
        record, module_cls, tier, scope = services._consume_and_authorize(request_id)
    except Exception:
        services._EXECUTION_LOCK.release()
        raise

    job = ExecutionJob(
        job_id=str(uuid.uuid4()),
        status="pending",
        module=record.module,
        phase=record.phase,
        target=record.target,
        created_at=_now(),
    )
    with _JOBS_REGISTRY_LOCK:
        _JOBS[job.job_id] = job

    def _worker() -> None:
        with job._lock:
            job.status = "running"
            job.started_at = _now()
        try:
            result = services._execute_module_phase_locked(record, module_cls, tier, scope)
        except MCPServiceError as exc:
            with job._lock:
                job.status = "failed"
                job.error = str(exc)
                job.error_code = exc.code
                job.completed_at = _now()
            return
        except Exception as exc:
            # module.run() already catches ReconForgeError internally
            # (see _execute_module_phase_locked); anything else reaching
            # here is a genuinely unexpected failure, still reported on
            # the job rather than crashing a daemon thread silently.
            with job._lock:
                job.status = "failed"
                job.error = str(exc)
                job.error_code = "MCP_SERVICE_ERROR"
                job.completed_at = _now()
            return
        finally:
            services._EXECUTION_LOCK.release()
        with job._lock:
            job.status = "completed"
            job.result = result
            job.completed_at = _now()

    threading.Thread(target=_worker, daemon=True, name=f"reconforge-mcp-job-{job.job_id[:8]}").start()
    return job


def get_execution_status(job_id: str) -> ExecutionJob:
    with _JOBS_REGISTRY_LOCK:
        job = _JOBS.get(job_id)
    if job is None:
        raise JobNotFoundError(f"No execution job found for id '{job_id}'.")
    with job._lock:
        # Return a snapshot rather than the live object — the worker
        # thread mutates fields under job._lock, so reading them under
        # the same lock avoids a caller observing a half-updated job.
        return ExecutionJob(
            job_id=job.job_id,
            status=job.status,
            module=job.module,
            phase=job.phase,
            target=job.target,
            created_at=job.created_at,
            started_at=job.started_at,
            completed_at=job.completed_at,
            result=job.result,
            error=job.error,
            error_code=job.error_code,
        )
