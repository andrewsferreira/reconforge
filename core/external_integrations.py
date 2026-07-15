"""Optional native integrations for SIEM/ticketing/approval workflows (E3)."""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any


def dispatch_workflow_event(summary: dict[str, Any]) -> list[str]:
    """Dispatch workflow summary to configured external endpoints.

    Optional env-based endpoints:
    - RECONFORGE_SIEM_WEBHOOK
    - RECONFORGE_TICKETING_WEBHOOK
    - RECONFORGE_APPROVAL_WEBHOOK
    """
    sent: list[str] = []
    for key, label in (
        ("RECONFORGE_SIEM_WEBHOOK", "siem"),
        ("RECONFORGE_TICKETING_WEBHOOK", "ticketing"),
        ("RECONFORGE_APPROVAL_WEBHOOK", "approval"),
    ):
        url = os.getenv(key, "").strip()
        if not url:
            continue
        if _post_json(url, summary):
            sent.append(label)
    return sent


def _post_json(url: str, payload: dict[str, Any]) -> bool:
    if not url.startswith(("http://", "https://")):
        # Endpoints come from operator-set env vars, not attacker input, but
        # reject non-http(s) schemes (file://, ftp://, ...) before urlopen
        # regardless — the same discipline required of any URL target.
        return False

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "ReconForge/1.1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:  # nosec B310 - scheme checked above
            return 200 <= resp.status < 300
    except Exception:
        return False
