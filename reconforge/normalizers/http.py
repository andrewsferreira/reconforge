"""HTTP observation normalization primitives for provider-agnostic collection."""

from __future__ import annotations

import base64
import uuid
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


@dataclass
class HTTPObservation:
    """Normalized HTTP observation model reusable across providers."""

    target_url: str = ""
    scheme: str = ""
    host: str = ""
    port: int = 0
    method: str = ""
    path: str = ""
    query: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_status: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_length: int = 0
    timestamp: str = ""
    source_tool: str = ""
    source_provider: str = ""
    evidence_id: str = ""
    raw_reference: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class HttpObservationNormalizer:
    """Transforms provider records into provider-agnostic HTTP observations."""

    def normalize(
        self,
        record: Any,
        *,
        source_tool: str,
        source_provider: str,
        raw_reference: str = "",
    ) -> HTTPObservation:
        data = _record_as_mapping(record)

        target_url = _text(data.get("url") or data.get("target_url"))
        parsed = _safe_parse_url(target_url)

        request_headers = _normalize_headers(data.get("request_headers") or data.get("requestHeaders"))
        response_headers = _normalize_headers(data.get("response_headers") or data.get("responseHeaders"))

        response_status = _to_int(data.get("status_code") or data.get("response_status") or data.get("statusCode"))
        response_length = _to_int(
            data.get("response_body_length") or data.get("response_length") or data.get("responseBodyLength")
        )

        response_body, body_size = _normalize_body(data.get("response_body") or data.get("responseBody"))
        if response_length <= 0:
            response_length = body_size

        request_body, _ = _normalize_body(data.get("request_body") or data.get("requestBody"))

        host = _text(data.get("host")) or parsed.hostname
        method = _text(data.get("method")).upper()
        scheme = parsed.scheme
        path = parsed.path
        query = parsed.query
        port = parsed.port or (443 if scheme == "https" else 80 if scheme == "http" else 0)

        timestamp = _normalize_timestamp(_text(data.get("timestamp")))

        return HTTPObservation(
            target_url=target_url,
            scheme=scheme,
            host=host,
            port=port,
            method=method,
            path=path,
            query=query,
            request_headers=request_headers,
            request_body=request_body,
            response_status=response_status,
            response_headers=response_headers,
            response_body=response_body,
            response_length=response_length,
            timestamp=timestamp,
            source_tool=source_tool,
            source_provider=source_provider,
            evidence_id=_generate_evidence_id(source_provider, source_tool),
            raw_reference=raw_reference,
        )


def _record_as_mapping(record: Any) -> Mapping[str, Any]:
    if isinstance(record, Mapping):
        return record
    if hasattr(record, "__dict__"):
        return vars(record)
    return {}


def _normalize_headers(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    normalized: dict[str, str] = {}
    for key, header_value in value.items():
        name = "-".join(part.capitalize() for part in str(key).strip().split("-") if part)
        if not name:
            continue
        normalized[name] = str(header_value)
    return normalized


def _normalize_body(value: Any) -> tuple[str, int]:
    if value is None:
        return "", 0
    if isinstance(value, bytes):
        encoded = base64.b64encode(value).decode("ascii")
        return f"base64:{encoded}", len(value)
    text = str(value)
    return text, len(text.encode("utf-8", errors="ignore"))


def _safe_parse_url(url: str):
    if not url:
        return urlparse("")
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return parsed
    if "://" not in url:
        parsed_guess = urlparse(f"https://{url}")
        if parsed_guess.netloc:
            return parsed_guess
    return parsed


def _normalize_timestamp(value: str) -> str:
    if not value:
        return datetime.now(timezone.utc).isoformat()
    try:
        ts = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(ts)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except ValueError:
        return datetime.now(timezone.utc).isoformat()


def _generate_evidence_id(provider: str, tool: str) -> str:
    return f"{provider}:{tool}:{uuid.uuid4().hex}"


def _to_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""
