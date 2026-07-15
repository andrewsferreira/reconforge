"""Normalization helpers for Burp safe subset responses."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from core.adapters.burp.models import NormalizedBurpHttpRecord


def normalize_http_history_records(payload: dict[str, Any], *, tool_name: str, evidence_source: str) -> list[NormalizedBurpHttpRecord]:
    records = payload.get("records")
    if not isinstance(records, list):
        # Common MCP content style fallback.
        content = payload.get("content")
        if isinstance(content, list):
            records = [item for item in content if isinstance(item, dict)]
        else:
            records = []

    normalized: list[NormalizedBurpHttpRecord] = []
    for item in records:
        normalized.append(_normalize_single_record(item, tool_name=tool_name, evidence_source=evidence_source))
    return normalized


def normalize_http_send_response(payload: dict[str, Any], *, tool_name: str, evidence_source: str) -> list[NormalizedBurpHttpRecord]:
    return [_normalize_single_record(payload, tool_name=tool_name, evidence_source=evidence_source)]


def _normalize_single_record(item: dict[str, Any], *, tool_name: str, evidence_source: str) -> NormalizedBurpHttpRecord:
    url = str(item.get("url", "") or item.get("requestUrl", "")).strip()
    host = str(item.get("host", "")).strip()
    method = str(item.get("method", "") or item.get("requestMethod", "")).upper()
    status_code = _to_int(item.get("statusCode", item.get("status", 0)))
    body_length = _to_int(item.get("responseBodyLength", item.get("bodyLength", 0)))

    if url and not host:
        parsed = urlparse(url)
        host = parsed.hostname or ""

    return NormalizedBurpHttpRecord(
        url=url,
        host=host,
        method=method,
        status_code=status_code,
        response_body_length=body_length,
        request_headers=_as_headers(item.get("requestHeaders", {})),
        response_headers=_as_headers(item.get("responseHeaders", {})),
        tool_name=tool_name,
        evidence_source=evidence_source,
    )


def _as_headers(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    return {}


def _to_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
