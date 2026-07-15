"""Structured HTTP collection pipeline backed by provider abstractions."""

from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import asdict
from typing import Any

from core.adapters.burp.provider import BurpMcpProvider
from reconforge.normalizers.http import HTTPObservation, HttpObservationNormalizer

LOGGER = logging.getLogger(__name__)


class HttpCollector:
    """Collects request/response and proxy history observations in normalized form."""

    def __init__(self, provider: BurpMcpProvider, normalizer: HttpObservationNormalizer | None = None):
        self.provider = provider
        self.normalizer = normalizer or HttpObservationNormalizer()

    def collect_request(
        self,
        target_url: str,
        *,
        http_version: str = "http1",
        arguments: dict[str, Any] | None = None,
    ) -> HTTPObservation:
        payload = dict(arguments or {})
        payload.setdefault("url", target_url)

        LOGGER.info(json.dumps({"event": "http_collection_request_start", "target_url": target_url, "http_version": http_version}))

        if http_version == "http2":
            records = self.provider.send_http2_request(payload)
            tool_name = "send_http2_request"
        else:
            records = self.provider.send_http1_request(payload)
            tool_name = "send_http1_request"

        if not records:
            LOGGER.warning(json.dumps({"event": "http_collection_request_empty", "target_url": target_url, "tool": tool_name}))
            observation = self.normalizer.normalize(
                {"url": target_url}, source_tool=tool_name, source_provider="burp_mcp", raw_reference="empty_request_result"
            )
            return observation

        observation = self.normalizer.normalize(records[0], source_tool=tool_name, source_provider="burp_mcp")
        LOGGER.info(
            json.dumps(
                {
                    "event": "http_collection_request_success",
                    "target_url": target_url,
                    "tool": tool_name,
                    "status": observation.response_status,
                    "evidence_id": observation.evidence_id,
                }
            )
        )
        return observation

    def collect_proxy_history(self, regex: str | None = None) -> list[HTTPObservation]:
        LOGGER.info(json.dumps({"event": "http_collection_history_start", "regex": regex or ""}))
        if regex:
            records = self.provider.get_proxy_http_history_regex({"regex": regex})
            tool_name = "get_proxy_http_history_regex"
        else:
            records = self.provider.get_proxy_http_history({})
            tool_name = "get_proxy_http_history"

        observations: list[HTTPObservation] = []
        for idx, record in enumerate(records):
            try:
                obs = self.normalizer.normalize(record, source_tool=tool_name, source_provider="burp_mcp")
                observations.append(obs)
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning(
                    json.dumps(
                        {
                            "event": "http_collection_history_normalization_skipped",
                            "index": idx,
                            "tool": tool_name,
                            "error": str(exc),
                        }
                    )
                )

        LOGGER.info(
            json.dumps(
                {
                    "event": "http_collection_history_complete",
                    "tool": tool_name,
                    "record_count": len(records),
                    "observation_count": len(observations),
                }
            )
        )
        return observations

    @staticmethod
    def summarize(observations: list[HTTPObservation]) -> dict[str, Any]:
        if not observations:
            return {
                "total_observations": 0,
                "unique_hosts": [],
                "status_code_distribution": {},
                "response_size_stats": {"min": 0, "max": 0, "avg": 0.0},
            }

        hosts = sorted({obs.host for obs in observations if obs.host})
        statuses = Counter(obs.response_status for obs in observations if obs.response_status)
        sizes = [obs.response_length for obs in observations if obs.response_length >= 0]
        avg_size = round(sum(sizes) / len(sizes), 2) if sizes else 0.0

        return {
            "total_observations": len(observations),
            "unique_hosts": hosts,
            "status_code_distribution": dict(sorted(statuses.items())),
            "response_size_stats": {
                "min": min(sizes) if sizes else 0,
                "max": max(sizes) if sizes else 0,
                "avg": avg_size,
            },
        }


def observations_to_dict(observations: list[HTTPObservation]) -> list[dict[str, Any]]:
    return [asdict(observation) for observation in observations]
