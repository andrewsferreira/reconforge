#!/usr/bin/env python3
"""Example: collect normalized HTTP observations through Burp provider."""

from __future__ import annotations

import json
import logging

from core.adapters.burp.config import BurpMcpConfig
from core.adapters.burp.provider import BurpMcpProvider
from reconforge.collectors.http_collector import HttpCollector, observations_to_dict


logging.basicConfig(level=logging.INFO, format="%(message)s")


def main() -> int:
    provider = BurpMcpProvider(
        config=BurpMcpConfig(
            scope_allowed_domains=("example.com",),
            scope_denied_domains=("google.com",),
            scope_allow_subdomains=True,
        )
    )

    provider.start()
    collector = HttpCollector(provider)

    try:
        request_observation = collector.collect_request("https://example.com/")
        history_observations = collector.collect_proxy_history()

        all_observations = [request_observation, *history_observations]
        summary = collector.summarize(all_observations)

        print("HTTP Observations")
        print(json.dumps(observations_to_dict(all_observations), indent=2))
        print("\nSummary")
        print(json.dumps(summary, indent=2))
    finally:
        provider.stop()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
