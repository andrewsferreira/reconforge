#!/usr/bin/env python3


from __future__ import annotations

import argparse

import logging
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_validation.burp.models import ValidationConfig
from mcp_validation.burp.validator import BurpMcpValidator

LOGGER = logging.getLogger(__name__)


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(message)s")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Burp MCP server using SSE + JSON-RPC")
    parser.add_argument("--url", default="http://127.0.0.1:9876", help="Burp MCP base URL")
    parser.add_argument("--output", default="mcp_validation/report.json", help="Path to JSON report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose structured logging")
    args = parser.parse_args()

    configure_logging(args.verbose)

    validator = BurpMcpValidator(ValidationConfig(base_url=args.url))
    report = validator.run()
    output_path = validator.save_report(report, Path(args.output))

    LOGGER.info("Recommendation: %s", report.recommendation)
    LOGGER.info("Tools discovered: %d", report.tool_count)
    LOGGER.info("Report written to: %s", output_path)
    if report.errors:
        for err in report.errors:
            LOGGER.error("[%s] %s: %s", err.stage, err.error_type, err.message)

    return 0 if report.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
