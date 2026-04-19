#!/usr/bin/env python3
"""Run Burp MCP validation and save report.json."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_validation.burp.models import ValidationConfig
from mcp_validation.burp.validator import BurpMcpValidator


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
    config = ValidationConfig(base_url=args.url)
    validator = BurpMcpValidator(config)

    report = validator.run()
    output_path = validator.save_report(report, Path(args.output))

    summary = {
        "recommendation": report.recommendation,
        "success": report.success,
        "tool_count": report.tool_count,
        "safe_execution": report.safe_execution.success,
        "output": output_path.as_posix(),
    }
    print(json.dumps(summary, indent=2))
    return 0 if report.success else 2


if __name__ == "__main__":
    raise SystemExit(main())
