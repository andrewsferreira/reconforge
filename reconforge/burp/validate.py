"""CLI wrapper for the official Burp MCP provider validator."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from reconforge.entrypoints.burp_validation import (
    FAILED,
    PARTIAL,
    READY,
    render_validation_console_summary,
    save_validation_json,
    validate_burp_provider,
)


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format="%(message)s")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Burp MCP provider integration for ReconForge")
    parser.add_argument("--url", default=None, help="Burp MCP base URL (or use BURP_MCP_URL)")
    parser.add_argument("--json", action="store_true", help="Print structured JSON report")
    parser.add_argument("--output", default="", help="Optional output file for JSON report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args(argv)

    _configure_logging(args.verbose)
    result = validate_burp_provider(base_url=args.url)

    print(render_validation_console_summary(result))

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))

    if args.output:
        output_path = save_validation_json(result, Path(args.output))
        print(f"JSON report written to: {output_path.as_posix()}")

    if result.readiness_status == READY:
        return 0
    if result.readiness_status == PARTIAL:
        return 2
    if result.readiness_status == FAILED:
        return 3
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
