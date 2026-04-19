#!/usr/bin/env python3


from __future__ import annotations

import argparse

import logging
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))




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
 main


if __name__ == "__main__":
    raise SystemExit(main())
