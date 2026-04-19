"""CLI wrapper for automated Burp MCP web lifecycle validation."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from reconforge.entrypoints.burp_web_validation import (
    render_lifecycle_console_report,
    run_burp_web_lifecycle_validation,
    save_lifecycle_json,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Burp MCP web lifecycle validation")
    parser.add_argument("--target-url", required=True, help="Target URL used for baseline and mutation replay")
    parser.add_argument("--mcp-url", default="http://127.0.0.1:9876", help="Burp MCP base URL")
    parser.add_argument(
        "--allow-domain",
        action="append",
        default=[],
        help="Allowed scope domain (repeatable, required for request execution)",
    )
    parser.add_argument("--deny-domain", action="append", default=[], help="Denied scope domain (repeatable)")
    parser.add_argument("--no-subdomains", action="store_true", help="Disable subdomain allowance")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument("--output", default="", help="Optional JSON report output path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logs")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s")

    try:
        report = run_burp_web_lifecycle_validation(
            target_url=args.target_url,
            base_url=args.mcp_url,
            scope_allowed_domains=tuple(args.allow_domain),
            scope_denied_domains=tuple(args.deny_domain),
            allow_subdomains=not args.no_subdomains,
        )
    except Exception as exc:  # noqa: BLE001
        failure_payload = {
            "mcp_server": args.mcp_url,
            "target_url": args.target_url,
            "status": "FAILED",
            "error": str(exc),
        }
        print("Burp MCP Web Lifecycle Validation\n=================================")
        print(f"FAILED: {exc}")
        if args.json:
            print(json.dumps(failure_payload, indent=2))
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(failure_payload, indent=2), encoding="utf-8")
            print(f"JSON report written to: {output_path.as_posix()}")
        return 3

    print(render_lifecycle_console_report(report))
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    if args.output:
        output_path = save_lifecycle_json(report, Path(args.output))
        print(f"JSON report written to: {output_path.as_posix()}")
    return 0 if all(status == "PASSED" for status in report.phase_status.values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
