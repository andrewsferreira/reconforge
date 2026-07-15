"""CLI wrapper for vulnerability intelligence validation loop."""

from __future__ import annotations

import argparse
import json
import logging

from reconforge.entrypoints.burp_intelligence import (
    IntelligenceRunConfig,
    run_vulnerability_intelligence,
    save_validation_result,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Burp vulnerability classification/correlation intelligence engine")
    parser.add_argument("--mcp-url", default="http://127.0.0.1:9876", help="Burp MCP base URL")
    parser.add_argument("--endpoint", action="append", default=[], help="Endpoint URL to test (repeatable)")
    parser.add_argument("--allow-domain", action="append", default=[], help="Allowed domain (repeatable)")
    parser.add_argument("--deny-domain", action="append", default=[], help="Denied domain (repeatable)")
    parser.add_argument("--no-subdomains", action="store_true", help="Disable subdomain allowance")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument("--output", default="", help="Optional output path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logs")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s")

    if not args.endpoint:
        parser.error("At least one --endpoint is required")

    config = IntelligenceRunConfig(
        mcp_url=args.mcp_url,
        endpoints=args.endpoint,
        allow_domains=tuple(args.allow_domain),
        deny_domains=tuple(args.deny_domain),
        allow_subdomains=not args.no_subdomains,
    )

    try:
        result = run_vulnerability_intelligence(config)
    except Exception as exc:  # noqa: BLE001
        payload = {"status": "FAILED", "error": str(exc), "mcp_url": args.mcp_url, "endpoints": args.endpoint}
        print("Vulnerability Intelligence Execution FAILED")
        print(f"Reason: {exc}")
        if args.json:
            print(json.dumps(payload, indent=2))
        return 3

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(json.dumps(result.improvement, indent=2))

    if args.output:
        path = save_validation_result(result, args.output)
        print(f"JSON report written to: {path.as_posix()}")

    return 0 if result.improvement.get("improved") else 2


if __name__ == "__main__":
    raise SystemExit(main())
