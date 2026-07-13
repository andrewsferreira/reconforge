"""CLI for attack path generation with live replay (unreachable/reachable/
corroborated tiers — see reconforge/entrypoints/attack_paths.py)."""

from __future__ import annotations

import argparse
import json
import logging

from reconforge.entrypoints.attack_paths import AttackPathRunConfig, run_attack_path_generation, save_attack_path_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run attack path generation engine")
    parser.add_argument("--mcp-url", default="http://127.0.0.1:9876", help="Burp MCP base URL")
    parser.add_argument("--endpoint", action="append", default=[], help="Endpoint URL to test (repeatable)")
    parser.add_argument("--allow-domain", action="append", default=[], help="Allowed scope domain")
    parser.add_argument("--deny-domain", action="append", default=[], help="Denied scope domain")
    parser.add_argument("--no-subdomains", action="store_true", help="Disable subdomain allowance")
    parser.add_argument("--refinement-rounds", type=int, default=1, help="Number of refinement iterations")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument("--output", default="", help="Optional output path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logs")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s")

    if not args.endpoint:
        parser.error("At least one --endpoint is required")

    config = AttackPathRunConfig(
        mcp_url=args.mcp_url,
        endpoints=args.endpoint,
        allow_domains=tuple(args.allow_domain),
        deny_domains=tuple(args.deny_domain),
        allow_subdomains=not args.no_subdomains,
        refinement_rounds=max(0, args.refinement_rounds),
    )

    try:
        report = run_attack_path_generation(config)
    except Exception as exc:  # noqa: BLE001
        payload = {"status": "FAILED", "error": str(exc), "mcp_url": args.mcp_url, "endpoints": args.endpoint}
        print("Attack Path Generation FAILED")
        print(f"Reason: {exc}")
        if args.json:
            print(json.dumps(payload, indent=2))
        return 3

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(
            json.dumps(
                {
                    "attack_paths": len(report.attack_paths),
                    "failure_analysis": report.failure_analysis,
                },
                indent=2,
            )
        )

    if args.output:
        path = save_attack_path_report(report, args.output)
        print(f"JSON report written to: {path.as_posix()}")

    return 0 if report.attack_paths else 2


if __name__ == "__main__":
    raise SystemExit(main())
