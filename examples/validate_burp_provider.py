#!/usr/bin/env python3
"""Example: run official Burp provider validation programmatically."""

from __future__ import annotations

import json

from reconforge.entrypoints.burp_validation import validate_burp_provider


def main() -> int:
    result = validate_burp_provider()
    print(json.dumps(result.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
