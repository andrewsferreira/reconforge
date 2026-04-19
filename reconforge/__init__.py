"""ReconForge package entrypoints."""

from reconforge.entrypoints.burp_validation import validate_burp_provider


def main() -> None:
    from reconforge.cli import main as cli_main

    cli_main()


__all__ = ["main", "validate_burp_provider"]
