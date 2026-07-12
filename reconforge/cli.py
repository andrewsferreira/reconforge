#!/usr/bin/env python3
"""ReconForge - Modular Pentest Reconnaissance Framework.

Author: Andrews Ferreira
Version: 2.0.0

Usage (after `pip install -e .` or `pipx install .`):
    reconforge network --target <target> [options]
    reconforge ad --target <dc-ip> --domain <domain> [options]
    reconforge api --target <api-url> [options]

Without installing, from a repo checkout:
    python -m reconforge network --target <target> [options]
"""

import argparse
import sys
from pathlib import Path

# Ensure the project root is on the path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.authorization_gate import ScopeAuthorization
from core.exceptions import ReconForgeError


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="reconforge",
        description="ReconForge - Modular Pentest Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  reconforge network --target 10.10.10.1
  reconforge network --target 10.10.10.0/24 --opsec stealth
  reconforge network --target 10.10.10.1 --opsec aggressive --brute-force
  reconforge network --target 10.10.10.1 --phases discovery,scanning -v

  reconforge ad --target 10.10.10.1 --domain corp.local
  reconforge ad --target 10.10.10.1 --domain corp.local --opsec stealth
  reconforge ad --target 10.10.10.1 --domain corp.local -u user -p pass --dc-ip 10.10.10.1
  reconforge ad --target 10.10.10.1 --domain corp.local --phases passive,identity -v

  reconforge web --target https://example.com
  reconforge web --target https://example.com --opsec stealth
  reconforge web --target https://example.com --opsec aggressive --phases surface,content,vuln,exploit
  reconforge web --target https://example.com --phases surface,content -e php,asp -v

  reconforge api --target https://api.example.com/v1
  reconforge api --target https://api.example.com --opsec stealth
  reconforge api --target https://api.example.com --auth-token "Bearer eyJ..."
  reconforge api --target https://api.example.com --phases discovery,authentication,fuzzing,authorization -v

  reconforge workflow --target 10.10.10.1
  reconforge workflow --target 10.10.10.1 --modules network,ad,web
  reconforge workflow --target 10.10.10.1 --opsec stealth --engagement "Q1 Pentest" --client "Acme"
"""
    )

    subparsers = parser.add_subparsers(dest="module", help="Module to run")

    burp_parser = subparsers.add_parser(
        "burp",
        help="Burp MCP provider utilities",
        description="Validate and inspect Burp MCP provider integration",
    )
    burp_subparsers = burp_parser.add_subparsers(dest="burp_command", help="Burp subcommand")
    burp_validate_parser = burp_subparsers.add_parser(
        "validate", help="Validate Burp MCP connectivity, capabilities, and safe execution"
    )
    burp_validate_parser.add_argument(
        "--url",
        default=None,
        help="Burp MCP base URL (defaults to BURP_MCP_URL or http://127.0.0.1:9876)",
    )
    burp_validate_parser.add_argument("--rpc-timeout", type=float, default=None, help="RPC timeout seconds")
    burp_validate_parser.add_argument("--connect-timeout", type=float, default=None, help="SSE/connect timeout seconds")
    burp_validate_parser.add_argument("--debug", action="store_true", help="Enable provider debug mode")
    burp_validate_parser.add_argument("--json", action="store_true", help="Print structured JSON report")
    burp_validate_parser.add_argument("--output", default="", help="Optional output path for JSON report")
    burp_validate_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")

    burp_lifecycle_parser = burp_subparsers.add_parser(
        "lifecycle-validate", help="Run full Burp MCP web request/replay/mutation/session lifecycle validation"
    )
    burp_lifecycle_parser.add_argument("--target-url", required=True, help="Target URL for baseline request capture/replay")
    burp_lifecycle_parser.add_argument("--mcp-url", default="http://127.0.0.1:9876", help="Burp MCP base URL")
    burp_lifecycle_parser.add_argument("--allow-domain", action="append", default=[], help="Allowed scope domain")
    burp_lifecycle_parser.add_argument("--deny-domain", action="append", default=[], help="Denied scope domain")
    burp_lifecycle_parser.add_argument("--no-subdomains", action="store_true", help="Disable subdomain allowance")
    burp_lifecycle_parser.add_argument("--json", action="store_true", help="Print structured JSON report")
    burp_lifecycle_parser.add_argument("--output", default="", help="Optional output path for JSON report")
    burp_lifecycle_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")

    burp_intel_parser = burp_subparsers.add_parser(
        "intelligence-validate",
        help="Run vulnerability classification and correlation validation loop",
    )
    burp_intel_parser.add_argument("--mcp-url", default="http://127.0.0.1:9876", help="Burp MCP base URL")
    burp_intel_parser.add_argument("--endpoint", action="append", default=[], help="Endpoint URL to test")
    burp_intel_parser.add_argument("--allow-domain", action="append", default=[], help="Allowed scope domain")
    burp_intel_parser.add_argument("--deny-domain", action="append", default=[], help="Denied scope domain")
    burp_intel_parser.add_argument("--no-subdomains", action="store_true", help="Disable subdomain allowance")
    burp_intel_parser.add_argument("--json", action="store_true", help="Print structured JSON report")
    burp_intel_parser.add_argument("--output", default="", help="Optional output path for JSON report")
    burp_intel_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")

    burp_attack_path_parser = burp_subparsers.add_parser(
        "attack-paths",
        help="Generate and validate multi-step attack paths from correlated findings",
    )
    burp_attack_path_parser.add_argument("--mcp-url", default="http://127.0.0.1:9876", help="Burp MCP base URL")
    burp_attack_path_parser.add_argument("--endpoint", action="append", default=[], help="Endpoint URL to test")
    burp_attack_path_parser.add_argument("--allow-domain", action="append", default=[], help="Allowed scope domain")
    burp_attack_path_parser.add_argument("--deny-domain", action="append", default=[], help="Denied scope domain")
    burp_attack_path_parser.add_argument("--no-subdomains", action="store_true", help="Disable subdomain allowance")
    burp_attack_path_parser.add_argument("--refinement-rounds", type=int, default=1, help="Refinement loop count")
    burp_attack_path_parser.add_argument("--json", action="store_true", help="Print structured JSON report")
    burp_attack_path_parser.add_argument("--output", default="", help="Optional output path for JSON report")
    burp_attack_path_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")

    # Network module
    net_parser = subparsers.add_parser("network", help="Network reconnaissance")
    net_parser.add_argument("-t", "--target", required=True, help="Target IP, hostname, or CIDR")
    net_parser.add_argument("--opsec", choices=["stealth", "normal", "aggressive"],
                            default="normal", help="OPSEC mode (default: normal)")
    net_parser.add_argument("--phases", type=str, default=None,
                            help="Comma-separated phases: discovery,scanning,enumeration,authentication")
    net_parser.add_argument("--brute-force", action="store_true",
                            help="Enable hydra brute-force testing (opt-in)")
    net_parser.add_argument("-o", "--output", default="outputs",
                            help="Output base directory (default: outputs)")
    net_parser.add_argument("-v", "--verbose", action="store_true",
                            help="Verbose output")
    net_parser.add_argument("--dry-run", action="store_true",
                            help="Show commands without executing")
    net_parser.add_argument("--timeout", type=int, default=600,
                            help="Default command timeout in seconds")
    net_parser.add_argument("--encrypt-loot", action="store_true",
                            help="Encrypt loot files with Fernet (key in ~/.reconforge/loot.key)")
    net_parser.add_argument("--enforce-scope", action="store_true",
                            help="Require scope/approval validation before active execution")
    net_parser.add_argument("--scope-file", default="",
                            help="Path to scope authorization YAML/JSON file")
    net_parser.add_argument("--approval-id", default="",
                            help="Approval token/ID matching the scope file")
    net_parser.add_argument("--authorized-target", action="store_true",
                            help="Explicit acknowledgement that this target is authorized "
                                 "for testing (required unless --enforce-scope or --lab-mode is used)")
    net_parser.add_argument("--lab-mode", action="store_true",
                            help="Acknowledge this run targets a lab/CTF environment you control "
                                 "(required unless --authorized-target or --enforce-scope is used)")

    # AD module
    ad_parser = subparsers.add_parser("ad", help="Active Directory reconnaissance")
    ad_parser.add_argument("-t", "--target", required=True,
                           help="Target DC IP or hostname")
    ad_parser.add_argument("--domain", default="",
                           help="AD domain name (e.g. corp.local)")
    ad_parser.add_argument("--opsec", choices=["stealth", "normal", "aggressive"],
                           default="normal", help="OPSEC mode (default: normal)")
    ad_parser.add_argument("--phases", type=str, default=None,
                           help="Comma-separated phases: passive,identity,configuration")
    ad_parser.add_argument("-u", "--username", default="",
                           help="Username for authenticated enumeration")
    ad_parser.add_argument("-p", "--password", default="",
                           help="Password for authenticated enumeration")
    ad_parser.add_argument("--dc-ip", default="",
                           help="Domain Controller IP (if different from target)")
    ad_parser.add_argument("-o", "--output", default="outputs",
                           help="Output base directory (default: outputs)")
    ad_parser.add_argument("-v", "--verbose", action="store_true",
                           help="Verbose output")
    ad_parser.add_argument("--dry-run", action="store_true",
                           help="Show commands without executing")
    ad_parser.add_argument("--timeout", type=int, default=600,
                            help="Default command timeout in seconds")
    ad_parser.add_argument("--encrypt-loot", action="store_true",
                            help="Encrypt loot files with Fernet (key in ~/.reconforge/loot.key)")
    ad_parser.add_argument("--enforce-scope", action="store_true",
                           help="Require scope/approval validation before active execution")
    ad_parser.add_argument("--scope-file", default="",
                           help="Path to scope authorization YAML/JSON file")
    ad_parser.add_argument("--approval-id", default="",
                           help="Approval token/ID matching the scope file")
    ad_parser.add_argument("--authorized-target", action="store_true",
                            help="Explicit acknowledgement that this target is authorized "
                                 "for testing (required unless --enforce-scope or --lab-mode is used)")
    ad_parser.add_argument("--lab-mode", action="store_true",
                            help="Acknowledge this run targets a lab/CTF environment you control "
                                 "(required unless --authorized-target or --enforce-scope is used)")

    # Web module
    web_parser = subparsers.add_parser(
        "web",
        help="Web application reconnaissance",
        description="Perform web application reconnaissance and vulnerability assessment",
    )
    web_parser.add_argument("--target", "-t", required=True,
                            help="Target URL (e.g., https://example.com)")
    web_parser.add_argument("--opsec", choices=["stealth", "normal", "aggressive"],
                            default="normal", help="OPSEC mode")
    web_parser.add_argument("--phases",
                            help="Comma-separated phases to run (surface,content,vuln,exploit)")
    web_parser.add_argument("--wordlist", "-w",
                            help="Custom wordlist for content discovery")
    web_parser.add_argument("--threads", "-th", type=int, default=40,
                            help="Number of threads for fuzzing")
    web_parser.add_argument("--extensions", "-e",
                            help="File extensions to search for (e.g., php,asp,aspx)")
    web_parser.add_argument("--follow-redirects", action="store_true", default=True,
                            help="Follow HTTP redirects")
    web_parser.add_argument("--verify-ssl", action="store_true",
                            help="Verify SSL certificates")
    web_parser.add_argument("-o", "--output", default="outputs",
                            help="Output directory")
    web_parser.add_argument("-v", "--verbose", action="store_true",
                            help="Verbose output")
    web_parser.add_argument("--dry-run", action="store_true",
                            help="Dry run mode (show commands without executing)")
    web_parser.add_argument("--timeout", type=int, default=600,
                            help="Global timeout for tools")
    web_parser.add_argument("--encrypt-loot", action="store_true",
                            help="Encrypt loot files with Fernet (key in ~/.reconforge/loot.key)")
    web_parser.add_argument("--enforce-scope", action="store_true",
                            help="Require scope/approval validation before active execution")
    web_parser.add_argument("--scope-file", default="",
                            help="Path to scope authorization YAML/JSON file")
    web_parser.add_argument("--approval-id", default="",
                            help="Approval token/ID matching the scope file")
    web_parser.add_argument("--authorized-target", action="store_true",
                            help="Explicit acknowledgement that this target is authorized "
                                 "for testing (required unless --enforce-scope or --lab-mode is used)")
    web_parser.add_argument("--lab-mode", action="store_true",
                            help="Acknowledge this run targets a lab/CTF environment you control "
                                 "(required unless --authorized-target or --enforce-scope is used)")

    # API module
    api_parser = subparsers.add_parser(
        "api",
        help="API reconnaissance and security assessment",
        description="Perform API reconnaissance, authentication testing, and authorization checks",
    )
    api_parser.add_argument("--target", "-t", required=True,
                            help="Target API base URL (e.g., https://api.example.com/v1)")
    api_parser.add_argument("--opsec", choices=["stealth", "normal", "aggressive"],
                            default="normal", help="OPSEC mode")
    api_parser.add_argument("--phases",
                            help="Comma-separated phases to run (discovery,authentication,fuzzing,authorization)")
    api_parser.add_argument("--header", action="append", dest="headers", default=[],
                            help="Extra HTTP header (repeatable, e.g., --header 'X-Api-Key: abc')")
    api_parser.add_argument("--auth-token",
                            help="Bearer/auth token for authenticated requests")
    api_parser.add_argument("--wordlist", "-w",
                            help="Custom wordlist for endpoint discovery")
    api_parser.add_argument("-o", "--output", default="outputs",
                            help="Output directory")
    api_parser.add_argument("-v", "--verbose", action="store_true",
                            help="Verbose output")
    api_parser.add_argument("--dry-run", action="store_true",
                            help="Dry run mode (show commands without executing)")
    api_parser.add_argument("--timeout", type=int, default=600,
                            help="Global timeout for tools")
    api_parser.add_argument("--encrypt-loot", action="store_true",
                            help="Encrypt loot files with Fernet (key in ~/.reconforge/loot.key)")
    api_parser.add_argument("--enforce-scope", action="store_true",
                            help="Require scope/approval validation before active execution")
    api_parser.add_argument("--scope-file", default="",
                            help="Path to scope authorization YAML/JSON file")
    api_parser.add_argument("--approval-id", default="",
                            help="Approval token/ID matching the scope file")
    api_parser.add_argument("--authorized-target", action="store_true",
                            help="Explicit acknowledgement that this target is authorized "
                                 "for testing (required unless --enforce-scope or --lab-mode is used)")
    api_parser.add_argument("--lab-mode", action="store_true",
                            help="Acknowledge this run targets a lab/CTF environment you control "
                                 "(required unless --authorized-target or --enforce-scope is used)")

    # Workflow orchestrator
    wf_parser = subparsers.add_parser(
        "workflow",
        help="Cross-module workflow orchestration",
        description="Chain multiple modules with automatic data passing and conditional branching",
    )
    wf_parser.add_argument("--target", "-t", required=True,
                           help="Primary target (IP, CIDR, hostname, or URL)")
    wf_parser.add_argument("--modules",
                           help="Comma-separated modules to run (default: full-recon pipeline)")
    wf_parser.add_argument("--opsec", choices=["stealth", "normal", "aggressive"],
                           default="normal", help="OPSEC mode")
    wf_parser.add_argument("-o", "--output", default="outputs",
                           help="Output directory")
    wf_parser.add_argument("-v", "--verbose", action="store_true",
                           help="Verbose output")
    wf_parser.add_argument("--dry-run", action="store_true",
                           help="Dry run mode")
    wf_parser.add_argument("--timeout", type=int, default=600,
                           help="Global timeout for tools")
    wf_parser.add_argument("--encrypt-loot", action="store_true",
                           help="Encrypt loot/vault files")
    wf_parser.add_argument("--engagement", default="",
                           help="Engagement name")
    wf_parser.add_argument("--client", default="",
                           help="Client name for engagement tracking")
    wf_parser.add_argument("--operator", default="Andrews Ferreira",
                           help="Operator name")
    wf_parser.add_argument("--resume", default="",
                           help="Path to saved engagement JSON to resume")
    wf_parser.add_argument("--auto-handoff", action="store_true",
                           help="Automatically enqueue safe follow-on module steps inferred from recon results")
    wf_parser.add_argument("--max-handoff-steps", type=int, default=5,
                           help="Maximum number of auto-handoff steps to enqueue")
    wf_parser.add_argument("--enforce-scope", action="store_true",
                           help="Require scope/approval validation before active execution")
    wf_parser.add_argument("--scope-file", default="",
                           help="Path to scope authorization YAML/JSON file")
    wf_parser.add_argument("--approval-id", default="",
                           help="Approval token/ID matching the scope file")
    wf_parser.add_argument("--authorized-target", action="store_true",
                            help="Explicit acknowledgement that this target is authorized "
                                 "for testing (required unless --enforce-scope or --lab-mode is used)")
    wf_parser.add_argument("--lab-mode", action="store_true",
                            help="Acknowledge this run targets a lab/CTF environment you control "
                                 "(required unless --authorized-target or --enforce-scope is used)")

    # Surface module
    surface_parser = subparsers.add_parser(
        "surface",
        help="Attack surface mapping",
        description="Map the attack surface of a target",
    )
    surface_parser.add_argument("--target", "-t", required=True,
                                help="Target IP or hostname")
    surface_parser.add_argument("--opsec", choices=["stealth", "normal", "aggressive"],
                                default="normal", help="OPSEC mode")
    surface_parser.add_argument("--phases",
                                help="Comma-separated phases")
    surface_parser.add_argument("-o", "--output", default="outputs",
                                help="Output directory")
    surface_parser.add_argument("-v", "--verbose", action="store_true",
                                help="Verbose output")
    surface_parser.add_argument("--dry-run", action="store_true",
                                help="Dry run mode")
    surface_parser.add_argument("--timeout", type=int, default=600,
                                help="Global timeout for tools")
    surface_parser.add_argument("--encrypt-loot", action="store_true",
                                help="Encrypt loot files with Fernet (key in ~/.reconforge/loot.key)")
    surface_parser.add_argument("--enforce-scope", action="store_true",
                                help="Require scope/approval validation before active execution")
    surface_parser.add_argument("--scope-file", default="",
                                help="Path to scope authorization YAML/JSON file")
    surface_parser.add_argument("--approval-id", default="",
                                help="Approval token/ID matching the scope file")
    surface_parser.add_argument("--authorized-target", action="store_true",
                            help="Explicit acknowledgement that this target is authorized "
                                 "for testing (required unless --enforce-scope or --lab-mode is used)")
    surface_parser.add_argument("--lab-mode", action="store_true",
                            help="Acknowledge this run targets a lab/CTF environment you control "
                                 "(required unless --authorized-target or --enforce-scope is used)")

    return parser


def enforce_scope_gate(args: argparse.Namespace) -> "ScopeAuthorization | None":
    """Enforce E1 scope/approval checks when explicitly enabled.

    Returns the parsed ScopeAuthorization (so it can be propagated into the
    module's Runner and re-checked at every command execution, not just
    here), or None when --enforce-scope was not requested.
    """
    if not getattr(args, "enforce_scope", False):
        return None
    if getattr(args, "dry_run", False):
        return None

    if not getattr(args, "scope_file", ""):
        raise ValueError("--enforce-scope requires --scope-file")
    if not getattr(args, "approval_id", ""):
        raise ValueError("--enforce-scope requires --approval-id")

    auth = ScopeAuthorization.from_file(args.scope_file)
    auth.assert_authorized(target=args.target, provided_approval_id=args.approval_id)
    return auth


def require_authorization(args: argparse.Namespace, scope: "ScopeAuthorization | None") -> None:
    """Refuse to run active modules without an explicit authorization signal.

    At least one of the following must be present before any non-dry-run
    execution: a successfully validated ``--enforce-scope`` (scope file +
    approval), an explicit ``--authorized-target`` acknowledgement, or an
    explicit ``--lab-mode`` acknowledgement. This closes the gap where a
    user could run active scans against an arbitrary target with zero
    acknowledgement of authorization.
    """
    if getattr(args, "dry_run", False):
        return
    if scope is not None:
        return
    if getattr(args, "authorized_target", False) or getattr(args, "lab_mode", False):
        return

    raise ValueError(
        "Authorization required before active execution: pass "
        "--authorized-target (you are authorized to test this target), "
        "--lab-mode (this is a lab/CTF environment you control), or "
        "--enforce-scope with --scope-file/--approval-id. Use --dry-run to "
        "preview without this acknowledgement."
    )


def main():
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.module:
        parser.print_help()
        sys.exit(1)
    try:
        scope = enforce_scope_gate(args)
        require_authorization(args, scope)
    except ValueError as e:
        parser.error(str(e))

    try:
        _dispatch(args, parser, scope=scope)
    except ReconForgeError as e:
        parser.error(str(e))


def _dispatch(args, parser, scope: "ScopeAuthorization | None" = None) -> None:
    """Run the module selected by ``args.module``. Exits the process on completion."""
    approval_id = getattr(args, "approval_id", None)
    if args.module == "network":
        from modules.network.network_module import NetworkModule

        phases = args.phases.split(",") if args.phases else None

        module = NetworkModule(
            target=args.target,
            output_base=args.output,
            opsec_mode=args.opsec,
            verbose=args.verbose,
            dry_run=args.dry_run,
            timeout=args.timeout,
            encrypt_loot=args.encrypt_loot,
            scope=scope,
            approval_id=approval_id,
        )

        results = module.run(
            phases=phases,
            brute_force=args.brute_force,
        )

        sys.exit(0 if results.get("phases") else 1)

    elif args.module == "ad":
        from modules.ad.ad_module import ADModule

        phases = args.phases.split(",") if args.phases else None

        module = ADModule(
            target=args.target,
            domain=args.domain,
            output_base=args.output,
            opsec_mode=args.opsec,
            verbose=args.verbose,
            dry_run=args.dry_run,
            timeout=args.timeout,
            username=args.username,
            password=args.password,
            dc_ip=args.dc_ip,
            encrypt_loot=args.encrypt_loot,
            scope=scope,
            approval_id=approval_id,
        )

        results = module.run(phases=phases)

        sys.exit(0 if results.get("phases") else 1)

    elif args.module == "web":
        from modules.web.web_module import WebModule

        phases = args.phases.split(",") if args.phases else None

        module = WebModule(
            target=args.target,
            output_base=args.output,
            opsec_mode=args.opsec,
            verbose=args.verbose,
            dry_run=args.dry_run,
            timeout=args.timeout,
            encrypt_loot=args.encrypt_loot,
            scope=scope,
            approval_id=approval_id,
        )

        results = module.run(
            phases=phases,
            opt_in="exploit" in phases if phases else False,
        )

        if results.get("success"):
            print("[+] Web reconnaissance completed successfully")
        else:
            print("[-] Web reconnaissance failed")

        sys.exit(0 if results.get("success") else 1)

    elif args.module == "api":
        from modules.api.api_module import APIModule

        phases = args.phases.split(",") if args.phases else None

        module = APIModule(
            target=args.target,
            output_base=args.output,
            opsec_mode=args.opsec,
            verbose=args.verbose,
            dry_run=args.dry_run,
            timeout=args.timeout,
            encrypt_loot=args.encrypt_loot,
            headers=args.headers,
            auth_token=args.auth_token,
            scope=scope,
            approval_id=approval_id,
        )

        results = module.run(
            phases=phases,
            opt_in="authorization" in phases if phases else False,
        )

        if results.get("success"):
            print("[+] API reconnaissance completed successfully")
        else:
            print("[-] API reconnaissance failed")

        sys.exit(0 if results.get("success") else 1)

    elif args.module == "workflow":
        from core.workflow_orchestrator import WorkflowOrchestrator
        from core.engagement import EngagementManager
        from core.credential_vault import CredentialVault

        # Resume or create engagement
        if args.resume:
            engagement = EngagementManager.load(args.resume)
        else:
            engagement = EngagementManager(
                name=args.engagement or f"Recon {args.target}",
                client=args.client,
                operator=args.operator,
                scope=[args.target],
            )

        vault = CredentialVault(encrypt=args.encrypt_loot)

        if args.modules:
            wf = WorkflowOrchestrator.targeted(
                targets=[args.target],
                modules=args.modules.split(","),
                opsec_mode=args.opsec,
                output_base=args.output,
                verbose=args.verbose,
                dry_run=args.dry_run,
                timeout=args.timeout,
                encrypt_loot=args.encrypt_loot,
                auto_handoff=args.auto_handoff,
                max_handoff_steps=args.max_handoff_steps,
                credential_vault=vault,
                engagement=engagement,
                scope=scope,
                approval_id=approval_id,
            )
        else:
            wf = WorkflowOrchestrator.full_recon(
                targets=[args.target],
                opsec_mode=args.opsec,
                output_base=args.output,
                verbose=args.verbose,
                dry_run=args.dry_run,
                timeout=args.timeout,
                encrypt_loot=args.encrypt_loot,
                auto_handoff=args.auto_handoff,
                max_handoff_steps=args.max_handoff_steps,
                credential_vault=vault,
                engagement=engagement,
                scope=scope,
                approval_id=approval_id,
            )

        summary = wf.run()
        sys.exit(0 if summary.get("steps_success", 0) > 0 else 1)

    elif args.module == "surface":
        from modules.surface.surface_module import SurfaceModule

        phases = args.phases.split(",") if args.phases else None

        module = SurfaceModule(
            target=args.target,
            output_base=args.output,
            opsec_mode=args.opsec,
            verbose=args.verbose,
            dry_run=args.dry_run,
            timeout=args.timeout,
            encrypt_loot=args.encrypt_loot,
        )

        results = module.run(phases=phases)
        sys.exit(0 if results.get("phases") else 1)

    elif args.module == "burp":
        if args.burp_command == "validate":
            from reconforge.burp.validate import main as burp_validate_main

            cli_args = []
            if args.url:
                cli_args.extend(["--url", args.url])
            if args.rpc_timeout is not None:
                cli_args.extend(["--rpc-timeout", str(args.rpc_timeout)])
            if args.connect_timeout is not None:
                cli_args.extend(["--connect-timeout", str(args.connect_timeout)])
            if args.debug:
                cli_args.append("--debug")
            if args.json:
                cli_args.append("--json")
            if args.output:
                cli_args.extend(["--output", args.output])
            if args.verbose:
                cli_args.append("--verbose")
            sys.exit(burp_validate_main(cli_args))

        if args.burp_command == "lifecycle-validate":
            from reconforge.burp.web_validate import main as burp_web_validate_main

            cli_args = ["--target-url", args.target_url, "--mcp-url", args.mcp_url]
            for domain in args.allow_domain:
                cli_args.extend(["--allow-domain", domain])
            for domain in args.deny_domain:
                cli_args.extend(["--deny-domain", domain])
            if args.no_subdomains:
                cli_args.append("--no-subdomains")
            if args.json:
                cli_args.append("--json")
            if args.output:
                cli_args.extend(["--output", args.output])
            if args.verbose:
                cli_args.append("--verbose")
            sys.exit(burp_web_validate_main(cli_args))

        if args.burp_command == "intelligence-validate":
            from reconforge.burp.intelligence import main as burp_intelligence_main

            cli_args = ["--mcp-url", args.mcp_url]
            for endpoint in args.endpoint:
                cli_args.extend(["--endpoint", endpoint])
            for domain in args.allow_domain:
                cli_args.extend(["--allow-domain", domain])
            for domain in args.deny_domain:
                cli_args.extend(["--deny-domain", domain])
            if args.no_subdomains:
                cli_args.append("--no-subdomains")
            if args.json:
                cli_args.append("--json")
            if args.output:
                cli_args.extend(["--output", args.output])
            if args.verbose:
                cli_args.append("--verbose")
            sys.exit(burp_intelligence_main(cli_args))

        if args.burp_command == "attack-paths":
            from reconforge.burp.attack_paths import main as burp_attack_paths_main

            cli_args = ["--mcp-url", args.mcp_url, "--refinement-rounds", str(args.refinement_rounds)]
            for endpoint in args.endpoint:
                cli_args.extend(["--endpoint", endpoint])
            for domain in args.allow_domain:
                cli_args.extend(["--allow-domain", domain])
            for domain in args.deny_domain:
                cli_args.extend(["--deny-domain", domain])
            if args.no_subdomains:
                cli_args.append("--no-subdomains")
            if args.json:
                cli_args.append("--json")
            if args.output:
                cli_args.extend(["--output", args.output])
            if args.verbose:
                cli_args.append("--verbose")
            sys.exit(burp_attack_paths_main(cli_args))

        parser.error("burp requires a supported subcommand (validate, lifecycle-validate, intelligence-validate, attack-paths)")

    else:
        print(f"Unknown module: {args.module}")
        sys.exit(1)


if __name__ == "__main__":
    main()
