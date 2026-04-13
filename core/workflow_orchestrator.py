"""ReconForge Workflow Orchestrator - Cross-module workflow engine.

Author: Andrews Ferreira

Chains multiple modules together with automatic data passing, conditional
branching based on findings, and integration with CredentialVault and
EngagementManager.

Usage::

    wf = WorkflowOrchestrator(
        targets=["10.10.10.1"],
        opsec_mode="normal",
        output_base="outputs",
    )
    wf.add_step("network")
    wf.add_step("ad", condition=lambda ctx: ctx.has_service("ldap"))
    wf.add_step("web", condition=lambda ctx: ctx.has_service("http"))
    wf.add_step("api", condition=lambda ctx: ctx.has_service("http"))
    wf.run()
"""

import json
import shlex
import traceback
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from core.logger import ReconLogger
from core.credential_vault import CredentialVault
from core.engagement import EngagementManager
from core.findings_manager import FindingsManager
from core.loot_manager import LootManager
from core.attack_workflow import AttackWorkflow
from core.exceptions import (
    WorkflowError,
    WorkflowAbortedError,
    ModuleError,
)


# ── Workflow context (data bus between steps) ────────────────────────

class WorkflowContext:
    """Shared context passed between workflow steps.

    Modules deposit results here; conditions query it to decide
    whether to run a downstream step.
    """

    def __init__(self):
        self.targets: List[str] = []
        self.live_hosts: List[str] = []
        self.open_ports: Dict[str, List[int]] = {}  # host → [ports]
        self.services: Dict[str, Set[str]] = {}     # host → {service_names}
        self.domains: List[str] = []
        self.urls: List[str] = []
        self.module_results: Dict[str, Dict[str, Any]] = {}
        self.extra: Dict[str, Any] = {}

    # ── Convenience helpers for conditions ───────────────────────────

    def has_service(self, service: str) -> bool:
        """Check if *any* host exposes a given service name."""
        service = service.lower()
        for host_services in self.services.values():
            if service in {s.lower() for s in host_services}:
                return True
        return False

    def has_port(self, port: int) -> bool:
        """Check if *any* host has a given port open."""
        for ports in self.open_ports.values():
            if port in ports:
                return True
        return False

    def has_domain(self) -> bool:
        return bool(self.domains)

    def has_url(self) -> bool:
        return bool(self.urls)

    def host_count(self) -> int:
        return len(self.live_hosts) if self.live_hosts else len(self.targets)

    # ── Data population ──────────────────────────────────────────────

    def add_hosts(self, hosts: List[str]):
        """Register discovered live hosts."""
        for h in hosts:
            if h and h not in self.live_hosts:
                self.live_hosts.append(h)

    def add_ports(self, host: str, ports: List[int]):
        self.open_ports.setdefault(host, [])
        for p in ports:
            if p not in self.open_ports[host]:
                self.open_ports[host].append(p)

    def add_services(self, host: str, services: List[str]):
        self.services.setdefault(host, set())
        self.services[host].update(services)

    def add_domain(self, domain: str):
        if domain and domain not in self.domains:
            self.domains.append(domain)

    def add_url(self, url: str):
        if url and url not in self.urls:
            self.urls.append(url)

    def store_result(self, module: str, result: Dict[str, Any]):
        self.module_results[module] = result

    def to_dict(self) -> Dict[str, Any]:
        return {
            "targets": self.targets,
            "live_hosts": self.live_hosts,
            "open_ports": self.open_ports,
            "services": {h: sorted(s) for h, s in self.services.items()},
            "domains": self.domains,
            "urls": self.urls,
            "extra": self.extra,
        }


def _add_autonomous_step(ctx: WorkflowContext, command: str, reason: str, priority: str = "medium") -> None:
    """Store deduplicated autonomous next steps inferred from recon evidence."""
    steps = ctx.extra.setdefault("autonomous_next_steps", [])
    key = command.strip()
    for item in steps:
        if item.get("command") == key:
            return
    steps.append({
        "command": key,
        "reason": reason,
        "priority": priority,
    })


# ── Workflow step definition ─────────────────────────────────────────

@dataclass
class WorkflowStep:
    """Definition of a single step in the workflow pipeline."""
    module_name: str
    condition: Optional[Callable[[WorkflowContext], bool]] = None
    config: Dict[str, Any] = field(default_factory=dict)
    critical: bool = False   # If True, abort workflow on failure
    description: str = ""


# ── Result tracking ──────────────────────────────────────────────────

@dataclass
class StepResult:
    """Outcome of an executed workflow step."""
    module_name: str
    status: str = "pending"  # pending, skipped, success, failed
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0
    error: str = ""
    result_data: Dict[str, Any] = field(default_factory=dict)


# ── Service-to-port / port-to-service maps ───────────────────────────

_PORT_SERVICE_MAP: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios", 143: "imap", 389: "ldap",
    443: "https", 445: "smb", 464: "kpasswd", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5985: "winrm", 5986: "winrms", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9200: "elasticsearch",
    27017: "mongodb",
}

_SERVICE_PORT_MAP: Dict[str, List[int]] = {}
for _p, _s in _PORT_SERVICE_MAP.items():
    _SERVICE_PORT_MAP.setdefault(_s, []).append(_p)

# AD-indicator services
_AD_SERVICES = {"ldap", "ldaps", "kerberos", "smb", "msrpc"}

# Web-indicator services
_WEB_SERVICES = {"http", "https", "http-alt", "https-alt"}


# ── Context extractor ────────────────────────────────────────────────

def _extract_context_from_result(module_name: str, result: Dict[str, Any],
                                 ctx: WorkflowContext):
    """Parse a module result dict and populate the workflow context."""
    phases = result.get("phases", {})

    # Network module: discovery → live_hosts, scanning → ports/services
    if module_name == "network":
        disc = phases.get("discovery", {})
        live = disc.get("live_hosts", [])
        if live:
            ctx.add_hosts(live)

        scan = phases.get("scanning", {})
        hosts_data = scan.get("hosts", {})
        for host, host_info in hosts_data.items():
            if isinstance(host_info, dict):
                ports = host_info.get("open_ports", [])
                ctx.add_ports(host, ports)
                svcs = host_info.get("services", [])
                ctx.add_services(host, svcs)
                # Infer services from ports
                for p in ports:
                    svc = _PORT_SERVICE_MAP.get(p)
                    if svc:
                        ctx.add_services(host, [svc])

    # AD module
    elif module_name == "ad":
        domain = result.get("domain", "")
        if domain:
            ctx.add_domain(domain)

    # Web / API modules
    elif module_name in ("web", "api"):
        target = result.get("target", "")
        if target and target.startswith(("http://", "https://")):
            ctx.add_url(target)

    # Surface module: may find ports/services
    elif module_name == "surface":
        disc = phases.get("port_discovery", {})
        hosts_data = disc.get("hosts", {})
        for host, host_info in hosts_data.items():
            if isinstance(host_info, dict):
                ports = host_info.get("open_ports", [])
                ctx.add_ports(host, ports)
                for p in ports:
                    svc = _PORT_SERVICE_MAP.get(p)
                    if svc:
                        ctx.add_services(host, [svc])


def _derive_autonomous_next_steps(module_name: str, result: Dict[str, Any], ctx: WorkflowContext) -> None:
    """Infer post-recon commands from ports/services/banners/OS hints."""
    if module_name not in {"network", "surface"}:
        return

    phases = result.get("phases", {})
    host_views: Dict[str, Dict[str, Any]] = {}
    if module_name == "network":
        host_views = phases.get("scanning", {}).get("hosts", {})
    elif module_name == "surface":
        host_views = phases.get("port_discovery", {}).get("hosts", {})

    if not isinstance(host_views, dict):
        return

    for host, host_info in host_views.items():
        if not isinstance(host_info, dict):
            continue
        ports = host_info.get("open_ports", []) or []
        services = {str(s).lower() for s in host_info.get("services", []) if s}
        banner_blob = " ".join(str(p.get("service", "")) + " " + str(p.get("version", ""))
                               for p in ports if isinstance(p, dict)).lower()

        port_numbers = set()
        for p in ports:
            if isinstance(p, dict):
                if isinstance(p.get("port"), int):
                    port_numbers.add(p["port"])
                svc = p.get("service")
                if svc:
                    services.add(str(svc).lower())

        if 80 in port_numbers or 443 in port_numbers or {"http", "https"} & services:
            _add_autonomous_step(
                ctx,
                command=f"python reconforge.py web --target http://{host}",
                reason=f"HTTP surface detected on {host}; continue web attack-surface and vuln probing.",
                priority="high",
            )
        if 22 in port_numbers or "ssh" in services:
            _add_autonomous_step(
                ctx,
                command=f"nmap -sV -p22 --script ssh2-enum-algos,ssh-hostkey {host}",
                reason=f"SSH exposed on {host}; enumerate algorithms, host keys and hardening posture.",
                priority="medium",
            )
        if 445 in port_numbers or 139 in port_numbers or "smb" in banner_blob:
            _add_autonomous_step(
                ctx,
                command=f"python reconforge.py network --target {host} --phases service,auth --brute-force",
                reason=f"SMB/NetBIOS evidence on {host}; escalate to authenticated service checks.",
                priority="high",
            )
        if 3306 in port_numbers or "mysql" in services:
            _add_autonomous_step(
                ctx,
                command=f"nmap -sV -p3306 --script mysql-info,mysql-empty-password {host}",
                reason=f"MySQL detected on {host}; validate weak/default database exposure.",
                priority="medium",
            )
        if 5432 in port_numbers or "postgres" in banner_blob:
            _add_autonomous_step(
                ctx,
                command=f"nmap -sV -p5432 --script pgsql-brute {host}",
                reason=f"PostgreSQL detected on {host}; test authentication and service exposure.",
                priority="medium",
            )

        if "apache" in banner_blob:
            _add_autonomous_step(
                ctx,
                command=f"nmap -sV -p80,443 --script http-enum,http-server-header,http-vuln* {host}",
                reason=f"Apache banner fingerprint on {host}; expand HTTP vulnerability checks.",
                priority="high",
            )

    os_blob = json.dumps(phases, default=str).lower()
    if "linux" in os_blob:
        _add_autonomous_step(
            ctx,
            command="linpeas.sh (after obtaining shell access)",
            reason="Linux indicators detected; prepare post-exploitation privilege-escalation checks.",
            priority="medium",
        )
    if "windows" in os_blob:
        _add_autonomous_step(
            ctx,
            command="winPEAS.exe (after obtaining shell access)",
            reason="Windows indicators detected; prepare local privilege-escalation checks.",
            priority="medium",
        )


# ── Default conditions ───────────────────────────────────────────────

def condition_ad(ctx: WorkflowContext) -> bool:
    """Run AD module if any AD-related service is found."""
    return any(ctx.has_service(s) for s in _AD_SERVICES) or ctx.has_domain()


def condition_web(ctx: WorkflowContext) -> bool:
    """Run web module if any HTTP service is found."""
    return any(ctx.has_service(s) for s in _WEB_SERVICES) or ctx.has_url()


def condition_api(ctx: WorkflowContext) -> bool:
    """Run API module if HTTP service is found (same gate as web)."""
    return any(ctx.has_service(s) for s in _WEB_SERVICES) or ctx.has_url()


def condition_surface(ctx: WorkflowContext) -> bool:
    """Always run surface module if there are targets."""
    return ctx.host_count() > 0


# ── Module runner factory ────────────────────────────────────────────

def _run_module(module_name: str, target: str, *,
                opsec_mode: str = "normal",
                output_base: str = "outputs",
                verbose: bool = False,
                dry_run: bool = False,
                timeout: int = 600,
                encrypt_loot: bool = False,
                credential_vault: Optional[CredentialVault] = None,
                extra_config: Optional[Dict[str, Any]] = None,
                ) -> Dict[str, Any]:
    """Dynamically import and run a ReconForge module.

    Returns the module result dict.
    """
    extra = extra_config or {}

    if module_name == "network":
        from modules.network.network_module import NetworkModule
        mod = NetworkModule(
            target=target, output_base=output_base,
            opsec_mode=opsec_mode, verbose=verbose,
            dry_run=dry_run, timeout=timeout,
            encrypt_loot=encrypt_loot,
        )
        if credential_vault:
            _inject_creds_network(mod, credential_vault)
        result = mod.run(
            phases=extra.get("phases"),
            brute_force=extra.get("brute_force", False),
        )
        if credential_vault:
            credential_vault.ingest_from_loot(mod.loot)
        return result

    elif module_name == "ad":
        from modules.ad.ad_module import ADModule
        mod = ADModule(
            target=target, output_base=output_base,
            opsec_mode=opsec_mode, verbose=verbose,
            dry_run=dry_run, timeout=timeout,
            domain=extra.get("domain", ""),
            username=extra.get("username", ""),
            password=extra.get("password", ""),
            dc_ip=extra.get("dc_ip", ""),
            encrypt_loot=encrypt_loot,
        )
        if credential_vault:
            _inject_creds_ad(mod, credential_vault)
        result = mod.run(phases=extra.get("phases"))
        if credential_vault:
            credential_vault.ingest_from_loot(mod.loot)
        return result

    elif module_name == "web":
        from modules.web.web_module import WebModule
        mod = WebModule(
            target=target, output_base=output_base,
            opsec_mode=opsec_mode, verbose=verbose,
            dry_run=dry_run, timeout=timeout,
            encrypt_loot=encrypt_loot,
        )
        if credential_vault:
            _inject_creds_web(mod, credential_vault)
        phases = extra.get("phases")
        result = mod.run(
            phases=phases,
            opt_in="exploit" in phases if phases else False,
        )
        if credential_vault:
            credential_vault.ingest_from_loot(mod.loot)
        return result

    elif module_name == "api":
        from modules.api.api_module import APIModule
        mod = APIModule(
            target=target, output_base=output_base,
            opsec_mode=opsec_mode, verbose=verbose,
            dry_run=dry_run, timeout=timeout,
            encrypt_loot=encrypt_loot,
            headers=extra.get("headers", []),
            auth_token=extra.get("auth_token", ""),
        )
        if credential_vault:
            _inject_creds_api(mod, credential_vault)
        phases = extra.get("phases")
        result = mod.run(
            phases=phases,
            opt_in="authorization" in phases if phases else False,
        )
        if credential_vault:
            credential_vault.ingest_from_loot(mod.loot)
        return result

    elif module_name == "surface":
        from modules.surface.surface_module import SurfaceModule
        mod = SurfaceModule(
            target=target, output_base=output_base,
            opsec_mode=opsec_mode, verbose=verbose,
            dry_run=dry_run, timeout=timeout,
        )
        result = mod.run(phases=extra.get("phases"))
        if credential_vault:
            credential_vault.ingest_from_loot(mod.loot)
        return result

    else:
        raise WorkflowError(f"Unknown module: {module_name}")


# ── Credential injection helpers ─────────────────────────────────────

def _inject_creds_network(mod, vault: CredentialVault):
    """Inject vault credentials into a NetworkModule before execution."""
    for cred in vault.get_passwords():
        mod.loot.add_credential(
            cred.username, cred.secret, f"vault:{cred.source}",
            "network", service=cred.service,
        )


def _inject_creds_ad(mod, vault: CredentialVault):
    """Inject vault credentials into an ADModule."""
    # If the module has no username set, try the first available password
    if not getattr(mod, "username", ""):
        passwords = vault.get_passwords()
        if passwords:
            best = passwords[0]
            mod.username = best.username
            mod.password = best.secret


def _inject_creds_web(mod, vault: CredentialVault):
    """Inject vault credentials into a WebModule."""
    for cred in vault.get_for_service("http"):
        mod.loot.add_credential(
            cred.username, cred.secret, f"vault:{cred.source}",
            "web", service="http",
        )


def _inject_creds_api(mod, vault: CredentialVault):
    """Inject vault credentials into an APIModule."""
    tokens = vault.get_tokens()
    if tokens and hasattr(mod, "auth_token") and not mod.auth_token:
        mod.auth_token = tokens[0].secret
    for cred in vault.get_by_type("api_key"):
        mod.loot.add(
            "api_key", cred.secret, f"vault:{cred.source}", "api",
        )


# ── Main orchestrator ────────────────────────────────────────────────

class WorkflowOrchestrator:
    """Chain multiple modules with automatic data passing and conditional logic.

    Args:
        targets: List of target strings.
        opsec_mode: OPSEC mode for all modules.
        output_base: Root output directory.
        verbose: Enable verbose logging.
        dry_run: Dry-run mode.
        timeout: Default timeout per command.
        encrypt_loot: Encrypt loot files.
        credential_vault: Shared CredentialVault (created if not given).
        engagement: Shared EngagementManager (created if not given).
    """

    def __init__(
        self,
        targets: Optional[List[str]] = None,
        opsec_mode: str = "normal",
        output_base: str = "outputs",
        verbose: bool = False,
        dry_run: bool = False,
        timeout: int = 600,
        encrypt_loot: bool = False,
        auto_handoff: bool = False,
        max_handoff_steps: int = 5,
        credential_vault: Optional[CredentialVault] = None,
        engagement: Optional[EngagementManager] = None,
    ):
        self.targets = targets or []
        self.opsec_mode = opsec_mode
        self.output_base = output_base
        self.verbose = verbose
        self.dry_run = dry_run
        self.timeout = timeout
        self.encrypt_loot = encrypt_loot
        self.auto_handoff = auto_handoff
        self.max_handoff_steps = max_handoff_steps

        self.logger = ReconLogger(name="workflow", verbose=verbose)
        self.vault = credential_vault or CredentialVault(encrypt=encrypt_loot)
        self.engagement = engagement or EngagementManager(
            operator="Andrews Ferreira",
        )

        # Aggregated managers
        self.findings = FindingsManager()
        self.loot = LootManager(encrypt=encrypt_loot)
        self.workflow = AttackWorkflow()

        # Pipeline
        self._steps: List[WorkflowStep] = []
        self._results: List[StepResult] = []
        self._handoff_keys: Set[tuple[str, str]] = set()
        self._context = WorkflowContext()
        self._context.targets = list(self.targets)

    # ── Step management ──────────────────────────────────────────────

    def add_step(self, module_name: str, *,
                 condition: Optional[Callable[[WorkflowContext], bool]] = None,
                 config: Optional[Dict[str, Any]] = None,
                 critical: bool = False,
                 description: str = "") -> "WorkflowOrchestrator":
        """Add a step to the workflow pipeline.

        Returns self for chaining.
        """
        self._steps.append(WorkflowStep(
            module_name=module_name,
            condition=condition,
            config=config or {},
            critical=critical,
            description=description or f"Run {module_name} module",
        ))
        return self

    def add_full_recon(self) -> "WorkflowOrchestrator":
        """Add the standard full-recon pipeline.

        Order: surface → network → ad (conditional) → web (conditional)
               → api (conditional)
        """
        self.add_step("surface", condition=condition_surface,
                       description="Attack surface mapping")
        self.add_step("network", description="Network reconnaissance")
        self.add_step("ad", condition=condition_ad,
                       description="Active Directory reconnaissance")
        self.add_step("web", condition=condition_web,
                       description="Web application reconnaissance")
        self.add_step("api", condition=condition_api,
                       description="API security assessment")
        return self

    def clear_steps(self):
        """Remove all steps from the pipeline."""
        self._steps.clear()

    @property
    def context(self) -> WorkflowContext:
        return self._context

    @property
    def results(self) -> List[StepResult]:
        return list(self._results)

    # ── Execution ────────────────────────────────────────────────────

    def run(self) -> Dict[str, Any]:
        """Execute the workflow pipeline sequentially.

        Returns a summary dict with results from all steps.
        """
        if not self._steps:
            raise WorkflowError("No steps defined in the workflow")

        if not self.targets:
            raise WorkflowError("No targets defined")

        self.logger.info(f"{'=' * 60}")
        self.logger.info("ReconForge Workflow Orchestrator")
        self.logger.info(f"Targets: {', '.join(self.targets)}")
        self.logger.info(f"OPSEC Mode: {self.opsec_mode}")
        self.logger.info(f"Steps: {len(self._steps)}")
        self.logger.info(f"{'=' * 60}")

        # Start engagement
        if self.engagement.status == "planning":
            self.engagement.meta.scope = list(self.targets)
            self.engagement.start()

        start_time = datetime.now()
        aborted = False

        for i, step in enumerate(self._steps, 1):
            self.logger.info(f"\n--- Step {i}/{len(self._steps)}: "
                             f"{step.description} ({step.module_name}) ---")

            step_result = StepResult(module_name=step.module_name)

            # Evaluate condition
            if step.condition is not None:
                try:
                    should_run = step.condition(self._context)
                except Exception as exc:
                    self.logger.warning(
                        f"Condition evaluation failed for {step.module_name}: {exc}"
                    )
                    should_run = False

                if not should_run:
                    self.logger.info(
                        f"Skipping {step.module_name} — condition not met"
                    )
                    step_result.status = "skipped"
                    self._results.append(step_result)
                    self.engagement.record_action(
                        step.module_name, "step_skipped",
                        detail="Condition not met",
                    )
                    continue

            # Determine target for this step
            target = self._pick_target(step)
            step_result.start_time = datetime.now().isoformat()

            try:
                self.engagement.record_action(
                    step.module_name, "step_started",
                    detail=f"Target: {target}",
                )

                result = _run_module(
                    step.module_name, target,
                    opsec_mode=self.opsec_mode,
                    output_base=self.output_base,
                    verbose=self.verbose,
                    dry_run=self.dry_run,
                    timeout=self.timeout,
                    encrypt_loot=self.encrypt_loot,
                    credential_vault=self.vault,
                    extra_config=step.config,
                )

                # Extract context for downstream steps
                _extract_context_from_result(step.module_name, result,
                                            self._context)
                _derive_autonomous_next_steps(step.module_name, result, self._context)
                self._enqueue_handoff_steps()
                self._context.store_result(step.module_name, result)

                step_result.status = "success"
                step_result.result_data = result
                self.engagement.record_module_result(step.module_name, result)

                self.logger.info(
                    f"Step {i} ({step.module_name}) completed successfully"
                )

            except KeyboardInterrupt:
                self.logger.warning("Workflow interrupted by user")
                step_result.status = "failed"
                step_result.error = "Interrupted by user"
                self._results.append(step_result)
                aborted = True
                break

            except Exception as exc:
                self.logger.error(
                    f"Step {i} ({step.module_name}) failed: {exc}"
                )
                step_result.status = "failed"
                step_result.error = str(exc)

                if step.critical:
                    self.logger.error(
                        "Critical step failed — aborting workflow"
                    )
                    self._results.append(step_result)
                    aborted = True
                    break

            finally:
                step_result.end_time = datetime.now().isoformat()
                if step_result.start_time:
                    try:
                        t0 = datetime.fromisoformat(step_result.start_time)
                        t1 = datetime.fromisoformat(step_result.end_time)
                        step_result.duration_seconds = (t1 - t0).total_seconds()
                    except Exception:
                        pass

            self._results.append(step_result)

        # ── Post-run ─────────────────────────────────────────────────

        end_time = datetime.now()
        total_duration = (end_time - start_time).total_seconds()

        if not aborted:
            self.engagement.complete()

        # Generate summary
        summary = self._build_summary(total_duration, aborted)

        # Save workflow report
        self._save_workflow_report(summary)

        self.logger.info(f"\n{'=' * 60}")
        self.logger.info("WORKFLOW COMPLETE")
        self.logger.info(
            f"Steps: {summary['steps_success']}/{summary['steps_total']} succeeded, "
            f"{summary['steps_skipped']} skipped, "
            f"{summary['steps_failed']} failed"
        )
        self.logger.info(f"Duration: {total_duration:.1f}s")
        self.logger.info(f"Credentials in vault: {len(self.vault)}")
        self.logger.info(f"{'=' * 60}")

        return summary

    # ── Target selection ─────────────────────────────────────────────

    def _pick_target(self, step: WorkflowStep) -> str:
        """Choose the best target string for a workflow step."""
        cfg = step.config

        # Explicit target in step config
        if cfg.get("target"):
            return cfg["target"]

        module = step.module_name

        # AD: prefer DC IP from context
        if module == "ad":
            if self._context.live_hosts:
                return self._context.live_hosts[0]

        # Web / API: prefer discovered URL
        if module in ("web", "api"):
            if self._context.urls:
                return self._context.urls[0]
            # Build URL from host + http port
            for host in (self._context.live_hosts or self.targets):
                ports = self._context.open_ports.get(host, [])
                if 443 in ports:
                    return f"https://{host}"
                if 80 in ports or 8080 in ports:
                    return f"http://{host}"

        # Default: first target
        return self.targets[0] if self.targets else ""

    # ── Summary / report ─────────────────────────────────────────────

    def _build_summary(self, duration: float, aborted: bool) -> Dict[str, Any]:
        success = sum(1 for r in self._results if r.status == "success")
        skipped = sum(1 for r in self._results if r.status == "skipped")
        failed = sum(1 for r in self._results if r.status == "failed")

        return {
            "workflow": "complete" if not aborted else "aborted",
            "targets": self.targets,
            "opsec_mode": self.opsec_mode,
            "steps_total": len(self._results),
            "steps_success": success,
            "steps_skipped": skipped,
            "steps_failed": failed,
            "duration_seconds": duration,
            "auto_handoff": self.auto_handoff,
            "credentials_count": len(self.vault),
            "context": self._context.to_dict(),
            "steps": [asdict(r) for r in self._results],
            "engagement_id": self.engagement.meta.id,
        }

    def _enqueue_handoff_steps(self) -> None:
        """Optionally convert autonomous suggestions into executable workflow steps."""
        if not self.auto_handoff:
            return
        suggestions = self._context.extra.get("autonomous_next_steps", [])
        if not isinstance(suggestions, list):
            return

        queued = 0
        for suggestion in suggestions:
            if queued >= self.max_handoff_steps:
                break
            if not isinstance(suggestion, dict):
                continue
            command = str(suggestion.get("command", "")).strip()
            if not command.startswith("python reconforge.py "):
                continue

            tokens = shlex.split(command)
            if len(tokens) < 4:
                continue
            module_name = tokens[2]
            if module_name not in {"surface", "network", "web", "api"}:
                continue

            target = None
            if "--target" in tokens:
                idx = tokens.index("--target")
                if idx + 1 < len(tokens):
                    target = tokens[idx + 1]
            if not target:
                continue

            key = (module_name, target)
            if key in self._handoff_keys:
                continue
            if any(s.module_name == module_name and s.config.get("target") == target for s in self._steps):
                self._handoff_keys.add(key)
                continue

            self._steps.append(WorkflowStep(
                module_name=module_name,
                config={"target": target},
                critical=False,
                description=f"Auto-handoff from recon intelligence ({module_name})",
            ))
            self._handoff_keys.add(key)
            queued += 1
            self.logger.info(f"Auto-handoff queued: {module_name} -> {target}")

    def _save_workflow_report(self, summary: Dict[str, Any]):
        """Save a JSON workflow report."""
        out_dir = Path(self.output_base) / "workflow"
        out_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = out_dir / f"workflow_{ts}.json"
        report_path.write_text(json.dumps(summary, indent=2, default=str))

        # Save engagement
        eng_path = out_dir / f"engagement_{ts}.json"
        self.engagement.save(eng_path)

        # Save credential vault
        vault_path = out_dir / f"vault_{ts}.json"
        self.vault.save(vault_path)

        self.logger.info(f"Workflow report saved to: {report_path}")

    # ── Convenience class methods ────────────────────────────────────

    @classmethod
    def full_recon(cls, targets: List[str], **kwargs) -> "WorkflowOrchestrator":
        """Create a pre-configured full-recon workflow.

        Usage::

            wf = WorkflowOrchestrator.full_recon(["10.10.10.1"])
            wf.run()
        """
        wf = cls(targets=targets, **kwargs)
        wf.add_full_recon()
        return wf

    @classmethod
    def targeted(cls, targets: List[str], modules: List[str],
                 **kwargs) -> "WorkflowOrchestrator":
        """Create a workflow with specific modules (no conditions).

        Usage::

            wf = WorkflowOrchestrator.targeted(
                ["10.10.10.1"], ["network", "ad"]
            )
            wf.run()
        """
        wf = cls(targets=targets, **kwargs)
        for mod in modules:
            wf.add_step(mod)
        return wf

    def __repr__(self) -> str:
        return (
            f"<WorkflowOrchestrator targets={self.targets} "
            f"steps={len(self._steps)} opsec={self.opsec_mode}>"
        )
