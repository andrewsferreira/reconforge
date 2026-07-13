"""Tests for core.workflow_orchestrator – WorkflowOrchestrator & WorkflowContext."""

import json
from unittest.mock import MagicMock, patch

import pytest

from core.workflow_orchestrator import (
    WorkflowOrchestrator,
    WorkflowContext,
    _derive_autonomous_next_steps,
)
from core.exceptions import WorkflowError


# ── WorkflowContext ─────────────────────────────────────────────

def test_context_set_and_get():
    ctx = WorkflowContext()
    ctx.extra["key"] = "value"
    assert ctx.extra["key"] == "value"


def test_context_add_hosts():
    ctx = WorkflowContext()
    ctx.add_hosts(["10.0.0.1", "10.0.0.2"])
    assert len(ctx.live_hosts) == 2


def test_context_add_hosts_dedup():
    ctx = WorkflowContext()
    ctx.add_hosts(["10.0.0.1"])
    ctx.add_hosts(["10.0.0.1", "10.0.0.2"])
    assert len(ctx.live_hosts) == 2


def test_context_add_ports():
    ctx = WorkflowContext()
    ctx.add_ports("10.0.0.1", [80, 443])
    assert ctx.has_port(80)
    assert ctx.has_port(443)


def test_context_add_services():
    ctx = WorkflowContext()
    ctx.add_services("10.0.0.1", ["http", "ldap"])
    assert ctx.has_service("http")
    assert ctx.has_service("LDAP")  # case-insensitive


def test_context_add_domain():
    ctx = WorkflowContext()
    ctx.add_domain("corp.local")
    assert ctx.has_domain()
    assert "corp.local" in ctx.domains


def test_context_add_url():
    ctx = WorkflowContext()
    ctx.add_url("https://app.corp.local")
    assert ctx.has_url()


def test_context_store_result():
    ctx = WorkflowContext()
    ctx.store_result("network", {"phases": {}})
    assert "network" in ctx.module_results


def test_context_to_dict():
    ctx = WorkflowContext()
    ctx.targets = ["10.0.0.1"]
    ctx.add_hosts(["10.0.0.1"])
    d = ctx.to_dict()
    assert d["targets"] == ["10.0.0.1"]
    assert d["live_hosts"] == ["10.0.0.1"]


def test_context_host_count():
    ctx = WorkflowContext()
    ctx.targets = ["10.0.0.1"]
    assert ctx.host_count() == 1
    ctx.add_hosts(["10.0.0.1", "10.0.0.2"])
    assert ctx.host_count() == 2


# ── WorkflowOrchestrator ────────────────────────────────────────

def test_init():
    wo = WorkflowOrchestrator(targets=["10.0.0.1"], opsec_mode="normal")
    assert wo.context.targets == ["10.0.0.1"]


def test_add_step():
    wo = WorkflowOrchestrator(targets=["10.0.0.1"])
    wo.add_step("network", description="Network recon")
    assert len(wo._steps) == 1
    assert wo._steps[0].module_name == "network"


def test_add_step_returns_self():
    wo = WorkflowOrchestrator(targets=["10.0.0.1"])
    result = wo.add_step("network")
    assert result is wo  # chainable


def test_add_step_with_condition():
    wo = WorkflowOrchestrator(targets=["10.0.0.1"])
    cond = lambda ctx: True
    wo.add_step("ad", condition=cond)
    assert wo._steps[0].condition is cond


def test_add_multiple_steps():
    wo = WorkflowOrchestrator(targets=["10.0.0.1"])
    wo.add_step("network")
    wo.add_step("web")
    wo.add_step("ad")
    assert len(wo._steps) == 3


def test_add_full_recon():
    wo = WorkflowOrchestrator(targets=["10.0.0.1"])
    wo.add_full_recon()
    # Should have steps for: surface, network, ad, web, api
    assert len(wo._steps) >= 4


def test_clear_steps():
    wo = WorkflowOrchestrator(targets=["10.0.0.1"])
    wo.add_step("network")
    wo.add_step("web")
    wo.clear_steps()
    assert len(wo._steps) == 0


def test_full_recon_class_method():
    wo = WorkflowOrchestrator.full_recon(["10.0.0.1"], opsec_mode="stealth")
    assert wo.context.targets == ["10.0.0.1"]
    assert len(wo._steps) >= 2


def test_targeted_class_method():
    wo = WorkflowOrchestrator.targeted(["10.0.0.1"], modules=["network", "web"])
    assert len(wo._steps) == 2
    module_names = [s.module_name for s in wo._steps]
    assert "network" in module_names
    assert "web" in module_names


def test_context_property():
    wo = WorkflowOrchestrator(targets=["10.0.0.1"])
    wo.context.extra["found_dc"] = True
    assert wo.context.extra["found_dc"] is True


def test_credential_vault_exists():
    wo = WorkflowOrchestrator(targets=["10.0.0.1"])
    assert wo.vault is not None
    assert wo.vault.count() == 0


def test_engagement_exists_by_default():
    wo = WorkflowOrchestrator(targets=["10.0.0.1"])
    # Engagement is always created by default
    assert wo.engagement is not None


def test_custom_engagement():
    from core.engagement import EngagementManager
    eng = EngagementManager(client="Acme", operator="alice")
    wo = WorkflowOrchestrator(targets=["10.0.0.1"], engagement=eng)
    assert wo.engagement.meta.client == "Acme"


def test_run_fails_fast_on_completed_engagement():
    """Phase 13-C regression: run() previously called
    self.engagement.complete() unconditionally at the end of the step
    loop. Resuming an already-completed engagement (via CLI --resume)
    meant the whole workflow ran against the target before crashing at
    that unconditional complete() call — losing the entire run's results,
    since _save_workflow_report() never executed after the crash. Must
    fail fast before any step runs instead."""
    from core.engagement import EngagementManager
    eng = EngagementManager(client="Acme", operator="alice")
    eng.start()
    eng.complete()

    wo = WorkflowOrchestrator(targets=["10.0.0.1"], engagement=eng)
    wo.add_step("network")

    with patch("core.workflow_orchestrator._run_module") as mock_run_module:
        with pytest.raises(WorkflowError):
            wo.run()
        mock_run_module.assert_not_called()


def test_run_fails_fast_on_cancelled_engagement():
    from core.engagement import EngagementManager
    eng = EngagementManager(client="Acme", operator="alice")
    eng.start()
    eng.cancel()

    wo = WorkflowOrchestrator(targets=["10.0.0.1"], engagement=eng)
    wo.add_step("network")

    with pytest.raises(WorkflowError):
        wo.run()


def test_repr():
    wo = WorkflowOrchestrator(targets=["10.0.0.1"], opsec_mode="stealth")
    r = repr(wo)
    assert "WorkflowOrchestrator" in r
    assert "stealth" in r


def test_derive_autonomous_next_steps_from_network_recon():
    ctx = WorkflowContext()
    result = {
        "phases": {
            "scanning": {
                "hosts": {
                    "10.10.10.10": {
                        "open_ports": [
                            {"port": 80, "service": "http", "version": "Apache httpd 2.4"},
                            {"port": 22, "service": "ssh", "version": "OpenSSH 8.9"},
                        ],
                        "services": ["http", "ssh"],
                    }
                }
            },
            "service_enumeration": {"smb": {"os_info": "Linux 5.x"}},
        }
    }
    _derive_autonomous_next_steps("network", result, ctx)

    steps = ctx.extra.get("autonomous_next_steps", [])
    commands = {s["command"] for s in steps}
    assert "reconforge web --target http://10.10.10.10" in commands
    assert "nmap -sV -p22 --script ssh2-enum-algos,ssh-hostkey 10.10.10.10" in commands
    assert "linpeas.sh (after obtaining shell access)" in commands


def test_derive_autonomous_next_steps_deduplicates():
    ctx = WorkflowContext()
    result = {
        "phases": {
            "scanning": {
                "hosts": {
                    "10.10.10.20": {
                        "open_ports": [{"port": 80, "service": "http", "version": "Apache"}],
                        "services": ["http"],
                    }
                }
            }
        }
    }
    _derive_autonomous_next_steps("network", result, ctx)
    _derive_autonomous_next_steps("network", result, ctx)
    steps = ctx.extra.get("autonomous_next_steps", [])
    assert len(steps) == len({s["command"] for s in steps})


def test_enqueue_handoff_steps_adds_web_step_when_enabled():
    wo = WorkflowOrchestrator(targets=["10.0.0.1"], auto_handoff=True)
    wo.context.extra["autonomous_next_steps"] = [
        {
            "command": "reconforge web --target http://10.10.10.10",
            "reason": "http detected",
            "priority": "high",
        }
    ]
    wo._enqueue_handoff_steps()
    assert any(
        s.module_name == "web" and s.config.get("target") == "http://10.10.10.10"
        for s in wo._steps
    )


def test_enqueue_handoff_steps_ignores_when_disabled():
    wo = WorkflowOrchestrator(targets=["10.0.0.1"], auto_handoff=False)
    wo.context.extra["autonomous_next_steps"] = [
        {"command": "reconforge web --target http://10.10.10.10"}
    ]
    wo._enqueue_handoff_steps()
    assert wo._steps == []


def test_enqueue_handoff_steps_respects_max():
    wo = WorkflowOrchestrator(targets=["10.0.0.1"], auto_handoff=True, max_handoff_steps=1)
    wo.context.extra["autonomous_next_steps"] = [
        {"command": "reconforge web --target http://10.10.10.10"},
        {"command": "reconforge surface --target 10.10.10.0/24"},
    ]
    wo._enqueue_handoff_steps()
    assert len(wo._steps) == 1


def test_enqueue_ai_decisions_adds_web_when_http_detected():
    wo = WorkflowOrchestrator(targets=["10.0.0.1"])
    wo.ai_engine.ingest_nmap_scan({
        "10.10.10.40": {
            "open_ports": [{"port": 80, "service": "http", "version": "Apache"}]
        }
    })
    wo._enqueue_ai_decisions()
    assert any(step.module_name == "web" for step in wo._steps)
