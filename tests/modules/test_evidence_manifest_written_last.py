"""Phase 15: same evidence-manifest-ordering bug as network_module.py,
confirmed and fixed in web/api/surface_module.py too (ad_module.py already
had the correct order). Rather than duplicate network_module's full
functional test 3x, this locks in the call order at the source level —
proportionate given the fix is the identical one-line reordering in each
file, already proven correct end-to-end for network_module.py.
"""

import inspect

from modules.ad.ad_module import ADModule
from modules.api.api_module import APIModule
from modules.network.network_module import NetworkModule
from modules.surface.surface_module import SurfaceModule
from modules.web.web_module import WebModule


def _manifest_call_is_after_quick_report(module_cls, generate_reports_name="_generate_reports"):
    source = inspect.getsource(getattr(module_cls, generate_reports_name))
    manifest_idx = source.index("write_evidence_manifest(")
    quick_report_idx = source.index("_generate_quick_report(")
    return manifest_idx > quick_report_idx


def test_network_module_writes_manifest_after_quick_report():
    assert _manifest_call_is_after_quick_report(NetworkModule)


def test_web_module_writes_manifest_after_quick_report():
    assert _manifest_call_is_after_quick_report(WebModule)


def test_api_module_writes_manifest_after_quick_report():
    assert _manifest_call_is_after_quick_report(APIModule)


def test_surface_module_writes_manifest_after_quick_report():
    assert _manifest_call_is_after_quick_report(SurfaceModule)


def test_ad_module_manifest_is_the_last_report_write():
    """ad_module.py doesn't call a separate _generate_quick_report() --
    its report_file() write happens inline earlier in the same method, and
    write_evidence_manifest() was already correctly the last call. Confirm
    it appears after every other *_file( write in the method body."""
    source = inspect.getsource(ADModule._generate_reports)
    manifest_idx = source.index("write_evidence_manifest(")
    other_write_indices = [
        idx for idx in (
            source.find(marker) for marker in (
                "report_file(", "audit_file(", "contract_file(",
            )
        ) if idx != -1
    ]
    assert other_write_indices, "expected to find other report-write calls"
    assert manifest_idx > max(other_write_indices)
