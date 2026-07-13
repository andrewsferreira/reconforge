"""Phase 9-D/9-E: correlation_engine.py fixes.

9-D: HTTP correlation previously grouped services by scheme alone
("http"/"https"), ignoring port — two distinct HTTP services on
different ports of the same host were conflated into one
CorrelatedService. Fixed to key by port, while still merging into an
existing port-scan-detected entry for the same port when one exists.

9-E: ConfidenceScorer's multi_detection signal (len(detection_methods)
>= 2) could never fire for TCP/UDP services because
CorrelationEngine._ingest_entry() hardcoded detection_method="port_scan"
for every entry, discarding ServiceDeduplicator's richer
"_detection_methods" tagging on pre-merged entries. Fixed to prefer the
entry's own tagging when present.
"""

from modules.surface.intelligence.correlation_engine import CorrelationEngine
from modules.surface.intelligence.deduplicator import ServiceDeduplicator


def test_distinct_http_ports_are_not_merged():
    engine = CorrelationEngine()
    http_services = [
        {"url": "http://10.10.10.1/", "status_code": 200, "title": "Main Site",
         "technologies": ["Apache"], "web_server": "Apache"},
        {"url": "http://10.10.10.1:8080/", "status_code": 200, "title": "Admin Panel",
         "technologies": ["Tomcat"], "web_server": "Tomcat"},
    ]

    surface = engine.correlate("10.10.10.1", [], [], http_services)

    assert len(surface.services) == 2
    port_80_svc = next(s for s in surface.services.values() if 80 in s.ports)
    port_8080_svc = next(s for s in surface.services.values() if 8080 in s.ports)
    assert port_80_svc is not port_8080_svc
    assert "Apache" in port_80_svc.technologies
    assert "Tomcat" in port_8080_svc.technologies
    assert "Apache" not in port_8080_svc.technologies
    assert "Tomcat" not in port_80_svc.technologies


def test_http_probe_merges_into_existing_port_scan_entry():
    """A URL probe for a port already discovered by port/version scan
    must link into that SAME correlated entry, not create a disconnected
    duplicate — this is the legitimate correlation the engine exists to
    do, and must keep working after the port-aware HTTP grouping fix."""
    engine = CorrelationEngine()
    ports = [{"port": 80, "protocol": "tcp", "service": "http", "version": "", "product": ""}]
    http_services = [
        {"url": "http://10.10.10.1/", "status_code": 200, "title": "Main Site",
         "technologies": ["Apache"], "web_server": "Apache"},
    ]

    surface = engine.correlate("10.10.10.1", ports, [], http_services)

    assert "http" in surface.services
    http_svc = surface.services["http"]
    assert 80 in http_svc.ports
    assert "http://10.10.10.1/" in http_svc.urls
    assert len(surface.services) == 1


def test_https_default_port_443_used_when_url_has_no_explicit_port():
    engine = CorrelationEngine()
    http_services = [
        {"url": "https://10.10.10.1/", "status_code": 200, "title": "",
         "technologies": [], "web_server": ""},
    ]

    surface = engine.correlate("10.10.10.1", [], [], http_services)

    svc = next(iter(surface.services.values()))
    assert 443 in svc.ports
    assert svc.canonical_name == "https"


def test_multi_detection_signal_fires_for_deduplicated_tcp_service():
    """A service confirmed by both port_scan and version_scan (merged by
    ServiceDeduplicator) must retain both tags through correlation, so
    ConfidenceScorer's multi_detection signal can fire for TCP/UDP
    services, not just HTTP (previously the only detection method that
    could reach 2+ tags via the separate http_probe path)."""
    dedup = ServiceDeduplicator()
    engine = CorrelationEngine()

    ports = [{"port": 445, "protocol": "tcp", "service": "microsoft-ds", "version": "", "product": ""}]
    services = [{"port": 445, "service": "microsoft-ds", "version": "4.15.2", "product": "Samba"}]

    deduped = dedup.deduplicate_ports(ports, services)
    surface = engine.correlate("10.10.10.1", deduped, [], [])

    smb = surface.services["smb"]
    assert smb.detection_methods == {"port_scan", "version_scan"}
    assert len(smb.detection_methods) >= 2


def test_single_detection_method_service_not_falsely_multi_detected():
    dedup = ServiceDeduplicator()
    engine = CorrelationEngine()

    ports = [{"port": 22, "protocol": "tcp", "service": "ssh", "version": "", "product": ""}]

    deduped = dedup.deduplicate_ports(ports, [])
    surface = engine.correlate("10.10.10.1", deduped, [], [])

    ssh = surface.services["ssh"]
    assert ssh.detection_methods == {"port_scan"}
    assert len(ssh.detection_methods) < 2
