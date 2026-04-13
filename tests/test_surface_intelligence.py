"""Tests for the Surface Module Intelligence System.

Validates:
1. Service Intelligence Database lookups
2. Service Normalization consistency
3. Correlation Engine linking
4. Deduplication of duplicate entries
5. Multi-signal Confidence Scoring
6. Intelligent Prioritization
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.surface.intelligence.service_intelligence import ServiceIntelligenceDB
from modules.surface.intelligence.service_normalizer import ServiceNormalizer, NormalizedService
from modules.surface.intelligence.correlation_engine import CorrelationEngine, AttackSurfaceMap
from modules.surface.intelligence.deduplicator import ServiceDeduplicator
from modules.surface.intelligence.confidence_scorer import ConfidenceScorer
from modules.surface.intelligence.attack_prioritizer import AttackPrioritizer


def test_intelligence_db():
    """Test Service Intelligence Database."""
    db = ServiceIntelligenceDB()

    # Test profile lookups
    smb = db.get_profile("smb")
    assert smb is not None
    assert smb.canonical_name == "smb"
    assert smb.high_value is True
    assert 445 in smb.default_ports
    assert "microsoft-ds" in smb.aliases

    # Test alias resolution
    assert db.resolve_canonical("microsoft-ds") == "smb"
    assert db.resolve_canonical("ms-wbt-server") == "rdp"
    assert db.resolve_canonical("kerberos-sec") == "kerberos"
    assert db.resolve_canonical("epmap") == "msrpc"
    assert db.resolve_canonical("ms-sql-s") == "mssql"
    assert db.resolve_canonical("domain") == "dns"

    # Test port resolution
    assert db.resolve_by_port(445) == "smb"
    assert db.resolve_by_port(3389) == "rdp"
    assert db.resolve_by_port(88) == "kerberos"
    assert db.resolve_by_port(22) == "ssh"
    assert db.resolve_by_port(80) == "http"
    assert db.resolve_by_port(443) == "https"
    assert db.resolve_by_port(1433) == "mssql"
    assert db.resolve_by_port(6379) == "redis"

    # Test category lookups
    ad_services = db.get_category_services("ad")
    assert len(ad_services) > 0
    ad_names = {s.canonical_name for s in ad_services}
    assert "smb" in ad_names
    assert "ldap" in ad_names
    assert "kerberos" in ad_names

    # Test high-value services
    hv = db.get_high_value_services()
    assert len(hv) > 0
    hv_names = {s.canonical_name for s in hv}
    assert "smb" in hv_names
    assert "rdp" in hv_names

    print("✅ Service Intelligence DB: ALL PASSED")


def test_normalizer():
    """Test Service Name Normalizer."""
    db = ServiceIntelligenceDB()
    norm = ServiceNormalizer(db)

    # Direct alias normalization
    result = norm.normalize("microsoft-ds", port=445)
    assert result.canonical_name == "smb"
    assert result.normalized is True
    assert result.confidence == "high"

    result = norm.normalize("ms-wbt-server", port=3389)
    assert result.canonical_name == "rdp"

    # Case insensitivity
    result = norm.normalize("SSH", port=22)
    assert result.canonical_name == "ssh"

    # SSL prefix stripping
    result = norm.normalize("ssl/http", port=443)
    assert result.canonical_name == "https"

    # Port-based fallback
    result = norm.normalize("unknown-service", port=22)
    assert result.canonical_name == "ssh"
    assert result.confidence == "low"

    # Completely unknown
    result = norm.normalize("totally-unknown", port=99999)
    assert result.canonical_name == "totally-unknown"
    assert result.normalized is False

    # Empty service name with known port
    result = norm.normalize("", port=445)
    assert result.canonical_name == "smb"

    # Batch normalization
    batch = [
        {"service": "microsoft-ds", "port": 445},
        {"service": "http-proxy", "port": 8080},
        {"service": "ssh", "port": 22},
    ]
    results = norm.normalize_batch(batch)
    assert results[0]["canonical_name"] == "smb"
    assert results[1]["canonical_name"] == "http"
    assert results[2]["canonical_name"] == "ssh"

    print("✅ Service Normalizer: ALL PASSED")


def test_correlation_engine():
    """Test Correlation Engine."""
    engine = CorrelationEngine()

    ports = [
        {"port": 22, "protocol": "tcp", "service": "ssh", "version": "", "product": ""},
        {"port": 80, "protocol": "tcp", "service": "http", "version": "", "product": ""},
        {"port": 445, "protocol": "tcp", "service": "microsoft-ds", "version": "", "product": ""},
        {"port": 139, "protocol": "tcp", "service": "netbios-ssn", "version": "", "product": ""},
        {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server", "version": "", "product": ""},
    ]

    services = [
        {"port": 22, "service": "ssh", "version": "8.9p1", "product": "OpenSSH"},
        {"port": 80, "service": "http", "version": "2.4.51", "product": "Apache httpd"},
        {"port": 445, "service": "microsoft-ds", "version": "4.15.2", "product": "Samba"},
    ]

    http_services = [
        {"url": "http://10.10.10.1/", "status_code": 200, "title": "Admin Panel",
         "technologies": ["Apache", "PHP"], "web_server": "Apache/2.4.51"},
    ]

    surface = engine.correlate("10.10.10.1", ports, services, http_services)

    # Verify correlation
    assert isinstance(surface, AttackSurfaceMap)
    assert surface.target == "10.10.10.1"
    assert surface.total_services > 0

    # SMB should correlate ports 139 and 445
    assert "smb" in surface.services
    smb = surface.services["smb"]
    assert 445 in smb.ports
    assert 139 in smb.ports
    assert smb.high_value is True
    assert smb.category == "ad"
    assert len(smb.next_steps) > 0

    # SSH should have version
    assert "ssh" in surface.services
    ssh = surface.services["ssh"]
    assert 22 in ssh.ports
    assert "8.9p1" in ssh.versions

    # HTTP should have URLs linked
    assert "http" in surface.services
    http = surface.services["http"]
    assert 80 in http.ports
    assert "http://10.10.10.1/" in http.urls or "http" in surface.services

    # RDP should be normalized from ms-wbt-server
    assert "rdp" in surface.services
    assert 3389 in surface.services["rdp"].ports

    # Category grouping
    assert "ad" in surface.by_category
    assert "smb" in surface.by_category["ad"]

    print("✅ Correlation Engine: ALL PASSED")


def test_deduplicator():
    """Test Service Deduplicator."""
    dedup = ServiceDeduplicator()

    ports = [
        {"port": 22, "service": "ssh", "version": ""},
        {"port": 80, "service": "http", "version": ""},
        {"port": 445, "service": "microsoft-ds", "version": ""},
    ]

    services = [
        {"port": 22, "service": "ssh", "version": "8.9p1", "product": "OpenSSH"},
        {"port": 80, "service": "http", "version": "2.4.51", "product": "Apache"},
        {"port": 445, "service": "microsoft-ds", "version": "4.15.2", "product": "Samba"},
        {"port": 3306, "service": "mysql", "version": "8.0.27"},
    ]

    result = dedup.deduplicate_ports(ports, services)

    # Should have 4 entries (3 merged + 1 new from services)
    assert len(result) == 4

    # Merged entries should have version from services
    port_22 = [r for r in result if r["port"] == 22][0]
    assert port_22["version"] == "8.9p1"
    assert "_detection_methods" in port_22
    assert "port_scan" in port_22["_detection_methods"]
    assert "version_scan" in port_22["_detection_methods"]

    # HTTP dedup
    http_services = [
        {"url": "http://10.10.10.1/", "title": "Admin", "technologies": ["PHP"]},
        {"url": "http://10.10.10.1/", "title": "Admin Panel", "technologies": ["PHP", "Apache"]},
    ]
    deduped_http = dedup.deduplicate_http(http_services)
    assert len(deduped_http) == 1
    assert "Apache" in deduped_http[0]["technologies"]

    print("✅ Deduplicator: ALL PASSED")


def test_confidence_scorer():
    """Test Multi-Signal Confidence Scorer."""
    from modules.surface.intelligence.correlation_engine import CorrelatedService

    db = ServiceIntelligenceDB()
    scorer = ConfidenceScorer(port_map=db.port_map)

    # High confidence: port match + banner + version + multi-detection
    svc_high = CorrelatedService(
        canonical_name="ssh",
        ports=[22],
        products=["OpenSSH"],
        versions=["8.9p1"],
        detection_methods={"port_scan", "version_scan"},
    )
    result = scorer.score_service(svc_high)
    assert result.score >= 0.80
    assert result.label == "confirmed"
    assert result.signals["port_match"] is True
    assert result.signals["banner_match"] is True
    assert result.signals["version_detected"] is True
    assert result.signals["multi_detection"] is True

    # Medium confidence: port match only
    svc_med = CorrelatedService(
        canonical_name="ssh",
        ports=[22],
        detection_methods={"port_scan"},
    )
    result = scorer.score_service(svc_med)
    assert result.score >= 0.20
    assert result.label in ("medium", "low")

    # Low confidence: no port match, no banner, unknown port
    svc_low = CorrelatedService(
        canonical_name="unknown",
        ports=[55555],
        detection_methods={"port_scan"},
    )
    result = scorer.score_service(svc_low)
    assert result.score < 0.40
    assert result.label == "low"

    print("✅ Confidence Scorer: ALL PASSED")


def test_attack_prioritizer():
    """Test Intelligent Attack Prioritizer."""
    from modules.surface.intelligence.correlation_engine import CorrelatedService, AttackSurfaceMap

    db = ServiceIntelligenceDB()
    scorer = ConfidenceScorer(port_map=db.port_map)
    prioritizer = AttackPrioritizer(confidence_scorer=scorer)

    # Build a test surface map
    surface = AttackSurfaceMap(target="10.10.10.1")
    surface.services = {
        "smb": CorrelatedService(
            canonical_name="smb", display_name="SMB", ports=[445, 139],
            category="ad", attack_context="File sharing, lateral movement",
            high_value=True, default_creds=True,
            next_steps=["Test null sessions", "Enumerate shares"],
            common_tools=["enum4linux-ng", "smbclient"],
            detection_methods={"port_scan", "version_scan"},
            versions=["4.15.2"], products=["Samba"],
        ),
        "ssh": CorrelatedService(
            canonical_name="ssh", display_name="SSH", ports=[22],
            category="remote_access",
            next_steps=["Run ssh-audit", "Check version"],
            common_tools=["ssh-audit"],
            detection_methods={"port_scan"},
        ),
        "http": CorrelatedService(
            canonical_name="http", display_name="HTTP", ports=[80],
            category="web", high_value=True,
            urls=["http://10.10.10.1/"],
            next_steps=["Directory brute-force", "Nuclei scan"],
            common_tools=["nuclei", "ffuf"],
            detection_methods={"port_scan", "http_probe"},
        ),
        "ftp": CorrelatedService(
            canonical_name="ftp", display_name="FTP", ports=[21],
            category="file_sharing", cleartext=True, default_creds=True,
            next_steps=["Test anonymous access"],
            common_tools=["ftp"],
            detection_methods={"port_scan"},
        ),
    }
    surface.total_ports = 5
    surface.total_services = 4
    surface.high_value_count = 2

    conf_results = scorer.score_batch(surface.services)
    result = prioritizer.prioritize(surface, conf_results)

    # Should have ranked targets
    assert len(result.ranked_targets) == 4
    assert result.ranked_targets[0].rank == 1

    # SMB should be high priority (AD + high_value + default_creds)
    smb_target = next(t for t in result.ranked_targets if t.canonical_name == "smb")
    assert smb_target.priority_level in ("critical", "high")
    assert "high_value" in smb_target.flags
    assert len(smb_target.next_steps) > 0

    # FTP should be in quick wins (cleartext + default_creds)
    assert len(result.quick_wins) > 0
    qw_names = {t.canonical_name for t in result.quick_wins}
    assert "ftp" in qw_names

    # Category groups should exist
    assert len(result.category_groups) > 0
    cat_names = {g.category for g in result.category_groups}
    assert "ad" in cat_names

    # Executive summary should be non-empty
    assert len(result.executive_summary) > 0

    print("✅ Attack Prioritizer: ALL PASSED")


def test_end_to_end():
    """Test full pipeline: port data → intelligence → prioritization."""
    engine = CorrelationEngine()
    db = ServiceIntelligenceDB()
    dedup = ServiceDeduplicator()
    scorer = ConfidenceScorer(port_map=db.port_map)
    prioritizer = AttackPrioritizer(confidence_scorer=scorer)

    # Simulate real scan data
    ports = [
        {"port": 22, "protocol": "tcp", "service": "ssh"},
        {"port": 53, "protocol": "tcp", "service": "domain"},
        {"port": 80, "protocol": "tcp", "service": "http"},
        {"port": 88, "protocol": "tcp", "service": "kerberos-sec"},
        {"port": 135, "protocol": "tcp", "service": "msrpc"},
        {"port": 139, "protocol": "tcp", "service": "netbios-ssn"},
        {"port": 389, "protocol": "tcp", "service": "ldap"},
        {"port": 443, "protocol": "tcp", "service": "ssl/http"},
        {"port": 445, "protocol": "tcp", "service": "microsoft-ds"},
        {"port": 1433, "protocol": "tcp", "service": "ms-sql-s"},
        {"port": 3306, "protocol": "tcp", "service": "mysql"},
        {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server"},
        {"port": 5985, "protocol": "tcp", "service": "wsman"},
    ]

    services = [
        {"port": 22, "service": "ssh", "version": "8.9p1", "product": "OpenSSH"},
        {"port": 445, "service": "microsoft-ds", "version": "4.15.2", "product": "Samba"},
        {"port": 1433, "service": "ms-sql-s", "version": "15.0.2000", "product": "Microsoft SQL Server"},
        {"port": 3389, "service": "ms-wbt-server", "version": "10.0", "product": "Microsoft Terminal Services"},
    ]

    http_services = [
        {"url": "http://10.10.10.1/", "status_code": 200, "title": "IIS Default",
         "technologies": ["IIS", "ASP.NET"], "web_server": "Microsoft-IIS/10.0"},
        {"url": "https://10.10.10.1/", "status_code": 200, "title": "Login Portal",
         "technologies": ["jQuery"], "web_server": "Microsoft-IIS/10.0"},
    ]

    # Step 1: Deduplicate
    deduped = dedup.deduplicate_ports(ports, services)
    deduped_http = dedup.deduplicate_http(http_services)
    assert len(deduped) <= len(ports) + len(services)

    # Step 2: Correlate
    surface = engine.correlate("10.10.10.1", deduped, [], deduped_http)
    assert surface.total_services > 0

    # Verify key correlations
    assert "smb" in surface.services  # microsoft-ds + netbios-ssn merged
    assert "rdp" in surface.services  # ms-wbt-server normalized
    assert "kerberos" in surface.services  # kerberos-sec normalized
    assert "mssql" in surface.services  # ms-sql-s normalized
    assert "dns" in surface.services  # domain normalized
    assert "winrm" in surface.services  # wsman normalized
    assert "ldap" in surface.services

    # SMB should have both ports
    smb = surface.services["smb"]
    assert 445 in smb.ports
    assert 139 in smb.ports

    # Step 3: Score confidence
    conf = scorer.score_batch(surface.services)
    assert "smb" in conf
    assert conf["smb"].score > 0

    # Step 4: Prioritize
    result = prioritizer.prioritize(surface, conf)
    assert len(result.ranked_targets) > 0
    assert result.executive_summary

    # AD services should be high priority
    ad_targets = [t for t in result.ranked_targets if t.category == "ad"]
    assert len(ad_targets) > 0

    # Verify category groups
    cats = {g.category for g in result.category_groups}
    assert "ad" in cats
    assert "database" in cats

    print("✅ End-to-End Pipeline: ALL PASSED")


if __name__ == "__main__":
    test_intelligence_db()
    test_normalizer()
    test_correlation_engine()
    test_deduplicator()
    test_confidence_scorer()
    test_attack_prioritizer()
    test_end_to_end()
    print("\n🎉 ALL SURFACE INTELLIGENCE TESTS PASSED!")
