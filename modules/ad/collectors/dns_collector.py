"""ReconForge AD Collector — DNS data gathering.

Author: Andrews Ferreira

Collects DNS SRV records and zone information for AD services.
"""

from typing import Any

from modules.ad.collectors.base import CollectorBase, CollectorResult
from modules.ad.parsers.nmap_parser import ADNmapParser
from modules.ad.tools.nmap import ADNmapTool


class DnsCollector(CollectorBase):
    """Pure DNS data collection for AD environments."""

    COLLECTOR_NAME = "dns"

    def __init__(self, nmap: ADNmapTool, nmap_parser: ADNmapParser,
                 **kwargs) -> None:
        super().__init__(**kwargs)
        self.nmap = nmap
        self.nmap_parser = nmap_parser

    def collect(
        self,
        target: str,
        domain: str = "",
        base_dn: str = "",
        username: str = "",
        password: str = "",
        **kwargs,
    ) -> CollectorResult:
        """Collect DNS-based AD intelligence."""
        result = CollectorResult(source=self.COLLECTOR_NAME)

        result.data["ad_services"] = self.collect_ad_services(target)
        if domain:
            result.data["srv_records"] = self.collect_srv_records(target, domain)

        result.success = True
        return result

    def collect_ad_services(self, target: str) -> dict[str, Any]:
        """Scan AD ports and extract domain intelligence."""
        if not self.nmap.is_available():
            return {}
        if not self.opsec.check("nmap_ad_service_scan"):
            return {}

        run = self.nmap.ad_service_scan(target)
        if not run.success:
            return {}

        xml_path = self.nmap.output_dir / "nmap_ad_services.xml"
        if xml_path.exists():
            nmap_result = self.nmap_parser.parse_xml(xml_path)
        else:
            nmap_result = self.nmap_parser.parse_text(run.stdout)

        return {
            "domain_name": nmap_result.domain_name,
            "forest_name": nmap_result.forest_name,
            "ldap_base_dn": nmap_result.ldap_base_dn,
            "dc_hostname": nmap_result.dc_hostname,
            "functional_level": nmap_result.functional_level,
            "smb_signing": nmap_result.smb_signing,
            "kerberos_detected": nmap_result.kerberos_detected,
            "open_ports": nmap_result.open_ports,
            "services": [
                {
                    "port": s.port, "service": s.service,
                    "product": s.product, "version": s.version,
                    "state": s.state,
                }
                for s in nmap_result.services
            ],
        }

    def collect_srv_records(self, target: str, domain: str) -> str:
        """Query DNS SRV records for DC locations."""
        if not self.nmap.is_available():
            return ""
        if not self.opsec.check("nmap_dns_srv"):
            return ""
        run = self.nmap.dns_srv_lookup(domain, target)
        if run.success and run.stdout.strip():
            return run.stdout.strip()[:500]
        return ""
