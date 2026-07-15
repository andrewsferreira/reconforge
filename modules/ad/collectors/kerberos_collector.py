"""ReconForge AD Collector — Kerberos data gathering.

Author: Andrews Ferreira

Collects Kerberos-related data: service detection, AS-REP hashes,
SPN tickets for Kerberoasting.
"""


from modules.ad.collectors.base import CollectorBase, CollectorResult
from modules.ad.parsers.impacket_parser import ImpacketParser
from modules.ad.tools.impacket import ImpacketTool
from modules.ad.tools.nmap import ADNmapTool


class KerberosCollector(CollectorBase):
    """Pure Kerberos data collection."""

    COLLECTOR_NAME = "kerberos"

    def __init__(self, nmap: ADNmapTool, impacket: ImpacketTool,
                 impacket_parser: ImpacketParser, **kwargs) -> None:
        super().__init__(**kwargs)
        self.nmap = nmap
        self.impacket = impacket
        self.impacket_parser = impacket_parser

    def collect(
        self,
        target: str,
        domain: str = "",
        base_dn: str = "",
        username: str = "",
        password: str = "",
        **kwargs,
    ) -> CollectorResult:
        """Collect all Kerberos-related data."""
        result = CollectorResult(source=self.COLLECTOR_NAME)

        result.data["kerberos_detected"] = self.detect_kerberos(target)
        result.data["asrep_hashes"] = self.collect_asrep_hashes(
            target, domain, username, password
        )
        result.data["rid_cycling"] = self.collect_rid_cycling(
            target, domain, username, password
        )

        result.success = True
        return result

    def detect_kerberos(self, target: str) -> bool:
        """Check if Kerberos service is running on port 88."""
        if not self.nmap.is_available():
            return False
        if not self.opsec.check("nmap_kerberos_detect"):
            return False
        run = self.nmap.kerberos_scan(target)
        return (
            run.success
            and "88/tcp" in run.stdout
            and "open" in run.stdout
        )

    def collect_asrep_hashes(
        self, target: str, domain: str,
        username: str = "", password: str = "",
    ) -> list[dict]:
        """Collect AS-REP hashes via GetNPUsers.py."""
        if not domain or not self.impacket.is_available("getnpusers"):
            return []
        if not self.opsec.check("impacket_getnpusers"):
            return []

        run = self.impacket.get_np_users(
            target=target, domain=domain,
            username=username, password=password,
            dc_ip=target,
        )
        if not run.success:
            return []

        hashes = self.impacket_parser.parse_getnpusers(run.stdout)
        return [
            {"username": h.username, "hash": h.hash, "hash_type": "krb5asrep"}
            for h in hashes
        ]

    def collect_rid_cycling(
        self, target: str, domain: str,
        username: str = "", password: str = "",
    ) -> dict[str, list[str]]:
        """Enumerate users and groups via RID cycling."""
        if not self.impacket.is_available("lookupsid"):
            return {"users": [], "groups": []}
        if not self.opsec.check("impacket_lookupsid"):
            return {"users": [], "groups": []}

        max_rid = 4000 if self.opsec_mode == "aggressive" else 2000
        run = self.impacket.lookup_sid(
            target, domain=domain,
            username=username, password=password,
            max_rid=max_rid,
        )
        if not run.success:
            return {"users": [], "groups": []}

        entries = self.impacket_parser.parse_lookupsid(run.stdout)
        return {
            "users": self.impacket_parser.extract_users_from_rid(entries),
            "groups": self.impacket_parser.extract_groups_from_rid(entries),
        }
