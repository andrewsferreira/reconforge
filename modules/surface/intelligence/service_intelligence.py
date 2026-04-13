"""ReconForge - Service Intelligence Database

Author: Andrews Ferreira

Comprehensive port-to-service mapping with attack context,
aliases, descriptions, and version-specific intelligence.
Transforms raw port/service data into actionable pentesting intelligence.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass(frozen=True)
class ServiceProfile:
    """Intelligence profile for a known service."""
    canonical_name: str
    display_name: str
    description: str
    category: str  # ad, web, database, remote_access, file_sharing, mail, monitoring, misc
    default_ports: tuple  # common ports for this service
    aliases: tuple = ()  # nmap/banner name variations
    attack_context: str = ""
    common_tools: tuple = ()  # pentesting tools for this service
    next_steps: tuple = ()  # suggested investigation steps
    high_value: bool = False  # is this a high-value target?
    cleartext: bool = False  # does this use cleartext by default?
    default_creds_common: bool = False  # are default creds common?
    version_critical: bool = False  # are specific versions notably vulnerable?


class ServiceIntelligenceDB:
    """Comprehensive service intelligence database for offensive recon.

    Provides:
    - Port → service mapping
    - Service aliases and canonical names
    - Attack context and investigation guidance
    - Category-based grouping for prioritization
    """

    def __init__(self) -> None:
        self._profiles: Dict[str, ServiceProfile] = {}
        self._port_map: Dict[int, str] = {}  # port → canonical_name
        self._alias_map: Dict[str, str] = {}  # alias → canonical_name
        self._build_database()

    def _build_database(self) -> None:
        """Build the complete service intelligence database."""
        profiles = [
            # ── Active Directory / Windows ──────────────────────────
            ServiceProfile(
                canonical_name="smb",
                display_name="SMB",
                description="Server Message Block - Windows file sharing and IPC",
                category="ad",
                default_ports=(445, 139),
                aliases=("microsoft-ds", "cifs", "netbios-ssn", "samba"),
                attack_context="File sharing, credential harvesting, lateral movement, relay attacks",
                common_tools=("enum4linux-ng", "smbclient", "crackmapexec", "smbmap", "impacket-smbexec"),
                next_steps=(
                    "Test for null session access",
                    "Enumerate shares and permissions",
                    "Check SMB signing status",
                    "Test for known CVEs (EternalBlue, PrintNightmare)",
                    "Attempt credential relay if signing disabled",
                ),
                high_value=True,
                default_creds_common=True,
                version_critical=True,
            ),
            ServiceProfile(
                canonical_name="ldap",
                display_name="LDAP",
                description="Lightweight Directory Access Protocol - AD directory service",
                category="ad",
                default_ports=(389, 3268),
                aliases=("ldapssl", "globalcatalog",),
                attack_context="AD enumeration, user/group discovery, GPO abuse, LDAP injection",
                common_tools=("ldapsearch", "ldapdomaindump", "bloodhound", "windapsearch"),
                next_steps=(
                    "Test anonymous LDAP bind",
                    "Enumerate domain users and groups",
                    "Query for SPNs (Kerberoasting)",
                    "Check for AS-REP roastable accounts",
                    "Enumerate trusts and GPOs",
                ),
                high_value=True,
            ),
            ServiceProfile(
                canonical_name="ldaps",
                display_name="LDAPS",
                description="LDAP over SSL/TLS - Encrypted directory service",
                category="ad",
                default_ports=(636, 3269),
                aliases=("ldap-ssl", "ldapssl"),
                attack_context="Encrypted AD enumeration - same attacks as LDAP but over TLS",
                common_tools=("ldapsearch", "ldapdomaindump", "bloodhound"),
                next_steps=(
                    "Enumerate domain objects via LDAPS",
                    "Check certificate validity",
                    "Same enumeration as LDAP but encrypted channel",
                ),
                high_value=True,
            ),
            ServiceProfile(
                canonical_name="kerberos",
                display_name="Kerberos",
                description="Kerberos authentication protocol - AD authentication backbone",
                category="ad",
                default_ports=(88,),
                aliases=("kerberos-sec", "krb5"),
                attack_context="Kerberoasting, AS-REP roasting, golden/silver tickets, delegation abuse",
                common_tools=("impacket-GetUserSPNs", "impacket-GetNPUsers", "Rubeus", "kerbrute"),
                next_steps=(
                    "Confirm Domain Controller role",
                    "Attempt Kerberoasting with known users",
                    "Test for AS-REP roastable accounts",
                    "Enumerate SPNs for service accounts",
                ),
                high_value=True,
            ),
            ServiceProfile(
                canonical_name="dns",
                display_name="DNS",
                description="Domain Name System",
                category="ad",
                default_ports=(53,),
                aliases=("domain", "nameserver"),
                attack_context="Zone transfers, subdomain enumeration, DNS poisoning",
                common_tools=("dig", "nslookup", "dnsrecon", "dnsenum", "fierce"),
                next_steps=(
                    "Attempt zone transfer (AXFR)",
                    "Enumerate DNS SRV records for AD services",
                    "Check for wildcard DNS",
                    "Brute-force subdomains",
                ),
                high_value=True,
            ),
            ServiceProfile(
                canonical_name="msrpc",
                display_name="MS-RPC",
                description="Microsoft Remote Procedure Call",
                category="ad",
                default_ports=(135, 593),
                aliases=("epmap", "msrpc", "http-rpc-epmap", "rpcbind"),
                attack_context="Endpoint enumeration, RID cycling, service discovery",
                common_tools=("rpcclient", "impacket-rpcdump", "rpcinfo"),
                next_steps=(
                    "Enumerate RPC endpoints",
                    "Attempt RID cycling for user enumeration",
                    "Check for accessible RPC services",
                ),
            ),
            ServiceProfile(
                canonical_name="winrm",
                display_name="WinRM",
                description="Windows Remote Management",
                category="remote_access",
                default_ports=(5985, 5986),
                aliases=("wsman", "wsmans"),
                attack_context="Remote command execution with valid credentials, lateral movement",
                common_tools=("evil-winrm", "crackmapexec winrm", "Invoke-Command"),
                next_steps=(
                    "Attempt authentication with discovered credentials",
                    "Test for default/weak credentials",
                    "Check for PS remoting access",
                ),
                high_value=True,
                default_creds_common=True,
            ),

            # ── Remote Access ──────────────────────────────────────
            ServiceProfile(
                canonical_name="ssh",
                display_name="SSH",
                description="Secure Shell - Encrypted remote access",
                category="remote_access",
                default_ports=(22,),
                aliases=("openssh", "ssh2"),
                attack_context="Brute force, key-based auth bypass, version-specific CVEs",
                common_tools=("ssh-audit", "hydra", "medusa", "ncrack"),
                next_steps=(
                    "Run ssh-audit for algorithm/config analysis",
                    "Check for weak/default credentials",
                    "Check SSH version for known CVEs",
                    "Test for key-based auth misconfiguration",
                ),
                version_critical=True,
            ),
            ServiceProfile(
                canonical_name="rdp",
                display_name="RDP",
                description="Remote Desktop Protocol - Windows remote access",
                category="remote_access",
                default_ports=(3389,),
                aliases=("ms-wbt-server", "ms-term-serv", "microsoft-rdp"),
                attack_context="Brute force, BlueKeep, credential stuffing, NLA bypass",
                common_tools=("xfreerdp", "rdesktop", "hydra", "crowbar"),
                next_steps=(
                    "Check NLA (Network Level Authentication) requirement",
                    "Test for default/weak credentials",
                    "Check for BlueKeep (CVE-2019-0708)",
                    "Screenshot for visual recon",
                ),
                high_value=True,
                default_creds_common=True,
                version_critical=True,
            ),
            ServiceProfile(
                canonical_name="vnc",
                display_name="VNC",
                description="Virtual Network Computing - Remote desktop",
                category="remote_access",
                default_ports=(5900, 5901, 5902),
                aliases=("rfb", "vnc-http"),
                attack_context="Authentication bypass, weak/no password, screenshot capture",
                common_tools=("vncviewer", "hydra", "ncrack"),
                next_steps=(
                    "Check for no-auth VNC access",
                    "Test for default/weak passwords",
                    "Attempt screenshot capture",
                ),
                default_creds_common=True,
            ),
            ServiceProfile(
                canonical_name="telnet",
                display_name="Telnet",
                description="Telnet - Unencrypted remote terminal",
                category="remote_access",
                default_ports=(23,),
                aliases=("telnetd",),
                attack_context="Cleartext credentials, banner grabbing, brute force",
                common_tools=("telnet", "hydra", "medusa"),
                next_steps=(
                    "Connect and grab banner",
                    "Test for default credentials",
                    "Capture credentials (cleartext protocol)",
                ),
                cleartext=True,
                default_creds_common=True,
            ),

            # ── Web ────────────────────────────────────────────────
            ServiceProfile(
                canonical_name="http",
                display_name="HTTP",
                description="Hypertext Transfer Protocol - Web service",
                category="web",
                default_ports=(80, 8080, 8000, 8888, 8443, 8081),
                aliases=("www", "http-proxy", "http-alt", "webcache", "web"),
                attack_context="Web application attacks, directory traversal, injection, misconfig",
                common_tools=("nikto", "nuclei", "gobuster", "ffuf", "burpsuite", "feroxbuster"),
                next_steps=(
                    "Run directory/file brute-force",
                    "Scan for common vulnerabilities (nuclei)",
                    "Check for exposed admin panels",
                    "Test for injection points",
                    "Enumerate virtual hosts",
                ),
                high_value=True,
            ),
            ServiceProfile(
                canonical_name="https",
                display_name="HTTPS",
                description="HTTP over TLS - Encrypted web service",
                category="web",
                default_ports=(443, 8443, 4443),
                aliases=("ssl/http", "https-alt", "ssl-http", "http/ssl"),
                attack_context="Same as HTTP + TLS misconfiguration, certificate issues",
                common_tools=("nikto", "nuclei", "sslscan", "testssl.sh", "gobuster"),
                next_steps=(
                    "Check TLS configuration (sslscan/testssl)",
                    "Run web vulnerability scanning",
                    "Check certificate for hostnames",
                    "Test for HTTP-specific vulnerabilities",
                ),
                high_value=True,
            ),

            # ── Database ───────────────────────────────────────────
            ServiceProfile(
                canonical_name="mssql",
                display_name="MSSQL",
                description="Microsoft SQL Server",
                category="database",
                default_ports=(1433, 1434),
                aliases=("ms-sql-s", "ms-sql-m", "microsoft-sql", "ms-sql"),
                attack_context="SQL injection, default sa account, xp_cmdshell, credential harvesting",
                common_tools=("impacket-mssqlclient", "sqsh", "crackmapexec mssql", "nmap --script ms-sql*"),
                next_steps=(
                    "Test for default sa:sa or sa:(blank) credentials",
                    "Check for xp_cmdshell availability",
                    "Enumerate databases and linked servers",
                    "Test for SQL injection in web apps pointing here",
                ),
                high_value=True,
                default_creds_common=True,
            ),
            ServiceProfile(
                canonical_name="mysql",
                display_name="MySQL",
                description="MySQL Database Server",
                category="database",
                default_ports=(3306,),
                aliases=("mariadb", "mysql-proxy"),
                attack_context="Default credentials, UDF exploitation, data exfiltration",
                common_tools=("mysql", "hydra", "mysqlclient", "crackmapexec"),
                next_steps=(
                    "Test for root:(blank) or default credentials",
                    "Check remote access restrictions",
                    "Enumerate databases",
                    "Check for UDF exploitation potential",
                ),
                default_creds_common=True,
            ),
            ServiceProfile(
                canonical_name="postgresql",
                display_name="PostgreSQL",
                description="PostgreSQL Database Server",
                category="database",
                default_ports=(5432,),
                aliases=("postgres",),
                attack_context="Default credentials, COPY FROM PROGRAM RCE, data exfiltration",
                common_tools=("psql", "hydra", "pgcli"),
                next_steps=(
                    "Test for postgres:(blank) or default credentials",
                    "Check for COPY FROM PROGRAM privilege",
                    "Enumerate databases and roles",
                ),
                default_creds_common=True,
            ),
            ServiceProfile(
                canonical_name="oracle",
                display_name="Oracle DB",
                description="Oracle Database",
                category="database",
                default_ports=(1521, 1522, 1630),
                aliases=("oracle-tns", "tns"),
                attack_context="TNS listener attacks, default SIDs, credential brute force",
                common_tools=("odat", "tnscmd10g", "hydra", "oscanner"),
                next_steps=(
                    "Enumerate SIDs/service names",
                    "Test for default credentials",
                    "Check TNS listener configuration",
                ),
                default_creds_common=True,
            ),
            ServiceProfile(
                canonical_name="redis",
                display_name="Redis",
                description="Redis In-Memory Data Store",
                category="database",
                default_ports=(6379,),
                aliases=("redis-server",),
                attack_context="No-auth access, data exfiltration, RCE via modules or SSH key write",
                common_tools=("redis-cli", "redis-rogue-server"),
                next_steps=(
                    "Test for unauthenticated access",
                    "Check CONFIG GET for sensitive settings",
                    "Attempt SSH key write for RCE",
                    "Check for Lua scripting",
                ),
                high_value=True,
                default_creds_common=True,
            ),
            ServiceProfile(
                canonical_name="mongodb",
                display_name="MongoDB",
                description="MongoDB NoSQL Database",
                category="database",
                default_ports=(27017, 27018),
                aliases=("mongod",),
                attack_context="No-auth access, data exfiltration, NoSQL injection",
                common_tools=("mongosh", "mongo", "nosqlmap"),
                next_steps=(
                    "Test for unauthenticated access",
                    "Enumerate databases and collections",
                    "Check for sensitive data exposure",
                ),
                default_creds_common=True,
            ),
            ServiceProfile(
                canonical_name="elasticsearch",
                display_name="Elasticsearch",
                description="Elasticsearch Search Engine",
                category="database",
                default_ports=(9200, 9300),
                aliases=("wap-wsp",),
                attack_context="No-auth access, data exfiltration, cluster takeover",
                common_tools=("curl", "elasticdump"),
                next_steps=(
                    "Check /_cluster/health for unauthenticated access",
                    "Enumerate indices",
                    "Search for sensitive data",
                ),
                default_creds_common=True,
            ),

            # ── File Transfer ──────────────────────────────────────
            ServiceProfile(
                canonical_name="ftp",
                display_name="FTP",
                description="File Transfer Protocol",
                category="file_sharing",
                default_ports=(21,),
                aliases=("ftpd", "ftp-data"),
                attack_context="Anonymous access, cleartext credentials, writable directories",
                common_tools=("ftp", "hydra", "lftp", "wget"),
                next_steps=(
                    "Test for anonymous FTP access",
                    "Check for writable directories",
                    "Look for sensitive files",
                    "Test for credential brute force",
                ),
                cleartext=True,
                default_creds_common=True,
            ),
            ServiceProfile(
                canonical_name="tftp",
                display_name="TFTP",
                description="Trivial File Transfer Protocol",
                category="file_sharing",
                default_ports=(69,),
                aliases=(),
                attack_context="No authentication, config file disclosure",
                common_tools=("tftp", "atftp"),
                next_steps=(
                    "Attempt to retrieve common config files",
                    "Test for file upload capability",
                ),
                cleartext=True,
            ),
            ServiceProfile(
                canonical_name="nfs",
                display_name="NFS",
                description="Network File System",
                category="file_sharing",
                default_ports=(2049,),
                aliases=("nfsd",),
                attack_context="Exported shares, UID spoofing, sensitive file access",
                common_tools=("showmount", "nfs-ls", "mount"),
                next_steps=(
                    "List exported shares (showmount -e)",
                    "Mount accessible shares",
                    "Check for sensitive files and UID restrictions",
                ),
            ),

            # ── Mail ───────────────────────────────────────────────
            ServiceProfile(
                canonical_name="smtp",
                display_name="SMTP",
                description="Simple Mail Transfer Protocol",
                category="mail",
                default_ports=(25, 465, 587),
                aliases=("smtps", "submission"),
                attack_context="User enumeration (VRFY/EXPN), open relay, phishing infrastructure",
                common_tools=("smtp-user-enum", "swaks", "nmap smtp scripts"),
                next_steps=(
                    "Test for VRFY/EXPN user enumeration",
                    "Check for open relay",
                    "Check for auth methods",
                ),
            ),
            ServiceProfile(
                canonical_name="pop3",
                display_name="POP3",
                description="Post Office Protocol v3",
                category="mail",
                default_ports=(110, 995),
                aliases=("pop3s",),
                attack_context="Credential brute force, email extraction",
                common_tools=("hydra", "nmap pop3 scripts"),
                next_steps=(
                    "Test for default/weak credentials",
                    "Extract emails if credentials found",
                ),
                cleartext=True,
            ),
            ServiceProfile(
                canonical_name="imap",
                display_name="IMAP",
                description="Internet Message Access Protocol",
                category="mail",
                default_ports=(143, 993),
                aliases=("imaps", "imap4"),
                attack_context="Credential brute force, email extraction",
                common_tools=("hydra", "nmap imap scripts"),
                next_steps=(
                    "Test for default/weak credentials",
                    "Enumerate mailboxes if credentials found",
                ),
            ),

            # ── Monitoring / Management ────────────────────────────
            ServiceProfile(
                canonical_name="snmp",
                display_name="SNMP",
                description="Simple Network Management Protocol",
                category="monitoring",
                default_ports=(161, 162),
                aliases=("snmptrap",),
                attack_context="Community string guessing, information disclosure, config extraction",
                common_tools=("snmpwalk", "snmp-check", "onesixtyone"),
                next_steps=(
                    "Brute-force community strings",
                    "Walk SNMP tree for system info",
                    "Extract network config and user data",
                ),
                default_creds_common=True,
            ),
            ServiceProfile(
                canonical_name="ipmi",
                display_name="IPMI",
                description="Intelligent Platform Management Interface",
                category="monitoring",
                default_ports=(623,),
                aliases=("asf-rmcp",),
                attack_context="IPMI cipher zero, hash dumping, default credentials",
                common_tools=("ipmitool", "metasploit ipmi_dumphashes"),
                next_steps=(
                    "Test for cipher zero vulnerability",
                    "Attempt hash dumping",
                    "Test for default IPMI credentials",
                ),
                high_value=True,
                default_creds_common=True,
            ),

            # ── Misc ───────────────────────────────────────────────
            ServiceProfile(
                canonical_name="docker",
                display_name="Docker API",
                description="Docker Remote API",
                category="misc",
                default_ports=(2375, 2376),
                aliases=("docker-api",),
                attack_context="Container escape, host filesystem access, crypto mining",
                common_tools=("docker", "curl"),
                next_steps=(
                    "Check for unauthenticated Docker API access",
                    "List containers and images",
                    "Attempt container escape to host",
                ),
                high_value=True,
            ),
            ServiceProfile(
                canonical_name="kubernetes",
                display_name="Kubernetes API",
                description="Kubernetes API Server",
                category="misc",
                default_ports=(6443, 10250),
                aliases=("k8s", "kubelet"),
                attack_context="API server access, RBAC bypass, secret extraction",
                common_tools=("kubectl", "kubeletctl", "kube-hunter"),
                next_steps=(
                    "Check for unauthenticated API access",
                    "Enumerate pods and namespaces",
                    "Check for exposed kubelet",
                ),
                high_value=True,
            ),
        ]

        for profile in profiles:
            self._profiles[profile.canonical_name] = profile
            # Map ports
            for port in profile.default_ports:
                self._port_map[port] = profile.canonical_name
            # Map aliases
            for alias in profile.aliases:
                self._alias_map[alias.lower()] = profile.canonical_name
            # Map canonical name to itself
            self._alias_map[profile.canonical_name] = profile.canonical_name

    # ── Lookups ────────────────────────────────────────────────────

    def get_profile(self, service_name: str) -> Optional[ServiceProfile]:
        """Get intelligence profile for a service by name or alias."""
        canonical = self.resolve_canonical(service_name)
        if canonical:
            return self._profiles.get(canonical)
        return None

    def get_profile_by_port(self, port: int) -> Optional[ServiceProfile]:
        """Get intelligence profile by port number."""
        canonical = self._port_map.get(port)
        if canonical:
            return self._profiles.get(canonical)
        return None

    def resolve_canonical(self, name: str) -> Optional[str]:
        """Resolve any service name/alias to its canonical name."""
        if not name:
            return None
        lower = name.lower().strip()
        return self._alias_map.get(lower)

    def resolve_by_port(self, port: int) -> Optional[str]:
        """Resolve a port number to its canonical service name."""
        return self._port_map.get(port)

    def get_category_services(self, category: str) -> List[ServiceProfile]:
        """Get all services in a category."""
        return [p for p in self._profiles.values() if p.category == category]

    def get_high_value_services(self) -> List[ServiceProfile]:
        """Get all high-value target services."""
        return [p for p in self._profiles.values() if p.high_value]

    def get_all_profiles(self) -> Dict[str, ServiceProfile]:
        """Return all service profiles."""
        return dict(self._profiles)

    def get_categories(self) -> Set[str]:
        """Return all known categories."""
        return {p.category for p in self._profiles.values()}

    @property
    def port_map(self) -> Dict[int, str]:
        return dict(self._port_map)

    @property
    def alias_map(self) -> Dict[str, str]:
        return dict(self._alias_map)
