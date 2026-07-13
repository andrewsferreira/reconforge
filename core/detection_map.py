"""ReconForge Detection Map - OPSEC risk assessment for tools and techniques."""

from typing import Dict, Optional


DETECTION_LEVELS = {
    "nmap_ping_sweep": {"noise": "low", "description": "ICMP/ARP ping sweep"},
    "nmap_syn_scan": {"noise": "medium", "description": "SYN stealth scan"},
    "nmap_connect_scan": {"noise": "high", "description": "Full TCP connect scan"},
    "nmap_version_scan": {"noise": "medium", "description": "Service version detection"},
    "nmap_script_scan": {"noise": "high", "description": "NSE script scanning"},
    "nmap_aggressive": {"noise": "very_high", "description": "Aggressive scan with OS/version/scripts"},
    "enum4linux": {"noise": "medium", "description": "SMB/NetBIOS enumeration"},
    "smbclient_list": {"noise": "low", "description": "SMB share listing"},
    "ldapsearch": {"noise": "low", "description": "LDAP anonymous query"},
    "hydra_brute": {"noise": "very_high", "description": "Password brute forcing"},

    # AD Module detection levels
    "enum4linux_ng_full": {"noise": "medium", "description": "Full enum4linux-ng AD enumeration"},
    "enum4linux_ng_rid": {"noise": "high", "description": "RID cycling user enumeration"},
    "enum4linux_ng_shares": {"noise": "low", "description": "SMB share enumeration via enum4linux-ng"},
    "impacket_getadusers": {"noise": "medium", "description": "Impacket GetADUsers LDAP user dump"},
    "impacket_getnpusers": {"noise": "medium", "description": "Impacket GetNPUsers AS-REP roasting recon"},
    "impacket_lookupsid": {"noise": "high", "description": "Impacket lookupsid RID brute-force"},
    "impacket_rpcdump": {"noise": "low", "description": "Impacket rpcdump RPC endpoint enumeration"},
    "ldap_anonymous_bind": {"noise": "low", "description": "LDAP anonymous bind test"},
    "ldap_user_enum": {"noise": "medium", "description": "LDAP user enumeration queries"},
    "ldap_group_enum": {"noise": "medium", "description": "LDAP group enumeration queries"},
    "ldap_computer_enum": {"noise": "medium", "description": "LDAP computer enumeration queries"},
    "ldap_trust_enum": {"noise": "medium", "description": "LDAP trust relationship queries"},
    "ldap_gpo_enum": {"noise": "medium", "description": "LDAP GPO enumeration queries"},
    "ldap_spn_query": {"noise": "medium", "description": "LDAP SPN account query (Kerberoast recon)"},
    "ldap_asrep_query": {"noise": "medium", "description": "LDAP AS-REP roastable user query"},
    "ldap_password_policy": {"noise": "low", "description": "LDAP password policy query"},
    "smb_null_session": {"noise": "low", "description": "SMB null session test"},
    "smb_share_access": {"noise": "medium", "description": "SMB share access testing"},
    "smb_admin_shares": {"noise": "high", "description": "SMB administrative share access test"},
    "nmap_ad_service_scan": {"noise": "medium", "description": "Nmap AD service port scan"},
    "nmap_ad_ldap_scripts": {"noise": "medium", "description": "Nmap LDAP NSE scripts"},
    "nmap_ad_smb_scripts": {"noise": "high", "description": "Nmap SMB NSE scripts (AD)"},
    "nmap_ad_kerberos": {"noise": "high", "description": "Nmap Kerberos enumeration scripts"},
    "nmap_kerberos_detect": {"noise": "low", "description": "Nmap Kerberos port/version probe (no NSE scripts)"},
    "nmap_ad_full_scripts": {"noise": "high", "description": "Nmap full AD NSE script suite"},
    "nmap_dns_srv": {"noise": "low", "description": "DNS SRV record enumeration"},
    "rid_cycling": {"noise": "high", "description": "RID cycling for user/group enumeration"},

    # AD Advanced Module detection levels
    "bloodhound_collection": {"noise": "high", "description": "Bloodhound AD graph data collection"},
    "bloodhound_all_collection": {"noise": "very_high", "description": "Bloodhound full collection (All method)"},
    "bloodhound_dconly": {"noise": "high", "description": "Bloodhound DC-only collection"},
    "netexec_smb": {"noise": "high", "description": "NetExec SMB enumeration"},
    "netexec_ldap": {"noise": "medium", "description": "NetExec LDAP enumeration"},
    "netexec_bloodhound": {"noise": "high", "description": "NetExec Bloodhound collection"},
    "delegation_discovery": {"noise": "medium", "description": "LDAP delegation discovery queries"},
    "unconstrained_delegation_query": {"noise": "medium", "description": "Query for unconstrained delegation"},
    "constrained_delegation_query": {"noise": "medium", "description": "Query for constrained delegation"},
    "rbcd_query": {"noise": "medium", "description": "Query for resource-based constrained delegation"},
    "impacket_finddelegation": {"noise": "medium", "description": "Impacket findDelegation enumeration"},
    "machine_account_quota_query": {"noise": "low", "description": "Query ms-DS-MachineAccountQuota"},

    # Web Module detection levels
    "whatweb_scan": {"noise": "low", "description": "WhatWeb technology fingerprinting"},
    "whatweb_aggressive": {"noise": "medium", "description": "WhatWeb aggressive plugin scan"},
    "wafw00f_detection": {"noise": "low", "description": "WAF detection scan"},
    "curl_header_grab": {"noise": "low", "description": "HTTP header retrieval via curl"},
    "nikto_scan": {"noise": "high", "description": "Nikto vulnerability scan"},
    "nikto_aggressive": {"noise": "very_high", "description": "Nikto aggressive tuning scan"},
    "gobuster_dir": {"noise": "medium", "description": "Gobuster directory brute force"},
    "gobuster_vhost": {"noise": "medium", "description": "Gobuster vhost enumeration"},
    "ffuf_scan": {"noise": "medium", "description": "FFUF web fuzzing"},
    "ffuf_aggressive": {"noise": "high", "description": "FFUF aggressive fuzzing"},
    "wpscan_enumerate": {"noise": "high", "description": "WPScan WordPress enumeration"},
    "wpscan_aggressive": {"noise": "very_high", "description": "WPScan aggressive plugin detection"},
    "nuclei_cve_scan": {"noise": "medium", "description": "Nuclei CVE template scan"},
    "nuclei_full_scan": {"noise": "high", "description": "Nuclei full template scan"},
    "sqlmap_detect": {"noise": "high", "description": "SQLMap injection detection"},
    "sqlmap_exploit": {"noise": "very_high", "description": "SQLMap exploitation"},
    "testssl_scan": {"noise": "low", "description": "TestSSL security assessment"},
    # API Module detection levels
    "httpx_api_probe": {"noise": "low", "description": "HTTP probe with httpx"},
    "api_spec_detection": {"noise": "low", "description": "OpenAPI/Swagger spec detection"},
    "ffuf_api_scan": {"noise": "medium", "description": "FFUF API endpoint enumeration"},
    "ffuf_api_fuzz": {"noise": "medium", "description": "FFUF API parameter fuzzing"},
    "arjun_param_discovery": {"noise": "medium", "description": "Arjun hidden parameter discovery"},
    "nuclei_api_scan": {"noise": "medium", "description": "Nuclei API template scan"},
    "api_auth_testing": {"noise": "medium", "description": "API authentication mechanism testing"},
    "api_authz_testing": {"noise": "high", "description": "API authorization/BOLA testing"},
    "api_rate_limit_check": {"noise": "low", "description": "API rate limiting assessment"},

    # Web module phase-level technique aliases
    "ffuf_dir_scan": {"noise": "medium", "description": "FFUF directory scanning"},
    "gobuster_dir_scan": {"noise": "medium", "description": "Gobuster directory brute force scan"},
    "wpscan_enum": {"noise": "high", "description": "WPScan WordPress enumeration"},
    "wafw00f_detect": {"noise": "low", "description": "WAF detection via wafw00f"},
    "nuclei_scan": {"noise": "medium", "description": "Nuclei template-based vulnerability scan"},
    "sqlmap_scan": {"noise": "high", "description": "SQLMap SQL injection detection"},
}


def get_detection_level(technique: str) -> Optional[Dict]:
    """Get detection level for a technique."""
    return DETECTION_LEVELS.get(technique)


def is_allowed(technique: str, opsec_mode: str) -> bool:
    """Check if a technique is allowed under the current OPSEC mode.

    Fails closed: an unrecognized opsec_mode (a typo, or a programmatic
    caller that bypasses the CLI's argparse `choices=` validation — every
    module's `opsec_mode` constructor parameter accepts an unvalidated
    string) denies the action rather than allowing it. The previous
    `return True` fallback meant any unrecognized mode string silently
    disabled all noise gating, including very_high-noise techniques.
    """
    level = DETECTION_LEVELS.get(technique, {}).get("noise", "unknown")
    if opsec_mode == "stealth":
        return level in ("low",)
    elif opsec_mode == "normal":
        return level in ("low", "medium")
    elif opsec_mode == "aggressive":
        return level in ("low", "medium", "high", "very_high")
    return False
