# Session Notes

**Target:** 10.10.10.1
**Started:** 2026-03-17 05:26:38
**Entries:** 13

## Timeline

- **[2026-03-17 05:26:38]** 🔄 AD module started against 10.10.10.1 (domain=corp.local, dc=10.10.10.1)
- **[2026-03-17 05:26:38]** 📝 OPSEC mode: normal, Authenticated: False, Phases: passive, identity, configuration, delegation, bloodhound
- **[2026-03-17 05:26:38]** 📝 Tool check: nmap available; enum4linux-ng, ldapsearch, smbclient, impacket, bloodhound-python, netexec, advanced-impacket missing
- **[2026-03-17 05:26:38]** 🔄 Starting phase: passive_recon
- **[2026-03-17 05:26:38]** 💻 Command: `nmap AD service scan` → Open ports: [], Domain: N/A
- **[2026-03-17 05:26:38]** 🔄 Completed phase: passive_recon. Domain: corp.local, Anon LDAP: False, Null session: False
- **[2026-03-17 05:26:38]** 🔄 Starting phase: identity_enumeration
- **[2026-03-17 05:26:38]** 💻 Command: `AS-REP roastable user detection` → 0 users found
- **[2026-03-17 05:26:38]** 🔄 Completed phase: identity_enumeration. Users: 0, Groups: 0, Computers: 0, Service Accounts: 0, AS-REP roastable: 0
- **[2026-03-17 05:26:38]** 🔄 Starting phase: configuration_enumeration
- **[2026-03-17 05:26:38]** 🔄 Completed phase: configuration_enumeration. Policy: N/A, Trusts: 0, GPOs: 0, Shares: 0
- **[2026-03-17 05:26:38]** 🔄 Starting phase: delegation_discovery
- **[2026-03-17 05:26:38]** 🔄 Completed phase: delegation_discovery. Unconstrained: 0, Constrained: 0, RBCD: 0, MachineAccountQuota: -1