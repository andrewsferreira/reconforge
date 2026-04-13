# Attack Workflow

**Current Phase:** passive_recon

## Steps

### Step 1: passive_recon
- **Hypothesis:** Target is an Active Directory domain controller
- **Command:** `nmap -sV -sC -p 53,88,135,139,389,445,636,3268 10.10.10.1`
- **Justification:** Identify AD services (LDAP, Kerberos, SMB, DNS, GC)
- **Alternatives:** Manual port check with nc/ncat
- **Result:** Open ports: [], Domain: N/A
- **Time:** 2026-03-17 05:26:38

### Step 2: passive_recon
- **Hypothesis:** DNS SRV records reveal domain controller locations for corp.local
- **Command:** `dig @10.10.10.1 _ldap._tcp.dc._msdcs.corp.local SRV`
- **Justification:** Standard AD DC location via DNS SRV records
- **Result:** No SRV records found or DNS query failed
- **Time:** 2026-03-17 05:26:38

## Attack Paths

### Weak Password Policy → Password Spraying [HIGH]
Weak password policy makes password spraying highly viable

**Steps:**
1. Compile user list from Phase 2 enumeration
2. Check policy: minLen=N/A, lockout=N/A
3. Spray with common passwords (Season+Year, Company+123, etc.)
4. Use crackmapexec or kerbrute for spray

**Prerequisites:** User list from Phase 2, Password policy analysis
**References:** https://attack.mitre.org/techniques/T1110/003/

## Suggested Next Commands

- [HIGH] `reconforge ad --target 10.10.10.1 --domain corp.local --phases identity`
  - Proceed to Phase 2: Identity Enumeration
- [HIGH] `crackmapexec smb 10.10.10.1 -u users.txt -p 'Spring2026!' --continue-on-success`
  - Weak policy (lockout=N/A, minLen=N/A) → password spray viable
- [HIGH] `reconforge ad --target 10.10.10.1 --domain corp.local --phases bloodhound`
  - Proceed to Phase 5: Bloodhound Collection for comprehensive attack path analysis