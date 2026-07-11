# Security Policy

## Scope

This policy covers vulnerabilities **in ReconForge itself** — the framework's code, not the third-party
security tools it invokes (nmap, nuclei, sqlmap, etc.), which have their own upstream security processes.

Examples of in-scope issues: command injection through target/argument handling, credential or secret
leakage in logs/reports, scope-enforcement bypasses, path traversal in output handling, unsafe
deserialization, HTML/report injection.

## Supported Versions

Only the latest release on the `main` branch is supported with security fixes. ReconForge does not yet
maintain long-term-support branches.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately via GitHub's
["Report a vulnerability"](https://github.com/andrewsferreira/reconforge/security/advisories/new)
feature (Security tab → Report a vulnerability) rather than opening a public issue.

Include, where possible:
- affected file(s)/function(s) and version or commit;
- a minimal reproduction (do not include real target data, credentials, or customer information);
- the potential impact.

We aim to acknowledge new reports within 5 business days. There is currently no bug bounty program.

## Ethical Use

ReconForge is built for **authorized** penetration testing and Red Team laboratory use only. Do not run it
against systems, networks, or accounts you do not own or do not have explicit written authorization to
test. The authors accept no responsibility for misuse. See [README.md § Safety and Scope](README.md#safety-and-scope)
and [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for operational guardrails and known gaps.

## Responsible Disclosure for Findings Produced *by* ReconForge

ReconForge is a tool for discovering issues in systems you are authorized to test — it does not itself
manage disclosure to third parties. Any vulnerabilities discovered while using ReconForge against an
authorized target should be disclosed following the scope, rules of engagement, and disclosure timeline
agreed with that target's owner, not through this repository.
