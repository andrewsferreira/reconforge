"""ReconForge Target Parser - Parse and validate target specifications."""

import ipaddress
from typing import List, Optional
from dataclasses import dataclass

from core.exceptions import TargetValidationError
from core.validators import validate_hostname, validate_ip


@dataclass
class Target:
    """Parsed target specification."""
    raw: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    network: Optional[str] = None
    is_network: bool = False

    @property
    def display(self) -> str:
        return self.hostname or self.ip or self.raw


def parse_target(target_str: str) -> Target:
    """Parse and validate a target string into a Target object.

    Accepts a CIDR network, a single IP address, or an RFC 952/1123
    hostname. Anything else (shell metacharacters, leading '-' that could
    be interpreted as a CLI flag by a downstream tool, control characters,
    embedded newlines/null bytes, oversized input, etc.) is rejected.

    Raises:
        TargetValidationError: If *target_str* is none of the above.
    """
    target_str = target_str.strip()
    if not target_str:
        raise TargetValidationError(target_str, "Empty target")
    if len(target_str) > 253:
        raise TargetValidationError(target_str, "Target exceeds 253 characters")
    if any(ord(ch) < 0x20 for ch in target_str):
        raise TargetValidationError(target_str, "Target contains control characters")

    target = Target(raw=target_str)

    # CIDR network. A single-address network (e.g. "10.0.0.5/32") is treated
    # as a plain IP target rather than a range, so downstream tools receive a
    # clean address instead of a "/32"-suffixed string.
    try:
        net = ipaddress.ip_network(target_str, strict=False)
        if net.num_addresses > 1:
            target.network = str(net)
            target.is_network = True
            return target
        target.ip = str(net.network_address)
        return target
    except ValueError:
        pass

    # Single IP?
    try:
        target.ip = validate_ip(target_str)
        return target
    except TargetValidationError:
        pass

    # Hostname — strict RFC 952/1123 validation. Raises TargetValidationError
    # if target_str is not a well-formed hostname (this is the rejection path
    # the previous implementation was missing entirely).
    target.hostname = validate_hostname(target_str)
    return target


def parse_targets(target_list: List[str]) -> List[Target]:
    """Parse a list of target strings.

    Raises:
        TargetValidationError: On the first invalid entry.
    """
    return [parse_target(t) for t in target_list]
