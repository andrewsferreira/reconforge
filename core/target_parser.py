"""ReconForge Target Parser - Parse and validate target specifications."""

import ipaddress
import re
from typing import List, Optional
from dataclasses import dataclass


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
    """Parse a target string into a Target object."""
    target_str = target_str.strip()
    target = Target(raw=target_str)

    # Check if it's a CIDR network
    try:
        net = ipaddress.ip_network(target_str, strict=False)
        if net.num_addresses > 1:
            target.network = str(net)
            target.is_network = True
            return target
    except ValueError:
        pass

    # Check if it's a single IP
    try:
        ip = ipaddress.ip_address(target_str)
        target.ip = str(ip)
        return target
    except ValueError:
        pass

    # Assume it's a hostname
    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+$', target_str):
        target.hostname = target_str
        return target

    target.hostname = target_str
    return target


def parse_targets(target_list: List[str]) -> List[Target]:
    """Parse a list of target strings."""
    return [parse_target(t) for t in target_list]
