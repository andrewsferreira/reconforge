"""ReconForge Validators - Input validation helpers.

Author: Andrews Ferreira

Provides reusable validation functions for targets, ports, CIDRs, and
URLs.  Each function returns the sanitised value on success or raises
:class:`core.exceptions.ValidationError`.
"""

import ipaddress
import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from core.exceptions import (
    ValidationError,
    TargetValidationError,
    PortValidationError,
)

# ── Constants ───────────────────────────────────────────────────────

_HOSTNAME_RE = re.compile(
    r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)'
    r'(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$'
)

_PORT_MIN = 1
_PORT_MAX = 65535


# ── IP / CIDR ───────────────────────────────────────────────────────

def validate_ip(value: str) -> str:
    """Validate and return a single IPv4/IPv6 address.

    Raises:
        TargetValidationError: If *value* is not a valid IP address.
    """
    value = value.strip()
    try:
        addr = ipaddress.ip_address(value)
        return str(addr)
    except ValueError:
        raise TargetValidationError(value, "Not a valid IP address")


def validate_cidr(value: str) -> str:
    """Validate and return a CIDR network notation.

    Accepts both strict (``10.0.0.0/24``) and non-strict (``10.0.0.5/24``).

    Raises:
        TargetValidationError: If *value* is not valid CIDR.
    """
    value = value.strip()
    try:
        net = ipaddress.ip_network(value, strict=False)
        return str(net)
    except ValueError:
        raise TargetValidationError(value, "Not a valid CIDR network")


def validate_ip_or_cidr(value: str) -> str:
    """Validate an IP address *or* CIDR network."""
    value = value.strip()
    try:
        return validate_ip(value)
    except TargetValidationError:
        return validate_cidr(value)


# ── Hostname ────────────────────────────────────────────────────────

def validate_hostname(value: str) -> str:
    """Validate a hostname (RFC 952 / 1123).

    Raises:
        TargetValidationError: If *value* is not a valid hostname.
    """
    value = value.strip().rstrip(".")
    if not value:
        raise TargetValidationError(value, "Empty hostname")
    if len(value) > 253:
        raise TargetValidationError(value, "Hostname exceeds 253 characters")
    if not _HOSTNAME_RE.match(value):
        raise TargetValidationError(value, "Invalid hostname characters or format")
    return value


def validate_target(value: str) -> str:
    """Validate a generic target: IP, CIDR, hostname, or URL.

    Returns the normalised value.
    """
    value = value.strip()
    if not value:
        raise TargetValidationError(value, "Empty target")

    # URL?
    if value.startswith(("http://", "https://")):
        return validate_url(value)

    # IP?
    try:
        return validate_ip(value)
    except TargetValidationError:
        pass

    # CIDR?
    if "/" in value:
        return validate_cidr(value)

    # Hostname fallback
    return validate_hostname(value)


# ── Ports ───────────────────────────────────────────────────────────

def validate_port(value) -> int:
    """Validate a single port number.

    Args:
        value: Integer or string representation of a port.

    Returns:
        The validated port as an ``int``.

    Raises:
        PortValidationError: If *value* is not a valid port (1-65535).
    """
    try:
        port = int(value)
    except (ValueError, TypeError):
        raise PortValidationError(str(value), "Not a valid integer")
    if port < _PORT_MIN or port > _PORT_MAX:
        raise PortValidationError(str(value), f"Port must be {_PORT_MIN}-{_PORT_MAX}")
    return port


def validate_port_range(value: str) -> str:
    """Validate an nmap-style port specification.

    Supports:
    - Single ports:  ``80``
    - Ranges:        ``80-443``
    - Comma lists:   ``22,80,443``
    - Mixed:         ``22,80-443,8080``
    - Dash (all):    ``-``

    Returns:
        The validated port specification string.
    """
    value = value.strip()
    if value == "-":
        return value  # nmap shorthand for all ports

    for segment in value.split(","):
        segment = segment.strip()
        if not segment:
            raise PortValidationError(value, "Empty segment")
        if "-" in segment:
            parts = segment.split("-", 1)
            if len(parts) != 2:
                raise PortValidationError(value, f"Bad range: {segment}")
            lo = validate_port(parts[0].strip())
            hi = validate_port(parts[1].strip())
            if lo > hi:
                raise PortValidationError(value, f"Range start > end: {segment}")
        else:
            validate_port(segment)

    return value


def parse_port_list(value: str) -> List[int]:
    """Parse an nmap-style port spec into a sorted list of integers."""
    validated = validate_port_range(value)
    if validated == "-":
        return list(range(1, 65536))

    ports: set = set()
    for segment in validated.split(","):
        segment = segment.strip()
        if "-" in segment:
            lo, hi = segment.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(segment))
    return sorted(ports)


# ── URL ─────────────────────────────────────────────────────────────

def validate_url(value: str) -> str:
    """Validate a URL (must have scheme and netloc).

    Raises:
        ValidationError: If *value* is not a well-formed URL.
    """
    value = value.strip()
    parsed = urlparse(value)
    if not parsed.scheme:
        raise ValidationError("url", value, "Missing scheme (http/https)")
    if parsed.scheme not in ("http", "https"):
        raise ValidationError("url", value, f"Unsupported scheme: {parsed.scheme}")
    if not parsed.netloc:
        raise ValidationError("url", value, "Missing host")
    return value


# ── Domain ──────────────────────────────────────────────────────────

def validate_domain(value: str) -> str:
    """Validate an AD / DNS domain name.

    Raises:
        ValidationError: If *value* is not a valid domain.
    """
    value = value.strip().lower()
    if not value:
        raise ValidationError("domain", value, "Empty domain")
    parts = value.rstrip(".").split(".")
    if len(parts) < 2:
        raise ValidationError("domain", value, "Domain must have at least two labels")
    for part in parts:
        if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', part):
            raise ValidationError("domain", value, f"Invalid label: {part}")
    return value
