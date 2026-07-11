"""ReconForge Utilities - Common helper functions."""

import re
import hashlib
from typing import Optional, List
from pathlib import Path


def sanitize_filename(name: str) -> str:
    """Sanitize a string for use as a filename."""
    return re.sub(r'[^\w\-.]', '_', name)


def is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IPv4 address."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def is_valid_port(port) -> bool:
    """Check if a value is a valid port number."""
    try:
        return 1 <= int(port) <= 65535
    except (ValueError, TypeError):
        return False


def truncate(text: str, max_len: int = 500) -> str:
    """Truncate text to max length."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "... [truncated]"


def md5sum(text: str) -> str:
    """Get an MD5 digest of text for non-cryptographic use (fingerprinting/dedup only)."""
    return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()


def parse_port_range(port_spec: str) -> List[int]:
    """Parse a port specification like '22,80,443' or '1-1024'."""
    ports = []
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def ensure_dir(path: Path) -> Path:
    """Ensure a directory exists."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path
