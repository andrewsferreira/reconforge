"""ReconForge SMB Parser - Parse smbclient output.

Extracts:
- Share names and types
- Share access permissions
- Directory listings
- Null session status
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class SmbShare:
    """A single SMB share."""
    name: str
    share_type: str = "Disk"
    comment: str = ""
    accessible: bool = False
    anonymous: bool = False
    permissions: str = ""
    files: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class SmbResult:
    """Parsed SMB enumeration result."""
    target: str = ""
    shares: List[SmbShare] = field(default_factory=list)
    null_session: bool = False
    server_name: str = ""
    domain: str = ""
    os_version: str = ""
    raw_output: str = ""
    errors: List[str] = field(default_factory=list)


class SmbParser:
    """Parse smbclient output into structured data."""

    # Shares typically safe to skip
    SYSTEM_SHARES = {"IPC$", "ADMIN$", "C$", "print$"}

    def parse_share_list(self, text: str, target: str = "") -> SmbResult:
        """Parse smbclient -L output.

        Args:
            text: Raw smbclient output text.
            target: Target IP or hostname.

        Returns:
            SmbResult with parsed share data.
        """
        result = SmbResult(target=target, raw_output=text)

        if not text.strip():
            result.errors.append("Empty output")
            return result

        # Check for null session success
        if self._is_access_denied(text):
            result.null_session = False
            result.errors.append("Access denied - null session may not be allowed")
        else:
            result.null_session = True

        # Parse share listing
        # Format: ShareName   Type   Comment
        for match in re.finditer(
            r"^\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*?)$",
            text, re.MULTILINE
        ):
            share = SmbShare(
                name=match.group(1).strip(),
                share_type=match.group(2).strip(),
                comment=match.group(3).strip(),
                anonymous=result.null_session,
            )
            result.shares.append(share)

        # Parse server info
        server_match = re.search(r"Server\s*=\s*\[([^\]]+)\]", text)
        if server_match:
            result.server_name = server_match.group(1)

        domain_match = re.search(r"Workgroup\s*=\s*\[([^\]]+)\]", text)
        if not domain_match:
            domain_match = re.search(r"Domain=\[([^\]]+)\]", text)
        if domain_match:
            result.domain = domain_match.group(1)

        return result

    def parse_share_access(self, text: str, share_name: str) -> SmbShare:
        """Parse smbclient share access output (dir listing).

        Args:
            text: Raw smbclient directory listing output.
            share_name: Name of the share tested.

        Returns:
            SmbShare with access results.
        """
        share = SmbShare(name=share_name)

        if self._is_access_denied(text):
            share.accessible = False
            share.permissions = "denied"
        elif "NT_STATUS_BAD_NETWORK_NAME" in text:
            share.accessible = False
            share.permissions = "not_found"
        elif "NT_STATUS" in text:
            share.accessible = False
            share.permissions = "error"
        else:
            share.accessible = True
            share.permissions = "read"

            # Parse file listing
            for match in re.finditer(
                r"^\s+(.+?)\s+(\d+)\s+\w{3}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4}$",
                text, re.MULTILINE
            ):
                filename = match.group(1).strip()
                size = match.group(2)
                if filename not in (".", ".."):
                    share.files.append({
                        "name": filename,
                        "size": size,
                    })

        return share

    def get_interesting_shares(self, result: SmbResult) -> List[SmbShare]:
        """Get non-default shares that may contain useful data.

        Args:
            result: SmbResult to filter.

        Returns:
            List of interesting shares.
        """
        return [
            s for s in result.shares
            if s.name not in self.SYSTEM_SHARES and s.share_type == "Disk"
        ]

    @staticmethod
    def _is_access_denied(text: str) -> bool:
        """Check if output indicates access denied.

        Broader than a single NT_STATUS_ACCESS_DENIED check: also
        catches NT_STATUS_LOGON_FAILURE/NT_STATUS_ACCOUNT_DISABLED and
        bare ACCESS_DENIED/LOGON_FAILURE strings some smbclient
        versions/locales emit without the NT_STATUS_ prefix. Deliberately
        excludes NT_STATUS_BAD_NETWORK_NAME — unlike
        modules/ad/parsers/smb_parser.py's ADSmbParser._is_access_denied()
        (which lumps it into "denied"), this module keeps it as a
        distinct "not_found" classification in parse_share_access().
        """
        denied_patterns = [
            "NT_STATUS_ACCESS_DENIED",
            "NT_STATUS_LOGON_FAILURE",
            "NT_STATUS_ACCOUNT_DISABLED",
            "ACCESS_DENIED",
            "LOGON_FAILURE",
        ]
        text_upper = text.upper()
        return any(p.upper() in text_upper for p in denied_patterns)
