"""ReconForge AD - SMB Output Parser.

Parses smbclient output to extract:
- Share listings
- Null session results
- Share accessibility
- Permission details

Author: Andrews Ferreira
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class SmbShare:
    """A discovered SMB share."""
    name: str = ""
    share_type: str = ""  # Disk, IPC, Printer
    comment: str = ""
    accessible: bool = False
    anonymous: bool = False
    permissions: str = ""  # read, write, read/write, denied


@dataclass
class SmbResult:
    """Structured result from SMB enumeration."""
    shares: List[SmbShare] = field(default_factory=list)
    null_session_allowed: bool = False
    smb_signing: str = ""
    os_info: str = ""
    server_name: str = ""
    domain: str = ""
    raw: str = ""


class ADSmbParser:
    """Parse smbclient and SMB-related output."""

    def parse_share_list(self, text: str, anonymous: bool = False) -> SmbResult:
        """Parse smbclient -L output.

        Args:
            text: smbclient output text.
            anonymous: Whether this was a null session attempt.

        Returns:
            SmbResult with discovered shares.
        """
        result = SmbResult(raw=text)

        # Detect null session success/failure
        if anonymous:
            if self._is_access_denied(text):
                result.null_session_allowed = False
            else:
                result.null_session_allowed = True

        # Parse share table
        # Format:  "    ShareName        Disk      Some comment"
        for m in re.finditer(
            r"^\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*?)$",
            text, re.MULTILINE
        ):
            share = SmbShare(
                name=m.group(1),
                share_type=m.group(2),
                comment=m.group(3).strip(),
                anonymous=anonymous and result.null_session_allowed,
            )
            result.shares.append(share)

        # Server / domain info
        m = re.search(r"Domain=\[([^\]]+)\]", text)
        if m:
            result.domain = m.group(1)
        m = re.search(r"OS=\[([^\]]+)\]", text)
        if m:
            result.os_info = m.group(1)

        return result

    def parse_share_access(self, text: str, share_name: str) -> SmbShare:
        """Parse output from a share access test (smbclient //host/share -c 'dir')."""
        share = SmbShare(name=share_name)

        if self._is_access_denied(text):
            share.accessible = False
            share.permissions = "denied"
        elif "NT_STATUS_" in text:
            share.accessible = False
            share.permissions = "error"
        else:
            share.accessible = True
            # If we see file listing output it's at least readable
            if re.search(r"\d+\s+blocks", text) or re.search(r"<DIR>", text, re.I):
                share.permissions = "read"
            else:
                share.permissions = "read"  # dir succeeded

        return share

    def parse_admin_share_results(self, results: Dict[str, bool]) -> List[SmbShare]:
        """Parse admin share test results dict."""
        shares = []
        for name, accessible in results.items():
            shares.append(SmbShare(
                name=name,
                share_type="Disk" if name != "IPC$" else "IPC",
                accessible=accessible,
                permissions="accessible" if accessible else "denied",
            ))
        return shares

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_access_denied(text: str) -> bool:
        """Check if output indicates access denied."""
        denied_patterns = [
            "NT_STATUS_ACCESS_DENIED",
            "NT_STATUS_LOGON_FAILURE",
            "NT_STATUS_ACCOUNT_DISABLED",
            "NT_STATUS_BAD_NETWORK_NAME",
            "ACCESS_DENIED",
            "LOGON_FAILURE",
        ]
        text_upper = text.upper()
        return any(p.upper() in text_upper for p in denied_patterns)
