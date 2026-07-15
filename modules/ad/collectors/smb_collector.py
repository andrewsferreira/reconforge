"""ReconForge AD Collector — SMB data gathering.

Author: Andrews Ferreira

Collects share lists, access levels, null session status,
and admin share accessibility via SMB.
"""

from typing import Any

from modules.ad.collectors.base import CollectorBase, CollectorResult
from modules.ad.parsers.enum4linux_ng_parser import Enum4linuxNgParser
from modules.ad.parsers.smb_parser import ADSmbParser
from modules.ad.tools.enum4linux_ng import Enum4linuxNgTool
from modules.ad.tools.smbclient import ADSmbclientTool


class SmbCollector(CollectorBase):
    """Pure SMB data collection — shares, sessions, null sessions."""

    COLLECTOR_NAME = "smb"

    def __init__(self, smbclient: ADSmbclientTool,
                 enum4linux_ng: Enum4linuxNgTool,
                 smb_parser: ADSmbParser,
                 enum4linux_ng_parser: Enum4linuxNgParser,
                 **kwargs) -> None:
        super().__init__(**kwargs)
        self.smbclient = smbclient
        self.enum4linux_ng = enum4linux_ng
        self.smb_parser = smb_parser
        self.enum_parser = enum4linux_ng_parser

    def collect(
        self,
        target: str,
        domain: str = "",
        base_dn: str = "",
        username: str = "",
        password: str = "",
        **kwargs,
    ) -> CollectorResult:
        """Collect all SMB data."""
        result = CollectorResult(source=self.COLLECTOR_NAME)

        result.data["null_session"] = self.collect_null_session(target)
        result.data["shares"] = self.collect_shares(
            target, username, password, domain,
            null_session=result.data["null_session"].get("allowed", False),
        )
        result.data["enum4linux"] = self.collect_enum4linux(
            target, username, password
        )

        result.success = True
        return result

    def collect_null_session(self, target: str) -> dict[str, Any]:
        """Test SMB null session and return share list."""
        if not self.smbclient.is_available():
            return {"allowed": False, "shares": []}
        if not self.opsec.check("smb_null_session"):
            return {"allowed": False, "shares": []}

        run = self.smbclient.null_session_list(target)
        parsed = self.smb_parser.parse_share_list(
            run.stdout + run.stderr, anonymous=True
        )
        return {
            "allowed": parsed.null_session_allowed,
            "shares": [
                {"name": s.name, "type": s.share_type,
                 "comment": s.comment, "accessible": s.accessible}
                for s in parsed.shares
            ],
        }

    def collect_shares(
        self, target: str, username: str = "", password: str = "",
        domain: str = "", null_session: bool = False,
    ) -> list[dict]:
        """Enumerate and test access to SMB shares."""
        if not self.smbclient.is_available():
            return []
        if not self.opsec.check("smb_share_access"):
            return []

        shares: list[dict] = []

        # Get share list
        if username and password:
            run = self.smbclient.authenticated_list(
                target, username, password, domain=domain
            )
            anonymous = False
        elif null_session:
            run = self.smbclient.null_session_list(target)
            anonymous = True
        else:
            return []

        parsed = self.smb_parser.parse_share_list(
            run.stdout + run.stderr, anonymous=anonymous
        )

        # Test important AD shares (admin-share access probing is noisier
        # than the base share listing above — gated separately)
        if self.opsec.check("smb_admin_shares"):
            for share_name in ["SYSVOL", "NETLOGON"]:
                access = self.smbclient.test_share_access(
                    target, share_name, username=username, password=password
                )
                share_parsed = self.smb_parser.parse_share_access(
                    access.stdout + access.stderr, share_name
                )
                shares.append({
                    "name": share_name,
                    "accessible": share_parsed.accessible,
                    "permissions": share_parsed.permissions,
                    "anonymous": anonymous and not username,
                })

        # Other discovered shares
        for share in parsed.shares:
            if share.name not in ("SYSVOL", "NETLOGON"):
                shares.append({
                    "name": share.name,
                    "type": share.share_type,
                    "comment": share.comment,
                    "accessible": share.accessible,
                })

        return shares

    def collect_enum4linux(
        self, target: str, username: str = "", password: str = "",
    ) -> dict[str, Any]:
        """Run enum4linux-ng full enum and return structured data."""
        if not self.enum4linux_ng.is_available():
            return {}
        if not self.opsec.check("enum4linux_ng_full"):
            return {}

        run = self.enum4linux_ng.full_enum(
            target, username=username, password=password
        )
        if not run.success:
            return {}

        json_path = self.enum4linux_ng.output_dir / "enum4linux_ng_full.json"
        if json_path.exists():
            parsed = self.enum_parser.parse_json(json_path)
        else:
            parsed = self.enum_parser.parse_text(run.stdout)

        return {
            "users": parsed.users,
            "groups": parsed.groups,
            "shares": parsed.shares,
            "password_policy": parsed.password_policy,
            "domain_sid": parsed.domain_sid,
        }
