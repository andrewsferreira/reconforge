"""ReconForge Hydra Tool Wrapper - Authentication testing (OPT-IN ONLY).

⚠️  WARNING: Hydra performs active authentication testing.
    This tool is opt-in only and requires explicit user confirmation.

All commands are built as structured argument lists (list[str]) to
prevent shell injection and improve reliability.

Config-aware: when a :class:`ConfigLoader` is provided, timeouts and
safety settings are read from ``tools.yaml``.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from core.runner import Runner, RunResult
from core.tool_config import ToolConfig

if TYPE_CHECKING:
    from core.config_loader import ConfigLoader


class HydraTool:
    """Wrapper for hydra authentication testing.

    ⚠️  This tool is opt-in only. All methods require explicit
    confirmation that brute-force testing is authorized.
    """

    TOOL_NAME = "hydra"

    # Common default credential pairs for testing
    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "admin123"),
        ("root", "root"),
        ("root", "toor"),
        ("administrator", "password"),
        ("guest", "guest"),
        ("user", "user"),
        ("test", "test"),
    ]

    def __init__(self, runner: Runner, logger, output_dir: Path,
                 authorized: bool = False,
                 config: Optional["ConfigLoader"] = None):
        self.runner = runner
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.authorized = authorized
        self.tool_cfg = ToolConfig(config, self.TOOL_NAME)

    def is_available(self) -> bool:
        """Check if hydra is installed."""
        return self.runner.check_tool(self.TOOL_NAME)

    def _check_authorization(self) -> bool:
        """Verify that brute-force testing is authorized."""
        if not self.authorized:
            self.logger.warning(
                "Hydra brute-force testing requires explicit opt-in. "
                "Set authorized=True or use --brute-force flag."
            )
            return False
        return True

    def _max_tasks(self) -> int:
        """Max parallel tasks from config or default 4."""
        return int(self.tool_cfg.safety("max_tasks", 4))

    def _wait_time(self) -> int:
        """Wait time between connections from config or default 3."""
        return int(self.tool_cfg.safety("wait_time", 3))

    def _build_cmd(self, target: str, service: str,
                   port: Optional[int] = None,
                   userlist: Optional[str] = None,
                   passlist: Optional[str] = None,
                   username: Optional[str] = None,
                   password: Optional[str] = None,
                   extra_args: Optional[List[str]] = None) -> List[str]:
        """Build hydra command as a list."""
        cmd: List[str] = ["hydra"]

        if username:
            cmd += ["-l", username]
        elif userlist:
            cmd += ["-L", userlist]

        if password:
            cmd += ["-p", password]
        elif passlist:
            cmd += ["-P", passlist]

        # Rate limiting from config safety settings
        cmd += ["-t", str(self._max_tasks())]
        cmd += ["-W", str(self._wait_time())]

        if extra_args:
            cmd.extend(extra_args)

        output_file = self.output_dir / f"hydra_{service}.txt"
        cmd += ["-o", str(output_file)]

        if port:
            cmd += ["-s", str(port)]

        cmd.append(target)
        cmd.append(service)

        return cmd

    def test_default_creds(self, target: str, service: str,
                           port: Optional[int] = None,
                           timeout: int = 120) -> RunResult:
        """Test common default credentials."""
        if not self._check_authorization():
            return RunResult(
                command="hydra [blocked]", returncode=-1, stdout="",
                stderr="Not authorized for brute-force testing",
                duration=0.0, success=False
            )

        self.logger.warning(f"⚠️  Testing default credentials on {target}:{service}")
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)

        # Create temp credential files
        user_file = self.output_dir / f"hydra_{service}_users.txt"
        pass_file = self.output_dir / f"hydra_{service}_passwords.txt"

        users = sorted(set(u for u, _ in self.DEFAULT_CREDS))
        passwords = sorted(set(p for _, p in self.DEFAULT_CREDS))

        user_file.write_text("\n".join(users) + "\n")
        pass_file.write_text("\n".join(passwords) + "\n")

        cmd = self._build_cmd(
            target, service, port=port,
            userlist=str(user_file), passlist=str(pass_file)
        )
        return self.runner.run(cmd, timeout=effective_timeout)

    def test_credentials(self, target: str, service: str,
                         userlist: str, passlist: str,
                         port: Optional[int] = None,
                         timeout: int = 300) -> RunResult:
        """Test credentials from custom wordlists."""
        if not self._check_authorization():
            return RunResult(
                command="hydra [blocked]", returncode=-1, stdout="",
                stderr="Not authorized for brute-force testing",
                duration=0.0, success=False
            )

        self.logger.warning(f"⚠️  Running credential test on {target}:{service}")
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        cmd = self._build_cmd(
            target, service, port=port,
            userlist=userlist, passlist=passlist
        )
        return self.runner.run(cmd, timeout=effective_timeout)

    def test_single_cred(self, target: str, service: str,
                         username: str, password: str,
                         port: Optional[int] = None,
                         timeout: int = 30) -> RunResult:
        """Test a single credential pair."""
        if not self._check_authorization():
            return RunResult(
                command="hydra [blocked]", returncode=-1, stdout="",
                stderr="Not authorized for brute-force testing",
                duration=0.0, success=False
            )

        self.logger.warning(f"⚠️  Testing {username}:{password} on {target}:{service}")
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        cmd = self._build_cmd(
            target, service, port=port,
            username=username, password=password
        )
        return self.runner.run(cmd, timeout=effective_timeout)
