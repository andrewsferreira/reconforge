"""ReconForge ffuf Tool Wrapper - Fast web fuzzer.

Author: Andrews Ferreira

All commands are built as structured argument lists (list[str]) to
prevent shell injection and improve reliability.

Config-aware: when a :class:`ConfigLoader` is provided, timeouts and
mode arguments are read from ``tools.yaml``.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from core.runner import Runner, RunResult, RC_PRECONDITION_FAILED
from core.tool_config import ToolConfig

if TYPE_CHECKING:
    from core.config_loader import ConfigLoader


class FfufTool:
    """Wrapper for ffuf web fuzzing."""

    TOOL_NAME = "ffuf"

    DEFAULT_WORDLISTS = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    ]

    def __init__(self, runner: Runner, logger, output_dir: Path,
                 opsec_mode: str = "normal",
                 config: Optional["ConfigLoader"] = None):
        self.runner = runner
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.opsec_mode = opsec_mode
        self.tool_cfg = ToolConfig(config, self.TOOL_NAME)

    def is_available(self) -> bool:
        return self.runner.check_tool(self.TOOL_NAME)

    def _threads(self) -> int:
        return {"stealth": 5, "normal": 20, "aggressive": 50}.get(
            self.opsec_mode, 20
        )

    def _rate(self) -> int:
        return {"stealth": 10, "normal": 100, "aggressive": 0}.get(
            self.opsec_mode, 100
        )

    def resolve_wordlist(self, custom: str = "") -> str:
        """Find a wordlist that exists on disk."""
        if custom and Path(custom).is_file():
            return custom
        for wl in self.DEFAULT_WORDLISTS:
            if Path(wl).is_file():
                return wl
        return ""

    def dir_scan(self, target_url: str, wordlist: str = "",
                 match_codes: str = "200,204,301,302,307,401,403,405,500",
                 timeout: int = 600) -> RunResult:
        """Directory/file discovery scan."""
        wordlist = self.resolve_wordlist(wordlist)
        if not wordlist:
            self.logger.warning("No wordlist found for ffuf")
            return RunResult(
                command="ffuf", returncode=RC_PRECONDITION_FAILED, stdout="", stderr="No wordlist found",
                duration=0.0, success=False,
            )

        json_path = self.output_dir / "ffuf_dirs.json"
        threads = self._threads()
        rate = self._rate()
        effective_timeout = self.tool_cfg.effective_timeout(self.opsec_mode, timeout)

        cmd: List[str] = [
            "ffuf", "-u", f"{target_url}/FUZZ", "-w", wordlist,
            "-t", str(threads), "-mc", match_codes,
            "-o", str(json_path), "-of", "json", "-noninteractive",
        ]
        if rate > 0:
            cmd += ["-rate", str(rate)]

        self.logger.info(f"Running ffuf dir scan on {target_url} (threads={threads})")
        # ffuf's own -o/-of json already writes json_path — passing
        # output_file= too would let Runner.run() overwrite it with ffuf's
        # non-JSON stdout results table (ffuf isn't run with -s/silent),
        # which FfufParser.parse_json()'s strict json.loads() then fails
        # to parse and silently returns zero findings. Same class of bug
        # fixed in curl_tool.py and whatweb.py.
        return self.runner.run(cmd, timeout=effective_timeout)

    def vhost_scan(self, target_url: str, wordlist: str = "",
                   timeout: int = 600) -> RunResult:
        """Virtual host discovery scan."""
        wordlist = self.resolve_wordlist(wordlist)
        if not wordlist:
            return RunResult(
                command="ffuf", returncode=RC_PRECONDITION_FAILED, stdout="", stderr="No wordlist",
                duration=0.0, success=False,
            )

        json_path = self.output_dir / "ffuf_vhosts.json"
        threads = self._threads()
        effective_timeout = self.tool_cfg.effective_timeout(self.opsec_mode, timeout)

        cmd: List[str] = [
            "ffuf", "-u", target_url,
            "-H", "Host: FUZZ.target",
            "-w", wordlist, "-t", str(threads),
            "-o", str(json_path), "-of", "json",
            "-noninteractive", "-fs", "0",
        ]

        self.logger.info(f"Running ffuf vhost scan on {target_url}")
        # See dir_scan() above — output_file= must not be passed here either.
        return self.runner.run(cmd, timeout=effective_timeout)

    def get_json_path(self, scan_type: str = "dirs") -> Path:
        return self.output_dir / f"ffuf_{scan_type}.json"
