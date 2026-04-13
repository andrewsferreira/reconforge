"""ReconForge Logger - Structured logging with color-coded output."""

import logging
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


# ── Credential sanitization patterns ────────────────────────────────
_SANITIZE_PATTERNS = [
    # password=... / -p ... / --password ...  (quoted or unquoted)
    (re.compile(
        r"""(?i)(password|passwd|pass|pwd)\s*[=:]\s*['"]?[^\s'"]{1,}['"]?"""),
     r"\1=***REDACTED***"),
    # -p <value> (short flag in CLI commands)
    (re.compile(r"""(?<!\w)-p\s+(?![\-])\S+"""), "-p ***REDACTED***"),
    # API keys / tokens / secrets (common env / header patterns)
    (re.compile(
        r"""(?i)(api[_-]?key|token|secret|authorization|bearer)\s*[=:]\s*['"]?\S+['"]?"""),
     r"\1=***REDACTED***"),
    # NTLM hashes  (LM:NT)
    (re.compile(r"""(?i)[a-f0-9]{32}:[a-f0-9]{32}"""), "***HASH_REDACTED***"),
    # Standalone 32-hex strings that look like hashes (MD5/NTLM)
    (re.compile(r"""\b[a-f0-9]{32}\b"""), "***HASH_REDACTED***"),
    # Base64 Bearer tokens (at least 20 chars)
    (re.compile(r"""(?i)Bearer\s+[A-Za-z0-9+/=]{20,}"""), "Bearer ***REDACTED***"),
]


def sanitize_log(message: str) -> str:
    """Redact passwords, tokens, API keys, and hashes from a log message.

    Args:
        message: Raw log message that may contain secrets.

    Returns:
        Sanitised string safe for log output.
    """
    for pattern, replacement in _SANITIZE_PATTERNS:
        message = pattern.sub(replacement, message)
    return message


class ReconLogger:
    """Centralized logger for ReconForge with file and console output."""

    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[41m",  # Red background
        "RESET": "\033[0m",
    }

    ICONS = {
        "DEBUG": "[*]",
        "INFO": "[+]",
        "WARNING": "[!]",
        "ERROR": "[-]",
        "CRITICAL": "[X]",
    }

    def __init__(self, name: str = "reconforge", log_dir: Optional[Path] = None, verbose: bool = False):
        self.name = name
        self.verbose = verbose
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.logger.handlers.clear()

        # Console handler
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.DEBUG if verbose else logging.INFO)
        console.setFormatter(self._ColorFormatter(self.COLORS, self.ICONS))
        self.logger.addHandler(console)

        # File handler
        if log_dir:
            log_dir = Path(log_dir)
            log_dir.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(log_dir / f"reconforge_{datetime.now():%Y%m%d_%H%M%S}.log")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
            self.logger.addHandler(fh)

    class _ColorFormatter(logging.Formatter):
        def __init__(self, colors, icons):
            super().__init__()
            self.colors = colors
            self.icons = icons

        def format(self, record):
            color = self.colors.get(record.levelname, "")
            reset = self.colors["RESET"]
            icon = self.icons.get(record.levelname, "[?]")
            ts = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
            return f"{color}{icon} [{ts}] {record.getMessage()}{reset}"

    def debug(self, msg: str, *args, **kwargs):
        self.logger.debug(msg, *args, **kwargs)

    def info(self, msg: str, *args, **kwargs):
        self.logger.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs):
        self.logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args, **kwargs):
        self.logger.error(msg, *args, **kwargs)

    def critical(self, msg: str, *args, **kwargs):
        self.logger.critical(msg, *args, **kwargs)

    def command(self, cmd: str):
        """Log a command being executed (credentials are redacted)."""
        self.logger.info(f"EXEC: {sanitize_log(cmd)}")

    def finding(self, severity: str, description: str):
        """Log a finding."""
        self.logger.warning(f"FINDING [{severity.upper()}]: {description}")

    def loot(self, loot_type: str, value: str):
        """Log loot discovery (sensitive values redacted)."""
        self.logger.info(f"LOOT [{loot_type}]: {sanitize_log(value)}")

    # ── Structured context logging (10/10 upgrade) ───────────────────

    def with_context(self, **fields) -> "ContextLogger":
        """Return a child logger that prepends *fields* to every message.

        Usage::

            log = logger.with_context(module="network", phase="scanning")
            log.info("Starting port scan")
            # => [+] [12:00:00] [network/scanning] Starting port scan
        """
        return ContextLogger(self, fields)

    def workflow(self, step: str, detail: str = ""):
        """Log a workflow-level event."""
        msg = f"WORKFLOW [{step}]"
        if detail:
            msg += f": {detail}"
        self.logger.info(msg)

    def credential(self, username: str, source: str):
        """Log credential discovery (password is never logged)."""
        self.logger.info(f"CRED: user={sanitize_log(username)} from {source}")

    def phase_start(self, phase: str):
        """Log the start of a module phase."""
        self.logger.info(f"▶ Phase: {phase}")

    def phase_end(self, phase: str, summary: str = ""):
        """Log the end of a module phase."""
        msg = f"✓ Phase complete: {phase}"
        if summary:
            msg += f" — {summary}"
        self.logger.info(msg)


class ContextLogger:
    """Lightweight wrapper that prefixes context fields to log messages.

    Created via :meth:`ReconLogger.with_context`.
    """

    def __init__(self, parent: ReconLogger, fields: dict):
        self._parent = parent
        parts = [f"{v}" for v in fields.values()]
        self._prefix = "[" + "/".join(parts) + "] " if parts else ""

    def _fmt(self, msg: str) -> str:
        return f"{self._prefix}{msg}"

    def debug(self, msg: str, *a, **kw):
        self._parent.debug(self._fmt(msg), *a, **kw)

    def info(self, msg: str, *a, **kw):
        self._parent.info(self._fmt(msg), *a, **kw)

    def warning(self, msg: str, *a, **kw):
        self._parent.warning(self._fmt(msg), *a, **kw)

    def error(self, msg: str, *a, **kw):
        self._parent.error(self._fmt(msg), *a, **kw)

    def critical(self, msg: str, *a, **kw):
        self._parent.critical(self._fmt(msg), *a, **kw)

    def command(self, cmd: str):
        self._parent.command(f"{self._prefix}{cmd}")

    def finding(self, severity: str, description: str):
        self._parent.finding(severity, f"{self._prefix}{description}")

    def loot(self, loot_type: str, value: str):
        self._parent.loot(loot_type, f"{self._prefix}{value}")
