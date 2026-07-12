"""ReconForge Logger - Structured logging with color-coded output."""

import logging
import json
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional


# ── Credential sanitization patterns ────────────────────────────────
# Order matters throughout this list: specific patterns for a value that
# would otherwise be a substring of a more generic pattern's match must run
# first. Example already found and fixed once (see git history): "Bearer
# <token>" has to be redacted before the generic "authorization=<value>"
# pattern, otherwise the generic pattern's \S+ only consumes the literal
# word "Bearer" (stopping at the following space) and leaves the actual
# token in "Authorization: Bearer <token>" unredacted. The private-key,
# cloud-credential, and connection-string patterns below are similarly
# ordered before the generic catch-all for the same reason.
_SANITIZE_PATTERNS = [
    # PEM private key blocks (RSA/EC/OPENSSH/DSA/generic). DOTALL so the
    # block is matched across embedded newlines when logged as one string.
    (re.compile(
        r"""-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"""
        r""".*?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----""",
        re.DOTALL),
     "***PRIVATE_KEY_REDACTED***"),
    # password=... / -p ... / --password ...  (quoted or unquoted)
    (re.compile(
        r"""(?i)(password|passwd|pass|pwd)\s*[=:]\s*['"]?[^\s'"]{1,}['"]?"""),
     r"\1=***REDACTED***"),
    # -p <value> (short flag in CLI commands)
    (re.compile(r"""(?<!\w)-p\s+(?![\-])\S+"""), "-p ***REDACTED***"),
    # Base64 Bearer / SPNEGO-Negotiate tokens (Kerberos-over-HTTP uses
    # "Authorization: Negotiate <base64 ticket>") — must run before the
    # generic api_key/token/secret/authorization pattern (see note above).
    (re.compile(r"""(?i)Bearer\s+[A-Za-z0-9+/=]{20,}"""), "Bearer ***REDACTED***"),
    (re.compile(r"""(?i)Negotiate\s+[A-Za-z0-9+/=]{20,}"""), "Negotiate ***REDACTED***"),
    # Cookie / Set-Cookie header or cookie=value field — one pattern for
    # both forms so the generic catch-all below never gets a second,
    # already-redacted-once value to needlessly re-match.
    (re.compile(r"""(?i)(Set-Cookie|Cookie)\s*[:=]\s*['"]?\S+['"]?"""), r"\1=***REDACTED***"),
    # AWS access key ID (AKIA/ASIA + 16 alnum) and secret access key by
    # field name — distinct patterns, an access key ID alone isn't secret
    # but is a strong enough indicator of adjacent secret material to
    # redact defensively.
    (re.compile(r"""\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"""), "***AWS_KEY_ID_REDACTED***"),
    (re.compile(
        r"""(?i)aws_secret_access_key\s*[=:]\s*['"]?\S+['"]?"""),
     "aws_secret_access_key=***REDACTED***"),
    # GCP API key
    (re.compile(r"""\bAIza[A-Za-z0-9_\-]{35}\b"""), "***GCP_KEY_REDACTED***"),
    # Azure storage connection-string account key. Connection strings are
    # ';'-delimited with no internal whitespace, so stop at ';' rather than
    # \S+ — otherwise this greedily eats the rest of the (non-sensitive)
    # connection string too (EndpointSuffix, etc.).
    (re.compile(r"""(?i)AccountKey\s*=\s*[^;\s]+"""), "AccountKey=***REDACTED***"),
    # Database connection strings with embedded credentials
    # (postgres://user:pass@host, mysql://..., mongodb://..., redis://...)
    (re.compile(
        r"""(?i)\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)://[^:@/\s]+:[^@/\s]+@"""),
     r"\1://***REDACTED***@"),
    # API keys / tokens / secrets (common env / header patterns). Negative
    # lookahead skips "Bearer"/"Negotiate" as the value — those are auth
    # scheme names already redacted (with their actual token) by the
    # dedicated patterns above; without this, "Authorization: Bearer
    # ***REDACTED***" gets re-matched here too, since \S+ is happy to
    # consume the literal word "Bearer" and turn it into a second,
    # redundant "***REDACTED***".
    (re.compile(
        r"""(?i)(api[_-]?key|token|secret|authorization|bearer)\s*[=:]\s*(?!(?:Bearer|Negotiate)\b)['"]?\S+['"]?"""),
     r"\1=***REDACTED***"),
    # NTLM hashes  (LM:NT)
    (re.compile(r"""(?i)[a-f0-9]{32}:[a-f0-9]{32}"""), "***HASH_REDACTED***"),
    # Standalone 32-hex strings that look like hashes (MD5/NTLM)
    (re.compile(r"""\b[a-f0-9]{32}\b"""), "***HASH_REDACTED***"),
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

    def __init__(self, name: str = "reconforge", log_dir: Optional[Path] = None, verbose: bool = False,
                 execution_id: Optional[str] = None):
        self.name = name
        self.verbose = verbose
        self.execution_id = execution_id or f"run_{uuid.uuid4().hex[:12]}"
        self._json_log_path: Optional[Path] = None
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.logger.handlers.clear()

        # Console handler
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.DEBUG if verbose else logging.INFO)
        console.setFormatter(self._ColorFormatter(self.COLORS, self.ICONS))
        self.logger.addHandler(console)

        # File handler
        if log_dir and isinstance(log_dir, (str, Path)):
            log_dir = Path(log_dir)
            log_dir.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(log_dir / f"reconforge_{datetime.now():%Y%m%d_%H%M%S}.log")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
            self.logger.addHandler(fh)
            self._json_log_path = log_dir / f"reconforge_{datetime.now():%Y%m%d_%H%M%S}.jsonl"

    def _json_event(self, level: str, message: str, **fields) -> None:
        if not self._json_log_path:
            return
        payload = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "logger": self.name,
            "execution_id": self.execution_id,
            "message": sanitize_log(message),
            **fields,
        }
        self._json_log_path.parent.mkdir(parents=True, exist_ok=True)
        with self._json_log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")

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
        self._json_event("DEBUG", msg)

    def info(self, msg: str, *args, **kwargs):
        self.logger.info(msg, *args, **kwargs)
        self._json_event("INFO", msg)

    def warning(self, msg: str, *args, **kwargs):
        self.logger.warning(msg, *args, **kwargs)
        self._json_event("WARNING", msg)

    def error(self, msg: str, *args, **kwargs):
        self.logger.error(msg, *args, **kwargs)
        self._json_event("ERROR", msg)

    def critical(self, msg: str, *args, **kwargs):
        self.logger.critical(msg, *args, **kwargs)
        self._json_event("CRITICAL", msg)

    def command(self, cmd: str):
        """Log a command being executed (credentials are redacted)."""
        self.logger.info(f"EXEC: {sanitize_log(cmd)}")

    def audit(self, event: str, **fields) -> None:
        """Emit a structured JSONL audit event (Phase 4 execution-layer
        requirement: every subprocess execution gets one).

        Unlike info()/warning()/etc., this does not also print to the
        console — it is a machine-readable record only, written to the
        same *.jsonl file as every other structured event, tagged with
        this logger's module-level execution_id automatically (see
        _json_event). Pass a per-call id in **fields (e.g.
        command_execution_id=...) to distinguish individual events within
        one module run.
        """
        self._json_event("AUDIT", event, **fields)

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
