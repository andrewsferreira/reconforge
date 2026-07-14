"""Sanitization primitives for content that may originate from a scanned
target (docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md §5, "Untrusted-Content
Handling").

Every string that could contain target-controlled text — a finding's
``description``/``evidence``, and anything derived from parsed tool
output in future phases — must pass through :func:`sanitize_untrusted_text`
before being embedded in an MCP response. None of the transformations
here interpret content as instructions: they bound, filter, and
normalize it as inert data. The one thing this module cannot do is stop
a client from choosing to *act on* text it receives — that responsibility
belongs to the client (Claude), which is why every MCP response also
carries an explicit trust label (``trust: "server_generated"`` at the
response root, ``trusted_metadata``/``untrusted_evidence`` field
separation within it) rather than relying on sanitization alone.
"""

from __future__ import annotations

import re
import unicodedata

from core.logger import sanitize_log

# Interim fixed limits — become the configurable mcp.max_evidence_bytes /
# mcp.max_response_bytes settings from docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md
# §9 once that config section is built (a later phase).
MAX_EVIDENCE_CHARS = 4000
MAX_EVIDENCE_LINES = 200

# C0 control characters and DEL, excluding \t \n \r which are legitimate
# in multi-line evidence text.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# ANSI/terminal escape sequences: CSI (`\x1b[...<letter>`), OSC
# (`\x1b]...BEL` or `\x1b]...ST`), and the shorter two-character Fe
# escape sequences. A banner or HTTP response body can carry these to
# manipulate a terminal that renders it directly; MCP responses are JSON,
# not a terminal, but a downstream client or log viewer might render this
# text in one, so it's stripped here rather than assumed harmless.
_ANSI_ESCAPE_RE = re.compile(r"\x1b(?:\[[0-9;?]*[a-zA-Z]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\\-_])")


def is_binary_content(value: bytes) -> bool:
    """Best-effort check for whether *value* looks like non-text binary data.

    Not currently reachable from any existing tool's response path — the
    two content sources this phase has (findings.json fields, dry-run's
    Runner.get_command_log()) are always already-decoded ``str``, since
    JSON requires valid UTF-8 and Runner only ever logs text it
    constructed itself. Provided now so a future phase (a raw command
    output or HTTP body viewer) has a tested rejection path to call
    rather than inventing one under time pressure then.
    """
    try:
        value.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def sanitize_untrusted_text(
    value: str,
    *,
    max_chars: int = MAX_EVIDENCE_CHARS,
    max_lines: int = MAX_EVIDENCE_LINES,
) -> tuple[str, bool]:
    """Bound and neutralize a string that may contain target-controlled content.

    Applies, in order: Unicode NFC normalization (so visually-identical
    lookalike characters compare consistently), ANSI/terminal escape
    stripping, control-character stripping, secret redaction
    (``core/logger.py::sanitize_log``), then line- and byte-length
    truncation. Returns ``(sanitized_text, truncated)``. Never raises —
    this function assumes *value* is already a Python ``str``; a caller
    holding raw bytes should check :func:`is_binary_content` first.
    """
    text = unicodedata.normalize("NFC", value)
    text = _ANSI_ESCAPE_RE.sub("", text)
    text = _CONTROL_CHAR_RE.sub("", text)
    text = sanitize_log(text)

    truncated = False
    lines = text.split("\n")
    if len(lines) > max_lines:
        text = "\n".join(lines[:max_lines])
        truncated = True

    if len(text.encode("utf-8", errors="ignore")) > max_chars:
        text = text.encode("utf-8", errors="ignore")[:max_chars].decode("utf-8", errors="ignore")
        truncated = True

    if truncated:
        text = f"{text}\n...[truncated]"

    return text, truncated
