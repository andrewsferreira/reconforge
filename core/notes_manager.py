"""ReconForge Notes Manager - Session documentation and timeline."""

from datetime import datetime
from pathlib import Path

from core.logger import sanitize_log


class NotesManager:
    """Manage session notes with timestamped entries."""

    def __init__(self, target: str = ""):
        self.target = target
        self._entries: list[dict] = []
        self._start_time = datetime.now()

    def add(self, note: str, category: str = "general"):
        """Add a timestamped note."""
        self._entries.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "category": category,
            "note": note,
        })

    def add_phase_start(self, phase: str):
        self.add(f"Starting phase: {phase}", "phase")

    def add_phase_end(self, phase: str, summary: str = ""):
        self.add(f"Completed phase: {phase}. {summary}", "phase")

    def add_finding_note(self, description: str):
        self.add(description, "finding")

    def add_command_note(self, command: str, result_summary: str = ""):
        """Record a command note, with secrets redacted from both fields.

        Session notes are persisted to disk as plain Markdown, so commands
        and result summaries (which may embed CLI-supplied credentials or
        tokens, e.g. from an authenticated tool run or a raw stderr excerpt)
        must never carry them through unredacted — same rule as command
        logs and the structured logger.
        """
        self.add(
            f"Command: `{sanitize_log(command)}` → {sanitize_log(result_summary)}",
            "command",
        )

    def to_markdown(self) -> str:
        lines = ["# Session Notes\n"]
        lines.append(f"**Target:** {self.target}")
        lines.append(f"**Started:** {self._start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Entries:** {len(self._entries)}\n")
        lines.append("## Timeline\n")

        for entry in self._entries:
            icon = {"phase": "🔄", "finding": "🎯", "command": "💻", "general": "📝"}.get(entry["category"], "📝")
            lines.append(f"- **[{entry['timestamp']}]** {icon} {entry['note']}")

        return "\n".join(lines)

    def save(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_markdown())
