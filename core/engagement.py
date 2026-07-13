"""ReconForge Engagement Manager - Engagement lifecycle tracking.

Author: Andrews Ferreira

Tracks engagement metadata (client, scope, timeline, operator), persists
sessions so they can be paused and resumed, aggregates reporting across
all modules, and maintains a timeline of all actions.

Usage::

    eng = EngagementManager(
        name="Q1 External Pentest",
        client="Acme Corp",
        operator="Andrews Ferreira",
        scope=["10.10.10.0/24", "web.acme.com"],
    )
    eng.start()
    eng.record_action("network", "Launched network module")
    eng.save("/tmp/engagement.json")

    # Later…
    eng = EngagementManager.load("/tmp/engagement.json")
    eng.resume()
"""

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.exceptions import EngagementError, EngagementNotFoundError
from core.version import __version__


# ── Status constants ─────────────────────────────────────────────────

ENGAGEMENT_STATUSES = ("planning", "active", "paused", "completed", "cancelled")


# ── Data classes ─────────────────────────────────────────────────────

@dataclass
class TimelineEntry:
    """A single entry in the engagement timeline."""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    module: str = ""
    action: str = ""
    detail: str = ""
    operator: str = ""


@dataclass
class EngagementMeta:
    """Core engagement metadata."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    name: str = ""
    client: str = ""
    operator: str = ""
    scope: List[str] = field(default_factory=list)
    status: str = "planning"
    start_time: str = ""
    end_time: str = ""
    pause_time: str = ""
    tags: List[str] = field(default_factory=list)
    notes: str = ""


# ── Manager ──────────────────────────────────────────────────────────

class EngagementManager:
    """Manage the lifecycle of an engagement session.

    Tracks metadata, module execution history, aggregated findings
    counts, and provides save/resume capabilities.
    """

    def __init__(
        self,
        name: str = "",
        client: str = "",
        operator: str = "",
        scope: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        notes: str = "",
    ):
        self.meta = EngagementMeta(
            name=name, client=client, operator=operator,
            scope=scope or [], tags=tags or [], notes=notes,
        )
        self._timeline: List[TimelineEntry] = []
        self._module_results: Dict[str, Dict[str, Any]] = {}
        self._findings_summary: Dict[str, int] = {}
        self._loot_summary: Dict[str, int] = {}

    # ── Lifecycle ────────────────────────────────────────────────────

    @property
    def status(self) -> str:
        return self.meta.status

    def start(self):
        """Transition to active state."""
        if self.meta.status not in ("planning", "paused"):
            raise EngagementError(
                f"Cannot start engagement in '{self.meta.status}' state"
            )
        self.meta.status = "active"
        self.meta.start_time = self.meta.start_time or datetime.now().isoformat()
        self._timeline.append(TimelineEntry(
            action="engagement_started",
            detail=f"Engagement '{self.meta.name}' started",
            operator=self.meta.operator,
        ))

    def pause(self):
        """Pause the engagement."""
        if self.meta.status != "active":
            raise EngagementError(
                f"Cannot pause engagement in '{self.meta.status}' state"
            )
        self.meta.status = "paused"
        self.meta.pause_time = datetime.now().isoformat()
        self._timeline.append(TimelineEntry(
            action="engagement_paused",
            detail="Engagement paused",
            operator=self.meta.operator,
        ))

    def resume(self):
        """Resume a paused engagement."""
        if self.meta.status != "paused":
            raise EngagementError(
                f"Cannot resume engagement in '{self.meta.status}' state"
            )
        self.meta.status = "active"
        self.meta.pause_time = ""
        self._timeline.append(TimelineEntry(
            action="engagement_resumed",
            detail="Engagement resumed",
            operator=self.meta.operator,
        ))

    def complete(self):
        """Mark engagement as completed."""
        if self.meta.status not in ("active", "paused"):
            raise EngagementError(
                f"Cannot complete engagement in '{self.meta.status}' state"
            )
        self.meta.status = "completed"
        self.meta.end_time = datetime.now().isoformat()
        self._timeline.append(TimelineEntry(
            action="engagement_completed",
            detail="Engagement completed",
            operator=self.meta.operator,
        ))

    def cancel(self):
        """Cancel the engagement."""
        self.meta.status = "cancelled"
        self.meta.end_time = datetime.now().isoformat()
        self._timeline.append(TimelineEntry(
            action="engagement_cancelled",
            detail="Engagement cancelled",
            operator=self.meta.operator,
        ))

    # ── Timeline / Actions ───────────────────────────────────────────

    def record_action(self, module: str, action: str,
                      detail: str = "", operator: str = ""):
        """Record an action in the engagement timeline."""
        self._timeline.append(TimelineEntry(
            module=module, action=action, detail=detail,
            operator=operator or self.meta.operator,
        ))

    def record_module_result(self, module: str, result: Dict[str, Any]):
        """Store the result dict from a module run."""
        self._module_results[module] = result
        self.record_action(module, "module_completed",
                           detail=f"Module '{module}' completed")

    def get_timeline(self) -> List[Dict[str, str]]:
        """Return the full timeline as a list of dicts."""
        return [asdict(e) for e in self._timeline]

    # ── Aggregated reporting ─────────────────────────────────────────

    def update_findings_summary(self, findings_manager):
        """Aggregate findings counts from a FindingsManager."""
        for sev, count in findings_manager.count_by_severity().items():
            self._findings_summary[sev] = (
                self._findings_summary.get(sev, 0) + count
            )

    def update_loot_summary(self, loot_manager):
        """Aggregate loot counts from a LootManager."""
        for ltype, count in loot_manager.summary().items():
            self._loot_summary[ltype] = (
                self._loot_summary.get(ltype, 0) + count
            )

    @property
    def findings_summary(self) -> Dict[str, int]:
        return dict(self._findings_summary)

    @property
    def loot_summary(self) -> Dict[str, int]:
        return dict(self._loot_summary)

    @property
    def modules_run(self) -> List[str]:
        return list(self._module_results.keys())

    # ── Persistence ──────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the engagement to a dict."""
        return {
            "meta": asdict(self.meta),
            "timeline": [asdict(e) for e in self._timeline],
            "module_results": self._module_results,
            "findings_summary": self._findings_summary,
            "loot_summary": self._loot_summary,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)

    def save(self, path: Path):
        """Save engagement state to a JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json())

    @classmethod
    def load(cls, path: Path) -> "EngagementManager":
        """Load a saved engagement session.

        Raises:
            EngagementNotFoundError: If the file does not exist.
        """
        path = Path(path)
        if not path.exists():
            raise EngagementNotFoundError(f"Engagement file not found: {path}")

        data = json.loads(path.read_text())
        meta_dict = data.get("meta", {})

        eng = cls(
            name=meta_dict.get("name", ""),
            client=meta_dict.get("client", ""),
            operator=meta_dict.get("operator", ""),
            scope=meta_dict.get("scope", []),
            tags=meta_dict.get("tags", []),
            notes=meta_dict.get("notes", ""),
        )
        # Restore meta fields
        eng.meta.id = meta_dict.get("id", eng.meta.id)
        eng.meta.status = meta_dict.get("status", "planning")
        eng.meta.start_time = meta_dict.get("start_time", "")
        eng.meta.end_time = meta_dict.get("end_time", "")
        eng.meta.pause_time = meta_dict.get("pause_time", "")

        # Restore timeline
        for entry_dict in data.get("timeline", []):
            eng._timeline.append(TimelineEntry(**entry_dict))

        # Restore results
        eng._module_results = data.get("module_results", {})
        eng._findings_summary = data.get("findings_summary", {})
        eng._loot_summary = data.get("loot_summary", {})

        return eng

    # ── Report generation ────────────────────────────────────────────

    def to_markdown(self) -> str:
        """Generate a Markdown engagement summary."""
        lines: List[str] = []
        lines.append("# Engagement Report\n")
        lines.append(f"**Engagement:** {self.meta.name}")
        lines.append(f"**Client:** {self.meta.client}")
        lines.append(f"**Operator:** {self.meta.operator}")
        lines.append(f"**Status:** {self.meta.status}")
        lines.append(f"**ID:** {self.meta.id}")
        if self.meta.start_time:
            lines.append(f"**Started:** {self.meta.start_time}")
        if self.meta.end_time:
            lines.append(f"**Ended:** {self.meta.end_time}")
        if self.meta.scope:
            lines.append(f"**Scope:** {', '.join(self.meta.scope)}")
        if self.meta.tags:
            lines.append(f"**Tags:** {', '.join(self.meta.tags)}")
        lines.append("")

        # Findings summary
        if self._findings_summary:
            lines.append("## Findings Summary\n")
            icon_map = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                        "low": "🔵", "info": "⚪"}
            total = sum(self._findings_summary.values())
            lines.append(f"**Total:** {total}\n")
            for sev in ("critical", "high", "medium", "low", "info"):
                count = self._findings_summary.get(sev, 0)
                if count:
                    icon = icon_map.get(sev, "⚪")
                    lines.append(f"- {icon} **{sev.upper()}:** {count}")
            lines.append("")

        # Loot summary
        if self._loot_summary:
            lines.append("## Loot Summary\n")
            for ltype, count in sorted(self._loot_summary.items()):
                lines.append(f"- **{ltype}:** {count}")
            lines.append("")

        # Modules
        if self._module_results:
            lines.append("## Modules Executed\n")
            for mod in self._module_results:
                lines.append(f"- {mod}")
            lines.append("")

        # Timeline
        if self._timeline:
            lines.append("## Timeline\n")
            for entry in self._timeline:
                mod = f"[{entry.module}] " if entry.module else ""
                lines.append(
                    f"- **{entry.timestamp}** {mod}{entry.action}"
                    + (f" — {entry.detail}" if entry.detail else "")
                )
            lines.append("")

        if self.meta.notes:
            lines.append("## Notes\n")
            lines.append(self.meta.notes)
            lines.append("")

        lines.append(f"\n---\n*Generated by ReconForge v{__version__}*\n")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"<EngagementManager name={self.meta.name!r} "
            f"status={self.meta.status!r} modules={self.modules_run}>"
        )
