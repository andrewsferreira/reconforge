"""ReconForge Attack Workflow - Kill chain tracking and hypothesis management."""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class WorkflowStep:
    """A single step in the attack workflow."""
    phase: str
    hypothesis: str
    command: str
    justification: str
    alternatives: list[str] = field(default_factory=list)
    result: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


@dataclass
class AttackPath:
    """An identified attack path."""
    name: str
    description: str
    steps: list[str]
    risk: str  # critical, high, medium, low
    prerequisites: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    tactic: str | None = None
    technique_id: str | None = None


class AttackWorkflow:
    """Track attack workflow progression and hypotheses."""

    def __init__(self):
        self.steps: list[WorkflowStep] = []
        self.attack_paths: list[AttackPath] = []
        self.current_phase: str = "discovery"
        self.rabbit_holes: list[str] = []
        self._next_commands: list[dict] = []
        self._seen_attack_paths: dict[str, AttackPath] = {}
        self._duplicate_attack_path_count = 0

    def add_step(self, phase: str, hypothesis: str, command: str,
                 justification: str, alternatives: list[str] | None = None) -> WorkflowStep:
        """Record a workflow step."""
        step = WorkflowStep(
            phase=phase, hypothesis=hypothesis, command=command,
            justification=justification, alternatives=alternatives or []
        )
        self.steps.append(step)
        self.current_phase = phase
        return step

    def record_result(self, result: str):
        """Record the result of the last step."""
        if self.steps:
            self.steps[-1].result = result

    def add_attack_path(self, name: str, description: str, steps: list[str],
                        risk: str, prerequisites: list[str] | None = None,
                        references: list[str] | None = None,
                        tactic: str | None = None,
                        technique_id: str | None = None) -> AttackPath:
        """Record an identified attack path.

        Exact-match dedup by name: independent phases/builders commonly
        derive the same chain from overlapping enumeration data (e.g. a
        Kerberoasting chain surfaced by both LDAP-based identity
        enumeration and BloodHound collection). A second call with a
        name already seen returns the first-seen path instead of
        appending a duplicate.
        """
        existing = self._seen_attack_paths.get(name)
        if existing is not None:
            self._duplicate_attack_path_count += 1
            return existing

        path = AttackPath(
            name=name, description=description, steps=steps,
            risk=risk, prerequisites=prerequisites or [],
            references=references or [],
            tactic=tactic,
            technique_id=technique_id,
        )
        self._seen_attack_paths[name] = path
        self.attack_paths.append(path)
        return path

    def suggest_next(self, command: str, justification: str, priority: str = "medium"):
        """Suggest a next command to run.

        Duplicate commands are merged and keep the highest priority.
        """
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        normalized_priority = priority if priority in priority_order else "medium"
        normalized_command = command.strip()

        for existing in self._next_commands:
            if existing["command"] != normalized_command:
                continue
            if priority_order[normalized_priority] < priority_order[existing["priority"]]:
                existing["priority"] = normalized_priority
            if justification and justification not in existing["justification"]:
                existing["justification"] = (
                    f"{existing['justification']} | {justification}"
                )
            return

        self._next_commands.append({
            "command": normalized_command,
            "justification": justification,
            "priority": normalized_priority,
        })

    def get_suggestions(self) -> list[dict]:
        """Get suggested next commands, sorted by priority."""
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(self._next_commands, key=lambda x: priority_order.get(x["priority"], 99))

    def add_rabbit_hole(self, description: str):
        """Record an avoided rabbit hole."""
        self.rabbit_holes.append(description)

    def to_markdown(self) -> str:
        """Export workflow as Markdown."""
        lines = ["# Attack Workflow\n"]
        lines.append(f"**Current Phase:** {self.current_phase}\n")

        if self.steps:
            lines.append("## Steps\n")
            for i, s in enumerate(self.steps, 1):
                lines.append(f"### Step {i}: {s.phase}")
                lines.append(f"- **Hypothesis:** {s.hypothesis}")
                lines.append(f"- **Command:** `{s.command}`")
                lines.append(f"- **Justification:** {s.justification}")
                if s.alternatives:
                    lines.append(f"- **Alternatives:** {', '.join(s.alternatives)}")
                if s.result:
                    lines.append(f"- **Result:** {s.result}")
                lines.append(f"- **Time:** {s.timestamp}\n")

        if self.attack_paths:
            lines.append("## Attack Paths\n")
            if self._duplicate_attack_path_count:
                lines.append(
                    f"**Duplicates Merged:** {self._duplicate_attack_path_count} "
                    "exact-name-duplicate add_attack_path() calls were collapsed "
                    "into their first-seen path\n"
                )
            for p in self.attack_paths:
                lines.append(f"### {p.name} [{p.risk.upper()}]")
                lines.append(f"{p.description}\n")
                if p.tactic:
                    lines.append(f"- **Tactic:** {p.tactic}")
                if p.technique_id:
                    lines.append(f"- **Technique:** {p.technique_id}")
                lines.append("**Steps:**")
                for j, step in enumerate(p.steps, 1):
                    lines.append(f"{j}. {step}")
                if p.prerequisites:
                    lines.append(f"\n**Prerequisites:** {', '.join(p.prerequisites)}")
                if p.references:
                    lines.append(f"**References:** {', '.join(p.references)}")
                lines.append("")

        if self._next_commands:
            lines.append("## Suggested Next Commands\n")
            for cmd in self.get_suggestions():
                lines.append(f"- [{cmd['priority'].upper()}] `{cmd['command']}`")
                lines.append(f"  - {cmd['justification']}")

        if self.rabbit_holes:
            lines.append("\n## Rabbit Holes Avoided\n")
            for rh in self.rabbit_holes:
                lines.append(f"- {rh}")

        return "\n".join(lines)
