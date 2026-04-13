"""ReconForge Attack Workflow - Kill chain tracking and hypothesis management."""

from dataclasses import dataclass, field
from typing import List, Optional, Dict
from datetime import datetime


@dataclass
class WorkflowStep:
    """A single step in the attack workflow."""
    phase: str
    hypothesis: str
    command: str
    justification: str
    alternatives: List[str] = field(default_factory=list)
    result: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


@dataclass
class AttackPath:
    """An identified attack path."""
    name: str
    description: str
    steps: List[str]
    risk: str  # critical, high, medium, low
    prerequisites: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


class AttackWorkflow:
    """Track attack workflow progression and hypotheses."""

    def __init__(self):
        self.steps: List[WorkflowStep] = []
        self.attack_paths: List[AttackPath] = []
        self.current_phase: str = "discovery"
        self.rabbit_holes: List[str] = []
        self._next_commands: List[Dict] = []

    def add_step(self, phase: str, hypothesis: str, command: str,
                 justification: str, alternatives: Optional[List[str]] = None) -> WorkflowStep:
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

    def add_attack_path(self, name: str, description: str, steps: List[str],
                        risk: str, prerequisites: Optional[List[str]] = None,
                        references: Optional[List[str]] = None) -> AttackPath:
        """Record an identified attack path."""
        path = AttackPath(
            name=name, description=description, steps=steps,
            risk=risk, prerequisites=prerequisites or [],
            references=references or []
        )
        self.attack_paths.append(path)
        return path

    def suggest_next(self, command: str, justification: str, priority: str = "medium"):
        """Suggest a next command to run."""
        self._next_commands.append({
            "command": command, "justification": justification, "priority": priority
        })

    def get_suggestions(self) -> List[Dict]:
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
            for p in self.attack_paths:
                lines.append(f"### {p.name} [{p.risk.upper()}]")
                lines.append(f"{p.description}\n")
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
