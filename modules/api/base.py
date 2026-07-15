"""ReconForge - API Module Base Class

Author: Andrews Ferreira

Abstract base for all API reconnaissance phases.
Provides shared access to tools, parsers, and core services
(findings, loot, workflow, notes, opsec).
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from core.attack_workflow import AttackWorkflow
from core.config_loader import ConfigLoader
from core.findings_manager import FindingsManager
from core.logger import ReconLogger
from core.loot_manager import LootManager
from core.notes_manager import NotesManager
from core.opsec_checks import OpsecChecker
from core.runner import Runner

if TYPE_CHECKING:
    from core.profile_loader import ProfileLoader


class APIPhaseBase(ABC):
    """Base class for every API reconnaissance phase.

    Subclasses must implement :meth:`run` which drives tool execution,
    result parsing, and finding generation for a single phase.

    Attributes:
        PHASE_NUMBER: Numeric identifier (1-4).
        PHASE_NAME: Short slug used in directory names and logs.
        PHASE_DESCRIPTION: Human-readable description.
    """

    PHASE_NUMBER: int = 0
    PHASE_NAME: str = "base"
    PHASE_DESCRIPTION: str = ""

    def __init__(
        self,
        logger: ReconLogger,
        runner: Runner,
        config: ConfigLoader,
        output_dir: Path,
        findings: FindingsManager,
        loot: LootManager,
        workflow: AttackWorkflow,
        notes: NotesManager,
        opsec: OpsecChecker,
        opsec_mode: str = "normal",
        profile: Optional["ProfileLoader"] = None,
    ) -> None:
        """Initialise an API phase.

        Args:
            logger: ReconForge logger instance.
            runner: Command runner for tool execution.
            config: Configuration loader for profiles and tool settings.
            output_dir: Parsed output directory for this module.
            findings: Findings manager for recording vulnerabilities.
            loot: Loot manager for credentials and sensitive data.
            workflow: Attack workflow tracker.
            notes: Session notes manager.
            opsec: OPSEC checker for action validation.
            opsec_mode: Current OPSEC profile (stealth/normal/aggressive).
            profile: Resolved OPSEC profile with timing, technique toggles,
                     and tool-specific configuration.
        """
        self.logger = logger
        self.runner = runner
        self.config = config
        self.output_dir = Path(output_dir)
        self.findings = findings
        self.loot = loot
        self.workflow = workflow
        self.notes = notes
        self.opsec = opsec
        self.opsec_mode = opsec_mode
        self.profile = profile
        self.tools_used: list[str] = []

    # ── Template method ────────────────────────────────────────────

    def execute(self, target_url: str, **kwargs) -> dict[str, Any]:
        """Execute the full phase lifecycle.

        1. Log phase start
        2. Record workflow hypothesis
        3. Run phase implementation
        4. Log phase end

        Args:
            target_url: The target API URL to scan.
            **kwargs: Additional phase-specific arguments.

        Returns:
            Dict with phase results.
        """
        self.logger.info(f"{'='*60}")
        self.logger.info(
            f"Phase {self.PHASE_NUMBER}: {self.PHASE_DESCRIPTION}"
        )
        self.logger.info(f"{'='*60}")

        self.notes.add_phase_start(self.PHASE_NAME)

        self.workflow.add_step(
            phase=self.PHASE_NAME,
            hypothesis=f"Executing {self.PHASE_DESCRIPTION}",
            command=f"Phase {self.PHASE_NUMBER} tools",
            justification=self.PHASE_DESCRIPTION,
        )

        try:
            results = self.run(target_url=target_url, **kwargs)
        except Exception as exc:
            self.logger.error(f"Phase {self.PHASE_NUMBER} failed: {exc}")
            self.notes.add_phase_end(self.PHASE_NAME, f"FAILED: {exc}")
            self.workflow.record_result(f"Failed: {exc}")
            raise

        finding_count = results.get("finding_count", 0)
        self.notes.add_phase_end(
            self.PHASE_NAME,
            f"{finding_count} findings generated. Tools: {', '.join(self.tools_used) or 'none'}",
        )
        self.workflow.record_result(
            f"Phase {self.PHASE_NUMBER} complete – {finding_count} findings"
        )

        self.logger.info(
            f"Phase {self.PHASE_NUMBER} complete: {finding_count} findings"
        )
        return results

    @abstractmethod
    def run(self, target_url: str, **kwargs) -> dict[str, Any]:
        """Run the phase tools and return results.

        Must be implemented by subclasses.

        Args:
            target_url: The target API URL to scan.
            **kwargs: Additional arguments.

        Returns:
            Dict with at least ``finding_count`` and ``success`` keys.
        """
        ...

    # ── Helpers ────────────────────────────────────────────────────

    def phase_output(self, filename: str) -> Path:
        """Return a path for a file in the phase output directory."""
        phase_dir = self.output_dir / self.PHASE_NAME
        phase_dir.mkdir(parents=True, exist_ok=True)
        return phase_dir / filename

    def add_finding(
        self,
        finding_type: str,
        severity: str,
        confidence: str,
        target: str,
        description: str,
        evidence: str = "",
        recommendation: str = "",
        references: list[str] | None = None,
        confidence_reason: str = "",
    ) -> None:
        """Convenience wrapper to add a finding with module/phase pre-filled."""
        self.findings.add(
            finding_type=finding_type,
            severity=severity,
            confidence=confidence,
            target=target,
            module="api",
            phase=self.PHASE_NAME,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            references=references,
            confidence_reason=confidence_reason,
        )

    def resolve_wordlist(self, tool_name: str, key: str = "common") -> str:
        """Find a wordlist that exists on disk.

        Args:
            tool_name: Tool config key to check for wordlist paths.
            key: Preferred wordlist key.

        Returns:
            Path string to the first existing wordlist, or empty string.
        """
        tool_cfg = self.config.get_tool_config(tool_name)
        wordlists = tool_cfg.get("wordlists", {})

        candidates = []
        if key in wordlists:
            candidates.append(wordlists[key])
        candidates.extend(v for k, v in wordlists.items() if k != key)

        # Common API wordlist fallbacks
        candidates.extend([
            "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
        ])

        for wl in candidates:
            if Path(wl).is_file():
                return wl
        return ""

    @staticmethod
    def sanitize_credential(value: str) -> str:
        """Mask credential values for safe logging."""
        if not value:
            return ""
        if len(value) <= 4:
            return "****"
        return value[:2] + "*" * (len(value) - 4) + value[-2:]
