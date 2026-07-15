"""ReconForge Output Manager - Structured output directory management."""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any


class OutputManager:
    """Manage output directory structure for a target."""

    def __init__(self, base_dir: str = "outputs", target: str = "default"):
        self.base = Path(base_dir) / self._sanitize(target)
        self.target = target

    @staticmethod
    def _sanitize(name: str) -> str:
        """Sanitize target name for directory use."""
        return name.replace("/", "_").replace(":", "_").replace(" ", "_")

    # ── Directory helpers ───────────────────────────────────────────

    def module_dir(self, module: str) -> Path:
        """Get the base directory for a module."""
        d = self.base / module
        d.mkdir(parents=True, exist_ok=True)
        return d

    def raw_dir(self, module: str) -> Path:
        """Get the raw output directory for a module."""
        d = self.base / module / "raw"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def parsed_dir(self, module: str) -> Path:
        """Get the parsed output directory for a module."""
        d = self.base / module / "parsed"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def findings_file(self, module: str, ext: str = "json") -> Path:
        """Get path for findings file."""
        d = self.module_dir(module)
        return d / f"findings.{ext}"

    def session_file(self, module: str) -> Path:
        """Get path for session notes."""
        return self.module_dir(module) / "session.md"

    def commands_log(self, module: str) -> Path:
        """Get path for commands log."""
        return self.module_dir(module) / "commands.log"

    def attack_paths_file(self, module: str) -> Path:
        """Get path for attack paths documentation."""
        return self.module_dir(module) / "attack_paths.md"

    def report_file(self, module: str) -> Path:
        """Get path for quick report."""
        return self.module_dir(module) / "quick_report.md"

    def loot_file(self, module: str) -> Path:
        """Get path for loot file."""
        return self.module_dir(module) / "loot.json"

    def contract_file(self, module: str, kind: str) -> Path:
        """Get path for versioned contract sidecar file."""
        return self.module_dir(module) / f"{kind}.contract.json"

    def audit_file(self, module: str) -> Path:
        """Get path for module execution audit metadata."""
        return self.module_dir(module) / "audit.json"

    def evidence_manifest_file(self, module: str) -> Path:
        """Get path for evidence chain manifest."""
        return self.module_dir(module) / "evidence.manifest.json"

    def write_evidence_manifest(self, module: str, execution_id: str) -> Path:
        """Write a chained-hash manifest for all module artifacts.

        The chain is deterministic (sorted by relative path). Each entry includes
        its file hash and a `chain_hash` bound to previous entry hash.
        """
        root = self.module_dir(module)
        manifest_path = self.evidence_manifest_file(module)
        entries: list[dict[str, str]] = []
        previous_chain_hash = ""

        for file_path in sorted(p for p in root.rglob("*") if p.is_file()):
            if file_path == manifest_path:
                continue
            rel = file_path.relative_to(root).as_posix()
            digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
            chain_hash = hashlib.sha256(
                f"{previous_chain_hash}:{rel}:{digest}".encode()
            ).hexdigest()
            entries.append(
                {
                    "path": rel,
                    "sha256": digest,
                    "chain_hash": chain_hash,
                }
            )
            previous_chain_hash = chain_hash

        payload: dict[str, Any] = {
            "version": "1.0",
            "execution_id": execution_id,
            "module": module,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "entries": entries,
            "root_chain_hash": previous_chain_hash,
        }
        manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return manifest_path

