"""Reporting artifact manifest generation."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from core.reporting.serializers.json_serializer import dump_json


class ReportManifestBuilder:
    schema_version = "1.0"

    def build(self, run_id: str, artifacts: Dict[str, Path], output_path: Path) -> Path:
        entries: List[dict] = []
        previous = ""

        for key in sorted(artifacts.keys()):
            path = artifacts[key]
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            chain = hashlib.sha256(f"{previous}:{key}:{path.name}:{digest}".encode("utf-8")).hexdigest()
            entries.append({
                "artifact_key": key,
                "path": path.as_posix(),
                "sha256": digest,
                "chain_hash": chain,
            })
            previous = chain

        payload = {
            "schema_version": self.schema_version,
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entry_count": len(entries),
            "entries": entries,
            "root_chain_hash": previous,
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(dump_json(payload), encoding="utf-8")
        return output_path
