"""Versioned data contracts for results/findings/loot with validation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

SCHEMA_VERSION = "1.1"
SUPPORTED_SCHEMA_VERSIONS = {"1.0", "1.1"}


@dataclass(frozen=True)
class ContractSpec:
    kind: str
    required_keys: List[str]


SPECS: Dict[str, ContractSpec] = {
    "results": ContractSpec("results", ["target", "phases"]),
    "findings": ContractSpec("findings", []),
    "loot": ContractSpec("loot", []),
}


def _normalize_findings(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        out: List[Dict[str, Any]] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            fixed = dict(item)
            fixed.setdefault("id", "")
            fixed.setdefault("severity", "info")
            fixed.setdefault("confidence", "low")
            fixed.setdefault("module", "")
            fixed.setdefault("phase", "")
            out.append(fixed)
        return out
    return []


def _normalize_loot(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [dict(i) for i in payload if isinstance(i, dict)]
    return []


def _normalize_results(payload: Any) -> Dict[str, Any]:
    if isinstance(payload, dict):
        fixed = dict(payload)
        fixed.setdefault("target", "")
        fixed.setdefault("phases", {})
        return fixed
    return {"target": "", "phases": {}}


def normalize_payload(kind: str, payload: Any) -> Any:
    if kind == "findings":
        return _normalize_findings(payload)
    if kind == "loot":
        return _normalize_loot(payload)
    if kind == "results":
        return _normalize_results(payload)
    return payload


def validate_payload(kind: str, payload: Any) -> None:
    if kind not in SPECS:
        raise ValueError(f"Unsupported contract kind: {kind}")

    if kind in ("findings", "loot"):
        if not isinstance(payload, list):
            raise ValueError(f"{kind} payload must be a list")
        return

    if kind == "results":
        if not isinstance(payload, dict):
            raise ValueError("results payload must be a dict")
        for key in SPECS[kind].required_keys:
            if key not in payload:
                raise ValueError(f"results payload missing required key: {key}")


def build_contract(kind: str, payload: Any, *, execution_id: str = "", module: str = "") -> Dict[str, Any]:
    normalized = normalize_payload(kind, payload)
    validate_payload(kind, normalized)
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "generated_at": datetime.utcnow().isoformat(),
        "execution_id": execution_id,
        "module": module,
        "data": normalized,
    }


def migrate_contract(contract: Dict[str, Any]) -> Dict[str, Any]:
    """Migrate legacy contract versions to current schema version.

    Backward compatibility:
    - v1.0 -> v1.1 (adds missing metadata keys when absent)
    """
    version = str(contract.get("schema_version", "1.0"))
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError(f"Unsupported schema version: {version}")

    migrated = dict(contract)
    migrated.setdefault("generated_at", datetime.utcnow().isoformat())
    migrated.setdefault("execution_id", "")
    migrated.setdefault("module", "")

    if version == "1.0":
        migrated["schema_version"] = "1.1"
    return migrated


def validate_contract(contract: Dict[str, Any]) -> None:
    """Validate full contract envelope and inner payload."""
    if not isinstance(contract, dict):
        raise ValueError("contract must be a dict")
    kind = contract.get("kind", "")
    if kind not in SPECS:
        raise ValueError(f"Unsupported contract kind: {kind}")
    if "data" not in contract:
        raise ValueError("contract missing data field")
    validate_payload(kind, normalize_payload(kind, contract["data"]))


def load_contract(path: Path) -> Dict[str, Any]:
    """Load, migrate and validate contract from disk."""
    p = Path(path)
    raw = json.loads(p.read_text())
    migrated = migrate_contract(raw)
    validate_contract(migrated)
    return migrated
