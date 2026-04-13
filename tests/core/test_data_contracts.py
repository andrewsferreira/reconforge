"""Tests for core.data_contracts."""

import json

import pytest

from core.data_contracts import (
    SCHEMA_VERSION,
    build_contract,
    load_contract,
    migrate_contract,
    validate_contract,
)


def test_build_contract_results():
    payload = {"target": "10.10.10.1", "phases": {}}
    c = build_contract("results", payload, execution_id="run_1", module="network")
    assert c["schema_version"] == SCHEMA_VERSION
    assert c["kind"] == "results"
    assert c["execution_id"] == "run_1"


def test_migrate_contract_1_0_to_1_1():
    legacy = {
        "schema_version": "1.0",
        "kind": "loot",
        "data": [],
    }
    migrated = migrate_contract(legacy)
    assert migrated["schema_version"] == "1.1"
    assert "generated_at" in migrated


def test_validate_contract_rejects_bad_kind():
    with pytest.raises(ValueError):
        validate_contract({"schema_version": "1.1", "kind": "invalid", "data": []})


def test_load_contract(tmp_path):
    path = tmp_path / "findings.contract.json"
    path.write_text(json.dumps({"schema_version": "1.0", "kind": "findings", "data": []}))
    loaded = load_contract(path)
    assert loaded["schema_version"] == "1.1"
    assert loaded["kind"] == "findings"
