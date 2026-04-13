# Observability, Enterprise Config, and Data Contracts

> Version 1.1.0 — Last updated: 2026-04-13

## Observability and Audit

Each module run now includes:

- `execution_id` (stable run identifier)
- structured JSON logs (`*.jsonl`) alongside text logs
- per-phase duration/status/error metadata
- runner metrics (command count, tool timing, failure count, error rate)

Generated audit artifact per module:

- `outputs/<target>/<module>/audit.json`

## Environment-Aware Configuration Layers

`ConfigLoader` now supports layered config resolution:

1. base files in `config/*.yaml`
2. environment overlay in `config/environments/<env>.yaml`
3. secret placeholder resolution (`${secret:KEY}`)

Environment selection:

- `RECONFORGE_ENV=dev|stage|prod`

Secret provider selection:

- `RECONFORGE_SECRET_PROVIDER=env|file|aws_secretsmanager|vault`
- `RECONFORGE_SECRETS_FILE=/path/to/secrets.json` (for `file` provider)
- `AWS_REGION` / `AWS_DEFAULT_REGION` (for `aws_secretsmanager`)
- `VAULT_ADDR` + `VAULT_TOKEN` (for `vault`)

## Versioned Data Contracts

In addition to legacy files (`findings.json`, `loot.json`, `results.json` where applicable),
versioned contract sidecars are generated with automatic normalization/validation:

- `findings.contract.json`
- `loot.contract.json`
- `results.contract.json`

Contract metadata includes:

- `schema_version`
- `kind`
- `generated_at`
- `execution_id`
- `module`
- `data`

Backward compatibility is preserved by keeping legacy outputs unchanged while adding
contract sidecars for strict consumers.

Additionally, contract loader utilities support migration from `schema_version: 1.0`
to the current schema to keep old artifacts consumable.
