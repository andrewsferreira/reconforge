# ReconForge Artifact Policy

> Version 1.1.0 — Last updated: 2026-04-13

## Objective

Keep operational outputs out of source control, while preserving reproducibility and auditability.

## Scope

Applies to all runtime artifacts generated under `outputs/<target>/<module>/`:

- raw command output
- parsed artifacts
- findings/loot/session files
- command logs and quick reports

## Policy

1. **Do not version runtime outputs**
   - The `outputs/` tree is ignored by Git.
   - Only synthetic fixtures required for tests may live under `tests/fixtures/`.

2. **Storage separation by environment**
   - Local development: `./outputs` (ephemeral)
   - CI: disposable workspace artifacts only
   - Production engagements: dedicated encrypted storage bucket/share

3. **Retention defaults**
   - Raw tool outputs: 30 days
   - Parsed JSON and findings: 180 days
   - Final reports: 365 days (or contract-specific)

4. **Sensitive data handling**
   - Enable `--encrypt-loot` for engagements handling credentials/tokens.
   - Avoid committing secrets, loot, command transcripts, or client identifiers.
   - Vault/loot files (encrypted or not) are written with mode `0600`.
   - By default the Fernet encryption key is stored at `~/.reconforge/{vault,loot}.key`
     (mode `0600`) — this protects against casual disk exposure, not against
     compromise of the operator's own account, since the key lives on the same
     machine as the data. Set `RECONFORGE_VAULT_KEY` / `RECONFORGE_LOOT_KEY`
     (a base64 urlsafe Fernet key) to supply the key out-of-band instead,
     recommended whenever the output directory may be synced, backed up, or
     shared somewhere the key should not follow it.
   - Saving without `--encrypt-loot` emits an explicit warning — it is never silent.

5. **Auditability**
   - Preserve `session.md` and final reports in approved storage for engagement traceability.
   - Record hash/checksum of final reports if chain-of-custody is required.

## Operational Notes

- If you need to share an example output in documentation, sanitize it first and store it under `docs/examples/`.
- Use redacted, synthetic targets in examples.
