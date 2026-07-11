# Contributing to ReconForge

Guidelines for contributing code, documentation, and new modules. For development setup and coding conventions, see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

---

## Branch Naming

```
<type>/<short-description>
```

| Type | Use |
|------|-----|
| `feature/` | New functionality (`feature/ad-ntlm-relay-detection`) |
| `fix/` | Bug fixes (`fix/nmap-parser-timeout-handling`) |
| `refactor/` | Internal restructuring, no behavior change (`refactor/runner-typing`) |
| `docs/` | Documentation only (`docs/api-reference-update`) |
| `test/` | Test additions/fixes only (`test/credential-vault-edge-cases`) |
| `chore/` | CI, config, tooling (`chore/github-actions-lint`) |

Rules:
- Branch from `main`. Rebase before opening PR.
- Use lowercase, hyphens only. No underscores, no slashes beyond the type prefix.
- Delete branch after merge.

---

## Commit Style

Follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types:** `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`

**Scopes:** `core`, `runner`, `config`, `findings`, `network`, `web`, `api`, `surface`, `ad`, `cli`, `docs`

Examples:
```
feat(ad): add NTLM relay path detection to attack_paths/
fix(runner): handle SIGPIPE in long-running nmap scans
refactor(config): remove deprecated fallback namespace logic
docs(api): document ffuf_api rate-limiting parameters
test(surface): add deduplicator edge-case coverage
```

Rules:
- Subject line ≤ 72 characters.
- Imperative mood ("add", not "added" or "adds").
- Breaking changes: append `!` after scope (`feat(runner)!: remove string command support`).
- Reference issues in footer: `Closes #42`.

---

## Test Expectations

All PRs must pass the full test suite (run `pytest --collect-only -q` for the current count — do not hardcode a number in docs, it drifts).

### Requirements

- **New tool wrapper** → unit tests mocking `Runner.run()`, verifying command list construction and parser invocation.
- **New parser** → tests with representative raw output samples (embed as string fixtures or `conftest.py` fixtures).
- **New phase** → integration-style tests verifying phase orchestration, tool invocation order, and finding generation.
- **New core component** → comprehensive unit tests including edge cases, error paths, and type validation.
- **Bug fix** → regression test that fails before the fix and passes after.

### Running

```bash
python -m pytest tests/ -v                    # Full suite
python -m pytest tests/ -v -k "test_runner"   # Targeted
python -m pytest tests/ --cov=core --cov=modules --cov-report=term-missing
```

### Standards

- Use `pytest` + `unittest.mock`. No external test frameworks.
- Fixtures go in `tests/conftest.py` or module-level `conftest.py`.
- Never call real external tools in tests. Mock `Runner.run()` and return canned `RunResult`.
- Test file naming: `test_<component>.py`. Class naming: `Test<Component>`.

---

## Documentation Expectations

### Code Changes

- Update `docs/API_REFERENCE.md` for any new/changed public class or method.
- Update the relevant module README (`modules/<mod>/README.md`) for new tools, parsers, or phases.
- Update `docs/CONFIGURATION.md` if adding new `tools.yaml` or `profiles.yaml` entries.
- Update `CHANGELOG.md` under `[Unreleased]` with a concise entry.

### New Modules or Major Features

- Add a section to `docs/MODULES.md`.
- Add entries to `docs/DOCUMENTATION_INDEX.md`.
- Update `docs/ARCHITECTURE.md` if the system-level design changes.
- Update `docs/SUPPORT_MATRIX.md` for new external tool dependencies.

### Standards

- Markdown only. Use ATX headers (`#`).
- Code examples must be copy-pasteable and accurate.
- No TODO/FIXME in committed documentation.

---

## Code Review Expectations

### Author Responsibilities

1. PR description states **what** changed and **why**.
2. Self-review diff before requesting review.
3. All tests pass locally (`pytest tests/ -v`).
4. No `shell=True` anywhere. All commands built as `list[str]`.
5. All user/tool input passes through `validate_arg()` or `validators.py`.
6. No hardcoded config — use `tools.yaml` / `profiles.yaml` via `ToolConfig`.

### Reviewer Checklist

- [ ] Command construction uses `list[str]`, no string interpolation into shell commands.
- [ ] Input validation present for all external/user-supplied values.
- [ ] Findings use correct confidence level; severity clamping not bypassed.
- [ ] New tools registered in `config/tools.yaml` with binary, timeout, detection level.
- [ ] Tests mock external tools; no network/disk side effects.
- [ ] Documentation updated per expectations above.
- [ ] No credentials, API keys, or secrets in committed code.

### Merge Policy

- Squash-merge to `main`. Single clean commit per PR.
- At least one approving review required.
- CI must be green (full test suite passing, no `continue-on-error` on security jobs).

---

## Proposing New Modules, Tools, or Phases

### New External Tool Integration

1. Open an issue with: tool name, purpose, install method, license, detection/noise level.
2. Confirm the tool is installable via `apt`, `pip`, or `go install`.
3. On approval, implement:
   - `modules/<mod>/tools/<tool>.py` — wrapper using `Runner.run()` with `list[str]` commands.
   - `modules/<mod>/parsers/<tool>_parser.py` — structured output parsing.
   - `config/tools.yaml` entry with binary, timeout, detection level, scan profiles.
   - Tests for both wrapper and parser.

### New Phase

1. Open an issue describing: purpose, which module, tool dependencies, expected findings.
2. Implement in `modules/<mod>/phases/<phase>.py` inheriting `<Mod>PhaseBase`.
3. Register in the module orchestrator (`<mod>_module.py`).
4. Add tests and update module README.

### New Module

1. Open an RFC issue with: module scope, target audience, tool inventory, phase breakdown, expected output structure.
2. Follow the canonical architecture: `tools/ → parsers/ → phases/ → <mod>_module.py → core/`.
3. Create `modules/<mod>/base.py` with the module's `PhaseBase` ABC.
4. Implement incrementally: tools first, then parsers, then phases, then orchestrator.
5. Full test suite, module README, and `docs/MODULES.md` entry required before merge.
