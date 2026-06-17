# Milestone 10: Terminal UX, Reports, And Release Hardening

## Purpose

Turn the working scanner into a polished v0 CLI that humans and automation can
trust.

## Scope

- Refine all terminal help and examples.
- Stabilize JSON output schemas for:
  - scan snapshots
  - diffs
  - rule test results
  - cache command results
- Add schema version documentation.
- Add human-readable output modes:
  - table
  - plain
  - concise summary
- Keep color accessible and optional:
  - auto-detect TTY
  - disable color for pipes
  - support `--no-color`
- Add shell completion generation if the chosen CLI stack supports it.
- Add documentation for:
  - installation
  - first scan
  - exit codes
  - configuration
  - cache behavior
  - offline mode
  - JSON output contracts
  - writing local rules
- Review dependency licenses.
- Add release metadata support for version, commit, date, and dirty state.
- Prepare cross-platform packaging guidance for macOS, Linux, and Windows.
- Audit temporary implementations from all previous milestones.

## Out Of Scope

- Web dashboard.
- Cloud account integration.
- Every future ecosystem adapter.
- Runtime sandboxing.
- Native database cache unless previous milestones proved JSON/JSONL insufficient.

## CLI Requirements

- `malox --help` is complete and readable in a standard terminal.
- Every command has examples and documented exit behavior.
- All commands support accessible no-color output.
- JSON output is stable, deterministic, and free from logs or progress text.
- Human output clearly separates:
  - confirmed malicious
  - known vulnerable
  - suspicious history
  - weak signals
  - suppressed allowlist matches
  - scan warnings
- Exit codes match the project policy consistently.

## Implementation Constraints

- Do not change established JSON field meanings without a schema version bump and
  migration note.
- Keep terminal formatting in `internal/report` or CLI boundary code.
- Do not expose internal structs directly as long-term JSON contracts if they
  contain implementation details.
- Keep docs factual and tested against actual CLI behavior.
- Keep release scripts or configs simple and explicit.
- Do not introduce cgo unless a specific feature justifies it.

## Temporary Data Or Implementation

- No fake threat records, demo rules, placeholder adapters, unused packages, or
  dead command bodies may remain in production code.
- Any unsupported format or source must be explicit in docs and runtime warnings.
- Development-only fixtures must stay under `testdata/`.
- Any milestone field that was introduced as an empty placeholder must either be
  populated by real logic, removed, or documented as intentionally reserved with a
  schema compatibility reason.

## Passing Criteria

- A new user can run `malox --help`, `malox scan`, `malox scan --json`,
  `malox diff`, `malox rules test`, `malox cache update`, and `malox cache clean`
  without needing hidden knowledge.
- CLI output is usable with screen readers and without color.
- JSON schemas are documented and covered by golden tests.
- Human summaries are concise but include enough context to act on findings.
- All previous temporary implementation notes are resolved or documented as
  intentional v0 limitations.
- Cross-platform path behavior is tested or isolated behind platform wrappers.
- Documentation covers non-goals and makes clear that weak heuristics are not
  malware verdicts.
- Release metadata appears in `malox version`.
