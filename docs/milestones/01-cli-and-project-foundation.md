# Milestone 1: CLI And Project Foundation

## Purpose

Create the first maintainable Go application shape for Malox and make the
terminal interface usable before scanner internals become complex.

## Scope

- Initialize the Go module and conventional layout:
  - `cmd/malox/main.go`
  - `internal/app`
  - `internal/config`
  - `internal/platform`
  - `internal/report`
  - `docs`
  - `testdata`
- Keep `main.go` minimal. It should delegate to application startup and exit-code
  handling.
- Add the initial command tree:
  - `malox scan`
  - `malox diff`
  - `malox rules test`
  - `malox cache update`
  - `malox cache clean`
  - `malox version`
- Add global flags:
  - `--help`
  - `--version`
  - `--config`
  - `--state-dir`
  - `--cache-dir`
  - `--offline`
  - `--no-color`
  - `--quiet`
  - `--verbose`
- Add scan flags:
  - `--root`
  - `--json`
  - `--output table|json|plain`
  - `--strict-hash`
  - `--max-workers`
  - `--max-file-size`
- Define exit-code constants:
  - `0`: no findings above threshold
  - `1`: findings at or above threshold
  - `2`: usage or configuration error
  - `3`: scan failed
  - `4`: required threat source unavailable
- Add typed configuration loading and validation near startup.
- Add app-level structured logging to stderr with `log/slog`.
- Make all command output capturable through command writers. Do not write from
  command logic directly to `os.Stdout` or `os.Stderr`.

## Out Of Scope

- Real file scanning.
- Diff logic.
- Threat intelligence network calls.
- JavaScript parsing or deobfuscation.
- Release packaging.

## CLI Requirements

- `malox --help` shows the product purpose, available commands, global flags, and
  examples.
- Every subcommand has its own help text with flags and examples.
- Invalid flags or arguments produce concise stderr errors and exit code `2`.
- Human-readable command output goes to stdout.
- Logs, diagnostics, and errors go to stderr.
- `--json` output must never contain progress text, logs, colors, or decorative
  formatting.

## Implementation Constraints

- Prefer the standard library unless the command tree becomes awkward enough to
  justify Cobra. If Cobra is used, set `SilenceUsage` and `SilenceErrors` and keep
  error printing in one application boundary.
- Keep package names short and specific.
- Do not create placeholder packages for future milestones.
- Do not store mutable configuration in package globals.
- Blocking operations must accept `context.Context`, even when they are stubs.
- Keep exported API surface minimal and documented.

## Temporary Data Or Implementation

- `scan`, `diff`, `rules`, and `cache` commands may initially return a clear
  "not implemented" error with exit code `3` or `2`, depending on the command.
- Temporary sample output is allowed only in tests or documentation examples.
- Do not emit fake scan findings, fake vulnerabilities, or fake malware verdicts
  from the real CLI.
- All "not implemented" command bodies must be replaced by Milestones 2, 3, 5,
  and 6.

## Passing Criteria

- A user can discover all commands and flags from terminal help without opening
  external docs.
- `malox version` prints version, commit, build date, and Go version fields, with
  unknown values shown explicitly when build metadata is absent.
- Invalid command usage exits with `2` and does not print full help unless the user
  asked for help.
- The CLI separates stdout and stderr correctly.
- Config validation reports all user-actionable configuration errors clearly.
- Unit tests cover command parsing, help output basics, exit-code mapping, config
  validation, and stdout/stderr separation.
- No production code contains fake scan, diff, cache, rule, or threat results.

