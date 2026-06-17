# Milestone 2: Baseline Project Scan Snapshot

## Purpose

Make `malox scan` produce a deterministic JSON snapshot for a project without
network access or threat intelligence.

## Scope

- Add packages:
  - `internal/fileid`
  - `internal/scan`
- Resolve the project root from `--root` or the current directory.
- Build a stable project ID from the normalized root path plus lockfile identity
  when lockfiles exist.
- Walk the project with bounded concurrency.
- Skip noisy directories by default:
  - `.git`
  - `.malox`
  - build output
  - coverage output
  - package manager caches
- Treat `node_modules` as a known dependency area, but only record coarse package
  ownership until Milestone 4 and Milestone 9.
- For every candidate file, collect:
  - slash-separated relative path
  - size
  - modified time
  - mode or permissions
  - symlink status and target when relevant
  - SHA-256
  - file type
  - scan status
  - structured skip reason when skipped
- Stream file contents when hashing.
- Bound file reads with `--max-file-size`.
- Produce a scan snapshot with:
  - schema version
  - scanner version
  - project root
  - scan start and end time
  - package manager signals discovered from filenames
  - file inventory
  - errors and skipped files
- Add JSON report output for `malox scan --json`.

## Out Of Scope

- Persisting snapshots to `.malox`.
- Diffing two snapshots.
- Full Node dependency parsing.
- Rule matching.
- Threat lookups.
- Obfuscation analysis.

## CLI Requirements

- `malox scan` should work with no configuration.
- `malox scan --json` writes only valid JSON to stdout.
- `malox scan --output table` gives a concise human summary.
- `malox scan --root <path>` scans that project root.
- `malox scan --max-workers <n>` controls bounded parallelism.
- `malox scan --max-file-size <bytes>` skips oversized files with a structured
  skip reason.
- `malox scan --strict-hash` is accepted but may behave the same as the default
  until snapshot reuse exists in Milestone 3.

## Implementation Constraints

- Use `filepath.WalkDir` or `fs.WalkDir`.
- Use `filepath.Rel`, `filepath.IsLocal`, and `filepath.ToSlash` for snapshot
  paths.
- Do not follow symlinks unless the policy is explicit and loop-safe.
- Do not shell out to npm, pnpm, yarn, bun, deno, git, or package managers.
- Keep JSON report structs explicit and separate from internal scanner structs
  when internal fields are not part of the public output contract.
- Sort output deterministically.
- Collect partial scan errors as structured warnings when scanning can continue.

## Temporary Data Or Implementation

- File type classification may start as extension and simple path-based detection.
- Package ownership inside `node_modules` may be `unknown` or coarse package name
  only.
- These temporary limitations must be replaced by:
  - Milestone 4 for Node manifests, lockfiles, package manager signals, and package
    ownership.
  - Milestone 8 for JavaScript-aware classification and obfuscation signals.
  - Milestone 9 for incremental `node_modules` package hashing.
- Do not add placeholder malware, vulnerability, or rule findings in this
  milestone.

## Passing Criteria

- Running `malox scan --json` on the same unchanged project produces stable,
  deterministic JSON apart from documented timestamp fields.
- Every scanned file has a SHA-256 value.
- Oversized, unreadable, or skipped files are represented as structured scan
  records or warnings without crashing the whole scan when continuation is safe.
- Absolute paths do not appear in the global portions of output. Local debug paths
  appear only where explicitly allowed by the schema.
- The scanner never executes project code.
- Unit tests cover path normalization, skip rules, SHA-256 hashing, symlink policy,
  max-file-size behavior, deterministic ordering, and JSON schema fields.
- The temporary file-type and package-ownership limitations are documented in code
  comments or issue notes and are referenced by later milestone work.

