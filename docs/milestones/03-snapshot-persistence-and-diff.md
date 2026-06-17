# Milestone 3: Snapshot Persistence And Diff

## Purpose

Persist scan history in the project and make `malox diff` report what changed
between scans.

## Scope

- Add packages:
  - `internal/cache` for project-local state only
  - `internal/diff`
- Create the project state directory:
  - default: `<project>/.malox`
  - environment override: `MALOX_PROJECT_STATE_DIR`
  - CLI override: `--state-dir <path>`
- Persist snapshots under:
  - `.malox/latest.json`
  - `.malox/scans/<timestamp>.json`
  - `.malox/indexes/files.jsonl`
- Use atomic writes for snapshots and indexes.
- Load the previous snapshot before scanning when present.
- Reuse a previous file hash only when path, size, modified time, mode, symlink
  target, and package owner match.
- Implement `--strict-hash` to force rehashing every file.
- Mark file state:
  - added
  - removed
  - modified
  - unchanged
  - skipped
  - previously unscanned
- Implement diff output for:
  - added files
  - removed files
  - modified files
  - unchanged files
  - skipped files
  - new findings
  - resolved findings
  - still-existing findings
- Add `malox diff --json`.

## Out Of Scope

- Dependency-level diffs.
- Rule-level findings beyond empty finding lists from current snapshots.
- Global threat-intelligence cache.
- Network access.

## CLI Requirements

- `malox scan` writes a snapshot by default unless explicitly configured for a
  dry-run mode.
- `malox diff` compares the two most recent snapshots by default.
- `malox diff --from <scan-id> --to <scan-id>` compares specific snapshots.
- `malox diff --json` emits valid machine-readable diff output.
- `malox diff` exits with:
  - `0` when no relevant differences are found
  - `1` when relevant differences are found
  - `2` for invalid arguments or missing scan IDs
  - `3` when state cannot be read

## Implementation Constraints

- Project state must stay under the project state directory.
- Do not store project scan history in the global cache.
- Use slash-separated paths in snapshots and diffs.
- Keep diff logic independent from terminal output.
- Keep all persisted data schema-versioned.
- Do not overwrite `latest.json` until a full new snapshot is written and
  verified.

## Temporary Data Or Implementation

- Dependency diff fields may be present as empty arrays until Milestone 4.
- Finding diff fields may be present as empty arrays until Milestone 5, Milestone
  7, and Milestone 8.
- JSONL indexes may start with file records only.
- Empty placeholder fields must be populated or removed by the later milestone
  that owns the data. Do not leave unused fields without tests documenting their
  expected empty state.

## Passing Criteria

- After two scans with a file added, changed, and removed, `malox diff --json`
  reports each state correctly.
- Repeated scans of an unchanged project mark files unchanged and reuse hashes
  only under the documented identity rules.
- `--strict-hash` rehashes files even when metadata matches.
- Snapshot writes are atomic and do not corrupt `latest.json` if a write fails.
- The state directory override works through both environment and CLI flag, with
  CLI taking precedence.
- Unit tests cover snapshot load/write, atomic replacement, diff state
  classification, strict hash behavior, scan ID selection, and missing-state
  errors.

