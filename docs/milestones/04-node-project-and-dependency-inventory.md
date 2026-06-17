# Milestone 4: Node Project And Dependency Inventory

## Purpose

Make Malox understand Node.js project metadata, lockfiles, package manager
signals, and dependency identity without relying on package manager executables.

## Scope

- Add package:
  - `internal/node`
- Parse:
  - `package.json`
  - `package-lock.json`
  - `npm-shrinkwrap.json`
  - `pnpm-lock.yaml`
  - `yarn.lock`
  - `bun.lock`
  - `deno.json`
  - `deno.lock`
- Detect `bun.lockb` and report a clear unsupported or partial-support warning
  until binary parsing is implemented.
- Infer package manager signals from manifests, lockfiles, and dependency layout.
- Normalize package identities to Package URLs where possible, for example
  `pkg:npm/%40scope/name@1.2.3`.
- Build dependency inventory with:
  - name
  - version
  - PURL
  - package manager source
  - dependency type when available
  - lockfile source path
  - integrity or checksum when available
  - resolved registry or tarball URL when available
  - lifecycle scripts when available from manifests or installed package metadata
- Connect dependency inventory to scan snapshots.
- Add dependency diff output:
  - new dependencies
  - removed dependencies
  - updated dependencies
  - new package scripts
  - changed package scripts
- Improve package ownership for files inside `node_modules`.

## Out Of Scope

- Threat intelligence lookups.
- npm registry network calls.
- Tarball integrity verification against registry metadata.
- Full `node_modules` incremental package skipping.
- JavaScript AST parsing.

## CLI Requirements

- `malox scan --json` includes package manager signals, manifest hashes, lockfile
  hashes, and dependency inventory.
- `malox diff --json` includes dependency and package-script changes.
- Human-readable scan output summarizes detected package managers, dependency
  count, lockfiles, and notable parser warnings.
- Parser warnings are visible without corrupting JSON output.

## Implementation Constraints

- Use structured parsers for JSON and lockfile formats.
- Do not parse structured files with fragile string matching when a real parser is
  available or reasonable to add.
- Keep parser dependencies justified and narrow.
- Treat all lockfile paths and URLs as untrusted.
- Keep package-manager-specific parsing behind small adapters.
- Do not require npm, pnpm, yarn, bun, or deno binaries to exist.
- Keep malformed file errors structured so one bad lockfile does not hide other
  scan results.

## Temporary Data Or Implementation

- `bun.lockb` may be detection-only with an unsupported warning in this milestone.
- Yarn support may start with the dominant lockfile version used by fixtures, but
  unsupported variants must report explicit warnings.
- PURL normalization may initially support npm and deno package forms only.
- These temporary gaps must be resolved or deliberately re-scoped before the v0
  release hardening milestone.
- Any sample package projects used for parser development must live under
  `testdata/` and must not be treated as built-in scanner knowledge.

## Passing Criteria

- Fixtures for npm, pnpm, yarn, bun text lock, and deno produce dependency
  inventories with stable PURLs where possible.
- A project with multiple lockfiles reports all detected signals and does not make
  a silent package-manager assumption.
- Package scripts are captured and diffed without executing them.
- `node_modules` file records include package owner for common npm and pnpm
  layouts.
- Malformed manifests and lockfiles produce structured warnings.
- Unit tests cover parser success and failure paths, package-manager detection,
  PURL normalization, package-script diffs, and node_modules ownership mapping.

