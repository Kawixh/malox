# Milestone 9: Incremental `node_modules` Scanning

## Purpose

Make repeated scans fast while still detecting changed installed dependency files.

## Scope

- Extend packages:
  - `internal/node`
  - `internal/scan`
  - `internal/diff`
  - `internal/cache`
- Build a `node_modules` package inventory.
- Support common installed layouts for:
  - npm
  - pnpm
  - yarn
  - bun where practical
- Hash package manifests and relevant package files.
- Compute package-level identity from:
  - package name
  - version
  - package path
  - manifest hash
  - relevant file hashes
  - lockfile identity
  - package manager layout metadata
- Compare package state to the previous scan snapshot.
- Skip unchanged packages where package hash and metadata match.
- Fully scan new or changed packages.
- Report installed packages missing from lockfiles.
- Report lockfile packages missing from `node_modules`.
- Verify lockfile integrity fields against installed files or package tarball
  metadata when available and safe.

## Out Of Scope

- Executing package install scripts.
- Downloading tarballs just to compare every package by default.
- Full support for every historical package-manager layout.
- Runtime behavior analysis.

## CLI Requirements

- `malox scan` summarizes how many `node_modules` packages were scanned, skipped,
  changed, missing from lockfiles, or missing from install tree.
- `malox scan --strict-hash` disables package skip reuse and rehashes relevant
  files.
- `malox diff --json` reports changed package files and dependency/package state
  changes.
- Human output makes incremental-scan reuse visible without being noisy.

## Implementation Constraints

- Treat `node_modules` as a dependency area, not as ordinary source.
- Bound package scanning concurrency.
- Use previous scan data only when identity checks match exactly.
- Keep package inventory deterministic and sorted.
- Do not trust lockfile paths or package metadata without validation.
- Do not store absolute project paths in the global cache.
- Keep package manager layout logic inside `internal/node`.

## Temporary Data Or Implementation

- Some package manager layouts may start as "detected but not fully optimized";
  those packages must still be scanned safely rather than skipped unsafely.
- Tarball integrity verification may start with lockfile integrity fields and
  installed package metadata before registry tarball comparison is added.
- Any package skip heuristic must fail open into scanning the package, not fail
  closed into skipping uncertain files.
- Coarse package ownership from Milestone 2 and Milestone 4 must be replaced by
  package-inventory-backed ownership in this milestone.

## Passing Criteria

- A repeated scan of an unchanged `node_modules` tree skips unchanged packages and
  reports reuse counts.
- Modifying a package file causes only the owning package and affected files to be
  rescanned.
- Adding or removing a dependency is reflected in both scan and diff output.
- Installed packages missing from lockfiles and lockfile packages missing from
  `node_modules` are reported.
- Unrecognized package-manager layouts are scanned conservatively and are not
  skipped due to uncertainty.
- Unit tests cover npm, pnpm, yarn, and supported bun layouts; package identity;
  strict hash; package skip reuse; missing package reports; and changed package
  files.

