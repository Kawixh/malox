# Milestone 6: Cache Architecture And Offline Mode

## Purpose

Implement the global cache and cache-management commands so threat sources can be
added without destabilizing scanner behavior.

## Scope

- Expand `internal/cache` to support the global cache root.
- Use Go's `os.UserCacheDir()` by default:
  - macOS: `~/Library/Caches/malox`
  - Linux: `$XDG_CACHE_HOME/malox` or `~/.cache/malox`
  - Windows: `%LocalAppData%\malox`
- Support `--cache-dir <path>` for tests, CI, and controlled runs.
- Create the global cache layout:
  - `index-v1.json`
  - `sources/`
  - `rules/builtin/`
  - `rules/downloaded/`
  - `decoded-payloads/sha256/`
- Store source metadata fields:
  - source
  - fetched_at
  - etag
  - last_modified
  - schema_version
  - license
- Add atomic content-addressed writes where practical.
- Implement:
  - `malox cache update`
  - `malox cache clean`
  - `malox cache clean --expired`
  - `malox cache clean --all`
- Implement `--offline` mode so scans use existing cache data and avoid network
  access.
- Add cache TTL configuration by source type.

## Out Of Scope

- Real threat-source downloads.
- OSV, OpenSSF, GitHub Advisory, npm, deps.dev, Package Analysis, or Scorecard
  adapters.
- Embedded key-value stores.
- Dynamic sandboxing or decoded-payload generation.

## CLI Requirements

- `malox cache update --help` explains that source updates may use the network.
- `malox cache update` exits successfully when there are no enabled remote sources
  yet and reports that nothing was updated.
- `malox cache clean --expired` removes only expired cache entries.
- `malox cache clean --all` requires explicit confirmation or a force flag.
- `malox scan --offline` must not perform network requests.
- Cache command JSON output includes source, records changed, bytes written or
  removed, and warnings.

## Implementation Constraints

- Never store project absolute paths in the global cache.
- Never cache secrets, environment variables, or project file contents.
- Keep decoded suspicious payload fragments only by SHA-256 under
  `decoded-payloads/`.
- Write new cache data to a temporary file, verify it, fsync when practical, then
  rename.
- Do not replace the last known-good cache until the new data is valid.
- Keep cache records schema-versioned.
- Avoid native database dependencies unless file-backed JSON/JSONL is proven too
  slow in later measurements.

## Temporary Data Or Implementation

- Cache update may initially update only metadata and built-in rule templates.
- Source directories may be empty until Milestone 7 adds real adapters.
- Do not seed fake OSV, npm, or malicious-package records into the production
  cache.
- Synthetic cache records are allowed only in tests under `testdata/`.
- Empty source adapters or placeholder interfaces must be removed when Milestone 7
  introduces real adapters.

## Passing Criteria

- Global cache root is correct by default and overrideable with `--cache-dir`.
- Offline scans do not attempt network access.
- Cache writes are atomic and preserve the previous valid cache on failure.
- `malox cache clean --expired` and `--all` remove only the intended files.
- Source metadata is written and read with schema validation.
- Unit tests cover cache path resolution, atomic writes, TTL expiry, clean modes,
  offline behavior, and global-cache privacy rules.

