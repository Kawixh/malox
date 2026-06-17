# Milestone 7: Threat Intelligence Source Adapters

## Purpose

Connect dependency inventory to real open source vulnerability and malware data
through modular, cache-aware source adapters.

## Scope

- Add package:
  - `internal/threat`
- Define a source adapter interface that supports:
  - update or fetch
  - query by PURL
  - query by package name and version
  - source metadata
  - offline cache reads
  - confidence classification
- Implement Priority 0 sources:
  - OSV.dev API with `/v1/querybatch` where possible
  - OpenSSF Malicious Packages
  - GitHub Advisory Database in OSV format
  - npm Registry API metadata
  - npm audit endpoints when the configured registry supports them
  - local organization allowlists and blocklists from Milestone 5
- Normalize source results to:
  - `confirmed-malicious`
  - `known-vulnerable`
  - `suspicious-history`
  - `weak-signal`
  - `unknown`
- Cache downloaded source records under the global cache.
- Add threat findings to scan snapshots.
- Add source status and cache age to human-readable summaries.

## Out Of Scope

- Priority 1 and Priority 2 sources unless the Priority 0 adapter shape is
  complete and tested.
- Runtime sandboxing.
- Full package tarball comparison.
- Ownership-change heuristics that require unavailable historical data.

## CLI Requirements

- `malox scan` performs configured online lookups unless `--offline` is set.
- `malox scan --offline` uses cached records and reports stale or missing source
  data.
- `malox cache update` prewarms enabled sources.
- `malox cache update --source osv` updates only the selected source.
- `malox scan --json` includes source status and normalized threat findings.
- If a required source is unavailable, exit with `4`.
- Optional source failures should produce structured warnings and should not hide
  local scan results.

## Implementation Constraints

- Use direct Go HTTP clients, not mandatory external tools.
- Bound all network calls with context, timeout, retry, and rate-limit policy.
- Keep HTTP client dependencies narrow and testable with `http.RoundTripper`.
- Store raw upstream IDs and normalized PURLs.
- Preserve upstream severity and advisory IDs when present.
- Do not treat weak or missing data as confirmed malicious.
- Do not send project file contents to remote services.
- Do not require users to install `osv-scanner`.

## Temporary Data Or Implementation

- Priority 1 sources such as deps.dev, OpenSSF Package Analysis, and Scorecard may
  be represented as planned adapters only in docs, not as empty production code.
- npm audit support may start as optional and registry-dependent, but unsupported
  responses must be explicit.
- Historical maintainer-change checks may start as npm metadata heuristics and
  must be labeled `suspicious-history` or `weak-signal`.
- Any fixture advisory or malicious-package records must live under `testdata/`
  and must not be copied into the production cache as defaults.
- Remove empty source adapter placeholders from Milestone 6 once real adapters are
  introduced.

## Passing Criteria

- OSV querybatch results produce known-vulnerable findings for affected package
  versions in fixtures.
- OpenSSF malicious package records produce confirmed-malicious findings when PURL
  or package-version identity matches.
- GitHub Advisory Database records can be read from cache in OSV format.
- npm registry metadata is cached with etag or last-modified metadata when
  available.
- Offline mode returns cached source results without network calls.
- Required-source failures exit with `4`; optional-source failures are warnings.
- Unit tests use local HTTP test servers or fixture files, not live network calls.
- Tests cover adapter normalization, cache reads and writes, source failures,
  confidence classification, and JSON finding shape.

