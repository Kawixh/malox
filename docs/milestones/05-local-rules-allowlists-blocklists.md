# Milestone 5: Local Rules, Allowlists, And Blocklists

## Purpose

Add local detection policy so Malox can produce real findings before remote threat
sources are available.

## Scope

- Add package:
  - `internal/rules`
- Define versioned schemas for:
  - detection rules
  - allowlists
  - blocklists
- Support rule match targets:
  - path patterns
  - file SHA-256
  - package name
  - package version range
  - PURL
  - registry URL
  - maintainer or publisher when available
  - script content
  - suspicious lifecycle hooks
  - encoded payload indicators discovered by simple file scanning
- Support allowlist entries with:
  - reason
  - owner
  - expiration
  - exact match scope
- Support blocklist entries for:
  - package
  - PURL
  - hash
  - maintainer
  - URL
  - path
- Embed default rule, allowlist, and blocklist templates into the binary.
- Load organization-managed policy from configured files.
- Emit findings with:
  - severity
  - confidence
  - source
  - rule ID
  - evidence
  - file hash
  - package owner
  - exact location when available
- Implement `malox rules test` for validating rule files against fixture
  snapshots or fixture projects.

## Out Of Scope

- Remote threat-source data.
- Full JavaScript deobfuscation.
- Registry metadata checks.
- Behavioral sandboxing.

## CLI Requirements

- `malox scan --json` includes rule, allowlist, and blocklist findings.
- Human scan output clearly separates confirmed blocklist hits from weak
  heuristic signals.
- `malox rules test <rule-file> --fixture <path>` validates syntax and expected
  matches.
- `malox rules test --json` emits machine-readable test results.
- Allowlisted findings are visible in JSON with suppression metadata and are
  summarized quietly in human output.

## Implementation Constraints

- Rules must be data-driven and deterministic.
- Keep rule execution independent from terminal output.
- Do not hardcode sample package names as real malware.
- Weak heuristic matches must not become confirmed malware verdicts.
- Version matching must use a real semver or ecosystem-appropriate parser, not
  ad-hoc string comparison.
- Expired allowlist entries must fail closed or report clearly.
- Rules must be bounded by file size and scan limits.

## Temporary Data Or Implementation

- Built-in rules may start with a small conservative set, but they must be real
  policy rules, not fake examples.
- Demo rules may exist only under `testdata/` or docs examples and must be labeled
  as examples.
- Simple encoded-payload indicators may be path, entropy, and regex based until
  Milestone 8 adds JavaScript-aware recovery.
- Any rule fields reserved for future remote sources must be either ignored with
  explicit validation warnings or left out of the schema until Milestone 7.

## Passing Criteria

- A blocklisted package, PURL, hash, path, or maintainer produces a high-confidence
  finding and exit code `1`.
- An allowlisted match is suppressed only when its scope matches and it has not
  expired.
- Weak heuristic findings are labeled as weak signals and never reported as
  confirmed malicious without stronger evidence.
- `malox rules test` validates rule syntax, reports match counts, and exits
  non-zero for invalid rules or failed expectations.
- Unit tests cover rule schema validation, allowlist expiration, blocklist
  matching, semver matching, script matching, finding shape, and JSON output.

