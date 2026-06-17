# Malox Goal

## Project Vision

Malox is a fast, cross-platform terminal security scanner for open source projects.
The first target is Node.js projects, with a design that can later support Rails and
other ecosystems without rewriting the core scanner.

The tool should help answer one question quickly:

> Did this project, its dependencies, or its installed packages change in a way that
> could introduce malware, obfuscated code, vulnerable packages, or suspicious files?

## Language Choice

Use Go for the first implementation.

Go is the best fit for this project because:

- It produces simple cross-platform CLI binaries for macOS, Linux, and Windows.
- It is fast enough for large dependency trees and filesystem-heavy scanning.
- Goroutines and worker pools make parallel scanning, hashing, parsing, and network
  lookups straightforward.
- It can ship as a single binary with embedded default rules, signatures, and
  metadata using `embed`.
- It has strong support for JSON, HTTP APIs, hashing, archive handling, process
  execution, and terminal CLI tooling.
- It is easier to distribute broadly than Swift for Linux and Windows users.

Swift is also fast, but Go is the more practical default for a terminal-first,
security-oriented, cross-platform tool.

## Core Goals

1. Scan the current project and produce a structured scan result.
2. Track every scanned file with path, size, timestamps, content hash, and SHA-256.
3. Create a diff object between the current scan and the previous scan.
4. Detect changed, added, removed, and previously-unscanned files.
5. Scan `node_modules` incrementally and only rescan packages or files that changed.
6. Work across Node package managers: npm, pnpm, yarn, bun, and deno.
7. Check dependency metadata against open source threat and vulnerability databases.
8. Detect packages with known malware, typosquatting, dependency confusion, suspicious
   maintainers, risky install scripts, or historical compromise signals.
9. Apply local rules, allowlists, blocklists, and obfuscation checks.
10. Run entirely from the terminal with useful machine-readable output.

## Dependency And Tooling Strategy

Malox should prefer native integrations over shelling out to external tools.

For OSV:

- Prefer calling the OSV.dev API directly from Go for vulnerability lookups.
- Support offline or cached OSV data later if the dataset size and update flow are
  practical.
- Optionally support using `osv-scanner` as an external helper when installed.
- Do not require users to install `osv-scanner` for the core flow.

For bundled assets:

- Embed default detection rules into the binary.
- Embed default allowlist and blocklist templates into the binary.
- Keep large threat databases outside the binary unless they are compact enough to
  ship safely.
- Cache downloaded threat intelligence under the user's cache directory.

## Threat Intelligence Sources

Research checked on 2026-06-17.

The scanner should be able to connect to multiple open source repositories,
registries, and databases. Threat sources should be separated into source adapters
so they can be enabled, disabled, cached, or replaced independently.

Priority 0 sources:

- [OSV.dev API](https://google.github.io/osv.dev/api/) for known vulnerabilities,
  malicious package records, and package-version lookups. Use
  [`/v1/querybatch`](https://google.github.io/osv.dev/post-v1-querybatch/) with
  Package URLs where possible.
- [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) for
  known malicious package reports, including typosquatting, dependency confusion,
  account takeover, malicious install-time payloads, and suspicious obfuscation
  reports.
- [GitHub Advisory Database](https://github.com/github/advisory-database) for a
  local mirror of CVE and GHSA advisory records in OSV format.
- [npm Registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md)
  for package metadata, version publish times, maintainers, publisher identity,
  scripts, tarball URL, tarball shasum, dist tags, deprecation messages, and
  package search signals.
- [npm audit endpoints](https://docs.npmjs.com/cli/v10/commands/npm-audit/)
  for npm advisory compatibility, registry signatures, provenance attestations,
  and advisory metadata when the configured registry supports them.
- Local organization-managed allowlists and blocklists.
- Package lockfiles and package manager metadata from the scanned project.

Priority 1 sources:

- [deps.dev API](https://docs.deps.dev/api/v3/) for package versions, publish
  times, deprecation status, licenses, known advisory IDs, package hash queries,
  source repository links, and npm SLSA provenance/attestation metadata.
- [OpenSSF Package Analysis](https://github.com/ossf/package-analysis) for
  behavioral package analysis data, especially when a package starts accessing new
  files, connecting to new addresses, or running new commands over time.
- [OpenSSF Scorecard](https://github.com/ossf/scorecard) for repository security
  posture signals such as maintenance, branch protection, pinned dependencies,
  signed releases, CI, SAST, and vulnerability posture.

Priority 2 sources:

- [GuardDog](https://github.com/DataDog/guarddog) rules and heuristics as
  inspiration for malicious package source-code and metadata checks. Do not depend
  on GuardDog at runtime; translate useful checks into Malox rules when the
  licenses and implementation shape are acceptable.
- Curated community blocklists, but only when the source has a clear license,
  update process, and false-positive review workflow.

Package identity should use
[Package URL](https://github.com/package-url/purl-spec) as the normalized package
identifier format, for example `pkg:npm/%40scope/name@1.2.3`.

Threat source support should be modular so future sources can be added without
changing the scanner core.

Threat source results should be classified by confidence:

- `confirmed-malicious`: strong match from OpenSSF malicious packages, OSV MAL
  records, or an organization blocklist.
- `known-vulnerable`: vulnerability advisory affects the installed package
  version.
- `suspicious-history`: package, maintainer, repository, publish timing, scripts,
  or behavioral history changed in a suspicious way.
- `weak-signal`: heuristic-only match that needs additional evidence.
- `unknown`: no matching data or source could not be reached.

## Cache Architecture

Malox should use two cache layers: a global cache for shared threat intelligence
and a project cache for scan snapshots.

Use Go's `os.UserCacheDir()` for the global cache root. Expected locations:

- macOS: `~/Library/Caches/malox`
- Linux: `$XDG_CACHE_HOME/malox` or `~/.cache/malox`
- Windows: `%LocalAppData%\malox`

Use a project-local state directory for scan history:

- Default: `<project>/.malox`
- Override: `MALOX_PROJECT_STATE_DIR`
- CI option: `malox scan --state-dir <path>`

Global cache layout:

```text
malox/
  index-v1.json
  sources/
    osv/
      querybatch/
      vulns/
      metadata.json
    github-advisory-database/
      records/
      metadata.json
    openssf-malicious-packages/
      records/
      by-purl/
      by-package/
      metadata.json
    npm/
      packuments/
      versions/
      audit-bulk/
      keys/
      metadata.json
    deps-dev/
      packages/
      versions/
      advisories/
      hash-query/
      metadata.json
    openssf-package-analysis/
      package-behavior/
      metadata.json
    scorecard/
      repositories/
      metadata.json
  rules/
    builtin/
    downloaded/
  decoded-payloads/
    sha256/
```

Project cache layout:

```text
.malox/
  project.json
  latest.json
  scans/
    2026-06-17T12-30-00Z.json
  indexes/
    files.jsonl
    packages.jsonl
    findings.jsonl
  node/
    package-inventory.json
    lockfile-inventory.json
```

Cache rules:

- Keep source downloads content-addressed where possible.
- Store source metadata with `source`, `fetched_at`, `etag`, `last_modified`,
  `schema_version`, and `license`.
- Store every source record with the raw upstream ID and normalized PURL.
- Never overwrite the last known-good cache until a new cache update is fully
  written and verified.
- Use atomic writes: write to a temporary file, fsync when practical, then rename.
- Apply TTLs by source type. Vulnerability and malicious package records should be
  refreshed aggressively; package metadata can be refreshed less often.
- Allow `--offline` mode to use the latest cache without network access.
- Allow `malox cache update` to prewarm all enabled sources.
- Allow `malox cache clean` to remove expired records and decoded payloads.
- Do not store project absolute paths in the global cache.
- Do not cache secrets, environment variables, or file contents from the user's
  project except decoded suspicious payload fragments needed for evidence, and
  only by SHA-256 under `decoded-payloads/`.

Start with content-addressed JSON and JSONL files. Add an embedded key-value store
later only if the cache becomes too slow; avoid native database dependencies that
make single-binary distribution harder.

## Node.js V0 Scope

The first version should support:

- `package.json`
- `package-lock.json`
- `npm-shrinkwrap.json`
- `pnpm-lock.yaml`
- `yarn.lock`
- `bun.lock`
- `bun.lockb` if practical
- `deno.json`
- `deno.lock`
- `node_modules`

The scanner should be package-manager agnostic. It should infer the package manager
from lockfiles, project files, and installed dependency layout, but it should not
depend on one package manager being present.

## Scan Model

Each scan should produce a persisted scan snapshot containing:

- Scanner version.
- Project root.
- Scan start and end time.
- Package manager signals.
- Manifest and lockfile hashes.
- File inventory.
- Dependency inventory.
- `node_modules` package inventory.
- SHA-256 for scanned files.
- Rule matches.
- Allowlist matches.
- Blocklist matches.
- Obfuscation findings.
- Vulnerability findings.
- Malware or historical compromise findings.
- Errors and skipped files.

Each file record should include:

- Relative path.
- Absolute path only when needed for local debugging.
- File size.
- Modified time.
- Mode or permissions.
- SHA-256.
- File type.
- Package ownership when inside `node_modules`.
- Whether the file was scanned, skipped, unchanged, added, removed, or modified.

## File Scan Pipeline

Each scan should be deterministic, parallel, and side-effect free.

1. Resolve the project root and create a stable project ID from the normalized root
   path plus lockfile identity.
2. Discover package manager signals from manifests, lockfiles, and dependency
   layouts.
3. Build an inventory of candidate files with a bounded parallel directory walk.
4. Skip noisy directories by default, such as `.git`, build output, coverage output,
   and package manager caches. Treat `node_modules` as a special dependency area
   instead of a normal source directory.
5. For each file, collect path, normalized relative path, size, modified time,
   permissions, symlink status, and package ownership.
6. Classify the file by extension, path, magic bytes, and package context.
7. Compute SHA-256 by streaming file contents in chunks. Reuse the previous SHA-256
   only when the file's path, size, modified time, mode, symlink target, and package
   owner match the previous scan. Add `--strict-hash` later to rehash every file.
8. Compare the current file identity to the previous scan and mark the file as
   added, removed, modified, unchanged, or previously unscanned.
9. Parse structured files with structured parsers: JSON for manifests, lockfile
   parsers for package manager files, and a JavaScript/TypeScript parser for code.
10. Apply metadata rules, path rules, hash rules, package rules, script rules, and
    source-code rules.
11. For JavaScript-like files, run the obfuscation recovery passes before final
    rule matching.
12. Emit findings with severity, confidence, source, rule ID, evidence, file hash,
    package owner, and exact location when available.
13. Write the scan snapshot and update `latest.json` atomically after the full scan
    succeeds.

Scanning should never run user code, package scripts, install scripts, or dynamic
imports. Dynamic sandboxing can be a future feature, but v0 should rely on static
analysis, metadata, registry data, and cached threat intelligence.

## Diff Model

The diff between two scans should report:

- Added files.
- Removed files.
- Modified files.
- Unchanged files.
- Files skipped in either scan.
- New dependencies.
- Removed dependencies.
- Updated dependencies.
- New package scripts.
- Changed package scripts.
- New findings.
- Resolved findings.
- Findings that still exist.

Diff output should be available as JSON first, with human-readable terminal output
as a secondary view.

## Rules, Allowlists, And Blocklists

Rules should support:

- Path patterns.
- File hash matches.
- Package name matches.
- Package version ranges.
- Registry URL matches.
- Maintainer or publisher matches.
- Script content matches.
- Suspicious install lifecycle hooks.
- Obfuscation indicators.
- Encoded payload indicators.
- Network, filesystem, or process execution indicators in package scripts.

Allowlists should suppress known-safe matches with a clear reason and expiration.
Blocklists should hard-fail known-bad packages, hashes, maintainers, URLs, or files.

## Obfuscation Checks

Initial obfuscation checks should look for:

- Minified or packed code in unexpected locations.
- High-entropy strings.
- Large encoded blobs.
- Suspicious `eval`, `Function`, `setTimeout` string execution, or dynamic imports.
- Base64 or hex payload decoding.
- Hidden files in packages.
- Postinstall scripts that fetch remote code.
- Files that differ from package tarball metadata or lockfile integrity data.

These checks should produce risk signals rather than automatic malware verdicts
unless paired with a strong blocklist or known malicious indicator.

## JavaScript Obfuscation Strategy

Malox should treat obfuscation as a signal amplifier, not proof of malware by
itself. The scanner should recover enough intent to expose dangerous behavior
without executing the package.

Base64 and encoded payloads:

- Detect base64, base64url, hex, unicode escapes, percent-encoded strings, and
  long high-entropy strings.
- Detect common decoders such as `Buffer.from(value, "base64")`, `atob`,
  `TextDecoder`, `decodeURIComponent`, `unescape`, `String.fromCharCode`,
  `Uint8Array`, and custom lookup tables.
- Reconstruct split encoded strings from simple concatenation, template literals,
  array joins, string replacement, reverse/split/join chains, and constant
  variables.
- Decode in a bounded recursive loop with maximum size, maximum depth, and timeout
  limits.
- Classify decoded bytes as JavaScript, shell, JSON, URL list, binary, archive,
  PE, ELF, Mach-O, or unknown.
- Rescan decoded JavaScript as a virtual file and compute a SHA-256 for the decoded
  payload.
- Store decoded evidence by SHA-256, not by original project path, and include the
  source file location that produced it.

Global object and alias tricks:

- Track aliases for `globalThis`, `global`, `window`, `self`, `process`, `module`,
  `exports`, `require`, and `import`.
- Resolve bracket notation where possible, such as `globalThis["pro" + "cess"]`
  or `global["requ" + "ire"]`.
- Detect constructor escapes such as `this.constructor.constructor`,
  `[].filter.constructor`, and other paths that recover `Function`.
- Track dangerous global access to `process.env`, `process.platform`,
  `process.cwd`, `process.exit`, `process.binding`, `module.require`, and
  `require.cache`.
- Treat unresolved dynamic global access as suspicious when it flows into a code
  execution, filesystem, network, child process, or credential access sink.

Runtime string and function construction:

- Implement a small partial evaluator for side-effect-free JavaScript expressions.
- Constant-fold string concatenation, template literals, array joins, char code
  arrays, simple arithmetic, simple XOR/ROT transforms, and lookup-table accesses.
- Track strings built over multiple assignments when the values are local and
  deterministic.
- Resolve common runtime-built API names like `eval`, `Function`, `require`,
  `child_process`, `exec`, `spawn`, `curl`, `wget`, `http`, `https`, `net`, `dns`,
  `fs`, `crypto`, and `os`.
- Flag `eval`, `Function`, string-based `setTimeout`, string-based `setInterval`,
  dynamic `import`, and dynamic `require` when the argument is encoded,
  partially-recovered, or cannot be resolved.
- Build a simple taint graph from suspicious string builders into dangerous sinks.
- Report both the original expression and the recovered value when recovery is
  possible.

Minified, packed, or generated code:

- Score files by line length, token density, entropy, identifier diversity,
  string-literal density, and ratio of printable to non-printable bytes.
- Allow expected bundles through package-aware rules, but flag minified files in
  unexpected places such as install scripts, nested hidden directories, or files
  added after the previous scan.
- Compare package contents against lockfile integrity and registry tarball metadata
  when available.

Limits and safety:

- Never execute suspicious JavaScript to deobfuscate it.
- Keep each deobfuscation pass bounded by file size, time, recursion depth, and
  output size.
- Downgrade findings when a package is known to ship legitimate generated bundles,
  but keep the recovered evidence in JSON output.
- Promote findings when obfuscation appears in lifecycle scripts, newly-added
  `node_modules` files, network code, credential access code, or packages with a
  known malicious history.

## Node Modules Incremental Scanning

Malox should scan `node_modules` with a cache-aware approach:

1. Build a package inventory from `node_modules`.
2. Hash package manifests and relevant files.
3. Compare the current package state to the previous scan snapshot.
4. Skip unchanged packages where the package hash and metadata match.
5. Fully scan new or changed packages.
6. Report packages that appear installed but are missing from lockfiles.
7. Report lockfile packages that are missing from `node_modules`.

This keeps repeated scans fast while still catching changed installed files.

## Malware History Checks

For each dependency, Malox should check:

- Known malicious versions.
- Known compromised package names.
- Known compromised maintainers.
- Suspicious publish timing.
- Sudden ownership or maintainer changes where data is available.
- Deprecation messages that mention malware, compromise, or security.
- Registry metadata anomalies.
- Whether the installed package contents match lockfile integrity where possible.

The result should distinguish between:

- Confirmed malicious.
- Known vulnerable.
- Suspicious.
- Policy blocked.
- Needs manual review.

## CLI Expectations

The CLI should eventually support commands like:

```sh
malox scan
malox scan --json
malox diff
malox rules test
malox cache update
malox cache clean
```

The default command should be useful without configuration:

```sh
malox scan
```

## Non-Goals For V0

- Do not build a web dashboard yet.
- Do not support every language ecosystem immediately.
- Do not require a cloud account.
- Do not require package manager commands to be available.
- Do not make malware verdicts from weak heuristics alone.
- Do not mutate project files during scanning.

## Future Ecosystems

After Node.js support is solid, add ecosystem adapters for:

- Ruby/Rails using `Gemfile`, `Gemfile.lock`, and installed gems.
- Python using `requirements.txt`, `pyproject.toml`, `poetry.lock`, and virtualenvs.
- Go using `go.mod` and `go.sum`.
- Rust using `Cargo.toml` and `Cargo.lock`.

The core scanner should remain ecosystem-independent. Each ecosystem should provide
manifest parsing, lockfile parsing, package inventory, and package-specific rules.

## Success Criteria

Malox is successful when it can:

- Run from a single terminal command.
- Scan a Node.js project quickly.
- Produce stable JSON output for automation.
- Detect changed files and dependency changes between scans.
- Hash every relevant scanned file with SHA-256.
- Check dependencies against open source vulnerability and threat sources.
- Flag known malicious or historically compromised packages.
- Catch suspicious package scripts and obfuscated payloads.
- Avoid noisy false positives through allowlists and clear severity levels.
- Stay fast on repeated scans through incremental caching.
