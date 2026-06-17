# Milestone 8: JavaScript Obfuscation And Payload Analysis

## Purpose

Detect suspicious JavaScript and TypeScript obfuscation without executing scanned
code.

## Scope

- Extend packages:
  - `internal/rules`
  - `internal/scan`
- Add package when needed:
  - `internal/node/jsanalysis`
- Detect:
  - base64, base64url, hex, unicode escapes, percent encoding, and high-entropy
    strings
  - split encoded strings from concatenation, template literals, array joins,
    string replacement, reverse/split/join chains, and constant variables
  - common decoders such as `Buffer.from`, `atob`, `TextDecoder`,
    `decodeURIComponent`, `unescape`, `String.fromCharCode`, and lookup tables
  - aliases for `globalThis`, `global`, `window`, `self`, `process`, `module`,
    `exports`, `require`, and `import`
  - bracket notation such as `globalThis["pro" + "cess"]`
  - constructor escapes that recover `Function`
  - string-based `eval`, `Function`, `setTimeout`, `setInterval`, dynamic import,
    and dynamic require
  - filesystem, network, child-process, credential, and environment access sinks
- Implement a bounded partial evaluator for side-effect-free JavaScript
  expressions.
- Decode suspicious payloads with maximum size, depth, and time limits.
- Classify decoded bytes as JavaScript, shell, JSON, URL list, binary, archive,
  PE, ELF, Mach-O, or unknown.
- Rescan decoded JavaScript as virtual files.
- Store decoded evidence by SHA-256 under the global cache, never by project path.
- Add finding evidence with original expression, recovered value when safe, file
  hash, package owner, and source location.

## Out Of Scope

- Executing JavaScript.
- Dynamic sandboxing.
- Perfect JavaScript interpretation.
- Deobfuscating every commercial packer.
- Treating obfuscation alone as confirmed malware.

## CLI Requirements

- `malox scan --json` includes obfuscation findings with confidence and evidence.
- Human output summarizes obfuscation findings by severity and package.
- `--max-file-size`, decode-depth, and timeout limits are reflected in skipped or
  partial-analysis warnings.
- `--offline` still performs local obfuscation checks because they do not require
  network access.

## Implementation Constraints

- Use a real parser for JavaScript or TypeScript source when practical.
- Never execute scanned JavaScript.
- Keep every decode and partial-evaluation pass bounded.
- Do not log decoded payload contents by default.
- Avoid regex-only JavaScript parsing for anything requiring syntax awareness.
- Keep virtual decoded files tied to source SHA-256 and finding evidence.
- Promote severity only when obfuscation combines with dangerous sinks, lifecycle
  scripts, newly added files, known bad packages, or threat-source matches.

## Temporary Data Or Implementation

- The first parser may support JavaScript before TypeScript if TypeScript parsing
  is tracked and clearly reported as partial.
- The first partial evaluator may cover only side-effect-free expressions listed
  in this milestone.
- Encoded payload recovery from Milestone 5 must be replaced or routed through
  this JavaScript-aware analyzer.
- Packer-specific detections may start as conservative signatures, but must not
  produce confirmed-malicious verdicts without stronger evidence.
- Decoded fixture payloads must live under `testdata/`; production decoded
  payloads must be written only by SHA-256 in the cache.

## Passing Criteria

- Fixture files with base64, hex, split strings, array joins, and simple lookup
  tables produce recovered evidence.
- Fixture files with `eval`, `Function`, dynamic require/import, and string-based
  timers produce findings when data flows from suspicious string builders.
- Legitimate minified bundles in expected package locations do not automatically
  become high-severity findings.
- Decoding limits stop oversized, recursive, or slow payload recovery and report
  structured warnings.
- Decoded JavaScript virtual files are hashed and rescanned without writing
  project-path data into the global cache.
- Unit tests cover parser behavior, partial evaluation, alias tracking, sink
  detection, decode limits, severity promotion, and false-positive controls.

