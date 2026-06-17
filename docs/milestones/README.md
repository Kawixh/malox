# Malox Milestones

These milestones turn the project goal into implementation slices that can be
built, reviewed, and accepted independently.

Every milestone must preserve the same engineering bar:

- Keep command-line behavior accessible, predictable, and documented through
  `malox --help` and subcommand help.
- Keep core packages independent from terminal formatting.
- Return structured data from scanner logic and format it only at the CLI/report
  boundary.
- Keep code readable, small, and package-focused. Do not create catch-all
  packages such as `utils`, `common`, `helpers`, `types`, or `models`.
- Treat scanned projects, lockfiles, registry metadata, and decoded payloads as
  untrusted input.
- Never execute project code, package scripts, dynamic imports, or installer
  hooks during scanning.
- Use temporary fixtures only in tests or clearly named development-only sample
  data. Do not let fake threat data or placeholder logic become product behavior.
- Replace or remove any temporary implementation in the later milestone that owns
  the real behavior.
- Do not consider a milestone complete until its temporary-data notes are resolved
  or explicitly carried forward by the next milestone.

## Milestone Order

1. [CLI And Project Foundation](./01-cli-and-project-foundation.md)
2. [Baseline Project Scan Snapshot](./02-baseline-project-scan-snapshot.md)
3. [Snapshot Persistence And Diff](./03-snapshot-persistence-and-diff.md)
4. [Node Project And Dependency Inventory](./04-node-project-and-dependency-inventory.md)
5. [Local Rules, Allowlists, And Blocklists](./05-local-rules-allowlists-blocklists.md)
6. [Cache Architecture And Offline Mode](./06-cache-architecture-and-offline-mode.md)
7. [Threat Intelligence Source Adapters](./07-threat-intelligence-source-adapters.md)
8. [JavaScript Obfuscation And Payload Analysis](./08-javascript-obfuscation-and-payload-analysis.md)
9. [Incremental `node_modules` Scanning](./09-incremental-node-modules-scanning.md)
10. [Terminal UX, Reports, And Release Hardening](./10-terminal-ux-reports-release-hardening.md)

