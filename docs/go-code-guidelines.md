# Go Code Guidelines

Research checked on 2026-06-17.

These guidelines define how Malox Go code should be written. The goal is a fast,
parallel, cross-platform terminal scanner that is easy to audit, easy to test, and
safe around hostile project contents.

This document combines:

- Local `golang-pro` skill guidance for concurrency, interfaces, generics, tests,
  and project structure.
- Local `find-skills` skill discovery. The public skills leaderboard was checked;
  `golang-pro` remains the relevant Go-specific local skill for this work.
- Current Go documentation and style references, including Go 1.26 release notes.

## Baseline

- Target Go: Go 1.26 toolchain for development.
- Module compatibility: choose the lowest supported `go` directive intentionally.
  Go 1.26 `go mod init` defaults new modules to `go 1.25.0`, encouraging
  compatibility with supported Go versions.
- Primary platforms: macOS, Linux, and Windows.
- Primary architectures: `amd64` and `arm64`.
- Default distribution: single CLI binary.
- Default cgo posture: `CGO_ENABLED=0` unless a feature has a strong reason to use
  cgo.

Do not make code clever just because Go makes it possible. Malox is a security
tool; boring code is a feature.

## Core Principles

1. Prefer clarity over cleverness.
2. Prefer standard library APIs before adding dependencies.
3. Keep package boundaries small and domain-focused.
4. Make every goroutine lifetime obvious.
5. Make every blocking operation cancelable.
6. Make all filesystem behavior explicit and cross-platform.
7. Never execute scanned project code.
8. Treat project files, package metadata, and decoded payloads as untrusted input.
9. Return structured data from core packages; format for humans only at the CLI
   boundary.
10. Write tests for behavior, edge cases, and platform assumptions.

## Recommended Project Layout

Start with a small, conventional layout:

```text
malox/
  cmd/
    malox/
      main.go
  internal/
    app/
    cache/
    config/
    diff/
    fileid/
    node/
    platform/
    report/
    rules/
    scan/
    threat/
  docs/
  testdata/
  go.mod
  go.sum
```

Use `internal/` for almost everything at first. Add `pkg/` only when Malox exposes
a stable library API intended for external users.

Do:

- Put command wiring in `cmd/malox`.
- Put business logic under `internal`.
- Keep package names short, lowercase, and specific.
- Use `testdata/` for fixtures.
- Keep generated code in clearly named generated files.

Don't:

- Create `pkg/` by default.
- Create vague packages like `utils`, `common`, `helpers`, `types`, or `models`.
- Put real logic in `main.go`.
- Let packages import upward through the architecture.

Good:

```go
package scan

type Scanner struct {
    files  FileInventory
    rules  RuleEngine
    output SnapshotWriter
}
```

Bad:

```go
package utils

func DoScanStuff(root string) {}
```

## Package Boundaries

Each package should own one idea.

Suggested responsibilities:

- `internal/app`: top-level orchestration.
- `internal/config`: config loading and validation.
- `internal/cache`: global and project cache storage.
- `internal/fileid`: path, hash, size, mtime, symlink, and file identity logic.
- `internal/scan`: project scan pipeline and worker coordination.
- `internal/node`: Node manifests, lockfiles, package manager detection, and
  `node_modules` inventory.
- `internal/rules`: allowlist, blocklist, and static rule execution.
- `internal/threat`: OSV, npm registry, deps.dev, and other source adapters.
- `internal/diff`: snapshot comparison.
- `internal/report`: JSON and terminal output models.
- `internal/platform`: OS-specific paths, terminal behavior, and file edge cases.

Do:

- Define domain types where they are used.
- Keep cyclic dependencies impossible.
- Return concrete types from constructors.
- Accept small interfaces at the consumer boundary.

Don't:

- Define interfaces in the producer package only for mocks.
- Export types before they are needed outside the package.
- Share mutable package globals.

## Naming

Follow standard Go naming:

- Packages: lowercase, short, no underscores.
- Exported names: `MixedCaps`.
- Unexported names: `mixedCaps`.
- Initialisms: `ID`, `URL`, `HTTP`, `JSON`, `OSV`, `SHA256`.
- Receiver names: short and consistent.
- Error values: `ErrNotFound`, `ErrBlocked`.
- Error types: `ParseError`, `PolicyError`.

Good:

```go
type PackageID struct {
    Name    string
    Version string
}

func (p PackageID) PURL() string {
    return "pkg:npm/" + p.Name + "@" + p.Version
}
```

Bad:

```go
type PackageId struct {
    Package_Name string
}

func (packageIdentifier PackageId) GetPackageUrl() string { return "" }
```

Do:

- Let package names reduce repetition: `scan.Snapshot`, not `scan.ScanSnapshot`
  unless the extra word is genuinely clarifying.
- Use longer names for wider scopes.
- Use short names for tiny local scopes.

Don't:

- Use `data`, `item`, `manager`, or `handler` when the domain has a better name.
- Use stutter like `rules.RuleRule`.
- Add `Get` to getters unless it is required by an existing interface.

## Formatting And Imports

All Go code must be formatted by `gofmt` or `goimports`.

Do:

- Use tabs as emitted by `gofmt`.
- Keep imports grouped as standard library, blank line, third-party or local.
- Let `goimports` add and remove imports.
- Wrap long lines when it improves meaning, not to satisfy a fixed column.

Don't:

- Manually align code into decorative columns.
- Add a hard line length rule.
- Rename imports unless avoiding a real collision.
- Use dot imports outside rare external test cases.

Good:

```go
import (
    "context"
    "errors"
    "fmt"

    "github.com/example/malox/internal/scan"
)
```

## Comments And Documentation

Comments should explain intent, constraints, and sharp edges.

Do:

- Document every exported package, type, function, method, constant, and variable.
- Start doc comments with the exported name.
- Explain "why" for tricky code.
- Document goroutine lifetimes and ownership.
- Document non-obvious performance tradeoffs.

Don't:

- Restate obvious code.
- Leave comments that contradict the implementation.
- Use comments to excuse confusing code that could be clearer.

Good:

```go
// Snapshot stores the normalized result of one completed project scan.
type Snapshot struct {
    Files []FileRecord `json:"files"`
}
```

Better for tricky code:

```go
// We keep slash-separated paths in snapshots so diffs stay stable across
// Windows, macOS, and Linux.
rel = filepath.ToSlash(rel)
```

Bad:

```go
// Set x to y.
x = y
```

## Error Handling

Errors are values. Handle them explicitly.

Do:

- Return errors instead of panicking.
- Wrap errors with `%w` when preserving cause matters.
- Use lowercase error strings without trailing punctuation.
- Use `errors.Is` and `errors.As` for classification.
- Include path, package, source, or rule context when it helps debugging.
- Treat partial scan errors as structured findings or warnings when scanning can
  safely continue.

Don't:

- Ignore errors with `_` unless there is a documented reason.
- Panic for normal control flow.
- Log and return the same error at low layers.
- Compare error strings.
- Hide the original cause.

Good:

```go
func loadManifest(path string) (*Manifest, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("read manifest %q: %w", path, err)
    }

    var manifest Manifest
    if err := json.Unmarshal(data, &manifest); err != nil {
        return nil, fmt.Errorf("parse manifest %q: %w", path, err)
    }

    return &manifest, nil
}
```

Good sentinel error:

```go
var ErrPolicyBlocked = errors.New("policy blocked")

func block(name string) error {
    return fmt.Errorf("%s: %w", name, ErrPolicyBlocked)
}
```

Bad:

```go
data, _ := os.ReadFile(path)
if data == nil {
    panic("Could not read file!")
}
```

## Context And Cancellation

Use `context.Context` for cancellation, deadlines, and request-scoped values.

Do:

- Put `ctx context.Context` as the first argument for blocking operations.
- Call every cancel function on all paths, usually with `defer cancel()`.
- Pass context through scan, threat lookup, cache update, and network APIs.
- Use context values only for request-scoped cross-boundary data.
- Use `context.TODO()` when wiring is incomplete, not `nil`.

Don't:

- Store `context.Context` in structs.
- Create custom context interfaces.
- Use context values for optional parameters.
- Start goroutines that cannot observe cancellation.

Good:

```go
func (c *Client) Query(ctx context.Context, purl string) (*ThreatResult, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url(purl), nil)
    if err != nil {
        return nil, fmt.Errorf("build threat request: %w", err)
    }
    // ...
    return nil, nil
}
```

Bad:

```go
type Scanner struct {
    ctx context.Context
}
```

## Interfaces

Use interfaces at consumption points. Keep them tiny.

Do:

- Accept interfaces, return concrete types.
- Define an interface only when there is a real consumer.
- Prefer one-method interfaces when they match the domain.
- Compose small interfaces instead of creating large ones.
- Use standard interfaces like `io.Reader`, `io.Writer`, `fs.FS`, and
  `http.RoundTripper`.

Don't:

- Add interfaces preemptively.
- Return interfaces from constructors unless hiding implementation is essential.
- Define `Manager` interfaces with many unrelated methods.

Good:

```go
type HashStore interface {
    Lookup(path string) (FileHash, bool)
}

type Hasher struct {
    previous HashStore
}

func NewHasher(previous HashStore) *Hasher {
    return &Hasher{previous: previous}
}
```

Bad:

```go
type ScannerManager interface {
    Scan()
    Diff()
    Print()
    Save()
    Load()
    Download()
    Configure()
}
```

## Generics

Use generics when they remove real duplication without hiding behavior.

Do:

- Use `any` for unconstrained values.
- Use `comparable` for map keys and equality checks.
- Use union constraints for small, explicit sets of supported types.
- Prefer ordinary functions when generic code would be harder to read.

Don't:

- Turn simple domain structs into generic machinery.
- Use generics to emulate inheritance.
- Add type parameters before two or more real call sites need them.
- Panic in generic code except for truly unreachable default branches.

Good:

```go
func Keys[K comparable, V any](m map[K]V) []K {
    keys := make([]K, 0, len(m))
    for k := range m {
        keys = append(keys, k)
    }
    return keys
}
```

Good domain-specific alternative:

```go
func PackageNames(pkgs map[string]Package) []string {
    names := make([]string, 0, len(pkgs))
    for name := range pkgs {
        names = append(names, name)
    }
    sort.Strings(names)
    return names
}
```

## Concurrency

Concurrency is for throughput and responsiveness, not decoration.

Do:

- Bound concurrency with worker pools, semaphores, or rate limiters.
- Make ownership of channels obvious.
- Close channels from the sender side.
- Use `sync.WaitGroup` to wait for goroutines.
- Propagate cancellation and first fatal error.
- Prefer `sync.Mutex` for shared state when it is simpler than channels.
- Document when goroutines exit.

Don't:

- Start goroutines without a clear lifetime.
- Let goroutines block forever on sends after cancellation.
- Close channels from receivers.
- Use unbounded goroutine-per-file scanning on large trees.
- Mix shared memory and channels casually.

Good bounded worker pool:

```go
type hashResult struct {
    hash FileHash
    err  error
}

func hashFiles(ctx context.Context, paths []string, workers int) ([]FileHash, error) {
    ctx, cancel := context.WithCancel(ctx)
    defer cancel()

    jobs := make(chan string)
    results := make(chan hashResult, len(paths))

    var wg sync.WaitGroup
    for range workers {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for path := range jobs {
                hash, err := hashFile(ctx, path)
                if err != nil {
                    results <- hashResult{err: err}
                    cancel()
                    return
                }

                select {
                case results <- hashResult{hash: hash}:
                case <-ctx.Done():
                    return
                }
            }
        }()
    }

    go func() {
        defer close(jobs)
        for _, path := range paths {
            select {
            case jobs <- path:
            case <-ctx.Done():
                return
            }
        }
    }()

    go func() {
        wg.Wait()
        close(results)
    }()

    var firstErr error
    hashes := make([]FileHash, 0, len(paths))
    for result := range results {
        if result.err != nil {
            if firstErr == nil {
                firstErr = result.err
                cancel()
            }
            continue
        }
        hashes = append(hashes, result.hash)
    }

    if firstErr != nil {
        return nil, firstErr
    }
    if err := ctx.Err(); err != nil {
        return nil, fmt.Errorf("hash files: %w", err)
    }
    return hashes, nil
}
```

Bad unbounded scan:

```go
for _, path := range paths {
    go hashFile(context.Background(), path)
}
```

For Malox:

- File hashing should be CPU and I/O bounded.
- Threat lookups should be network-rate bounded.
- Decoding and AST analysis should be CPU bounded.
- Cache writes should be serialized or atomic.

## Filesystem And Cross-Platform Rules

The scanner must behave the same on macOS, Linux, and Windows.

Do:

- Use `filepath` for OS paths.
- Use slash-separated paths in snapshots and JSON output.
- Convert with `filepath.ToSlash` and `filepath.Localize` where appropriate.
- Use `filepath.IsLocal` before joining untrusted relative paths.
- Use `os.UserCacheDir` for global cache roots.
- Use `os.UserConfigDir` for user config roots if needed.
- Use `filepath.WalkDir` or `fs.WalkDir` for tree walks.
- Treat symlinks explicitly.
- Normalize paths before comparing.
- Be careful with case-insensitive filesystems.
- Use atomic write-then-rename for cache and snapshot files.

Don't:

- Hardcode `/` or `\` for filesystem paths.
- Assume case sensitivity.
- Assume executable bits exist on Windows.
- Assume symlinks work the same way on Windows.
- Store absolute project paths in global cache.
- Follow symlinks without a loop and escape strategy.
- Use shell commands for file operations that the standard library can perform.

Good path normalization:

```go
func snapshotPath(root, path string) (string, error) {
    rel, err := filepath.Rel(root, path)
    if err != nil {
        return "", fmt.Errorf("make relative path: %w", err)
    }
    if !filepath.IsLocal(rel) {
        return "", fmt.Errorf("path escapes root: %q", rel)
    }
    return filepath.ToSlash(rel), nil
}
```

Good cache root:

```go
func cacheRoot() (string, error) {
    base, err := os.UserCacheDir()
    if err != nil {
        return "", fmt.Errorf("find user cache dir: %w", err)
    }
    return filepath.Join(base, "malox"), nil
}
```

Good safe project-relative open on Go 1.24+:

```go
func openProjectFile(root, rel string) (*os.File, error) {
    if !filepath.IsLocal(rel) {
        return nil, fmt.Errorf("unsafe relative path %q", rel)
    }
    f, err := os.OpenInRoot(root, rel)
    if err != nil {
        return nil, fmt.Errorf("open project file %q: %w", rel, err)
    }
    return f, nil
}
```

Bad:

```go
path := root + "/" + userInput
data, _ := os.ReadFile(path)
```

## CLI Design

The CLI should be predictable for humans and automation.

Do:

- Print human-readable output to stdout.
- Print logs and diagnostics to stderr.
- Support `--json` for machine-readable output.
- Use stable exit codes.
- Make `malox scan` useful without configuration.
- Keep network-affecting operations explicit when they are not part of normal
  scanning.

Don't:

- Print progress into JSON output.
- Hide partial errors.
- Require shell-specific behavior.
- Require npm, pnpm, yarn, bun, or deno commands to exist for basic scans.

Recommended exit codes:

```text
0 no findings above threshold
1 findings at or above threshold
2 usage or configuration error
3 scan failed
4 threat source unavailable when required
```

## Logging

Use structured logging at the application boundary. Core packages should usually
return structured results instead of logging.

Do:

- Prefer `log/slog` for app-level logs.
- Use stable keys.
- Redact secrets and environment values.
- Include package name, source, rule ID, path, or PURL when helpful.

Don't:

- Log scanned file contents.
- Log decoded payload contents by default.
- Log secrets from environment variables or package scripts.
- Use logs as a substitute for returned errors.

Good:

```go
logger.Info("threat source updated",
    "source", "osv",
    "records", count,
    "duration", elapsed,
)
```

Bad:

```go
log.Printf("downloaded thing: %+v", response)
```

## Configuration

Keep configuration explicit and small.

Do:

- Load config once near startup.
- Validate config before running.
- Pass typed config structs into packages.
- Use functional options only where a constructor genuinely needs optional
  settings.
- Prefer environment variables for CI overrides.

Don't:

- Read environment variables deep inside business logic.
- Use package globals for mutable configuration.
- Let defaults change based on the current directory in surprising ways.

Good:

```go
type ScanConfig struct {
    Root        string
    StateDir    string
    Offline     bool
    MaxWorkers  int
    MaxFileSize int64
}

func (c ScanConfig) Validate() error {
    if c.Root == "" {
        return errors.New("root is required")
    }
    if c.MaxWorkers < 1 {
        return errors.New("max workers must be positive")
    }
    return nil
}
```

## Dependency Policy

Dependencies expand the supply chain. Add them deliberately.

Do:

- Prefer the standard library.
- Add dependencies only for parsing, formats, or protocols that would be risky to
  hand-roll.
- Pin versions through `go.mod` and commit `go.sum`.
- Run vulnerability checks in CI when the Go project exists.
- Review licenses.
- Prefer small, maintained libraries with clear APIs.

Don't:

- Add large frameworks for small helpers.
- Add dependencies for trivial string or path manipulation.
- Vendor by default.
- Use `replace` directives in committed release code unless documented.

For Malox, reasonable dependency candidates may include:

- CLI argument parsing if the standard `flag` package becomes too limited.
- YAML lockfile parsing.
- JavaScript or TypeScript parsing.
- Semver and package URL parsing.

## Security Rules

Malox scans untrusted projects. Code must be defensive by default.

Do:

- Never execute package install scripts during scanning.
- Never evaluate JavaScript to deobfuscate payloads.
- Limit file sizes, decode depths, archive depths, and runtime per file.
- Use `crypto/sha256` for file hashing.
- Use `crypto/rand` for security tokens or random IDs.
- Validate all untrusted paths.
- Bound memory use for large files.
- Treat archive extraction as hostile input.
- Keep network requests timeout-bound and context-bound.

Don't:

- Use `math/rand` for security-sensitive values.
- Trust package metadata.
- Trust lockfile paths.
- Trust tarball contents to stay inside extraction roots.
- Store secrets in snapshots.
- Shell out to package managers for normal scanning.

Good bounded read:

```go
func readSmallJSON(path string, max int64) ([]byte, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, fmt.Errorf("open json %q: %w", path, err)
    }
    defer f.Close()

    limited := io.LimitReader(f, max+1)
    data, err := io.ReadAll(limited)
    if err != nil {
        return nil, fmt.Errorf("read json %q: %w", path, err)
    }
    if int64(len(data)) > max {
        return nil, fmt.Errorf("json file too large: %q", path)
    }
    return data, nil
}
```

## Performance

Optimize with evidence.

Do:

- Start with clear code.
- Benchmark hot paths.
- Use `pprof` for CPU, memory, blocking, and mutex profiles.
- Preallocate slices when size is known.
- Stream large files instead of loading them whole.
- Reuse buffers only when the lifetime is obvious.
- Keep JSON output stable even if internal processing is parallel.

Don't:

- Optimize before measuring.
- Add pooling that makes ownership unclear.
- Share mutable buffers across goroutines without protection.
- Sacrifice correctness for micro-optimizations.

Good streaming hash:

```go
func hashSHA256(path string) ([32]byte, error) {
    f, err := os.Open(path)
    if err != nil {
        return [32]byte{}, fmt.Errorf("open %q: %w", path, err)
    }
    defer f.Close()

    h := sha256.New()
    if _, err := io.Copy(h, f); err != nil {
        return [32]byte{}, fmt.Errorf("hash %q: %w", path, err)
    }

    var sum [32]byte
    copy(sum[:], h.Sum(nil))
    return sum, nil
}
```

## Testing

Use tests to lock down behavior, not implementation trivia.

Do:

- Write table-driven tests.
- Use subtests with clear names.
- Use `t.Helper()` in helpers.
- Use `t.TempDir()` for filesystem tests.
- Use `t.Setenv()` for environment tests.
- Add fuzz tests for parsers and decoders.
- Add golden files for stable JSON reports.
- Run race tests for concurrent code in CI.
- Test platform-sensitive code on Windows, macOS, and Linux in CI.

Don't:

- Depend on test order.
- Use real user cache or config directories in tests.
- Leave tests that need network enabled by default.
- Compare raw JSON strings when decoding and comparing structures is clearer.
- Use sleeps for synchronization when channels or contexts can express the event.

Good table test:

```go
func TestNormalizeSnapshotPath(t *testing.T) {
    root := t.TempDir()

    tests := []struct {
        name string
        path string
        want string
    }{
        {name: "file", path: filepath.Join(root, "package.json"), want: "package.json"},
        {name: "nested", path: filepath.Join(root, "src", "main.js"), want: "src/main.js"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := snapshotPath(root, tt.path)
            if err != nil {
                t.Fatalf("snapshotPath() error = %v", err)
            }
            if got != tt.want {
                t.Fatalf("snapshotPath() = %q, want %q", got, tt.want)
            }
        })
    }
}
```

Good fuzz target:

```go
func FuzzDecodeBase64Candidate(f *testing.F) {
    f.Add("Y29uc29sZS5sb2coJ2hpJyk=")
    f.Add("")

    f.Fuzz(func(t *testing.T, input string) {
        _, _ = DecodeBase64Candidate(input)
    })
}
```

Note for Go 1.22+:

- Loop variables are created per iteration, so the old `tt := tt` workaround is
  not needed when the package is built with Go 1.22 or newer semantics.
- If the project intentionally supports older Go directives, keep the capture in
  parallel subtests.

## Linting And Static Analysis

Use the built-in Go tools first, then focused linters.

Expected checks for code contributors:

```sh
gofmt
goimports
go vet
golangci-lint
go test
go test -race
govulncheck
```

Do:

- Keep linter config strict but explain intentional exclusions.
- Prefer `//nolint:<name>` with a reason.
- Enable linters for unchecked errors, context misuse, security checks, logging
  key/value mistakes, naked returns, unused code, and interface bloat.
- Use `go fix` modernizers intentionally when upgrading idioms.

Don't:

- Add blanket `//nolint`.
- Turn on noisy linters without a path to fix violations.
- Let generated code dominate lint results.

Example `nolint`:

```go
// The close error is intentionally ignored because the write error above is
// already being returned and close cannot add useful recovery here.
_ = f.Close() //nolint:errcheck
```

## JSON And Output Contracts

Malox output should be stable and diff-friendly.

Do:

- Define explicit JSON structs.
- Use snake_case JSON field names.
- Add fields without removing or changing existing meaning.
- Sort output where map iteration would be nondeterministic.
- Include schema version in scan snapshots.

Don't:

- Marshal internal structs directly if they include implementation details.
- Put absolute paths into global cache output.
- Emit nondeterministic map order where humans will diff files.

Good:

```go
type Finding struct {
    RuleID     string `json:"rule_id"`
    Severity   string `json:"severity"`
    Confidence string `json:"confidence"`
    Path       string `json:"path,omitempty"`
    Package    string `json:"package,omitempty"`
}
```

## Build Tags And Platform Files

Use build tags for real platform differences.

Do:

- Name platform files with suffixes like `_windows.go`, `_unix.go`, `_darwin.go`,
  `_linux.go`.
- Keep shared behavior in shared files.
- Use `//go:build` constraints.
- Test each platform implementation in CI.

Don't:

- Scatter `runtime.GOOS` branches everywhere.
- Hide large behavioral differences behind tiny helper names.
- Use build tags to avoid fixing portable code.

Good:

```go
//go:build windows

package platform

func executableSuffix() string {
    return ".exe"
}
```

```go
//go:build !windows

package platform

func executableSuffix() string {
    return ""
}
```

## Review Checklist

Before code is considered ready:

- `gofmt` or `goimports` has formatted changed files.
- All errors are handled or intentionally documented.
- Public APIs have doc comments.
- Blocking operations accept context.
- Goroutines have clear exit paths.
- Channels have clear ownership.
- Filesystem paths are portable and validated.
- Tests cover success, failure, and edge cases.
- Platform-sensitive code has platform tests or isolated wrappers.
- Threat-source network code has timeout and retry policy.
- JSON output is deterministic.
- No scanned code is executed.
- No secrets are logged or cached.
- New dependencies are justified.

## Small Do And Don't Summary

Do:

- Use `filepath.Join`, `filepath.Rel`, `filepath.ToSlash`, `filepath.IsLocal`.
- Use `os.UserCacheDir` and project-local `.malox` state.
- Use `context.Context` for scan, cache, and network operations.
- Use small consumer-side interfaces.
- Use worker pools for file scanning.
- Use streaming hashes for large files.
- Use structured findings instead of ad-hoc strings.
- Use table tests and fuzz tests for parsers.
- Use `slog` at the CLI/app boundary.
- Use `govulncheck` once the Go module exists.

Don't:

- Don't use shell commands for normal scanner behavior.
- Don't execute package code.
- Don't trust paths from lockfiles or packages.
- Don't use unbounded goroutines.
- Don't ignore errors.
- Don't panic for normal failures.
- Don't store contexts in structs.
- Don't create broad `Manager` interfaces.
- Don't hardcode Unix-only paths.
- Don't add dependencies for trivial helpers.

## Sources

- [Go 1.26 Release Notes](https://go.dev/doc/go1.26)
- [Effective Go](https://go.dev/doc/effective_go)
- [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments)
- [Google Go Style Guide](https://google.github.io/styleguide/go/guide)
- [Google Go Style Decisions](https://google.github.io/styleguide/go/decisions)
- [Google Go Best Practices](https://google.github.io/styleguide/go/best-practices)
- [Managing dependencies](https://go.dev/doc/modules/managing-dependencies)
- [Go Vulnerability Management](https://go.dev/doc/security/vuln/)
- [Go fuzzing tutorial](https://go.dev/doc/tutorial/fuzz)
- [context package](https://pkg.go.dev/context)
- [testing package](https://pkg.go.dev/testing)
- [log/slog package](https://pkg.go.dev/log/slog)
- [path/filepath package](https://pkg.go.dev/path/filepath)
- [os package](https://pkg.go.dev/os)
- [golangci-lint linters](https://golangci-lint.run/docs/linters/)
- [skills.sh directory](https://www.skills.sh/)
