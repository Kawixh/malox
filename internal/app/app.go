// Package app wires the Malox command-line application.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"malox/internal/cache"
	"malox/internal/config"
	"malox/internal/diff"
	"malox/internal/report"
	"malox/internal/rules"
	"malox/internal/scan"
	"malox/internal/threat"
)

// Options controls one CLI invocation.
type Options struct {
	Args    []string
	Stdout  io.Writer
	Stderr  io.Writer
	WorkDir string
	Build   BuildInfo
}

// BuildInfo describes build metadata injected by the main package.
type BuildInfo struct {
	Version   string
	Commit    string
	BuildDate string
}

// Run executes the Malox CLI and returns a process exit code.
func Run(ctx context.Context, opts Options) int {
	opts = normalizeOptions(opts)

	inv, err := parseInvocation(opts.Args)
	if err != nil {
		writeUsageError(opts.Stderr, err)
		return ExitUsage
	}

	if inv.help {
		return writeHelp(opts.Stdout, inv.command)
	}
	if inv.version || inv.command == commandVersion {
		if err := writeVersion(opts.Stdout, opts.Build); err != nil {
			writeRuntimeError(opts.Stderr, err)
			return ExitScanFailed
		}
		return ExitOK
	}
	if inv.command == commandRoot {
		return writeHelp(opts.Stdout, commandRoot)
	}

	cfg, err := config.Load(ctx, config.LoadOptions{
		Flags:   inv.flags,
		WorkDir: opts.WorkDir,
	})
	if err != nil {
		writeConfigError(opts.Stderr, err)
		return ExitUsage
	}

	logger := newLogger(opts.Stderr, cfg)
	if cfg.Verbose {
		logger.DebugContext(ctx, "command parsed", "command", inv.command.String())
	}

	if err := runCommand(ctx, inv.command, cfg, opts.Stdout, opts.Build); err != nil {
		code := ExitCode(err)
		if cfg.Verbose {
			logger.DebugContext(ctx, "command failed", "command", inv.command.String(), "exit_code", code)
		}
		if code != ExitFindings {
			writeRuntimeError(opts.Stderr, err)
		}
		return code
	}

	return ExitOK
}

func normalizeOptions(opts Options) Options {
	if opts.Stdout == nil {
		opts.Stdout = io.Discard
	}
	if opts.Stderr == nil {
		opts.Stderr = io.Discard
	}
	if opts.Build.Version == "" {
		opts.Build.Version = "unknown"
	}
	if opts.Build.Commit == "" {
		opts.Build.Commit = "unknown"
	}
	if opts.Build.BuildDate == "" {
		opts.Build.BuildDate = "unknown"
	}
	return opts
}

func newLogger(w io.Writer, cfg config.Values) *slog.Logger {
	if cfg.Quiet {
		w = io.Discard
	}
	level := slog.LevelInfo
	if cfg.Verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}

func runCommand(ctx context.Context, command command, cfg config.Values, stdout io.Writer, build BuildInfo) error {
	if err := ctx.Err(); err != nil {
		return withExitCode(ExitScanFailed, fmt.Errorf("command canceled: %w", err))
	}

	switch command {
	case commandScan:
		globalCache, err := cache.NewGlobalStore(cfg.CacheDir)
		if err != nil {
			return withExitCode(ExitScanFailed, fmt.Errorf("open global cache: %w", err))
		}
		if err := globalCache.Ensure(ctx); err != nil {
			return withExitCode(ExitScanFailed, fmt.Errorf("prepare global cache: %w", err))
		}
		policies, err := rules.Load(ctx, rules.LoadOptions{
			PolicyFiles: cfg.Rules.PolicyFiles,
			UseBuiltins: cfg.Rules.UseBuiltins,
		})
		if err != nil {
			return withExitCode(ExitUsage, fmt.Errorf("load rules: %w", err))
		}
		store, err := cache.NewStore(cfg.StateDir)
		if err != nil {
			return withExitCode(ExitScanFailed, fmt.Errorf("open project state: %w", err))
		}
		previous, found, err := store.LoadLatest(ctx)
		if err != nil {
			return withExitCode(ExitScanFailed, fmt.Errorf("load previous snapshot: %w", err))
		}
		var previousSnapshot *scan.Snapshot
		if found {
			previousSnapshot = &previous
		}
		snapshot, err := scan.Project(ctx, scan.Options{
			Root:              cfg.Scan.Root,
			StateDir:          store.Dir(),
			ScannerVersion:    build.Version,
			MaxWorkers:        cfg.Scan.MaxWorkers,
			MaxFileSize:       cfg.Scan.MaxFileSize,
			StrictHash:        cfg.Scan.StrictHash,
			Previous:          previousSnapshot,
			RulePolicies:      policies,
			DecodedPayloadDir: filepath.Join(globalCache.Dir(), "decoded-payloads", "sha256"),
		})
		if err != nil {
			return withExitCode(ExitScanFailed, fmt.Errorf("scan project: %w", err))
		}
		threatResult, err := threat.Evaluate(ctx, snapshot.Node, threat.Options{
			Store:           globalCache,
			Offline:         cfg.Offline,
			Sources:         cfg.Threat.Sources,
			RequiredSources: cfg.Threat.RequiredSources,
			OSVURL:          cfg.Threat.OSVURL,
			NPMRegistryURL:  cfg.Threat.NPMRegistryURL,
		})
		if err != nil {
			if errors.Is(err, threat.ErrRequiredSourceUnavailable) {
				return withExitCode(ExitThreatUnavailable, err)
			}
			return withExitCode(ExitScanFailed, fmt.Errorf("evaluate threat sources: %w", err))
		}
		snapshot.Findings = append(snapshot.Findings, threatResult.Findings...)
		snapshot.ThreatSources = threatResult.Sources
		scan.RefreshSummary(&snapshot)
		if err := store.WriteSnapshot(ctx, snapshot); err != nil {
			return withExitCode(ExitScanFailed, fmt.Errorf("persist scan snapshot: %w", err))
		}
		if err := report.WriteScan(stdout, snapshot, cfg.Scan.Output); err != nil {
			return withExitCode(ExitScanFailed, fmt.Errorf("write scan report: %w", err))
		}
		if rules.HasBlockingFindings(snapshot.Findings) {
			return withExitCode(ExitFindings, errors.New("blocking policy findings found"))
		}
		return nil
	case commandDiff:
		diffReport, err := runDiff(ctx, cfg)
		if err != nil {
			return err
		}
		if err := report.WriteDiff(stdout, diffReport, cfg.Diff.Output); err != nil {
			return withExitCode(ExitScanFailed, fmt.Errorf("write diff report: %w", err))
		}
		if diffReport.HasRelevantChanges() {
			return withExitCode(ExitFindings, errors.New("snapshot differences found"))
		}
		return nil
	case commandRulesTest:
		return runRulesTest(ctx, cfg, stdout, build)
	case commandCacheUpdate:
		globalCache, err := cache.NewGlobalStore(cfg.CacheDir)
		if err != nil {
			return withExitCode(ExitScanFailed, fmt.Errorf("open global cache: %w", err))
		}
		result, err := globalCache.Update(ctx, cache.UpdateOptions{
			Offline: cfg.Offline,
			Source:  cfg.Cache.Source,
		})
		if err != nil {
			return withExitCode(ExitScanFailed, fmt.Errorf("update cache: %w", err))
		}
		threatChanges, warnings, err := threat.UpdateSource(ctx, threat.Options{
			Store:   globalCache,
			Offline: cfg.Offline,
		}, cfg.Cache.Source)
		if err != nil {
			return withExitCode(ExitScanFailed, fmt.Errorf("update threat source: %w", err))
		}
		result.Sources = append(result.Sources, threatChanges...)
		result.Warnings = append(result.Warnings, warnings...)
		if err := report.WriteCache(stdout, result, cfg.Cache.Output); err != nil {
			return withExitCode(ExitScanFailed, fmt.Errorf("write cache report: %w", err))
		}
		return nil
	case commandCacheClean:
		globalCache, err := cache.NewGlobalStore(cfg.CacheDir)
		if err != nil {
			return withExitCode(ExitScanFailed, fmt.Errorf("open global cache: %w", err))
		}
		result, err := globalCache.Clean(ctx, cache.CleanOptions{
			Expired: cfg.Cache.Clean.Expired,
			All:     cfg.Cache.Clean.All,
			Force:   cfg.Cache.Clean.Force,
		})
		if err != nil {
			if errors.Is(err, cache.ErrCleanAllRequiresForce) {
				return withExitCode(ExitUsage, err)
			}
			return withExitCode(ExitScanFailed, fmt.Errorf("clean cache: %w", err))
		}
		if err := report.WriteCache(stdout, result, cfg.Cache.Output); err != nil {
			return withExitCode(ExitScanFailed, fmt.Errorf("write cache report: %w", err))
		}
		return nil
	default:
		return usageError("command %q is not implemented", command.String())
	}
}

func runRulesTest(ctx context.Context, cfg config.Values, stdout io.Writer, build BuildInfo) error {
	if cfg.Rules.Test.RuleFile == "" {
		return usageError("rules test requires a rule file")
	}
	if cfg.Rules.Test.Fixture == "" {
		return usageError("rules test requires --fixture")
	}
	info, err := os.Stat(cfg.Rules.Test.Fixture)
	if err != nil {
		return withExitCode(ExitUsage, fmt.Errorf("fixture %q is not accessible: %w", cfg.Rules.Test.Fixture, err))
	}
	if !info.IsDir() {
		return withExitCode(ExitUsage, fmt.Errorf("fixture %q must be a directory", cfg.Rules.Test.Fixture))
	}

	policies, err := rules.LoadFiles(ctx, []string{cfg.Rules.Test.RuleFile})
	if err != nil {
		return withExitCode(ExitUsage, fmt.Errorf("load rule file: %w", err))
	}
	expected := cfg.Rules.Test.ExpectedFindings
	if expected == nil {
		expected = policyExpectedFindings(policies)
	}

	snapshot, err := scan.Project(ctx, scan.Options{
		Root:           cfg.Rules.Test.Fixture,
		ScannerVersion: build.Version,
		MaxWorkers:     cfg.Scan.MaxWorkers,
		MaxFileSize:    cfg.Scan.MaxFileSize,
		StrictHash:     true,
	})
	if err != nil {
		return withExitCode(ExitScanFailed, fmt.Errorf("scan fixture: %w", err))
	}
	result, err := rules.Evaluate(ctx, rules.EvaluateOptions{
		Root:        cfg.Rules.Test.Fixture,
		Files:       appRuleFiles(snapshot.Files),
		Node:        snapshot.Node,
		Policies:    policies,
		MaxFileSize: cfg.Scan.MaxFileSize,
	})
	if err != nil {
		return withExitCode(ExitScanFailed, fmt.Errorf("evaluate rule file: %w", err))
	}
	testResult := rules.NewTestResult(
		cfg.Rules.Test.RuleFile,
		cfg.Rules.Test.Fixture,
		result.Findings,
		result.Warnings,
		expected,
	)
	if err := report.WriteRulesTest(stdout, testResult, cfg.Rules.Test.Output); err != nil {
		return withExitCode(ExitScanFailed, fmt.Errorf("write rules test report: %w", err))
	}
	if !testResult.Passed {
		return withExitCode(ExitFindings, errors.New("rules test expectations failed"))
	}
	return nil
}

func appRuleFiles(files []scan.File) []rules.File {
	refs := make([]rules.File, 0, len(files))
	for _, file := range files {
		if file.Status != scan.StatusScanned {
			continue
		}
		refs = append(refs, rules.File{
			Path:         file.Path,
			SHA256:       file.SHA256,
			Type:         file.Type,
			PackageOwner: file.PackageOwner,
			Size:         file.Size,
		})
	}
	return refs
}

func policyExpectedFindings(policies []rules.Policy) *int {
	for _, policy := range policies {
		if policy.Tests != nil && policy.Tests.ExpectedFindings != nil {
			return policy.Tests.ExpectedFindings
		}
	}
	return nil
}

func runDiff(ctx context.Context, cfg config.Values) (diff.Report, error) {
	store, err := cache.NewStore(cfg.StateDir)
	if err != nil {
		return diff.Report{}, withExitCode(ExitScanFailed, fmt.Errorf("open project state: %w", err))
	}

	fromID := cfg.Diff.From
	toID := cfg.Diff.To
	if fromID == "" && toID == "" {
		from, to, err := store.RecentPair(ctx)
		if err != nil {
			return diff.Report{}, withExitCode(ExitScanFailed, fmt.Errorf("select recent snapshots: %w", err))
		}
		fromID = from.ID
		toID = to.ID
	}

	fromSnapshot, err := store.LoadSnapshot(ctx, fromID)
	if err != nil {
		return diff.Report{}, diffLoadError("load from snapshot", fromID, err)
	}
	toSnapshot, err := store.LoadSnapshot(ctx, toID)
	if err != nil {
		return diff.Report{}, diffLoadError("load to snapshot", toID, err)
	}
	return diff.Compare(fromSnapshot, toSnapshot), nil
}

func diffLoadError(action, id string, err error) error {
	if errors.Is(err, cache.ErrSnapshotNotFound) {
		return withExitCode(ExitUsage, fmt.Errorf("%s %q: %w", action, id, err))
	}
	return withExitCode(ExitScanFailed, fmt.Errorf("%s %q: %w", action, id, err))
}

func writeVersion(w io.Writer, build BuildInfo) error {
	_, err := fmt.Fprintf(
		w,
		"version: %s\ncommit: %s\nbuild_date: %s\ngo_version: %s\n",
		build.Version,
		build.Commit,
		build.BuildDate,
		runtime.Version(),
	)
	return err
}

func writeUsageError(w io.Writer, err error) {
	_, _ = fmt.Fprintf(w, "error: %v\n", err)
}

func writeRuntimeError(w io.Writer, err error) {
	_, _ = fmt.Fprintf(w, "error: %v\n", err)
}

func writeConfigError(w io.Writer, err error) {
	validationErr, ok := config.AsValidationError(err)
	if !ok {
		_, _ = fmt.Fprintf(w, "error: %v\n", err)
		return
	}

	_, _ = fmt.Fprintln(w, "configuration error:")
	for _, problem := range validationErr.Problems {
		_, _ = fmt.Fprintf(w, "  - %s\n", problem)
	}
}
