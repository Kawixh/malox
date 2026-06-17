// Package app wires the Malox command-line application.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime"

	"malox/internal/config"
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

	if err := runCommand(ctx, inv.command, cfg); err != nil {
		code := ExitCode(err)
		if cfg.Verbose {
			logger.DebugContext(ctx, "command failed", "command", inv.command.String(), "exit_code", code)
		}
		writeRuntimeError(opts.Stderr, err)
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

func runCommand(ctx context.Context, command command, cfg config.Values) error {
	_ = cfg

	if err := ctx.Err(); err != nil {
		return withExitCode(ExitScanFailed, fmt.Errorf("command canceled: %w", err))
	}

	switch command {
	case commandScan:
		return withExitCode(ExitScanFailed, errors.New("scan is not implemented yet; milestone 2 will add baseline scanning"))
	case commandDiff:
		return withExitCode(ExitScanFailed, errors.New("diff is not implemented yet; milestone 3 will add snapshot comparison"))
	case commandRulesTest:
		return withExitCode(ExitScanFailed, errors.New("rules test is not implemented yet; milestone 5 will add rule execution"))
	case commandCacheUpdate:
		return withExitCode(ExitScanFailed, errors.New("cache update is not implemented yet; milestone 6 will add cache updates"))
	case commandCacheClean:
		return withExitCode(ExitScanFailed, errors.New("cache clean is not implemented yet; milestone 6 will add cache cleanup"))
	default:
		return usageError("command %q is not implemented", command.String())
	}
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
