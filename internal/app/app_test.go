package app

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRunRootHelp(t *testing.T) {
	code, stdout, stderr := runApp(t)
	if code != ExitOK {
		t.Fatalf("Run() exit code = %d, want %d", code, ExitOK)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	for _, want := range []string{
		"Malox scans open source projects",
		"Commands:",
		"--config",
		"Examples:",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunScanHelp(t *testing.T) {
	code, stdout, stderr := runApp(t, "scan", "--help")
	if code != ExitOK {
		t.Fatalf("Run() exit code = %d, want %d", code, ExitOK)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	for _, want := range []string{
		"Usage:",
		"--strict-hash",
		"--max-workers",
		"malox scan --json",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunVersionWritesStdoutOnly(t *testing.T) {
	code, stdout, stderr := runApp(t, "version")
	if code != ExitOK {
		t.Fatalf("Run() exit code = %d, want %d", code, ExitOK)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	for _, want := range []string{
		"version: test-version",
		"commit: test-commit",
		"build_date: 2026-06-17",
		"go_version:",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunGlobalVersionWritesStdoutOnly(t *testing.T) {
	code, stdout, stderr := runApp(t, "--version")
	if code != ExitOK {
		t.Fatalf("Run() exit code = %d, want %d", code, ExitOK)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	if !strings.Contains(stdout, "version: test-version") {
		t.Fatalf("stdout missing version field:\n%s", stdout)
	}
	if strings.Contains(stdout, "Usage:") {
		t.Fatalf("stdout printed help for --version:\n%s", stdout)
	}
}

func TestRunInvalidFlagIsUsageError(t *testing.T) {
	code, stdout, stderr := runApp(t, "scan", "--wat")
	if code != ExitUsage {
		t.Fatalf("Run() exit code = %d, want %d", code, ExitUsage)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "unknown flag --wat") {
		t.Fatalf("stderr missing invalid flag message: %q", stderr)
	}
	if strings.Contains(stderr, "Usage:") {
		t.Fatalf("stderr printed full help for invalid usage: %q", stderr)
	}
}

func TestRunScanNotImplementedUsesScanFailure(t *testing.T) {
	workDir := t.TempDir()
	code, stdout, stderr := runAppWithWorkDir(t, workDir, "scan", "--root", workDir, "--json")
	if code != ExitScanFailed {
		t.Fatalf("Run() exit code = %d, want %d", code, ExitScanFailed)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "scan is not implemented yet") {
		t.Fatalf("stderr missing not implemented message: %q", stderr)
	}
	if strings.Contains(stdout, "finding") || strings.Contains(stderr, "finding") {
		t.Fatalf("command emitted fake finding output: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestRunRulesRequiresSubcommand(t *testing.T) {
	code, stdout, stderr := runApp(t, "rules")
	if code != ExitUsage {
		t.Fatalf("Run() exit code = %d, want %d", code, ExitUsage)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "rules requires a subcommand: test") {
		t.Fatalf("stderr missing subcommand message: %q", stderr)
	}
}

func TestParseInvocationAllowsGlobalFlagsAfterCommand(t *testing.T) {
	inv, err := parseInvocation([]string{
		"scan",
		"--root",
		".",
		"--offline",
		"--max-workers=4",
	})
	if err != nil {
		t.Fatalf("parseInvocation() error = %v", err)
	}
	if inv.command != commandScan {
		t.Fatalf("command = %v, want %v", inv.command, commandScan)
	}
	if inv.flags.Offline == nil || !*inv.flags.Offline {
		t.Fatal("offline flag was not parsed")
	}
	if inv.flags.Scan.MaxWorkers == nil || *inv.flags.Scan.MaxWorkers != 4 {
		t.Fatalf("max workers = %v, want 4", inv.flags.Scan.MaxWorkers)
	}
}

func TestExitCodeMapping(t *testing.T) {
	if got := ExitCode(nil); got != ExitOK {
		t.Fatalf("ExitCode(nil) = %d, want %d", got, ExitOK)
	}

	err := withExitCode(ExitThreatUnavailable, errors.New("source unavailable"))
	if got := ExitCode(err); got != ExitThreatUnavailable {
		t.Fatalf("ExitCode(exit error) = %d, want %d", got, ExitThreatUnavailable)
	}

	if got := ExitCode(errors.New("plain error")); got != ExitScanFailed {
		t.Fatalf("ExitCode(plain error) = %d, want %d", got, ExitScanFailed)
	}
}

func runApp(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	return runAppWithWorkDir(t, t.TempDir(), args...)
}

func runAppWithWorkDir(t *testing.T, workDir string, args ...string) (int, string, string) {
	t.Helper()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(t.Context(), Options{
		Args:    args,
		Stdout:  &stdout,
		Stderr:  &stderr,
		WorkDir: workDir,
		Build: BuildInfo{
			Version:   "test-version",
			Commit:    "test-commit",
			BuildDate: "2026-06-17",
		},
	})
	return code, stdout.String(), stderr.String()
}
