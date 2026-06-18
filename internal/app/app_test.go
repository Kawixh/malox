package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestRunScanJSONWritesSnapshotStdoutOnly(t *testing.T) {
	workDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(workDir, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runAppWithWorkDir(t, workDir, "scan", "--root", workDir, "--json")
	if code != ExitOK {
		t.Fatalf("Run() exit code = %d, want %d", code, ExitOK)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}

	var document struct {
		SchemaVersion  string `json:"schema_version"`
		ScannerVersion string `json:"scanner_version"`
		ProjectRoot    string `json:"project_root"`
		ProjectID      string `json:"project_id"`
		Files          []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Status string `json:"status"`
		} `json:"files"`
		Summary struct {
			ScannedFiles int `json:"scanned_files"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if document.SchemaVersion != "malox.scan.snapshot.v1" {
		t.Fatalf("schema_version = %q", document.SchemaVersion)
	}
	if document.ScannerVersion != "test-version" {
		t.Fatalf("scanner_version = %q, want test-version", document.ScannerVersion)
	}
	if document.ProjectRoot != "." {
		t.Fatalf("project_root = %q, want .", document.ProjectRoot)
	}
	if !strings.HasPrefix(document.ProjectID, "sha256:") {
		t.Fatalf("project_id = %q, want sha256 prefix", document.ProjectID)
	}
	if len(document.Files) != 1 {
		t.Fatalf("files length = %d, want 1", len(document.Files))
	}
	if document.Files[0].Path != "package.json" || document.Files[0].Status != "scanned" || document.Files[0].SHA256 == "" {
		t.Fatalf("file record = %#v, want scanned package.json with SHA256", document.Files[0])
	}
	if document.Summary.ScannedFiles != 1 {
		t.Fatalf("scanned_files = %d, want 1", document.Summary.ScannedFiles)
	}
	if strings.Contains(stdout, workDir) {
		t.Fatalf("stdout leaked absolute root path %q:\n%s", workDir, stdout)
	}
}

func TestRunDiffJSONComparesRecentSnapshots(t *testing.T) {
	workDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(workDir, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runAppWithWorkDir(t, workDir, "scan", "--root", workDir, "--json")
	if code != ExitOK {
		t.Fatalf("first scan exit code = %d, want %d; stderr = %q", code, ExitOK, stderr)
	}
	if err := os.Remove(filepath.Join(workDir, "package.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "added.js"), []byte("console.log('added')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)

	code, _, stderr = runAppWithWorkDir(t, workDir, "scan", "--root", workDir, "--json")
	if code != ExitOK {
		t.Fatalf("second scan exit code = %d, want %d; stderr = %q", code, ExitOK, stderr)
	}

	code, stdout, stderr := runAppWithWorkDir(t, workDir, "diff", "--json")
	if code != ExitFindings {
		t.Fatalf("diff exit code = %d, want %d; stderr = %q", code, ExitFindings, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}

	var document struct {
		SchemaVersion string `json:"schema_version"`
		AddedFiles    []struct {
			Path  string `json:"path"`
			State string `json:"state"`
		} `json:"added_files"`
		RemovedFiles []struct {
			Path  string `json:"path"`
			State string `json:"state"`
		} `json:"removed_files"`
	}
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if document.SchemaVersion != "malox.diff.v1" {
		t.Fatalf("schema_version = %q, want malox.diff.v1", document.SchemaVersion)
	}
	if len(document.AddedFiles) != 1 || document.AddedFiles[0].Path != "added.js" || document.AddedFiles[0].State != "added" {
		t.Fatalf("added_files = %#v, want added.js", document.AddedFiles)
	}
	if len(document.RemovedFiles) != 1 ||
		document.RemovedFiles[0].Path != "package.json" ||
		document.RemovedFiles[0].State != "removed" {
		t.Fatalf("removed_files = %#v, want package.json", document.RemovedFiles)
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

func TestRunRulesTestJSON(t *testing.T) {
	workDir := t.TempDir()
	fixture := filepath.Join(workDir, "fixture")
	if err := os.Mkdir(fixture, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(workDir, "policy.json")
	policy := `{
  "schema_version": "malox.rules.policy.v1",
  "rules": [{
    "id": "test:path",
    "description": "package manifest present",
    "severity": "medium",
    "confidence": "weak-signal",
    "path_patterns": ["package.json"]
  }]
}`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runAppWithWorkDir(
		t,
		workDir,
		"rules",
		"test",
		policyPath,
		"--fixture",
		fixture,
		"--json",
		"--expect-findings",
		"1",
	)
	if code != ExitOK {
		t.Fatalf("Run() exit code = %d, want %d; stderr = %q", code, ExitOK, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}

	var document struct {
		SchemaVersion string `json:"schema_version"`
		Passed        bool   `json:"passed"`
		MatchCount    int    `json:"match_count"`
		Findings      []struct {
			RuleID string `json:"rule_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if document.SchemaVersion != "malox.rules.test.v1" || !document.Passed || document.MatchCount != 1 {
		t.Fatalf("rules test document = %#v, want passed one-match result", document)
	}
	if len(document.Findings) != 1 || document.Findings[0].RuleID != "test:path" {
		t.Fatalf("findings = %#v, want test:path", document.Findings)
	}
}

func TestRunScanReturnsFindingsExitForBlocklist(t *testing.T) {
	workDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(workDir, "blocked.js"), []byte("console.log('blocked')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(workDir, "policy.json")
	policy := `{
  "schema_version": "malox.rules.policy.v1",
  "blocklist": [{
    "id": "block:path",
    "path": "blocked.js"
  }]
}`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runAppWithWorkDir(
		t,
		workDir,
		"scan",
		"--root",
		workDir,
		"--policy",
		policyPath,
		"--json",
	)
	if code != ExitFindings {
		t.Fatalf("Run() exit code = %d, want %d; stderr = %q", code, ExitFindings, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}

	var document struct {
		Findings []struct {
			RuleID   string `json:"rule_id"`
			Blocking bool   `json:"blocking"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if len(document.Findings) != 1 || document.Findings[0].RuleID != "block:path" || !document.Findings[0].Blocking {
		t.Fatalf("findings = %#v, want blocking block:path", document.Findings)
	}
}

func TestRunCacheUpdateJSON(t *testing.T) {
	workDir := t.TempDir()
	cacheDir := filepath.Join(workDir, "cache")

	code, stdout, stderr := runAppWithWorkDir(
		t,
		workDir,
		"cache",
		"update",
		"--cache-dir",
		cacheDir,
		"--json",
	)
	if code != ExitOK {
		t.Fatalf("Run() exit code = %d, want %d; stderr = %q", code, ExitOK, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}

	var document struct {
		SchemaVersion string `json:"schema_version"`
		Operation     string `json:"operation"`
		Sources       []struct {
			Source         string `json:"source"`
			RecordsChanged int    `json:"records_changed"`
			BytesWritten   int64  `json:"bytes_written"`
		} `json:"sources"`
	}
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if document.SchemaVersion != "malox.cache.report.v1" || document.Operation != "update" {
		t.Fatalf("document = %#v, want cache update report", document)
	}
	if len(document.Sources) != 1 ||
		document.Sources[0].Source != "builtin-rules" ||
		document.Sources[0].RecordsChanged == 0 ||
		document.Sources[0].BytesWritten == 0 {
		t.Fatalf("sources = %#v, want builtin-rules changes", document.Sources)
	}
}

func TestRunCacheCleanAllRequiresForce(t *testing.T) {
	workDir := t.TempDir()
	cacheDir := filepath.Join(workDir, "cache")

	code, stdout, stderr := runAppWithWorkDir(
		t,
		workDir,
		"cache",
		"clean",
		"--cache-dir",
		cacheDir,
		"--all",
	)
	if code != ExitUsage {
		t.Fatalf("Run() exit code = %d, want %d", code, ExitUsage)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "requires --force") {
		t.Fatalf("stderr missing force message: %q", stderr)
	}
}

func TestRunCacheCleanAllForceJSON(t *testing.T) {
	workDir := t.TempDir()
	cacheDir := filepath.Join(workDir, "cache")
	if code, _, stderr := runAppWithWorkDir(t, workDir, "cache", "update", "--cache-dir", cacheDir); code != ExitOK {
		t.Fatalf("cache update exit code = %d, want %d; stderr = %q", code, ExitOK, stderr)
	}

	code, stdout, stderr := runAppWithWorkDir(
		t,
		workDir,
		"cache",
		"clean",
		"--cache-dir",
		cacheDir,
		"--all",
		"--force",
		"--json",
	)
	if code != ExitOK {
		t.Fatalf("Run() exit code = %d, want %d; stderr = %q", code, ExitOK, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}

	var document struct {
		Operation string `json:"operation"`
		Sources   []struct {
			Source       string `json:"source"`
			BytesRemoved int64  `json:"bytes_removed"`
		} `json:"sources"`
	}
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if document.Operation != "clean" ||
		len(document.Sources) != 1 ||
		document.Sources[0].Source != "all" ||
		document.Sources[0].BytesRemoved == 0 {
		t.Fatalf("document = %#v, want forced all clean report", document)
	}
}

func TestRunScanOfflinePreparesGlobalCache(t *testing.T) {
	workDir := t.TempDir()
	cacheDir := filepath.Join(workDir, "cache")
	if err := os.WriteFile(filepath.Join(workDir, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runAppWithWorkDir(
		t,
		workDir,
		"scan",
		"--root",
		workDir,
		"--cache-dir",
		cacheDir,
		"--offline",
		"--json",
	)
	if code != ExitOK {
		t.Fatalf("Run() exit code = %d, want %d; stderr = %q", code, ExitOK, stderr)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "index-v1.json")); err != nil {
		t.Fatalf("scan offline did not prepare global cache: %v", err)
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

func TestParseInvocationRejectsCacheCleanFlagsOutsideCacheClean(t *testing.T) {
	_, err := parseInvocation([]string{"scan", "--expired"})
	if err == nil {
		t.Fatal("parseInvocation() error = nil, want usage error")
	}
	if !strings.Contains(err.Error(), "--expired is only valid for cache clean") {
		t.Fatalf("error = %q, want cache clean scope message", err)
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
