package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"malox/internal/report"
)

func TestLoadAppliesFlagsAndDefaults(t *testing.T) {
	workDir := t.TempDir()
	root := filepath.Join(workDir, "project")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(workDir, "state")
	cacheDir := filepath.Join(workDir, "cache")

	values, err := Load(t.Context(), LoadOptions{
		WorkDir: workDir,
		Flags: FlagValues{
			StateDir: ptr(stateDir),
			CacheDir: ptr(cacheDir),
			Offline:  ptr(true),
			Scan: ScanFlags{
				Root:        ptr(root),
				Output:      ptr("plain"),
				StrictHash:  ptr(true),
				MaxWorkers:  ptr(4),
				MaxFileSize: ptr[int64](2048),
			},
		},
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if values.StateDir != stateDir {
		t.Fatalf("StateDir = %q, want %q", values.StateDir, stateDir)
	}
	if values.CacheDir != cacheDir {
		t.Fatalf("CacheDir = %q, want %q", values.CacheDir, cacheDir)
	}
	if !values.Offline {
		t.Fatal("Offline = false, want true")
	}
	if values.Scan.Root != root {
		t.Fatalf("Scan.Root = %q, want %q", values.Scan.Root, root)
	}
	if values.Scan.Output != report.FormatPlain {
		t.Fatalf("Scan.Output = %q, want %q", values.Scan.Output, report.FormatPlain)
	}
	if !values.Scan.StrictHash {
		t.Fatal("Scan.StrictHash = false, want true")
	}
	if values.Scan.MaxWorkers != 4 {
		t.Fatalf("Scan.MaxWorkers = %d, want 4", values.Scan.MaxWorkers)
	}
	if values.Scan.MaxFileSize != 2048 {
		t.Fatalf("Scan.MaxFileSize = %d, want 2048", values.Scan.MaxFileSize)
	}
}

func TestLoadStateDirEnvironmentAndFlagPrecedence(t *testing.T) {
	workDir := t.TempDir()
	envState := filepath.Join(workDir, "env-state")
	flagState := filepath.Join(workDir, "flag-state")
	t.Setenv(stateDirEnv, envState)

	values, err := Load(t.Context(), LoadOptions{
		WorkDir: workDir,
	})
	if err != nil {
		t.Fatalf("Load() env error = %v", err)
	}
	if values.StateDir != envState {
		t.Fatalf("StateDir = %q, want env state %q", values.StateDir, envState)
	}

	values, err = Load(t.Context(), LoadOptions{
		WorkDir: workDir,
		Flags: FlagValues{
			StateDir: ptr(flagState),
		},
	})
	if err != nil {
		t.Fatalf("Load() flag error = %v", err)
	}
	if values.StateDir != flagState {
		t.Fatalf("StateDir = %q, want flag state %q", values.StateDir, flagState)
	}
}

func TestLoadJSONShortcutDoesNotConflictWithDefaultOutput(t *testing.T) {
	workDir := t.TempDir()
	cacheDir := filepath.Join(workDir, "cache")
	jsonOutput := true

	values, err := Load(t.Context(), LoadOptions{
		WorkDir: workDir,
		Flags: FlagValues{
			CacheDir: ptr(cacheDir),
			Scan: ScanFlags{
				JSON: &jsonOutput,
			},
		},
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if values.Scan.Output != report.FormatJSON {
		t.Fatalf("Scan.Output = %q, want %q", values.Scan.Output, report.FormatJSON)
	}
}

func TestLoadRejectsJSONShortcutWithDifferentOutput(t *testing.T) {
	workDir := t.TempDir()
	cacheDir := filepath.Join(workDir, "cache")

	_, err := Load(t.Context(), LoadOptions{
		WorkDir: workDir,
		Flags: FlagValues{
			CacheDir: ptr(cacheDir),
			Scan: ScanFlags{
				JSON:   ptr(true),
				Output: ptr("plain"),
			},
		},
	})
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}

	validationErr, ok := AsValidationError(err)
	if !ok {
		t.Fatalf("Load() error type = %T, want ValidationError", err)
	}
	problems := strings.Join(validationErr.Problems, "\n")
	if !strings.Contains(problems, "--json cannot be combined with --output plain") {
		t.Fatalf("validation problems missing json/output conflict:\n%s", problems)
	}
}

func TestLoadReportsAllValidationProblems(t *testing.T) {
	workDir := t.TempDir()
	missingRoot := filepath.Join(workDir, "missing")
	quiet := true
	verbose := true

	_, err := Load(t.Context(), LoadOptions{
		WorkDir: workDir,
		Flags: FlagValues{
			CacheDir: ptr(""),
			Quiet:    &quiet,
			Verbose:  &verbose,
			Scan: ScanFlags{
				Root:        ptr(missingRoot),
				MaxWorkers:  ptr(0),
				MaxFileSize: ptr[int64](0),
			},
		},
	})
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}

	validationErr, ok := AsValidationError(err)
	if !ok {
		t.Fatalf("Load() error type = %T, want ValidationError", err)
	}
	problems := strings.Join(validationErr.Problems, "\n")
	for _, want := range []string{
		"cache dir is required",
		"--quiet and --verbose cannot both be set",
		"scan root",
		"max workers must be greater than 0",
		"max file size must be greater than 0",
	} {
		if !strings.Contains(problems, want) {
			t.Fatalf("validation problems missing %q:\n%s", want, problems)
		}
	}
}

func TestLoadReadsJSONConfigFile(t *testing.T) {
	workDir := t.TempDir()
	root := filepath.Join(workDir, "project")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(workDir, "cache")
	configPath := filepath.Join(workDir, "malox.json")
	configBody := `{
  "cache_dir": "cache",
  "scan": {
    "root": "project",
    "output": "json",
    "max_workers": 2
  }
}`
	if err := os.WriteFile(configPath, []byte(configBody), 0o644); err != nil {
		t.Fatal(err)
	}

	values, err := Load(t.Context(), LoadOptions{
		WorkDir: workDir,
		Flags: FlagValues{
			ConfigPath: ptr(configPath),
		},
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if values.CacheDir != cacheDir {
		t.Fatalf("CacheDir = %q, want %q", values.CacheDir, cacheDir)
	}
	if values.Scan.Root != root {
		t.Fatalf("Scan.Root = %q, want %q", values.Scan.Root, root)
	}
	if values.Scan.Output != report.FormatJSON {
		t.Fatalf("Scan.Output = %q, want %q", values.Scan.Output, report.FormatJSON)
	}
	if values.Scan.MaxWorkers != 2 {
		t.Fatalf("Scan.MaxWorkers = %d, want 2", values.Scan.MaxWorkers)
	}
}

func TestLoadReadsRulesConfig(t *testing.T) {
	workDir := t.TempDir()
	configPath := filepath.Join(workDir, "malox.json")
	configBody := `{
  "rules": {
    "policy_files": ["security/malox-policy.json"],
    "use_builtins": false
  }
}`
	if err := os.Mkdir(filepath.Join(workDir, "security"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(configBody), 0o644); err != nil {
		t.Fatal(err)
	}

	values, err := Load(t.Context(), LoadOptions{
		WorkDir: workDir,
		Flags: FlagValues{
			ConfigPath: ptr(configPath),
		},
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	wantPolicy := filepath.Join(workDir, "security", "malox-policy.json")
	if len(values.Rules.PolicyFiles) != 1 || values.Rules.PolicyFiles[0] != wantPolicy {
		t.Fatalf("Rules.PolicyFiles = %#v, want %q", values.Rules.PolicyFiles, wantPolicy)
	}
	if values.Rules.UseBuiltins {
		t.Fatal("Rules.UseBuiltins = true, want false")
	}
}

func ptr[T any](v T) *T {
	return &v
}
