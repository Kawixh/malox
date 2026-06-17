package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"
)

func TestProjectScansFilesDeterministically(t *testing.T) {
	root := t.TempDir()
	modTime := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	writeTestFile(t, root, "package.json", "{}\n", modTime)
	writeTestFile(t, root, "src/index.js", "console.log('ok')\n", modTime)
	writeTestFile(t, root, "node_modules/@scope/pkg/index.js", "module.exports = 1\n", modTime)
	writeTestFile(t, root, "node_modules/.cache/ignored.js", "ignored\n", modTime)
	writeTestFile(t, root, ".git/config", "ignored\n", modTime)

	snapshot, err := Project(t.Context(), Options{
		Root:           root,
		ScannerVersion: "test-version",
		MaxWorkers:     4,
		MaxFileSize:    1024,
		Now:            fixedNow(modTime),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	if snapshot.SchemaVersion != SchemaVersion {
		t.Fatalf("SchemaVersion = %q, want %q", snapshot.SchemaVersion, SchemaVersion)
	}
	if snapshot.ScannerVersion != "test-version" {
		t.Fatalf("ScannerVersion = %q, want test-version", snapshot.ScannerVersion)
	}
	if snapshot.ProjectRoot != "." {
		t.Fatalf("ProjectRoot = %q, want .", snapshot.ProjectRoot)
	}

	paths := make([]string, 0, len(snapshot.Files))
	for _, file := range snapshot.Files {
		paths = append(paths, file.Path)
	}
	wantPaths := []string{
		"node_modules/@scope/pkg/index.js",
		"package.json",
		"src/index.js",
	}
	if !slices.Equal(paths, wantPaths) {
		t.Fatalf("files = %#v, want %#v", paths, wantPaths)
	}

	index := findFile(t, snapshot, "src/index.js")
	if index.Status != StatusScanned {
		t.Fatalf("src/index.js status = %q, want scanned", index.Status)
	}
	if index.State != FileStatePreviouslyUnscanned {
		t.Fatalf("src/index.js state = %q, want previously_unscanned", index.State)
	}
	if index.SHA256 != sha256String("console.log('ok')\n") {
		t.Fatalf("src/index.js SHA256 = %q", index.SHA256)
	}

	dependency := findFile(t, snapshot, "node_modules/@scope/pkg/index.js")
	if dependency.PackageOwner != "@scope/pkg" {
		t.Fatalf("PackageOwner = %q, want @scope/pkg", dependency.PackageOwner)
	}

	if snapshot.Summary.ScannedFiles != 3 {
		t.Fatalf("ScannedFiles = %d, want 3", snapshot.Summary.ScannedFiles)
	}
	if snapshot.Summary.SkippedDirectories != 2 {
		t.Fatalf("SkippedDirectories = %d, want 2", snapshot.Summary.SkippedDirectories)
	}
	if snapshot.Summary.NodeModulesFiles != 1 || snapshot.Summary.NodeModulesPackages != 1 {
		t.Fatalf("node_modules summary = files %d packages %d, want 1/1",
			snapshot.Summary.NodeModulesFiles,
			snapshot.Summary.NodeModulesPackages,
		)
	}

	signalPaths := make([]string, 0, len(snapshot.PackageManagers))
	for _, signal := range snapshot.PackageManagers {
		signalPaths = append(signalPaths, signal.Manager+":"+signal.Kind+":"+signal.Path)
	}
	wantSignals := []string{
		"node:dependency_directory:node_modules",
		"node:manifest:package.json",
	}
	if !slices.Equal(signalPaths, wantSignals) {
		t.Fatalf("signals = %#v, want %#v", signalPaths, wantSignals)
	}
}

func TestProjectReusesPreviousHashUnlessStrict(t *testing.T) {
	root := t.TempDir()
	modTime := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	writeTestFile(t, root, "same-size.js", "old!", modTime)

	previous, err := Project(t.Context(), Options{
		Root:           root,
		ScannerVersion: "test-version",
		MaxWorkers:     1,
		MaxFileSize:    1024,
		Now:            fixedNow(modTime),
	})
	if err != nil {
		t.Fatalf("Project() previous error = %v", err)
	}

	writeTestFile(t, root, "same-size.js", "new!", modTime)
	reused, err := Project(t.Context(), Options{
		Root:           root,
		ScannerVersion: "test-version",
		MaxWorkers:     1,
		MaxFileSize:    1024,
		Previous:       &previous,
		Now:            fixedNow(modTime.Add(time.Minute)),
	})
	if err != nil {
		t.Fatalf("Project() reused error = %v", err)
	}
	reusedFile := findFile(t, reused, "same-size.js")
	if reusedFile.State != FileStateUnchanged {
		t.Fatalf("reused state = %q, want unchanged", reusedFile.State)
	}
	if reusedFile.SHA256 != sha256String("old!") {
		t.Fatalf("reused SHA256 = %q, want old hash", reusedFile.SHA256)
	}

	strict, err := Project(t.Context(), Options{
		Root:           root,
		ScannerVersion: "test-version",
		MaxWorkers:     1,
		MaxFileSize:    1024,
		StrictHash:     true,
		Previous:       &previous,
		Now:            fixedNow(modTime.Add(2 * time.Minute)),
	})
	if err != nil {
		t.Fatalf("Project() strict error = %v", err)
	}
	strictFile := findFile(t, strict, "same-size.js")
	if strictFile.State != FileStateModified {
		t.Fatalf("strict state = %q, want modified", strictFile.State)
	}
	if strictFile.SHA256 != sha256String("new!") {
		t.Fatalf("strict SHA256 = %q, want new hash", strictFile.SHA256)
	}
}

func TestProjectSkipsConfiguredStateDir(t *testing.T) {
	root := t.TempDir()
	modTime := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	writeTestFile(t, root, "src/index.js", "console.log('ok')\n", modTime)
	writeTestFile(t, root, "state/latest.json", "{}\n", modTime)

	snapshot, err := Project(t.Context(), Options{
		Root:           root,
		StateDir:       filepath.Join(root, "state"),
		ScannerVersion: "test-version",
		MaxWorkers:     2,
		MaxFileSize:    1024,
		Now:            fixedNow(modTime),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	if len(snapshot.Files) != 1 || snapshot.Files[0].Path != "src/index.js" {
		t.Fatalf("files = %#v, want only src/index.js", snapshot.Files)
	}
	if len(snapshot.SkippedDirectories) != 1 || snapshot.SkippedDirectories[0].Path != "state" {
		t.Fatalf("SkippedDirectories = %#v, want state", snapshot.SkippedDirectories)
	}
}

func TestProjectSkipsOversizedFiles(t *testing.T) {
	root := t.TempDir()
	modTime := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	writeTestFile(t, root, "large.txt", "12345", modTime)

	snapshot, err := Project(t.Context(), Options{
		Root:           root,
		ScannerVersion: "test-version",
		MaxWorkers:     2,
		MaxFileSize:    4,
		Now:            fixedNow(modTime),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	file := findFile(t, snapshot, "large.txt")
	if file.Status != StatusSkipped {
		t.Fatalf("large.txt status = %q, want skipped", file.Status)
	}
	if file.SHA256 != "" {
		t.Fatalf("large.txt SHA256 = %q, want empty", file.SHA256)
	}
	if file.SkipReason == nil || file.SkipReason.Code != "max_file_size" {
		t.Fatalf("large.txt skip reason = %#v, want max_file_size", file.SkipReason)
	}
	if len(snapshot.SkippedFiles) != 1 || snapshot.SkippedFiles[0].Path != "large.txt" {
		t.Fatalf("SkippedFiles = %#v, want large.txt", snapshot.SkippedFiles)
	}
}

func TestProjectRecordsSymlinkWithoutFollowing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink privileges vary on windows")
	}

	root := t.TempDir()
	modTime := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	writeTestFile(t, root, "target.js", "console.log('target')\n", modTime)
	if err := os.Symlink("target.js", filepath.Join(root, "link.js")); err != nil {
		t.Skipf("create symlink: %v", err)
	}

	snapshot, err := Project(t.Context(), Options{
		Root:           root,
		ScannerVersion: "test-version",
		MaxWorkers:     2,
		MaxFileSize:    1024,
		Now:            fixedNow(modTime),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	link := findFile(t, snapshot, "link.js")
	if !link.Symlink {
		t.Fatal("link.js Symlink = false, want true")
	}
	if link.SymlinkTarget != "target.js" {
		t.Fatalf("link.js SymlinkTarget = %q, want target.js", link.SymlinkTarget)
	}
	if link.Status != StatusSkipped {
		t.Fatalf("link.js status = %q, want skipped", link.Status)
	}
	if link.SkipReason == nil || link.SkipReason.Code != "symlink_not_followed" {
		t.Fatalf("link.js skip reason = %#v, want symlink_not_followed", link.SkipReason)
	}
}

func TestClassifyAndPackageOwner(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantType  string
		wantOwner string
	}{
		{
			name:     "node manifest",
			path:     "package.json",
			wantType: "node_manifest",
		},
		{
			name:     "lockfile",
			path:     "pnpm-lock.yaml",
			wantType: "lockfile",
		},
		{
			name:      "scoped dependency",
			path:      "node_modules/@scope/name/index.ts",
			wantType:  "typescript",
			wantOwner: "@scope/name",
		},
		{
			name:      "nested dependency",
			path:      "node_modules/a/node_modules/b/index.js",
			wantType:  "javascript",
			wantOwner: "b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.path); got != tt.wantType {
				t.Fatalf("Classify() = %q, want %q", got, tt.wantType)
			}
			if got := PackageOwner(tt.path); got != tt.wantOwner {
				t.Fatalf("PackageOwner() = %q, want %q", got, tt.wantOwner)
			}
		})
	}
}

func writeTestFile(t *testing.T, root, rel, body string, modTime time.Time) {
	t.Helper()

	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, modTime, modTime); err != nil {
		t.Fatal(err)
	}
}

func findFile(t *testing.T, snapshot Snapshot, rel string) File {
	t.Helper()

	for _, file := range snapshot.Files {
		if file.Path == rel {
			return file
		}
	}
	t.Fatalf("file %q not found in snapshot", rel)
	return File{}
}

func sha256String(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func fixedNow(t time.Time) func() time.Time {
	return func() time.Time {
		return t
	}
}
