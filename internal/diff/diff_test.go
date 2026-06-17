package diff

import (
	"testing"
	"time"

	"malox/internal/node"
	"malox/internal/rules"
	"malox/internal/scan"
)

func TestCompareClassifiesFileStates(t *testing.T) {
	when := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	oldSnapshot := scan.Snapshot{
		ScanID: "old",
		Files: []scan.File{
			scanFile("modified.js", "old", 3, when, scan.StatusScanned),
			scanFile("removed.js", "removed", 7, when, scan.StatusScanned),
			scanFile("same.js", "same", 4, when, scan.StatusScanned),
			scanFile("skipped.js", "", 10, when, scan.StatusSkipped),
		},
	}
	newSnapshot := scan.Snapshot{
		ScanID: "new",
		Files: []scan.File{
			scanFile("added.js", "added", 5, when, scan.StatusScanned),
			scanFile("modified.js", "new", 3, when, scan.StatusScanned),
			scanFile("same.js", "same", 4, when, scan.StatusScanned),
			scanFile("skipped.js", "", 10, when, scan.StatusSkipped),
		},
	}

	report := Compare(oldSnapshot, newSnapshot)
	if report.SchemaVersion != SchemaVersion {
		t.Fatalf("SchemaVersion = %q, want %q", report.SchemaVersion, SchemaVersion)
	}
	assertChange(t, report.AddedFiles, "added.js", scan.FileStateAdded)
	assertChange(t, report.RemovedFiles, "removed.js", scan.FileStateRemoved)
	assertChange(t, report.ModifiedFiles, "modified.js", scan.FileStateModified)
	assertChange(t, report.UnchangedFiles, "same.js", scan.FileStateUnchanged)
	assertChange(t, report.SkippedFiles, "skipped.js", scan.FileStateSkipped)
	if !report.HasRelevantChanges() {
		t.Fatal("HasRelevantChanges() = false, want true")
	}
}

func TestCompareUnchangedHasNoRelevantChanges(t *testing.T) {
	when := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	oldSnapshot := scan.Snapshot{
		ScanID: "old",
		Files:  []scan.File{scanFile("same.js", "same", 4, when, scan.StatusScanned)},
	}
	newSnapshot := scan.Snapshot{
		ScanID: "new",
		Files:  []scan.File{scanFile("same.js", "same", 4, when, scan.StatusScanned)},
	}

	report := Compare(oldSnapshot, newSnapshot)
	if report.HasRelevantChanges() {
		t.Fatal("HasRelevantChanges() = true, want false")
	}
	if len(report.UnchangedFiles) != 1 {
		t.Fatalf("UnchangedFiles length = %d, want 1", len(report.UnchangedFiles))
	}
}

func TestCompareDependencyAndScriptChanges(t *testing.T) {
	oldSnapshot := scan.Snapshot{
		ScanID: "old",
		Node: node.Inventory{
			Dependencies: []node.Dependency{
				{
					Name:           "left-pad",
					Version:        "1.2.0",
					PURL:           "pkg:npm/left-pad@1.2.0",
					PackageManager: "npm",
					DependencyType: "dependencies",
					SourcePath:     "package-lock.json",
					PackagePath:    "node_modules/left-pad",
				},
				{
					Name:           "removed",
					Version:        "1.0.0",
					PURL:           "pkg:npm/removed@1.0.0",
					PackageManager: "npm",
					SourcePath:     "package-lock.json",
					PackagePath:    "node_modules/removed",
				},
			},
			PackageScripts: []node.PackageScript{
				{
					PackageName:    "left-pad",
					PackageManager: "package.json",
					SourcePath:     "node_modules/left-pad/package.json",
					PackagePath:    "node_modules/left-pad",
					ScriptName:     "install",
					Command:        "node old.js",
				},
			},
		},
	}
	newSnapshot := scan.Snapshot{
		ScanID: "new",
		Node: node.Inventory{
			Dependencies: []node.Dependency{
				{
					Name:           "left-pad",
					Version:        "1.3.0",
					PURL:           "pkg:npm/left-pad@1.3.0",
					PackageManager: "npm",
					DependencyType: "dependencies",
					SourcePath:     "package-lock.json",
					PackagePath:    "node_modules/left-pad",
				},
				{
					Name:           "new",
					Version:        "2.0.0",
					PURL:           "pkg:npm/new@2.0.0",
					PackageManager: "npm",
					SourcePath:     "package-lock.json",
					PackagePath:    "node_modules/new",
				},
			},
			PackageScripts: []node.PackageScript{
				{
					PackageName:    "left-pad",
					PackageManager: "package.json",
					SourcePath:     "node_modules/left-pad/package.json",
					PackagePath:    "node_modules/left-pad",
					ScriptName:     "install",
					Command:        "node new.js",
				},
				{
					PackageName:    "new",
					PackageManager: "package.json",
					SourcePath:     "node_modules/new/package.json",
					PackagePath:    "node_modules/new",
					ScriptName:     "postinstall",
					Command:        "node setup.js",
				},
			},
		},
	}

	report := Compare(oldSnapshot, newSnapshot)
	if len(report.UpdatedDependencies) != 1 || report.UpdatedDependencies[0].Name != "left-pad" {
		t.Fatalf("UpdatedDependencies = %#v, want left-pad", report.UpdatedDependencies)
	}
	if len(report.NewDependencies) != 1 || report.NewDependencies[0].Name != "new" {
		t.Fatalf("NewDependencies = %#v, want new", report.NewDependencies)
	}
	if len(report.RemovedDependencies) != 1 || report.RemovedDependencies[0].Name != "removed" {
		t.Fatalf("RemovedDependencies = %#v, want removed", report.RemovedDependencies)
	}
	if len(report.ChangedPackageScripts) != 1 || report.ChangedPackageScripts[0].ScriptName != "install" {
		t.Fatalf("ChangedPackageScripts = %#v, want install", report.ChangedPackageScripts)
	}
	if len(report.NewPackageScripts) != 1 || report.NewPackageScripts[0].ScriptName != "postinstall" {
		t.Fatalf("NewPackageScripts = %#v, want postinstall", report.NewPackageScripts)
	}
	if !report.HasRelevantChanges() {
		t.Fatal("HasRelevantChanges() = false, want true")
	}
}

func TestCompareFindingChanges(t *testing.T) {
	oldSnapshot := scan.Snapshot{
		ScanID: "old",
		Findings: []rules.Finding{
			{
				ID:       "old-finding",
				RuleID:   "rule:old",
				RuleType: "detection",
				Path:     "old.js",
			},
			{
				ID:       "same-finding",
				RuleID:   "rule:same",
				RuleType: "detection",
				Path:     "same.js",
			},
		},
	}
	newSnapshot := scan.Snapshot{
		ScanID: "new",
		Findings: []rules.Finding{
			{
				ID:       "same-finding",
				RuleID:   "rule:same",
				RuleType: "detection",
				Path:     "same.js",
			},
			{
				ID:         "new-finding",
				RuleID:     "rule:new",
				RuleType:   "blocklist",
				Path:       "new.js",
				Severity:   rules.SeverityCritical,
				Confidence: rules.ConfidenceConfirmedMalicious,
				Blocking:   true,
			},
		},
	}

	report := Compare(oldSnapshot, newSnapshot)
	if len(report.NewFindings) != 1 || report.NewFindings[0].RuleID != "rule:new" {
		t.Fatalf("NewFindings = %#v, want rule:new", report.NewFindings)
	}
	if len(report.ResolvedFindings) != 1 || report.ResolvedFindings[0].RuleID != "rule:old" {
		t.Fatalf("ResolvedFindings = %#v, want rule:old", report.ResolvedFindings)
	}
	if len(report.StillExistingFindings) != 1 || report.StillExistingFindings[0].RuleID != "rule:same" {
		t.Fatalf("StillExistingFindings = %#v, want rule:same", report.StillExistingFindings)
	}
	if !report.HasRelevantChanges() {
		t.Fatal("HasRelevantChanges() = false, want true")
	}
}

func scanFile(path, hash string, size int64, modifiedTime time.Time, status scan.Status) scan.File {
	return scan.File{
		Path:         path,
		Size:         size,
		ModifiedTime: modifiedTime,
		Mode:         "-rw-r--r--",
		Permissions:  "0644",
		SHA256:       hash,
		Type:         "javascript",
		Status:       status,
	}
}

func assertChange(t *testing.T, changes []FileChange, path string, state scan.FileState) {
	t.Helper()
	if len(changes) != 1 {
		t.Fatalf("%s changes length = %d, want 1: %#v", state, len(changes), changes)
	}
	if changes[0].Path != path || changes[0].State != state {
		t.Fatalf("change = %#v, want %s %s", changes[0], path, state)
	}
}
