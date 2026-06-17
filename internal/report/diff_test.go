package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"malox/internal/diff"
	"malox/internal/scan"
)

func TestWriteDiffJSONUsesPublicSchema(t *testing.T) {
	report := diff.Report{
		SchemaVersion: diff.SchemaVersion,
		FromScanID:    "old",
		ToScanID:      "new",
		AddedFiles: []diff.FileChange{
			{
				Path:     "added.js",
				State:    scan.FileStateAdded,
				ToStatus: scan.StatusScanned,
				ToSHA256: "abc123",
				ToSize:   6,
			},
		},
		RemovedFiles:   []diff.FileChange{},
		ModifiedFiles:  []diff.FileChange{},
		UnchangedFiles: []diff.FileChange{},
		SkippedFiles:   []diff.FileChange{},
		NewDependencies: []diff.DependencyChange{
			{
				Name:           "left-pad",
				PackageManager: "npm",
				ToVersion:      "1.3.0",
				ToPURL:         "pkg:npm/left-pad@1.3.0",
			},
		},
		RemovedDependencies: []diff.DependencyChange{},
		UpdatedDependencies: []diff.DependencyChange{},
		NewPackageScripts: []diff.PackageScriptChange{
			{
				PackageName:    "left-pad",
				PackageManager: "package.json",
				ScriptName:     "install",
				ToCommand:      "node install.js",
			},
		},
		ChangedPackageScripts: []diff.PackageScriptChange{},
		NewFindings:           []diff.FindingChange{},
		ResolvedFindings:      []diff.FindingChange{},
		StillExistingFindings: []diff.FindingChange{},
	}

	var out bytes.Buffer
	if err := WriteDiff(&out, report, FormatJSON); err != nil {
		t.Fatalf("WriteDiff() error = %v", err)
	}

	var document DiffReport
	if err := json.Unmarshal(out.Bytes(), &document); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	if document.SchemaVersion != diff.SchemaVersion {
		t.Fatalf("SchemaVersion = %q, want %q", document.SchemaVersion, diff.SchemaVersion)
	}
	if len(document.AddedFiles) != 1 || document.AddedFiles[0].Path != "added.js" {
		t.Fatalf("AddedFiles = %#v, want added.js", document.AddedFiles)
	}
	if len(document.NewDependencies) != 1 || document.NewDependencies[0].Name != "left-pad" {
		t.Fatalf("NewDependencies = %#v, want left-pad", document.NewDependencies)
	}
	if len(document.NewPackageScripts) != 1 || document.NewPackageScripts[0].ScriptName != "install" {
		t.Fatalf("NewPackageScripts = %#v, want install", document.NewPackageScripts)
	}
	if document.NewFindings == nil || document.ResolvedFindings == nil || document.StillExistingFindings == nil {
		t.Fatalf("finding arrays must be present as empty arrays: %#v", document)
	}
}
