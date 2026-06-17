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
		RemovedFiles:          []diff.FileChange{},
		ModifiedFiles:         []diff.FileChange{},
		UnchangedFiles:        []diff.FileChange{},
		SkippedFiles:          []diff.FileChange{},
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
	if document.NewFindings == nil || document.ResolvedFindings == nil || document.StillExistingFindings == nil {
		t.Fatalf("finding arrays must be present as empty arrays: %#v", document)
	}
}
