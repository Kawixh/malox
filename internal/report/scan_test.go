package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"malox/internal/scan"
)

func TestWriteScanJSONUsesPublicSchema(t *testing.T) {
	when := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	snapshot := scan.Snapshot{
		SchemaVersion:  scan.SchemaVersion,
		ScannerVersion: "test-version",
		ProjectID:      "sha256:test",
		ProjectRoot:    ".",
		StartedAt:      when,
		FinishedAt:     when,
		Files: []scan.File{
			{
				Path:         "package.json",
				Size:         3,
				ModifiedTime: when,
				Mode:         "-rw-r--r--",
				Permissions:  "0644",
				SHA256:       "abc123",
				Type:         "node_manifest",
				Status:       scan.StatusScanned,
			},
		},
		Summary: scan.Summary{
			TotalFiles:   1,
			ScannedFiles: 1,
		},
	}

	var out bytes.Buffer
	if err := WriteScan(&out, snapshot, FormatJSON); err != nil {
		t.Fatalf("WriteScan() error = %v", err)
	}
	if strings.Contains(out.String(), "Usage:") {
		t.Fatalf("JSON output contained help text:\n%s", out.String())
	}

	var document ScanSnapshot
	if err := json.Unmarshal(out.Bytes(), &document); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	if document.SchemaVersion != scan.SchemaVersion {
		t.Fatalf("SchemaVersion = %q, want %q", document.SchemaVersion, scan.SchemaVersion)
	}
	if len(document.Files) != 1 || document.Files[0].Path != "package.json" {
		t.Fatalf("Files = %#v, want package.json", document.Files)
	}
}

func TestWriteScanTableSummarizesCounts(t *testing.T) {
	snapshot := scan.Snapshot{
		ProjectID:   "sha256:test",
		ProjectRoot: ".",
		Summary: scan.Summary{
			ScannedFiles:       2,
			SkippedFiles:       1,
			ErroredFiles:       0,
			SkippedDirectories: 3,
		},
	}

	var out bytes.Buffer
	if err := WriteScan(&out, snapshot, FormatTable); err != nil {
		t.Fatalf("WriteScan() error = %v", err)
	}
	for _, want := range []string{"Scan snapshot", "2 scanned", "1 skipped", "Skipped directories: 3"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("table output missing %q:\n%s", want, out.String())
		}
	}
}
