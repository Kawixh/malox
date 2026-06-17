package diff

import (
	"testing"
	"time"

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
