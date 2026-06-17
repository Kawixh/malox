package cache

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"malox/internal/scan"
)

func TestStoreWriteAndLoadSnapshot(t *testing.T) {
	stateDir := t.TempDir()
	store, err := NewStore(stateDir)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	snapshot := testSnapshot("2026-06-17T12-00-00.000000000Z", "package.json", "abc123")
	if err := store.WriteSnapshot(t.Context(), snapshot); err != nil {
		t.Fatalf("WriteSnapshot() error = %v", err)
	}

	latest, ok, err := store.LoadLatest(t.Context())
	if err != nil {
		t.Fatalf("LoadLatest() error = %v", err)
	}
	if !ok {
		t.Fatal("LoadLatest() ok = false, want true")
	}
	if latest.ScanID != snapshot.ScanID {
		t.Fatalf("latest ScanID = %q, want %q", latest.ScanID, snapshot.ScanID)
	}
	if latest.Files[0].Path != "package.json" || latest.Files[0].SHA256 != "abc123" {
		t.Fatalf("latest file = %#v", latest.Files[0])
	}

	snapshots, err := store.ListSnapshots(t.Context())
	if err != nil {
		t.Fatalf("ListSnapshots() error = %v", err)
	}
	if len(snapshots) != 1 || snapshots[0].ID != snapshot.ScanID {
		t.Fatalf("snapshots = %#v, want one snapshot", snapshots)
	}

	indexPath := filepath.Join(stateDir, "indexes", "files.jsonl")
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("ReadFile(index) error = %v", err)
	}
	if !strings.Contains(string(indexData), `"schema_version":"malox.files.index.v1"`) {
		t.Fatalf("file index missing schema version:\n%s", string(indexData))
	}
}

func TestStoreRecentPairRequiresTwoSnapshots(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	_, _, err = store.RecentPair(t.Context())
	if !errors.Is(err, ErrInsufficientSnapshots) {
		t.Fatalf("RecentPair() error = %v, want ErrInsufficientSnapshots", err)
	}
}

func TestWriteFileAtomicReplacesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "latest.json")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writeFileAtomic(t.Context(), path, []byte("new\n"), 0o644); err != nil {
		t.Fatalf("writeFileAtomic() error = %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "new\n" {
		t.Fatalf("file content = %q, want new", string(got))
	}
}

func testSnapshot(scanID, path, hash string) scan.Snapshot {
	when := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	return scan.Snapshot{
		SchemaVersion:  scan.SchemaVersion,
		ScannerVersion: "test-version",
		ScanID:         scanID,
		ProjectID:      "sha256:test",
		ProjectRoot:    ".",
		StartedAt:      when,
		FinishedAt:     when,
		Files: []scan.File{
			{
				Path:         path,
				Size:         int64(len(hash)),
				ModifiedTime: when,
				Mode:         "-rw-r--r--",
				Permissions:  "0644",
				SHA256:       hash,
				Type:         "unknown",
				Status:       scan.StatusScanned,
				State:        scan.FileStatePreviouslyUnscanned,
			},
		},
		Summary: scan.Summary{
			TotalFiles:   1,
			ScannedFiles: 1,
		},
	}
}
