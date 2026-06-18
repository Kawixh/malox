package cache

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGlobalStoreEnsureCreatesLayout(t *testing.T) {
	store, err := NewGlobalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewGlobalStore() error = %v", err)
	}

	if err := store.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}

	for _, path := range []string{
		"index-v1.json",
		"sources/osv/querybatch",
		"sources/npm/packuments",
		"rules/builtin",
		"rules/downloaded",
		"decoded-payloads/sha256",
	} {
		fullPath := filepath.Join(store.Dir(), filepath.FromSlash(path))
		if _, err := os.Stat(fullPath); err != nil {
			t.Fatalf("expected cache layout path %q: %v", path, err)
		}
	}
}

func TestGlobalStoreUpdateWritesBuiltinRulesAndMetadata(t *testing.T) {
	store, err := NewGlobalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewGlobalStore() error = %v", err)
	}
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)

	report, err := store.Update(t.Context(), UpdateOptions{Now: now})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if report.SchemaVersion != CacheReportSchemaVersion || report.Operation != "update" {
		t.Fatalf("report = %#v, want update report", report)
	}
	if len(report.Sources) != 1 || report.Sources[0].Source != "builtin-rules" {
		t.Fatalf("sources = %#v, want builtin-rules", report.Sources)
	}

	entries, err := os.ReadDir(filepath.Join(store.Dir(), "rules", "builtin"))
	if err != nil {
		t.Fatalf("ReadDir(builtin) error = %v", err)
	}
	var jsonDocs int
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") && entry.Name() != "metadata.json" {
			jsonDocs++
		}
	}
	if jsonDocs == 0 {
		t.Fatal("expected content-addressed builtin rule documents")
	}

	metadata, err := ReadSourceMetadata(filepath.Join(store.Dir(), "rules", "builtin", "metadata.json"))
	if err != nil {
		t.Fatalf("ReadSourceMetadata() error = %v", err)
	}
	if metadata.Source != "builtin-rules" || metadata.FetchedAt != now || metadata.RecordCount == 0 {
		t.Fatalf("metadata = %#v, want builtin metadata", metadata)
	}

	indexData, err := os.ReadFile(filepath.Join(store.Dir(), "index-v1.json"))
	if err != nil {
		t.Fatalf("ReadFile(index) error = %v", err)
	}
	var index GlobalIndex
	if err := json.Unmarshal(indexData, &index); err != nil {
		t.Fatalf("index is not JSON: %v", err)
	}
	if index.SchemaVersion != GlobalIndexSchemaVersion || len(index.Sources) != 1 {
		t.Fatalf("index = %#v, want one source", index)
	}
}

func TestGlobalStoreUpdateOfflineReportsSkippedRemoteSources(t *testing.T) {
	store, err := NewGlobalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewGlobalStore() error = %v", err)
	}

	report, err := store.Update(t.Context(), UpdateOptions{Offline: true})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if !report.Offline {
		t.Fatal("report.Offline = false, want true")
	}
	if len(report.Warnings) != 1 || !strings.Contains(report.Warnings[0], "remote source updates skipped") {
		t.Fatalf("warnings = %#v, want offline warning", report.Warnings)
	}
}

func TestGlobalStoreCleanAllRequiresForce(t *testing.T) {
	store, err := NewGlobalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewGlobalStore() error = %v", err)
	}

	_, err = store.Clean(t.Context(), CleanOptions{All: true})
	if !errors.Is(err, ErrCleanAllRequiresForce) {
		t.Fatalf("Clean() error = %v, want ErrCleanAllRequiresForce", err)
	}
}

func TestGlobalStoreCleanExpiredRemovesOnlyExpiredMetadataDir(t *testing.T) {
	store, err := NewGlobalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewGlobalStore() error = %v", err)
	}
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	if _, err := store.Update(t.Context(), UpdateOptions{Now: now}); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	expiredDir := filepath.Join(store.Dir(), "sources", "osv")
	expiredMetadata := SourceMetadata{
		SchemaVersion: SourceMetadataSchemaVersion,
		Source:        "osv",
		FetchedAt:     now.Add(-48 * time.Hour),
		ETag:          "",
		LastModified:  "",
		License:       "test license",
		SourceType:    "vulnerability",
		TTL:           (24 * time.Hour).String(),
		RecordCount:   2,
	}
	data, err := marshalJSON(expiredMetadata)
	if err != nil {
		t.Fatalf("marshalJSON() error = %v", err)
	}
	if err := writeFileAtomic(t.Context(), filepath.Join(expiredDir, "metadata.json"), data, 0o644); err != nil {
		t.Fatalf("write expired metadata: %v", err)
	}
	if err := writeFileAtomic(t.Context(), filepath.Join(expiredDir, "vulns", "record.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write expired record: %v", err)
	}

	report, err := store.Clean(t.Context(), CleanOptions{Expired: true, Now: now})
	if err != nil {
		t.Fatalf("Clean() error = %v", err)
	}
	if len(report.Sources) != 1 || report.Sources[0].Source != "osv" || report.Sources[0].BytesRemoved == 0 {
		t.Fatalf("sources = %#v, want expired osv removal", report.Sources)
	}
	if _, err := os.Stat(filepath.Join(expiredDir, "metadata.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired metadata still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.Dir(), "rules", "builtin", "metadata.json")); err != nil {
		t.Fatalf("fresh builtin metadata was removed: %v", err)
	}
}

func TestGlobalCacheUpdateDoesNotStoreProjectAbsolutePath(t *testing.T) {
	cacheDir := t.TempDir()
	projectDir := t.TempDir()
	store, err := NewGlobalStore(cacheDir)
	if err != nil {
		t.Fatalf("NewGlobalStore() error = %v", err)
	}
	if _, err := store.Update(t.Context(), UpdateOptions{}); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	err = filepath.WalkDir(cacheDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), projectDir) {
			t.Fatalf("global cache file %q leaked project path %q", path, projectDir)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir() error = %v", err)
	}
}
