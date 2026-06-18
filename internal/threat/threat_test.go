package threat

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"malox/internal/cache"
	"malox/internal/node"
	"malox/internal/rules"
)

func TestOSVQueryBatchProducesKnownVulnerableFindingAndOfflineCache(t *testing.T) {
	store := newTestStore(t)
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/v1/querybatch" {
			t.Fatalf("path = %q, want /v1/querybatch", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		_, _ = w.Write([]byte(`{
  "results": [{
    "vulns": [{
      "id": "GHSA-test",
      "summary": "test vulnerability",
      "affected": [{
        "package": {"purl": "pkg:npm/left-pad@1.3.0"},
        "versions": ["1.3.0"]
      }]
    }]
  }]
}`))
	}))
	defer server.Close()

	inv := testInventory()
	result, err := Evaluate(t.Context(), inv, Options{
		Store:   store,
		Sources: []string{SourceOSV},
		OSVURL:  server.URL,
		Now:     fixedNow,
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
	assertFinding(t, result.Findings, SourceOSV, rules.ConfidenceKnownVulnerable)

	server.Close()
	offline, err := Evaluate(t.Context(), inv, Options{
		Store:   store,
		Offline: true,
		Sources: []string{SourceOSV},
		OSVURL:  server.URL,
		Now:     fixedNow,
	})
	if err != nil {
		t.Fatalf("offline Evaluate() error = %v", err)
	}
	assertFinding(t, offline.Findings, SourceOSV, rules.ConfidenceKnownVulnerable)
	if len(offline.Sources) != 1 || offline.Sources[0].Mode != "offline" || offline.Sources[0].Status != "cached" {
		t.Fatalf("offline sources = %#v, want cached offline status", offline.Sources)
	}
}

func TestOpenSSFCacheProducesConfirmedMaliciousFinding(t *testing.T) {
	store := newTestStore(t)
	record := osvRecord{
		ID:      "MAL-2026-left-pad",
		Summary: "malicious package",
		Affected: []osvAffected{{
			Package:  osvPackage{Name: "left-pad", Ecosystem: "npm"},
			Versions: []string{"1.3.0"},
		}},
	}
	writeJSON(t, filepath.Join(store.Dir(), "sources", SourceOpenSSF, "records", "left-pad.json"), record)

	result, err := Evaluate(t.Context(), testInventory(), Options{
		Store:   store,
		Offline: true,
		Sources: []string{SourceOpenSSF},
		Now:     fixedNow,
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	assertFinding(t, result.Findings, SourceOpenSSF, rules.ConfidenceConfirmedMalicious)
	if !result.Findings[0].Blocking {
		t.Fatal("OpenSSF malicious finding Blocking = false, want true")
	}
}

func TestGitHubAdvisoryCacheProducesKnownVulnerableFinding(t *testing.T) {
	store := newTestStore(t)
	record := osvRecord{
		ID:      "GHSA-left-pad",
		Summary: "cached advisory",
		Affected: []osvAffected{{
			Package: osvPackage{Name: "left-pad", Ecosystem: "npm"},
			Ranges: []osvRange{{
				Type: "SEMVER",
				Events: []osvEvent{
					{Introduced: "0"},
					{Fixed: "1.3.1"},
				},
			}},
		}},
	}
	writeJSON(t, filepath.Join(store.Dir(), "sources", SourceGitHubAdvisory, "records", "left-pad.json"), record)

	result, err := Evaluate(t.Context(), testInventory(), Options{
		Store:   store,
		Offline: true,
		Sources: []string{SourceGitHubAdvisory},
		Now:     fixedNow,
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	assertFinding(t, result.Findings, SourceGitHubAdvisory, rules.ConfidenceKnownVulnerable)
}

func TestNPMRegistryMetadataCachesHeadersAndDeprecatedFinding(t *testing.T) {
	store := newTestStore(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/left-pad" {
			t.Fatalf("path = %q, want /left-pad", r.URL.Path)
		}
		w.Header().Set("ETag", `"abc"`)
		w.Header().Set("Last-Modified", "Thu, 18 Jun 2026 12:00:00 GMT")
		_, _ = w.Write([]byte(`{
  "name": "left-pad",
  "versions": {
    "1.3.0": {
      "name": "left-pad",
      "version": "1.3.0",
      "deprecated": "use String.prototype.padStart",
      "dist": {"tarball": "https://registry.example/left-pad/-/left-pad-1.3.0.tgz"}
    }
  }
}`))
	}))
	defer server.Close()

	result, err := Evaluate(t.Context(), testInventory(), Options{
		Store:          store,
		Sources:        []string{SourceNPM},
		NPMRegistryURL: server.URL,
		Now:            fixedNow,
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	assertFinding(t, result.Findings, SourceNPM, rules.ConfidenceSuspiciousHistory)

	metadata, err := cache.ReadSourceMetadata(filepath.Join(store.Dir(), "sources", SourceNPM, "metadata.json"))
	if err != nil {
		t.Fatalf("ReadSourceMetadata() error = %v", err)
	}
	if metadata.ETag != `"abc"` || metadata.LastModified == "" {
		t.Fatalf("metadata headers = %#v, want etag and last-modified", metadata)
	}
}

func TestRequiredSourceFailureReturnsSentinel(t *testing.T) {
	store := newTestStore(t)
	_, err := Evaluate(context.Background(), testInventory(), Options{
		Store:           store,
		Sources:         []string{SourceOSV},
		RequiredSources: []string{SourceOSV},
		OSVURL:          "http://127.0.0.1:1",
	})
	if err == nil {
		t.Fatal("Evaluate() error = nil, want required source failure")
	}
}

func newTestStore(t *testing.T) cache.GlobalStore {
	t.Helper()
	store, err := cache.NewGlobalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewGlobalStore() error = %v", err)
	}
	if err := store.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	return store
}

func testInventory() node.Inventory {
	return node.Inventory{
		SchemaVersion: node.SchemaVersion,
		Dependencies: []node.Dependency{{
			Name:           "left-pad",
			Version:        "1.3.0",
			PURL:           "pkg:npm/left-pad@1.3.0",
			PackageManager: "npm",
			SourcePath:     "package-lock.json",
			PackagePath:    "node_modules/left-pad",
		}},
	}
}

func assertFinding(t *testing.T, findings []rules.Finding, source string, confidence rules.Confidence) {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one", findings)
	}
	if findings[0].Source != source || findings[0].Confidence != confidence {
		t.Fatalf("finding = %#v, want source %s confidence %s", findings[0], source, confidence)
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.WriteFileAtomic(t.Context(), path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fixedNow() time.Time {
	return time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
}
