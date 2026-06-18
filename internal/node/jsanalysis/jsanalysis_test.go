package jsanalysis

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"malox/internal/rules"
)

func TestAnalyzeRecoversEncodedPayloadAndWritesCache(t *testing.T) {
	root := t.TempDir()
	cacheDir := t.TempDir()
	body := "const payload = ['Y29u', 'c29sZS5sb2coMSk='].join(''); eval(atob(payload));\n"
	writeJSFile(t, root, "node_modules/pkg/index.js", body)

	result, err := Analyze(t.Context(), Options{
		Root:              root,
		DecodedPayloadDir: cacheDir,
		MaxFileSize:       1024,
		Files: []File{{
			Path:         "node_modules/pkg/index.js",
			SHA256:       sha256String(body),
			Type:         "javascript",
			PackageOwner: "pkg",
			Size:         int64(len(body)),
		}},
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	finding := findFinding(t, result, "jsanalysis:encoded-sink-flow")
	if finding.Severity != "high" || finding.Confidence != "weak-signal" {
		t.Fatalf("finding risk = %s/%s, want high/weak-signal", finding.Severity, finding.Confidence)
	}
	if finding.PackageOwner != "pkg" {
		t.Fatalf("PackageOwner = %q, want pkg", finding.PackageOwner)
	}
	if finding.Evidence[0].Classification != "javascript" || finding.Evidence[0].DecodedSHA256 == "" {
		t.Fatalf("evidence = %#v, want javascript decoded hash", finding.Evidence[0])
	}

	cachePath := filepath.Join(cacheDir, finding.Evidence[0].DecodedSHA256+".bin")
	data, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("ReadFile(decoded cache) error = %v", err)
	}
	if string(data) != "console.log(1)" {
		t.Fatalf("cached decoded payload = %q", string(data))
	}
	if strings.Contains(cachePath, "node_modules") {
		t.Fatalf("decoded cache path contains project path: %s", cachePath)
	}
}

func TestAnalyzeDetectsHexPercentUnicodeAndBracketGlobal(t *testing.T) {
	root := t.TempDir()
	body := strings.Join([]string{
		`const h = "636f6e736f6c652e6c6f67283129";`,
		`const p = "%72%65%71%75%69%72%65%28%27%66%73%27%29";`,
		`const u = "\u0063\u006f\u006e\u0073\u006f\u006c\u0065\u002e\u006c\u006f\u0067\u0028\u0031\u0029";`,
		`globalThis["pro" + "cess"];`,
	}, "\n")
	writeJSFile(t, root, "src/index.js", body)

	result, err := Analyze(t.Context(), Options{
		Root:        root,
		MaxFileSize: 4096,
		Files: []File{{
			Path:   "src/index.js",
			SHA256: sha256String(body),
			Type:   "javascript",
			Size:   int64(len(body)),
		}},
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	decoders := map[string]bool{}
	for _, finding := range result.Findings {
		decoders[finding.Evidence[0].Decoder] = true
	}
	for _, decoder := range []string{"hex", "percent", "unicode_escape"} {
		if !decoders[decoder] {
			t.Fatalf("decoder %q not found in findings: %#v", decoder, result.Findings)
		}
	}
	findFinding(t, result, "jsanalysis:bracket-global-access")
}

func TestAnalyzeReportsDecodeLimit(t *testing.T) {
	root := t.TempDir()
	body := `const payload = "Y29uc29sZS5sb2coMSk=";`
	writeJSFile(t, root, "index.js", body)

	result, err := Analyze(t.Context(), Options{
		Root:            root,
		MaxFileSize:     1024,
		MaxDecodedBytes: 4,
		Files: []File{{
			Path:   "index.js",
			SHA256: sha256String(body),
			Type:   "javascript",
			Size:   int64(len(body)),
		}},
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("Findings = %#v, want none when decoded payload exceeds limit", result.Findings)
	}
	if len(result.Warnings) != 1 || result.Warnings[0].Code != "jsanalysis_decode_limit" {
		t.Fatalf("Warnings = %#v, want decode limit warning", result.Warnings)
	}
}

func TestAnalyzeDetectsStringTransformsAndConstructorEscape(t *testing.T) {
	root := t.TempDir()
	body := strings.Join([]string{
		`const cmd = "sj.elif_dlihc".split("").reverse().join("");`,
		`require(cmd);`,
		`const fn = this.constructor.constructor("return process")();`,
	}, "\n")
	writeJSFile(t, root, "index.cjs", body)

	result, err := Analyze(t.Context(), Options{
		Root:        root,
		MaxFileSize: 2048,
		Files: []File{{
			Path:   "index.cjs",
			SHA256: sha256String(body),
			Type:   "javascript",
			Size:   int64(len(body)),
		}},
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	findFinding(t, result, "jsanalysis:string-sink-flow")
	findFinding(t, result, "jsanalysis:constructor-escape")
}

func writeJSFile(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

func findFinding(t *testing.T, result Result, ruleID string) rules.Finding {
	t.Helper()
	for _, finding := range result.Findings {
		if finding.RuleID == ruleID {
			return finding
		}
	}
	t.Fatalf("finding %q not found in %#v", ruleID, result.Findings)
	return rules.Finding{}
}

func sha256String(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
