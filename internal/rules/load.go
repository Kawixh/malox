package rules

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed defaults/*.json
var defaultPolicies embed.FS

// BuiltinDocument is one embedded policy document.
type BuiltinDocument struct {
	Name string
	Data []byte
}

// LoadOptions describes local policy sources.
type LoadOptions struct {
	PolicyFiles []string
	UseBuiltins bool
}

// Load reads built-in and organization-managed policy files.
func Load(ctx context.Context, opts LoadOptions) ([]Policy, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}

	policies := []Policy{}
	if opts.UseBuiltins {
		builtin, err := LoadBuiltin()
		if err != nil {
			return nil, err
		}
		policies = append(policies, builtin...)
	}

	filePolicies, err := LoadFiles(ctx, opts.PolicyFiles)
	if err != nil {
		return nil, err
	}
	policies = append(policies, filePolicies...)
	return policies, nil
}

// LoadBuiltin returns policies embedded in the Malox binary.
func LoadBuiltin() ([]Policy, error) {
	docs, err := BuiltinDocuments()
	if err != nil {
		return nil, err
	}

	policies := make([]Policy, 0, len(docs))
	for _, doc := range docs {
		policy, err := DecodePolicy("builtin:"+doc.Name, doc.Data)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

// BuiltinDocuments returns the embedded local policy documents.
func BuiltinDocuments() ([]BuiltinDocument, error) {
	entries, err := fs.ReadDir(defaultPolicies, "defaults")
	if err != nil {
		return nil, fmt.Errorf("read built-in rules: %w", err)
	}

	docs := make([]BuiltinDocument, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := "defaults/" + entry.Name()
		data, err := defaultPolicies.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read built-in policy %q: %w", entry.Name(), err)
		}
		docs = append(docs, BuiltinDocument{
			Name: entry.Name(),
			Data: data,
		})
	}
	return docs, nil
}

// LoadFiles reads policy files from disk.
func LoadFiles(ctx context.Context, paths []string) ([]Policy, error) {
	policies := make([]Policy, 0, len(paths))
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("load rule files: %w", err)
		}
		if strings.TrimSpace(path) == "" {
			return nil, errors.New("policy file path is required")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read policy file %q: %w", path, err)
		}
		policy, err := DecodePolicy("policy:"+filepath.Base(path), data)
		if err != nil {
			return nil, fmt.Errorf("load policy file %q: %w", path, err)
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

// DecodePolicy parses and validates one policy document.
func DecodePolicy(source string, data []byte) (Policy, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var policy Policy
	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, fmt.Errorf("parse policy %s: %w", source, err)
	}
	if strings.TrimSpace(policy.Source) == "" {
		policy.Source = source
	}
	if err := Validate(policy); err != nil {
		return Policy{}, fmt.Errorf("validate policy %s: %w", source, err)
	}
	return policy, nil
}

// Validate checks the policy schema and rule-level expressions.
func Validate(policy Policy) error {
	problems := []string{}
	if policy.SchemaVersion != PolicySchemaVersion {
		problems = append(problems, fmt.Sprintf("schema_version must be %q", PolicySchemaVersion))
	}
	if strings.TrimSpace(policy.Source) == "" {
		problems = append(problems, "source is required")
	}

	for i, rule := range policy.Rules {
		prefix := fmt.Sprintf("rules[%d]", i)
		problems = append(problems, validateRule(prefix, rule)...)
	}
	for i, entry := range policy.Allowlist {
		prefix := fmt.Sprintf("allowlist[%d]", i)
		problems = append(problems, validateAllowlist(prefix, entry)...)
	}
	for i, entry := range policy.Blocklist {
		prefix := fmt.Sprintf("blocklist[%d]", i)
		problems = append(problems, validateBlocklist(prefix, entry)...)
	}

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func validateRule(prefix string, rule Rule) []string {
	problems := []string{}
	if strings.TrimSpace(rule.ID) == "" {
		problems = append(problems, prefix+".id is required")
	}
	if !validSeverity(rule.Severity) {
		problems = append(problems, prefix+".severity is invalid")
	}
	if !validConfidence(rule.Confidence) {
		problems = append(problems, prefix+".confidence is invalid")
	}
	for _, pattern := range rule.ScriptPatterns {
		if _, err := compilePattern(pattern); err != nil {
			problems = append(problems, fmt.Sprintf("%s.script_patterns contains invalid regex %q: %v", prefix, pattern, err))
		}
	}
	for j, pattern := range rule.FilePatterns {
		if strings.TrimSpace(pattern.Pattern) == "" {
			problems = append(problems, fmt.Sprintf("%s.file_patterns[%d].pattern is required", prefix, j))
			continue
		}
		if _, err := compilePattern(pattern.Pattern); err != nil {
			problems = append(problems, fmt.Sprintf("%s.file_patterns[%d].pattern is invalid: %v", prefix, j, err))
		}
		if pattern.MaxBytes < 0 {
			problems = append(problems, fmt.Sprintf("%s.file_patterns[%d].max_bytes must be non-negative", prefix, j))
		}
	}
	for _, versionRange := range rule.PackageVersionRanges {
		if _, err := parseRange(versionRange.Range); err != nil {
			problems = append(problems, fmt.Sprintf("%s.package_version_ranges contains invalid range %q: %v", prefix, versionRange.Range, err))
		}
	}
	return problems
}

func validateAllowlist(prefix string, entry AllowlistEntry) []string {
	problems := []string{}
	if strings.TrimSpace(entry.ID) == "" {
		problems = append(problems, prefix+".id is required")
	}
	if strings.TrimSpace(entry.Reason) == "" {
		problems = append(problems, prefix+".reason is required")
	}
	if strings.TrimSpace(entry.Owner) == "" {
		problems = append(problems, prefix+".owner is required")
	}
	if strings.TrimSpace(entry.ExpiresAt) == "" {
		problems = append(problems, prefix+".expires_at is required")
	} else if _, err := time.Parse(time.RFC3339, entry.ExpiresAt); err != nil {
		problems = append(problems, fmt.Sprintf("%s.expires_at must be RFC3339: %v", prefix, err))
	}
	if emptyScope(entry.Scope) {
		problems = append(problems, prefix+".scope must contain at least one exact match field")
	}
	return problems
}

func validateBlocklist(prefix string, entry BlocklistEntry) []string {
	problems := []string{}
	if strings.TrimSpace(entry.ID) == "" {
		problems = append(problems, prefix+".id is required")
	}
	if entry.Severity != "" && !validSeverity(entry.Severity) {
		problems = append(problems, prefix+".severity is invalid")
	}
	if entry.Confidence != "" && !validConfidence(entry.Confidence) {
		problems = append(problems, prefix+".confidence is invalid")
	}
	if entry.VersionRange != "" {
		if _, err := parseRange(entry.VersionRange); err != nil {
			problems = append(problems, fmt.Sprintf("%s.version_range is invalid: %v", prefix, err))
		}
	}
	if entry.Package == "" &&
		entry.PURL == "" &&
		entry.Hash == "" &&
		entry.Maintainer == "" &&
		entry.URL == "" &&
		entry.Path == "" &&
		entry.PathPattern == "" {
		problems = append(problems, prefix+" must define a package, purl, hash, maintainer, url, path, or path_pattern")
	}
	return problems
}

func validSeverity(severity Severity) bool {
	switch severity {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

func validConfidence(confidence Confidence) bool {
	switch confidence {
	case ConfidenceConfirmedMalicious,
		ConfidenceKnownVulnerable,
		ConfidenceSuspiciousHistory,
		ConfidenceWeakSignal,
		ConfidenceUnknown:
		return true
	default:
		return false
	}
}

func emptyScope(scope MatchScope) bool {
	return scope.FindingID == "" &&
		scope.RuleID == "" &&
		scope.Package == "" &&
		scope.Version == "" &&
		scope.PURL == "" &&
		scope.Path == "" &&
		scope.Hash == "" &&
		scope.Maintainer == "" &&
		scope.URL == "" &&
		scope.ScriptName == ""
}
