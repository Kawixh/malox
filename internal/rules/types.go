// Package rules evaluates deterministic local Malox policy.
package rules

import (
	"time"

	"malox/internal/node"
)

// PolicySchemaVersion is the supported local policy schema.
const PolicySchemaVersion = "malox.rules.policy.v1"

// FindingSchemaVersion is the schema used for scan finding records.
const FindingSchemaVersion = "malox.finding.v1"

// TestSchemaVersion is the schema used by rules test output.
const TestSchemaVersion = "malox.rules.test.v1"

// Severity describes the operational impact of a finding.
type Severity string

const (
	// SeverityLow is informational or low-risk policy output.
	SeverityLow Severity = "low"
	// SeverityMedium needs review but is not a confirmed block.
	SeverityMedium Severity = "medium"
	// SeverityHigh is serious and may be promoted by policy.
	SeverityHigh Severity = "high"
	// SeverityCritical is used for confirmed local blocklist hits.
	SeverityCritical Severity = "critical"
)

// Confidence describes how strong the evidence is.
type Confidence string

const (
	// ConfidenceConfirmedMalicious is a strong local or upstream malicious signal.
	ConfidenceConfirmedMalicious Confidence = "confirmed-malicious"
	// ConfidenceKnownVulnerable is reserved for vulnerability source matches.
	ConfidenceKnownVulnerable Confidence = "known-vulnerable"
	// ConfidenceSuspiciousHistory is reserved for historical risk signals.
	ConfidenceSuspiciousHistory Confidence = "suspicious-history"
	// ConfidenceWeakSignal is a heuristic signal that needs supporting evidence.
	ConfidenceWeakSignal Confidence = "weak-signal"
	// ConfidenceUnknown means the rule source did not classify confidence.
	ConfidenceUnknown Confidence = "unknown"
)

// Policy groups detection rules, allowlists, blocklists, and test expectations.
type Policy struct {
	SchemaVersion string            `json:"schema_version"`
	Source        string            `json:"source,omitempty"`
	Rules         []Rule            `json:"rules,omitempty"`
	Allowlist     []AllowlistEntry  `json:"allowlist,omitempty"`
	Blocklist     []BlocklistEntry  `json:"blocklist,omitempty"`
	Tests         *TestExpectations `json:"tests,omitempty"`
}

// Rule is one deterministic local detection rule.
type Rule struct {
	ID                       string         `json:"id"`
	Description              string         `json:"description,omitempty"`
	Severity                 Severity       `json:"severity"`
	Confidence               Confidence     `json:"confidence"`
	PathPatterns             []string       `json:"path_patterns,omitempty"`
	FileSHA256               []string       `json:"file_sha256,omitempty"`
	PackageNames             []string       `json:"package_names,omitempty"`
	PackageVersionRanges     []VersionRange `json:"package_version_ranges,omitempty"`
	PURLs                    []string       `json:"purls,omitempty"`
	RegistryURLs             []string       `json:"registry_urls,omitempty"`
	Maintainers              []string       `json:"maintainers,omitempty"`
	ScriptNames              []string       `json:"script_names,omitempty"`
	ScriptPatterns           []string       `json:"script_patterns,omitempty"`
	SuspiciousLifecycleHooks bool           `json:"suspicious_lifecycle_hooks,omitempty"`
	FilePatterns             []FilePattern  `json:"file_patterns,omitempty"`
}

// VersionRange matches a package version using parsed semantic version rules.
type VersionRange struct {
	Package string `json:"package,omitempty"`
	Range   string `json:"range"`
}

// FilePattern matches bounded file contents with a regular expression.
type FilePattern struct {
	ID           string   `json:"id,omitempty"`
	Pattern      string   `json:"pattern"`
	PathPatterns []string `json:"path_patterns,omitempty"`
	FileTypes    []string `json:"file_types,omitempty"`
	MaxBytes     int64    `json:"max_bytes,omitempty"`
}

// AllowlistEntry suppresses an exact matching finding until it expires.
type AllowlistEntry struct {
	ID        string     `json:"id"`
	Reason    string     `json:"reason"`
	Owner     string     `json:"owner"`
	ExpiresAt string     `json:"expires_at"`
	Scope     MatchScope `json:"scope"`
}

// BlocklistEntry creates a high-confidence blocking finding when it matches.
type BlocklistEntry struct {
	ID           string     `json:"id"`
	Reason       string     `json:"reason,omitempty"`
	Severity     Severity   `json:"severity,omitempty"`
	Confidence   Confidence `json:"confidence,omitempty"`
	Package      string     `json:"package,omitempty"`
	VersionRange string     `json:"version_range,omitempty"`
	PURL         string     `json:"purl,omitempty"`
	Hash         string     `json:"hash,omitempty"`
	Maintainer   string     `json:"maintainer,omitempty"`
	URL          string     `json:"url,omitempty"`
	Path         string     `json:"path,omitempty"`
	PathPattern  string     `json:"path_pattern,omitempty"`
}

// MatchScope defines the exact scope required for allowlist suppression.
type MatchScope struct {
	FindingID  string `json:"finding_id,omitempty"`
	RuleID     string `json:"rule_id,omitempty"`
	Package    string `json:"package,omitempty"`
	Version    string `json:"version,omitempty"`
	PURL       string `json:"purl,omitempty"`
	Path       string `json:"path,omitempty"`
	Hash       string `json:"hash,omitempty"`
	Maintainer string `json:"maintainer,omitempty"`
	URL        string `json:"url,omitempty"`
	ScriptName string `json:"script_name,omitempty"`
}

// TestExpectations defines optional rules test pass/fail assertions.
type TestExpectations struct {
	ExpectedFindings *int `json:"expected_findings,omitempty"`
}

// File is the file metadata visible to the rule engine.
type File struct {
	Path         string
	SHA256       string
	Type         string
	PackageOwner string
	Size         int64
}

// EvaluateOptions configures one rule engine evaluation pass.
type EvaluateOptions struct {
	Root        string
	Files       []File
	Node        node.Inventory
	Policies    []Policy
	MaxFileSize int64
	Now         time.Time
}

// EvaluateResult contains local policy findings and non-fatal rule warnings.
type EvaluateResult struct {
	Findings []Finding
	Warnings []Warning
}

// Warning reports a non-fatal policy evaluation issue.
type Warning struct {
	Path    string `json:"path,omitempty"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Finding is one local policy finding emitted in scan JSON.
type Finding struct {
	SchemaVersion  string       `json:"schema_version"`
	ID             string       `json:"id"`
	Severity       Severity     `json:"severity"`
	Confidence     Confidence   `json:"confidence"`
	Source         string       `json:"source"`
	RuleID         string       `json:"rule_id"`
	RuleType       string       `json:"rule_type"`
	Summary        string       `json:"summary"`
	Evidence       []Evidence   `json:"evidence"`
	Path           string       `json:"path,omitempty"`
	FileHash       string       `json:"file_hash,omitempty"`
	PackageOwner   string       `json:"package_owner,omitempty"`
	PackageName    string       `json:"package_name,omitempty"`
	PackageVersion string       `json:"package_version,omitempty"`
	PURL           string       `json:"purl,omitempty"`
	RegistryURL    string       `json:"registry_url,omitempty"`
	Maintainer     string       `json:"maintainer,omitempty"`
	ScriptName     string       `json:"script_name,omitempty"`
	Location       *Location    `json:"location,omitempty"`
	Suppressed     bool         `json:"suppressed"`
	Suppression    *Suppression `json:"suppression,omitempty"`
	Blocking       bool         `json:"blocking"`
}

// Evidence describes the matched fact behind a finding.
type Evidence struct {
	Kind           string `json:"kind"`
	Value          string `json:"value,omitempty"`
	Pattern        string `json:"pattern,omitempty"`
	Path           string `json:"path,omitempty"`
	FileHash       string `json:"file_hash,omitempty"`
	PackageName    string `json:"package_name,omitempty"`
	PackageVersion string `json:"package_version,omitempty"`
	PURL           string `json:"purl,omitempty"`
	RegistryURL    string `json:"registry_url,omitempty"`
	Maintainer     string `json:"maintainer,omitempty"`
	ScriptName     string `json:"script_name,omitempty"`
	Command        string `json:"command,omitempty"`
}

// Location identifies the best available exact location for a finding.
type Location struct {
	Path       string `json:"path,omitempty"`
	ScriptName string `json:"script_name,omitempty"`
}

// Suppression records the allowlist entry that suppressed a finding.
type Suppression struct {
	AllowlistID string `json:"allowlist_id"`
	Reason      string `json:"reason"`
	Owner       string `json:"owner"`
	ExpiresAt   string `json:"expires_at"`
}

// TestResult is the machine-readable output for malox rules test.
type TestResult struct {
	SchemaVersion    string    `json:"schema_version"`
	RuleFile         string    `json:"rule_file"`
	Fixture          string    `json:"fixture"`
	Valid            bool      `json:"valid"`
	Passed           bool      `json:"passed"`
	MatchCount       int       `json:"match_count"`
	ExpectedFindings *int      `json:"expected_findings,omitempty"`
	Findings         []Finding `json:"findings"`
	Warnings         []Warning `json:"warnings,omitempty"`
	Errors           []string  `json:"errors,omitempty"`
}
