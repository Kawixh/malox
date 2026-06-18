// Package scan walks a project tree and builds deterministic scan snapshots.
package scan

import (
	"time"

	"malox/internal/node"
	"malox/internal/rules"
)

// SchemaVersion is the public scan snapshot schema emitted for milestone 2.
const SchemaVersion = "malox.scan.snapshot.v1"

// Options configures one baseline project scan.
type Options struct {
	Root           string
	StateDir       string
	ScannerVersion string
	MaxWorkers     int
	MaxFileSize    int64
	StrictHash     bool
	Previous       *Snapshot
	RulePolicies   []rules.Policy
	Now            func() time.Time
}

// Snapshot stores the normalized result of one completed project scan.
type Snapshot struct {
	SchemaVersion      string
	ScannerVersion     string
	ScanID             string
	ProjectID          string
	ProjectRoot        string
	StartedAt          time.Time
	FinishedAt         time.Time
	PackageManagers    []PackageManagerSignal
	Node               node.Inventory
	ThreatSources      []ThreatSourceStatus
	Findings           []rules.Finding
	Files              []File
	SkippedFiles       []SkippedFile
	SkippedDirectories []SkippedDirectory
	Errors             []Issue
	Summary            Summary
}

// PackageManagerSignal describes a package manager clue discovered from names.
type PackageManagerSignal = node.PackageManagerSignal

// ThreatSourceStatus summarizes one threat source consulted during a scan.
type ThreatSourceStatus struct {
	Source        string    `json:"source"`
	Status        string    `json:"status"`
	Mode          string    `json:"mode"`
	FetchedAt     time.Time `json:"fetched_at,omitempty"`
	CacheAge      string    `json:"cache_age,omitempty"`
	Records       int       `json:"records,omitempty"`
	Warning       string    `json:"warning,omitempty"`
	Required      bool      `json:"required,omitempty"`
	SchemaVersion string    `json:"schema_version,omitempty"`
}

// File describes one filesystem entry considered by the scanner.
type File struct {
	Path          string
	Size          int64
	ModifiedTime  time.Time
	Mode          string
	Permissions   string
	Symlink       bool
	SymlinkTarget string
	SHA256        string
	Type          string
	Status        Status
	State         FileState
	SkipReason    *SkipReason
	PackageOwner  string
}

// Status identifies how the scanner handled a file.
type Status string

const (
	// StatusScanned means the file was read and hashed.
	StatusScanned Status = "scanned"
	// StatusSkipped means the file was intentionally not read.
	StatusSkipped Status = "skipped"
	// StatusError means the scanner tried to read metadata or content and failed.
	StatusError Status = "error"
)

// FileState identifies how a file compares to a previous scan.
type FileState string

const (
	// FileStatePreviouslyUnscanned means no previous file identity was available.
	FileStatePreviouslyUnscanned FileState = "previously_unscanned"
	// FileStateAdded means the file did not exist in the previous snapshot.
	FileStateAdded FileState = "added"
	// FileStateRemoved means the file existed in a previous snapshot but not the current one.
	FileStateRemoved FileState = "removed"
	// FileStateModified means the file identity or hash changed since the previous snapshot.
	FileStateModified FileState = "modified"
	// FileStateUnchanged means the file identity and hash match the previous snapshot.
	FileStateUnchanged FileState = "unchanged"
	// FileStateSkipped means the scanner intentionally did not read file contents.
	FileStateSkipped FileState = "skipped"
)

// SkipReason describes why a path was skipped.
type SkipReason struct {
	Code        string
	Message     string
	LimitBytes  int64
	ActualBytes int64
}

// SkippedFile reports an intentionally skipped file.
type SkippedFile struct {
	Path   string
	Reason SkipReason
}

// SkippedDirectory reports an intentionally skipped directory subtree.
type SkippedDirectory struct {
	Path   string
	Reason SkipReason
}

// Issue describes a partial scan error that did not abort the whole scan.
type Issue struct {
	Path    string
	Code    string
	Message string
}

// Summary contains aggregate scan counts for human output and quick checks.
type Summary struct {
	TotalFiles          int
	ScannedFiles        int
	SkippedFiles        int
	ErroredFiles        int
	SkippedDirectories  int
	PackageManagers     int
	NodeModulesFiles    int
	NodeModulesPackages int
	Findings            int
	SuppressedFindings  int
	BlockingFindings    int
	WeakFindings        int
}
