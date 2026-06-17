package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"malox/internal/node"
	"malox/internal/scan"
)

// ScanSnapshot is the public JSON contract for baseline scan snapshots.
type ScanSnapshot struct {
	SchemaVersion      string                 `json:"schema_version"`
	ScannerVersion     string                 `json:"scanner_version"`
	ScanID             string                 `json:"scan_id"`
	ProjectID          string                 `json:"project_id"`
	ProjectRoot        string                 `json:"project_root"`
	StartedAt          string                 `json:"started_at"`
	FinishedAt         string                 `json:"finished_at"`
	PackageManagers    []PackageManagerSignal `json:"package_manager_signals"`
	NodeInventory      node.Inventory         `json:"node_inventory"`
	Files              []FileRecord           `json:"files"`
	SkippedFiles       []SkippedFile          `json:"skipped_files,omitempty"`
	SkippedDirectories []SkippedDirectory     `json:"skipped_directories,omitempty"`
	Errors             []Issue                `json:"errors,omitempty"`
	Summary            ScanSummary            `json:"summary"`
}

// PackageManagerSignal is a package manager clue in scan JSON output.
type PackageManagerSignal struct {
	Manager string `json:"manager"`
	Kind    string `json:"kind"`
	Path    string `json:"path"`
}

// FileRecord is one file entry in scan JSON output.
type FileRecord struct {
	Path          string      `json:"path"`
	Size          int64       `json:"size"`
	ModifiedTime  string      `json:"modified_time"`
	Mode          string      `json:"mode"`
	Permissions   string      `json:"permissions"`
	Symlink       bool        `json:"symlink"`
	SymlinkTarget string      `json:"symlink_target,omitempty"`
	SHA256        string      `json:"sha256,omitempty"`
	Type          string      `json:"type"`
	Status        string      `json:"status"`
	State         string      `json:"state"`
	SkipReason    *SkipReason `json:"skip_reason,omitempty"`
	PackageOwner  string      `json:"package_owner,omitempty"`
}

// SkipReason describes why a path was skipped in scan JSON output.
type SkipReason struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	LimitBytes  int64  `json:"limit_bytes,omitempty"`
	ActualBytes int64  `json:"actual_bytes,omitempty"`
}

// SkippedFile is an intentionally skipped file in scan JSON output.
type SkippedFile struct {
	Path   string     `json:"path"`
	Reason SkipReason `json:"reason"`
}

// SkippedDirectory is an intentionally skipped directory in scan JSON output.
type SkippedDirectory struct {
	Path   string     `json:"path"`
	Reason SkipReason `json:"reason"`
}

// Issue is a partial scan error in scan JSON output.
type Issue struct {
	Path    string `json:"path"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ScanSummary contains aggregate scan counts in scan JSON output.
type ScanSummary struct {
	TotalFiles          int `json:"total_files"`
	ScannedFiles        int `json:"scanned_files"`
	SkippedFiles        int `json:"skipped_files"`
	ErroredFiles        int `json:"errored_files"`
	SkippedDirectories  int `json:"skipped_directories"`
	PackageManagers     int `json:"package_managers"`
	NodeModulesFiles    int `json:"node_modules_files"`
	NodeModulesPackages int `json:"node_modules_packages"`
}

// WriteScan writes a scan snapshot in the requested output format.
func WriteScan(w io.Writer, snapshot scan.Snapshot, format Format) error {
	switch format {
	case FormatJSON:
		return writeScanJSON(w, snapshot)
	case FormatTable:
		return writeScanTable(w, snapshot)
	case FormatPlain:
		return writeScanPlain(w, snapshot)
	default:
		return fmt.Errorf("unsupported scan output format %q", format)
	}
}

func writeScanJSON(w io.Writer, snapshot scan.Snapshot) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(NewScanSnapshot(snapshot))
}

func writeScanTable(w io.Writer, snapshot scan.Snapshot) error {
	signals := signalSummary(snapshot.PackageManagers)
	if signals == "" {
		signals = "none"
	}
	if _, err := fmt.Fprintf(
		w,
		"Scan snapshot\nProject: %s\nProject ID: %s\nFiles: %d scanned, %d skipped, %d errors\nSkipped directories: %d\nPackage managers: %s\nNode inventory: %d dependencies, %d lockfiles, %d package scripts, %d warnings\nnode_modules: %d files across %d packages\n",
		snapshot.ProjectRoot,
		snapshot.ProjectID,
		snapshot.Summary.ScannedFiles,
		snapshot.Summary.SkippedFiles,
		snapshot.Summary.ErroredFiles,
		snapshot.Summary.SkippedDirectories,
		signals,
		snapshot.Node.Summary.DependencyCount,
		snapshot.Node.Summary.LockfileCount,
		snapshot.Node.Summary.PackageScripts,
		snapshot.Node.Summary.Warnings,
		snapshot.Summary.NodeModulesFiles,
		snapshot.Summary.NodeModulesPackages,
	); err != nil {
		return err
	}

	if len(snapshot.Node.Warnings) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, "Node warnings:"); err != nil {
		return err
	}
	for _, warning := range snapshot.Node.Warnings {
		if _, err := fmt.Fprintf(w, "  - %s: %s (%s)\n", warning.Path, warning.Message, warning.Code); err != nil {
			return err
		}
	}
	return nil
}

func writeScanPlain(w io.Writer, snapshot scan.Snapshot) error {
	_, err := fmt.Fprintf(
		w,
		"scanned=%d skipped=%d errors=%d skipped_directories=%d package_managers=%d node_dependencies=%d node_lockfiles=%d node_package_scripts=%d node_warnings=%d node_modules_files=%d\n",
		snapshot.Summary.ScannedFiles,
		snapshot.Summary.SkippedFiles,
		snapshot.Summary.ErroredFiles,
		snapshot.Summary.SkippedDirectories,
		snapshot.Summary.PackageManagers,
		snapshot.Node.Summary.DependencyCount,
		snapshot.Node.Summary.LockfileCount,
		snapshot.Node.Summary.PackageScripts,
		snapshot.Node.Summary.Warnings,
		snapshot.Summary.NodeModulesFiles,
	)
	return err
}

// NewScanSnapshot converts an internal scan snapshot into the public JSON model.
func NewScanSnapshot(snapshot scan.Snapshot) ScanSnapshot {
	return ScanSnapshot{
		SchemaVersion:      snapshot.SchemaVersion,
		ScannerVersion:     snapshot.ScannerVersion,
		ScanID:             snapshot.ScanID,
		ProjectID:          snapshot.ProjectID,
		ProjectRoot:        snapshot.ProjectRoot,
		StartedAt:          formatTime(snapshot.StartedAt),
		FinishedAt:         formatTime(snapshot.FinishedAt),
		PackageManagers:    scanSignals(snapshot.PackageManagers),
		NodeInventory:      snapshot.Node,
		Files:              scanFiles(snapshot.Files),
		SkippedFiles:       scanSkippedFiles(snapshot.SkippedFiles),
		SkippedDirectories: scanSkippedDirectories(snapshot.SkippedDirectories),
		Errors:             scanIssues(snapshot.Errors),
		Summary: ScanSummary{
			TotalFiles:          snapshot.Summary.TotalFiles,
			ScannedFiles:        snapshot.Summary.ScannedFiles,
			SkippedFiles:        snapshot.Summary.SkippedFiles,
			ErroredFiles:        snapshot.Summary.ErroredFiles,
			SkippedDirectories:  snapshot.Summary.SkippedDirectories,
			PackageManagers:     snapshot.Summary.PackageManagers,
			NodeModulesFiles:    snapshot.Summary.NodeModulesFiles,
			NodeModulesPackages: snapshot.Summary.NodeModulesPackages,
		},
	}
}

func scanSignals(signals []scan.PackageManagerSignal) []PackageManagerSignal {
	if len(signals) == 0 {
		return nil
	}
	out := make([]PackageManagerSignal, 0, len(signals))
	for _, signal := range signals {
		out = append(out, PackageManagerSignal{
			Manager: signal.Manager,
			Kind:    signal.Kind,
			Path:    signal.Path,
		})
	}
	return out
}

func scanFiles(files []scan.File) []FileRecord {
	out := make([]FileRecord, 0, len(files))
	for _, file := range files {
		out = append(out, FileRecord{
			Path:          file.Path,
			Size:          file.Size,
			ModifiedTime:  formatTime(file.ModifiedTime),
			Mode:          file.Mode,
			Permissions:   file.Permissions,
			Symlink:       file.Symlink,
			SymlinkTarget: file.SymlinkTarget,
			SHA256:        file.SHA256,
			Type:          file.Type,
			Status:        string(file.Status),
			State:         string(file.State),
			SkipReason:    scanSkipReason(file.SkipReason),
			PackageOwner:  file.PackageOwner,
		})
	}
	return out
}

func scanSkippedFiles(skipped []scan.SkippedFile) []SkippedFile {
	if len(skipped) == 0 {
		return nil
	}
	out := make([]SkippedFile, 0, len(skipped))
	for _, item := range skipped {
		out = append(out, SkippedFile{
			Path:   item.Path,
			Reason: scanReason(item.Reason),
		})
	}
	return out
}

func scanSkippedDirectories(skipped []scan.SkippedDirectory) []SkippedDirectory {
	if len(skipped) == 0 {
		return nil
	}
	out := make([]SkippedDirectory, 0, len(skipped))
	for _, item := range skipped {
		out = append(out, SkippedDirectory{
			Path:   item.Path,
			Reason: scanReason(item.Reason),
		})
	}
	return out
}

func scanIssues(issues []scan.Issue) []Issue {
	if len(issues) == 0 {
		return nil
	}
	out := make([]Issue, 0, len(issues))
	for _, issue := range issues {
		out = append(out, Issue{
			Path:    issue.Path,
			Code:    issue.Code,
			Message: issue.Message,
		})
	}
	return out
}

func scanSkipReason(reason *scan.SkipReason) *SkipReason {
	if reason == nil {
		return nil
	}
	out := scanReason(*reason)
	return &out
}

func scanReason(reason scan.SkipReason) SkipReason {
	return SkipReason{
		Code:        reason.Code,
		Message:     reason.Message,
		LimitBytes:  reason.LimitBytes,
		ActualBytes: reason.ActualBytes,
	}
}

func signalSummary(signals []scan.PackageManagerSignal) string {
	if len(signals) == 0 {
		return ""
	}
	parts := make([]string, 0, len(signals))
	for _, signal := range signals {
		parts = append(parts, signal.Manager+" "+signal.Kind+" at "+signal.Path)
	}
	return strings.Join(parts, ", ")
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
