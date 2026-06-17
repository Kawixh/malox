package report

import (
	"encoding/json"
	"fmt"
	"io"

	"malox/internal/diff"
)

// DiffReport is the public JSON contract for snapshot diffs.
type DiffReport struct {
	SchemaVersion         string          `json:"schema_version"`
	FromScanID            string          `json:"from_scan_id"`
	ToScanID              string          `json:"to_scan_id"`
	AddedFiles            []FileChange    `json:"added_files"`
	RemovedFiles          []FileChange    `json:"removed_files"`
	ModifiedFiles         []FileChange    `json:"modified_files"`
	UnchangedFiles        []FileChange    `json:"unchanged_files"`
	SkippedFiles          []FileChange    `json:"skipped_files"`
	NewFindings           []FindingChange `json:"new_findings"`
	ResolvedFindings      []FindingChange `json:"resolved_findings"`
	StillExistingFindings []FindingChange `json:"still_existing_findings"`
}

// FileChange is one file state transition in diff JSON output.
type FileChange struct {
	Path         string `json:"path"`
	State        string `json:"state"`
	FromStatus   string `json:"from_status,omitempty"`
	ToStatus     string `json:"to_status,omitempty"`
	FromSHA256   string `json:"from_sha256,omitempty"`
	ToSHA256     string `json:"to_sha256,omitempty"`
	FromSize     int64  `json:"from_size,omitempty"`
	ToSize       int64  `json:"to_size,omitempty"`
	PackageOwner string `json:"package_owner,omitempty"`
}

// FindingChange is reserved for later rule and threat milestones.
type FindingChange struct {
	ID string `json:"id,omitempty"`
}

// WriteDiff writes a snapshot diff in the requested output format.
func WriteDiff(w io.Writer, report diff.Report, format Format) error {
	switch format {
	case FormatJSON:
		return writeDiffJSON(w, report)
	case FormatTable:
		return writeDiffTable(w, report)
	case FormatPlain:
		return writeDiffPlain(w, report)
	default:
		return fmt.Errorf("unsupported diff output format %q", format)
	}
}

// NewDiffReport converts an internal diff report into the public JSON model.
func NewDiffReport(report diff.Report) DiffReport {
	return DiffReport{
		SchemaVersion:         report.SchemaVersion,
		FromScanID:            report.FromScanID,
		ToScanID:              report.ToScanID,
		AddedFiles:            diffFiles(report.AddedFiles),
		RemovedFiles:          diffFiles(report.RemovedFiles),
		ModifiedFiles:         diffFiles(report.ModifiedFiles),
		UnchangedFiles:        diffFiles(report.UnchangedFiles),
		SkippedFiles:          diffFiles(report.SkippedFiles),
		NewFindings:           diffFindings(report.NewFindings),
		ResolvedFindings:      diffFindings(report.ResolvedFindings),
		StillExistingFindings: diffFindings(report.StillExistingFindings),
	}
}

func writeDiffJSON(w io.Writer, report diff.Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(NewDiffReport(report))
}

func writeDiffTable(w io.Writer, report diff.Report) error {
	_, err := fmt.Fprintf(
		w,
		"Snapshot diff\nFrom: %s\nTo: %s\nFiles: %d added, %d removed, %d modified, %d unchanged, %d skipped\nFindings: %d new, %d resolved, %d still existing\n",
		report.FromScanID,
		report.ToScanID,
		len(report.AddedFiles),
		len(report.RemovedFiles),
		len(report.ModifiedFiles),
		len(report.UnchangedFiles),
		len(report.SkippedFiles),
		len(report.NewFindings),
		len(report.ResolvedFindings),
		len(report.StillExistingFindings),
	)
	return err
}

func writeDiffPlain(w io.Writer, report diff.Report) error {
	_, err := fmt.Fprintf(
		w,
		"added=%d removed=%d modified=%d unchanged=%d skipped=%d new_findings=%d resolved_findings=%d still_existing_findings=%d\n",
		len(report.AddedFiles),
		len(report.RemovedFiles),
		len(report.ModifiedFiles),
		len(report.UnchangedFiles),
		len(report.SkippedFiles),
		len(report.NewFindings),
		len(report.ResolvedFindings),
		len(report.StillExistingFindings),
	)
	return err
}

func diffFiles(changes []diff.FileChange) []FileChange {
	out := make([]FileChange, 0, len(changes))
	for _, change := range changes {
		out = append(out, FileChange{
			Path:         change.Path,
			State:        string(change.State),
			FromStatus:   string(change.FromStatus),
			ToStatus:     string(change.ToStatus),
			FromSHA256:   change.FromSHA256,
			ToSHA256:     change.ToSHA256,
			FromSize:     change.FromSize,
			ToSize:       change.ToSize,
			PackageOwner: change.PackageOwner,
		})
	}
	return out
}

func diffFindings(changes []diff.FindingChange) []FindingChange {
	out := make([]FindingChange, 0, len(changes))
	for _, change := range changes {
		out = append(out, FindingChange{ID: change.ID})
	}
	return out
}
