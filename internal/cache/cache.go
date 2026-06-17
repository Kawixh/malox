// Package cache persists project-local Malox scan state.
package cache

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"malox/internal/node"
	"malox/internal/scan"
)

const fileIndexSchemaVersion = "malox.files.index.v1"

var (
	// ErrSnapshotNotFound reports that a requested scan ID does not exist.
	ErrSnapshotNotFound = errors.New("snapshot not found")
	// ErrInsufficientSnapshots reports that there are not enough scans to diff.
	ErrInsufficientSnapshots = errors.New("not enough snapshots")
)

// Store reads and writes one project's local Malox state directory.
type Store struct {
	dir string
}

// SnapshotInfo identifies one persisted scan snapshot.
type SnapshotInfo struct {
	ID   string
	Path string
}

// NewStore returns a project state store rooted at stateDir.
func NewStore(stateDir string) (Store, error) {
	if strings.TrimSpace(stateDir) == "" {
		return Store{}, errors.New("state dir is required")
	}
	absolute, err := filepath.Abs(stateDir)
	if err != nil {
		return Store{}, fmt.Errorf("resolve state dir: %w", err)
	}
	return Store{dir: filepath.Clean(absolute)}, nil
}

// Dir returns the store root directory.
func (s Store) Dir() string {
	return s.dir
}

// LoadLatest reads latest.json when it exists.
func (s Store) LoadLatest(ctx context.Context) (scan.Snapshot, bool, error) {
	if err := ctx.Err(); err != nil {
		return scan.Snapshot{}, false, fmt.Errorf("load latest snapshot: %w", err)
	}
	snapshot, err := readSnapshotFile(filepath.Join(s.dir, "latest.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return scan.Snapshot{}, false, nil
		}
		return scan.Snapshot{}, false, err
	}
	return snapshot, true, nil
}

// WriteSnapshot persists snapshot under scans, indexes, and latest.json.
func (s Store) WriteSnapshot(ctx context.Context, snapshot scan.Snapshot) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("write snapshot: %w", err)
	}
	if strings.TrimSpace(snapshot.ScanID) == "" {
		return errors.New("snapshot scan id is required")
	}

	data, err := marshalSnapshot(snapshot)
	if err != nil {
		return err
	}

	scanPath, err := s.snapshotPath(snapshot.ScanID)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(ctx, scanPath, data, 0o644); err != nil {
		return fmt.Errorf("write scan snapshot: %w", err)
	}

	verified, err := s.LoadSnapshot(ctx, snapshot.ScanID)
	if err != nil {
		return fmt.Errorf("verify scan snapshot: %w", err)
	}
	if verified.ScanID != snapshot.ScanID {
		return fmt.Errorf("verify scan snapshot: got scan id %q, want %q", verified.ScanID, snapshot.ScanID)
	}

	indexData, err := marshalFileIndex(snapshot)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(ctx, filepath.Join(s.dir, "indexes", "files.jsonl"), indexData, 0o644); err != nil {
		return fmt.Errorf("write file index: %w", err)
	}
	if err := writeFileAtomic(ctx, filepath.Join(s.dir, "latest.json"), data, 0o644); err != nil {
		return fmt.Errorf("write latest snapshot: %w", err)
	}
	return nil
}

// LoadSnapshot reads a snapshot by scan ID.
func (s Store) LoadSnapshot(ctx context.Context, id string) (scan.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return scan.Snapshot{}, fmt.Errorf("load snapshot: %w", err)
	}
	path, err := s.snapshotPath(id)
	if err != nil {
		return scan.Snapshot{}, err
	}
	snapshot, err := readSnapshotFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return scan.Snapshot{}, fmt.Errorf("%w: %s", ErrSnapshotNotFound, id)
		}
		return scan.Snapshot{}, err
	}
	return snapshot, nil
}

// ListSnapshots returns persisted snapshots sorted from oldest to newest.
func (s Store) ListSnapshots(ctx context.Context) ([]SnapshotInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("list snapshots: %w", err)
	}
	dir := filepath.Join(s.dir, "scans")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read scans dir: %w", err)
	}

	snapshots := make([]SnapshotInfo, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		snapshots = append(snapshots, SnapshotInfo{
			ID:   id,
			Path: filepath.Join(dir, entry.Name()),
		})
	}
	slices.SortFunc(snapshots, func(a, b SnapshotInfo) int {
		return cmp.Compare(a.ID, b.ID)
	})
	return snapshots, nil
}

// RecentPair returns the two newest persisted snapshots.
func (s Store) RecentPair(ctx context.Context) (SnapshotInfo, SnapshotInfo, error) {
	snapshots, err := s.ListSnapshots(ctx)
	if err != nil {
		return SnapshotInfo{}, SnapshotInfo{}, err
	}
	if len(snapshots) < 2 {
		return SnapshotInfo{}, SnapshotInfo{}, ErrInsufficientSnapshots
	}
	return snapshots[len(snapshots)-2], snapshots[len(snapshots)-1], nil
}

func (s Store) snapshotPath(id string) (string, error) {
	id = strings.TrimSuffix(id, ".json")
	if strings.TrimSpace(id) == "" {
		return "", errors.New("scan id is required")
	}
	if filepath.Base(id) != id || !filepath.IsLocal(id) {
		return "", fmt.Errorf("unsafe scan id %q", id)
	}
	return filepath.Join(s.dir, "scans", id+".json"), nil
}

func writeFileAtomic(ctx context.Context, path string, data []byte, perm os.FileMode) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create parent dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace file: %w", err)
	}
	removeTemp = false
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("sync parent dir: %w", err)
	}
	return nil
}

func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()
	return f.Sync()
}

func readSnapshotFile(path string) (scan.Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return scan.Snapshot{}, err
	}
	var doc snapshotDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return scan.Snapshot{}, fmt.Errorf("parse snapshot %q: %w", path, err)
	}
	snapshot, err := doc.toSnapshot()
	if err != nil {
		return scan.Snapshot{}, fmt.Errorf("parse snapshot %q: %w", path, err)
	}
	return snapshot, nil
}

func marshalSnapshot(snapshot scan.Snapshot) ([]byte, error) {
	data, err := json.MarshalIndent(newSnapshotDocument(snapshot), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal snapshot: %w", err)
	}
	return append(data, '\n'), nil
}

func marshalFileIndex(snapshot scan.Snapshot) ([]byte, error) {
	files := slices.Clone(snapshot.Files)
	slices.SortFunc(files, func(a, b scan.File) int {
		return cmp.Compare(a.Path, b.Path)
	})

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	for _, file := range files {
		record := fileIndexRecord{
			SchemaVersion: fileIndexSchemaVersion,
			ScanID:        snapshot.ScanID,
			Path:          file.Path,
			Size:          file.Size,
			ModifiedTime:  formatTime(file.ModifiedTime),
			Mode:          file.Mode,
			Permissions:   file.Permissions,
			SHA256:        file.SHA256,
			Status:        string(file.Status),
			State:         string(file.State),
			PackageOwner:  file.PackageOwner,
		}
		if err := encoder.Encode(record); err != nil {
			return nil, fmt.Errorf("marshal file index: %w", err)
		}
	}
	return buf.Bytes(), nil
}

type snapshotDocument struct {
	SchemaVersion      string                 `json:"schema_version"`
	ScannerVersion     string                 `json:"scanner_version"`
	ScanID             string                 `json:"scan_id"`
	ProjectID          string                 `json:"project_id"`
	ProjectRoot        string                 `json:"project_root"`
	StartedAt          string                 `json:"started_at"`
	FinishedAt         string                 `json:"finished_at"`
	PackageManagers    []packageManagerSignal `json:"package_manager_signals,omitempty"`
	Node               node.Inventory         `json:"node_inventory,omitempty"`
	Files              []fileDocument         `json:"files"`
	SkippedFiles       []skippedFileDocument  `json:"skipped_files,omitempty"`
	SkippedDirectories []skippedDirDocument   `json:"skipped_directories,omitempty"`
	Errors             []issueDocument        `json:"errors,omitempty"`
	Summary            summaryDocument        `json:"summary"`
}

type packageManagerSignal struct {
	Manager string `json:"manager"`
	Kind    string `json:"kind"`
	Path    string `json:"path"`
}

type fileDocument struct {
	Path          string              `json:"path"`
	Size          int64               `json:"size"`
	ModifiedTime  string              `json:"modified_time"`
	Mode          string              `json:"mode"`
	Permissions   string              `json:"permissions"`
	Symlink       bool                `json:"symlink"`
	SymlinkTarget string              `json:"symlink_target,omitempty"`
	SHA256        string              `json:"sha256,omitempty"`
	Type          string              `json:"type"`
	Status        string              `json:"status"`
	State         string              `json:"state"`
	SkipReason    *skipReasonDocument `json:"skip_reason,omitempty"`
	PackageOwner  string              `json:"package_owner,omitempty"`
}

type skipReasonDocument struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	LimitBytes  int64  `json:"limit_bytes,omitempty"`
	ActualBytes int64  `json:"actual_bytes,omitempty"`
}

type skippedFileDocument struct {
	Path   string             `json:"path"`
	Reason skipReasonDocument `json:"reason"`
}

type skippedDirDocument struct {
	Path   string             `json:"path"`
	Reason skipReasonDocument `json:"reason"`
}

type issueDocument struct {
	Path    string `json:"path"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type summaryDocument struct {
	TotalFiles          int `json:"total_files"`
	ScannedFiles        int `json:"scanned_files"`
	SkippedFiles        int `json:"skipped_files"`
	ErroredFiles        int `json:"errored_files"`
	SkippedDirectories  int `json:"skipped_directories"`
	PackageManagers     int `json:"package_managers"`
	NodeModulesFiles    int `json:"node_modules_files"`
	NodeModulesPackages int `json:"node_modules_packages"`
}

type fileIndexRecord struct {
	SchemaVersion string `json:"schema_version"`
	ScanID        string `json:"scan_id"`
	Path          string `json:"path"`
	Size          int64  `json:"size"`
	ModifiedTime  string `json:"modified_time"`
	Mode          string `json:"mode"`
	Permissions   string `json:"permissions"`
	SHA256        string `json:"sha256,omitempty"`
	Status        string `json:"status"`
	State         string `json:"state"`
	PackageOwner  string `json:"package_owner,omitempty"`
}

func newSnapshotDocument(snapshot scan.Snapshot) snapshotDocument {
	return snapshotDocument{
		SchemaVersion:      snapshot.SchemaVersion,
		ScannerVersion:     snapshot.ScannerVersion,
		ScanID:             snapshot.ScanID,
		ProjectID:          snapshot.ProjectID,
		ProjectRoot:        snapshot.ProjectRoot,
		StartedAt:          formatTime(snapshot.StartedAt),
		FinishedAt:         formatTime(snapshot.FinishedAt),
		PackageManagers:    newPackageManagerSignals(snapshot.PackageManagers),
		Node:               snapshot.Node,
		Files:              newFileDocuments(snapshot.Files),
		SkippedFiles:       newSkippedFileDocuments(snapshot.SkippedFiles),
		SkippedDirectories: newSkippedDirDocuments(snapshot.SkippedDirectories),
		Errors:             newIssueDocuments(snapshot.Errors),
		Summary: summaryDocument{
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

func newPackageManagerSignals(signals []scan.PackageManagerSignal) []packageManagerSignal {
	if len(signals) == 0 {
		return nil
	}
	out := make([]packageManagerSignal, 0, len(signals))
	for _, signal := range signals {
		out = append(out, packageManagerSignal{
			Manager: signal.Manager,
			Kind:    signal.Kind,
			Path:    signal.Path,
		})
	}
	return out
}

func newFileDocuments(files []scan.File) []fileDocument {
	out := make([]fileDocument, 0, len(files))
	for _, file := range files {
		out = append(out, fileDocument{
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
			SkipReason:    newSkipReasonDocument(file.SkipReason),
			PackageOwner:  file.PackageOwner,
		})
	}
	return out
}

func newSkipReasonDocument(reason *scan.SkipReason) *skipReasonDocument {
	if reason == nil {
		return nil
	}
	doc := newSkipReasonValue(*reason)
	return &doc
}

func newSkipReasonValue(reason scan.SkipReason) skipReasonDocument {
	return skipReasonDocument{
		Code:        reason.Code,
		Message:     reason.Message,
		LimitBytes:  reason.LimitBytes,
		ActualBytes: reason.ActualBytes,
	}
}

func newSkippedFileDocuments(skipped []scan.SkippedFile) []skippedFileDocument {
	if len(skipped) == 0 {
		return nil
	}
	out := make([]skippedFileDocument, 0, len(skipped))
	for _, item := range skipped {
		out = append(out, skippedFileDocument{
			Path:   item.Path,
			Reason: newSkipReasonValue(item.Reason),
		})
	}
	return out
}

func newSkippedDirDocuments(skipped []scan.SkippedDirectory) []skippedDirDocument {
	if len(skipped) == 0 {
		return nil
	}
	out := make([]skippedDirDocument, 0, len(skipped))
	for _, item := range skipped {
		out = append(out, skippedDirDocument{
			Path:   item.Path,
			Reason: newSkipReasonValue(item.Reason),
		})
	}
	return out
}

func newIssueDocuments(issues []scan.Issue) []issueDocument {
	if len(issues) == 0 {
		return nil
	}
	out := make([]issueDocument, 0, len(issues))
	for _, issue := range issues {
		out = append(out, issueDocument{
			Path:    issue.Path,
			Code:    issue.Code,
			Message: issue.Message,
		})
	}
	return out
}

func (d snapshotDocument) toSnapshot() (scan.Snapshot, error) {
	startedAt, err := parseTime(d.StartedAt)
	if err != nil {
		return scan.Snapshot{}, fmt.Errorf("parse started_at: %w", err)
	}
	finishedAt, err := parseTime(d.FinishedAt)
	if err != nil {
		return scan.Snapshot{}, fmt.Errorf("parse finished_at: %w", err)
	}
	files, err := d.scanFiles()
	if err != nil {
		return scan.Snapshot{}, err
	}

	return scan.Snapshot{
		SchemaVersion:      d.SchemaVersion,
		ScannerVersion:     d.ScannerVersion,
		ScanID:             d.ScanID,
		ProjectID:          d.ProjectID,
		ProjectRoot:        d.ProjectRoot,
		StartedAt:          startedAt,
		FinishedAt:         finishedAt,
		PackageManagers:    d.scanSignals(),
		Node:               d.Node,
		Files:              files,
		SkippedFiles:       d.scanSkippedFiles(),
		SkippedDirectories: d.scanSkippedDirectories(),
		Errors:             d.scanIssues(),
		Summary: scan.Summary{
			TotalFiles:          d.Summary.TotalFiles,
			ScannedFiles:        d.Summary.ScannedFiles,
			SkippedFiles:        d.Summary.SkippedFiles,
			ErroredFiles:        d.Summary.ErroredFiles,
			SkippedDirectories:  d.Summary.SkippedDirectories,
			PackageManagers:     d.Summary.PackageManagers,
			NodeModulesFiles:    d.Summary.NodeModulesFiles,
			NodeModulesPackages: d.Summary.NodeModulesPackages,
		},
	}, nil
}

func (d snapshotDocument) scanSignals() []scan.PackageManagerSignal {
	if len(d.PackageManagers) == 0 {
		return nil
	}
	out := make([]scan.PackageManagerSignal, 0, len(d.PackageManagers))
	for _, signal := range d.PackageManagers {
		out = append(out, scan.PackageManagerSignal{
			Manager: signal.Manager,
			Kind:    signal.Kind,
			Path:    signal.Path,
		})
	}
	return out
}

func (d snapshotDocument) scanFiles() ([]scan.File, error) {
	out := make([]scan.File, 0, len(d.Files))
	for _, file := range d.Files {
		modifiedTime, err := parseTime(file.ModifiedTime)
		if err != nil {
			return nil, fmt.Errorf("parse modified_time for %q: %w", file.Path, err)
		}
		out = append(out, scan.File{
			Path:          file.Path,
			Size:          file.Size,
			ModifiedTime:  modifiedTime,
			Mode:          file.Mode,
			Permissions:   file.Permissions,
			Symlink:       file.Symlink,
			SymlinkTarget: file.SymlinkTarget,
			SHA256:        file.SHA256,
			Type:          file.Type,
			Status:        scan.Status(file.Status),
			State:         scan.FileState(file.State),
			SkipReason:    file.scanSkipReason(),
			PackageOwner:  file.PackageOwner,
		})
	}
	return out, nil
}

func (d snapshotDocument) scanSkippedFiles() []scan.SkippedFile {
	if len(d.SkippedFiles) == 0 {
		return nil
	}
	out := make([]scan.SkippedFile, 0, len(d.SkippedFiles))
	for _, item := range d.SkippedFiles {
		out = append(out, scan.SkippedFile{
			Path:   item.Path,
			Reason: item.Reason.scanReason(),
		})
	}
	return out
}

func (d snapshotDocument) scanSkippedDirectories() []scan.SkippedDirectory {
	if len(d.SkippedDirectories) == 0 {
		return nil
	}
	out := make([]scan.SkippedDirectory, 0, len(d.SkippedDirectories))
	for _, item := range d.SkippedDirectories {
		out = append(out, scan.SkippedDirectory{
			Path:   item.Path,
			Reason: item.Reason.scanReason(),
		})
	}
	return out
}

func (d snapshotDocument) scanIssues() []scan.Issue {
	if len(d.Errors) == 0 {
		return nil
	}
	out := make([]scan.Issue, 0, len(d.Errors))
	for _, issue := range d.Errors {
		out = append(out, scan.Issue{
			Path:    issue.Path,
			Code:    issue.Code,
			Message: issue.Message,
		})
	}
	return out
}

func (d fileDocument) scanSkipReason() *scan.SkipReason {
	if d.SkipReason == nil {
		return nil
	}
	reason := d.SkipReason.scanReason()
	return &reason
}

func (d skipReasonDocument) scanReason() scan.SkipReason {
	return scan.SkipReason{
		Code:        d.Code,
		Message:     d.Message,
		LimitBytes:  d.LimitBytes,
		ActualBytes: d.ActualBytes,
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, value)
}
