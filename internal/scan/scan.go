package scan

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"malox/internal/fileid"
	"malox/internal/node"
	"malox/internal/node/jsanalysis"
	"malox/internal/rules"
)

type candidate struct {
	meta fileid.Metadata
}

type previousIndex struct {
	files       map[string]File
	hasSnapshot bool
}

type processResult struct {
	file    File
	skipped *SkippedFile
	issue   *Issue
}

// Project scans a project root and returns a deterministic baseline snapshot.
func Project(ctx context.Context, opts Options) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, fmt.Errorf("start scan: %w", err)
	}

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	if opts.ScannerVersion == "" {
		opts.ScannerVersion = "unknown"
	}
	if opts.MaxWorkers < 1 {
		opts.MaxWorkers = 1
	}
	if opts.MaxFileSize < 1 {
		return Snapshot{}, errors.New("max file size must be greater than 0")
	}

	root, err := fileid.NormalizeRoot(opts.Root)
	if err != nil {
		return Snapshot{}, fmt.Errorf("resolve project root: %w", err)
	}

	startedAt := now().UTC()
	stateRel := stateRelativePath(root, opts.StateDir)
	candidates, skippedDirs, walkIssues, signals, err := walkProject(ctx, root, stateRel)
	if err != nil {
		return Snapshot{}, err
	}

	previous := indexPrevious(opts.Previous)
	files, skippedFiles, processIssues, err := processCandidates(
		ctx,
		root,
		candidates,
		opts.MaxWorkers,
		opts.MaxFileSize,
		opts.StrictHash,
		previous,
	)
	if err != nil {
		return Snapshot{}, err
	}

	nodeInventory, err := node.Build(ctx, node.BuildOptions{
		Root:    root,
		Files:   nodeFileRefs(files),
		Signals: signals,
	})
	if err != nil {
		return Snapshot{}, fmt.Errorf("build node inventory: %w", err)
	}
	signals = nodeInventory.Signals

	ruleResult, err := rules.Evaluate(ctx, rules.EvaluateOptions{
		Root:        root,
		Files:       ruleFileRefs(files),
		Node:        nodeInventory,
		Policies:    opts.RulePolicies,
		MaxFileSize: opts.MaxFileSize,
		Now:         now().UTC(),
	})
	if err != nil {
		return Snapshot{}, fmt.Errorf("evaluate rules: %w", err)
	}
	jsResult, err := jsanalysis.Analyze(ctx, jsanalysis.Options{
		Root:              root,
		Files:             jsAnalysisFileRefs(files),
		MaxFileSize:       opts.MaxFileSize,
		DecodedPayloadDir: opts.DecodedPayloadDir,
	})
	if err != nil {
		return Snapshot{}, fmt.Errorf("analyze javascript payloads: %w", err)
	}

	issues := append(walkIssues, processIssues...)
	issues = append(issues, ruleWarningIssues(ruleResult.Warnings)...)
	issues = append(issues, jsAnalysisWarningIssues(jsResult.Warnings)...)
	sortSnapshotData(files, skippedFiles, skippedDirs, issues, signals)
	signals = uniqueSignals(signals)

	snapshot := Snapshot{
		SchemaVersion:      SchemaVersion,
		ScannerVersion:     opts.ScannerVersion,
		ScanID:             scanID(startedAt),
		ProjectRoot:        ".",
		StartedAt:          startedAt,
		FinishedAt:         now().UTC(),
		PackageManagers:    signals,
		Node:               nodeInventory,
		Findings:           append(ruleResult.Findings, jsResult.Findings...),
		Files:              files,
		SkippedFiles:       skippedFiles,
		SkippedDirectories: skippedDirs,
		Errors:             issues,
	}
	snapshot.ProjectID = buildProjectID(root, files)
	RefreshSummary(&snapshot)
	return snapshot, nil
}

func walkProject(
	ctx context.Context,
	root string,
	stateRel string,
) ([]candidate, []SkippedDirectory, []Issue, []PackageManagerSignal, error) {
	candidates := []candidate{}
	skippedDirs := []SkippedDirectory{}
	issues := []Issue{}
	signals := []PackageManagerSignal{}

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		rel := displayPath(root, path)
		if walkErr != nil {
			issues = append(issues, Issue{
				Path:    rel,
				Code:    "walk_error",
				Message: cleanErrorMessage(root, walkErr),
			})
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if path == root {
			return nil
		}

		if signal, ok := detectPackageManagerSignal(rel, entry.IsDir()); ok {
			signals = append(signals, signal)
		}

		if entry.IsDir() {
			reason, ok := skipDirectoryReason(rel, stateRel)
			if !ok {
				return nil
			}
			skippedDirs = append(skippedDirs, SkippedDirectory{
				Path:   rel,
				Reason: reason,
			})
			return filepath.SkipDir
		}

		meta, err := fileid.Inspect(root, path)
		if err != nil {
			issues = append(issues, Issue{
				Path:    rel,
				Code:    "metadata_error",
				Message: cleanErrorMessage(root, err),
			})
			return nil
		}
		candidates = append(candidates, candidate{meta: meta})
		return nil
	})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("walk project: %w", err)
	}

	return candidates, skippedDirs, issues, signals, nil
}

func processCandidates(
	ctx context.Context,
	root string,
	candidates []candidate,
	maxWorkers int,
	maxFileSize int64,
	strictHash bool,
	previous previousIndex,
) ([]File, []SkippedFile, []Issue, error) {
	if len(candidates) == 0 {
		return nil, nil, nil, ctx.Err()
	}
	workers := min(maxWorkers, len(candidates))
	jobs := make(chan candidate)
	results := make(chan processResult, len(candidates))

	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for job := range jobs {
				result := processCandidate(ctx, root, job, maxFileSize, strictHash, previous)
				select {
				case results <- result:
				case <-ctx.Done():
					return
				}
			}
		})
	}

	go func() {
		defer close(jobs)
		for _, job := range candidates {
			select {
			case jobs <- job:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	files := make([]File, 0, len(candidates))
	skipped := []SkippedFile{}
	issues := []Issue{}
	for result := range results {
		files = append(files, result.file)
		if result.skipped != nil {
			skipped = append(skipped, *result.skipped)
		}
		if result.issue != nil {
			issues = append(issues, *result.issue)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("process scan files: %w", err)
	}
	return files, skipped, issues, nil
}

func processCandidate(
	ctx context.Context,
	root string,
	candidate candidate,
	maxFileSize int64,
	strictHash bool,
	previous previousIndex,
) processResult {
	meta := candidate.meta
	file := File{
		Path:          meta.RelativePath,
		Size:          meta.Size,
		ModifiedTime:  meta.ModifiedTime,
		Mode:          meta.Mode.String(),
		Permissions:   meta.Permissions,
		Symlink:       meta.Symlink,
		SymlinkTarget: meta.SymlinkTarget,
		Type:          Classify(meta.RelativePath),
		Status:        StatusScanned,
		State:         FileStatePreviouslyUnscanned,
		PackageOwner:  PackageOwner(meta.RelativePath),
	}
	prev, hasPrevious := previous.files[file.Path]
	file.State = classifyInitialState(file, prev, hasPrevious, previous.hasSnapshot)

	if meta.Symlink {
		reason := SkipReason{
			Code:    "symlink_not_followed",
			Message: "symlinks are recorded but not followed",
		}
		file.Status = StatusSkipped
		file.State = FileStateSkipped
		file.SkipReason = &reason
		return processResult{
			file: file,
			skipped: &SkippedFile{
				Path:   file.Path,
				Reason: reason,
			},
		}
	}

	if !meta.Mode.IsRegular() {
		reason := SkipReason{
			Code:    "unsupported_file_mode",
			Message: "only regular files are scanned in the baseline snapshot",
		}
		file.Status = StatusSkipped
		file.State = FileStateSkipped
		file.SkipReason = &reason
		return processResult{
			file: file,
			skipped: &SkippedFile{
				Path:   file.Path,
				Reason: reason,
			},
		}
	}

	if meta.Size > maxFileSize {
		reason := SkipReason{
			Code:        "max_file_size",
			Message:     "file exceeds configured maximum size",
			LimitBytes:  maxFileSize,
			ActualBytes: meta.Size,
		}
		file.Status = StatusSkipped
		file.State = FileStateSkipped
		file.SkipReason = &reason
		return processResult{
			file: file,
			skipped: &SkippedFile{
				Path:   file.Path,
				Reason: reason,
			},
		}
	}

	if !strictHash && reusableHash(file, prev, hasPrevious) {
		file.SHA256 = prev.SHA256
		file.State = FileStateUnchanged
		return processResult{file: file}
	}

	hash, err := fileid.HashFile(ctx, root, meta.RelativePath, maxFileSize)
	if err != nil {
		if errors.Is(err, fileid.ErrFileTooLarge) {
			reason := SkipReason{
				Code:        "max_file_size",
				Message:     "file grew beyond configured maximum size while hashing",
				LimitBytes:  maxFileSize,
				ActualBytes: meta.Size,
			}
			file.Status = StatusSkipped
			file.State = FileStateSkipped
			file.SkipReason = &reason
			return processResult{
				file: file,
				skipped: &SkippedFile{
					Path:   file.Path,
					Reason: reason,
				},
			}
		}
		file.Status = StatusError
		return processResult{
			file: file,
			issue: &Issue{
				Path:    file.Path,
				Code:    "hash_error",
				Message: cleanErrorMessage(root, err),
			},
		}
	}

	file.SHA256 = hash
	file.State = classifyHashedState(file, prev, hasPrevious, previous.hasSnapshot)
	return processResult{file: file}
}

func skipDirectoryReason(rel, stateRel string) (SkipReason, bool) {
	if rel == stateRel {
		return SkipReason{
			Code:    "malox_state",
			Message: "malox project state is skipped by default",
		}, true
	}

	base := lastPathElement(rel)
	switch base {
	case ".git":
		return SkipReason{
			Code:    "version_control",
			Message: "version control metadata is skipped by default",
		}, true
	case ".malox":
		return SkipReason{
			Code:    "malox_state",
			Message: "malox project state is skipped by default",
		}, true
	case "dist", "build", "out", "target", ".next", ".nuxt", ".svelte-kit":
		return SkipReason{
			Code:    "build_output",
			Message: "build output is skipped by default",
		}, true
	case "coverage", ".nyc_output":
		return SkipReason{
			Code:    "coverage_output",
			Message: "coverage output is skipped by default",
		}, true
	case ".cache", ".parcel-cache", ".turbo", ".vite", ".rollup.cache", ".npm", ".pnpm-store":
		return SkipReason{
			Code:    "package_manager_cache",
			Message: "package manager or tool cache is skipped by default",
		}, true
	}

	if rel == ".yarn/cache" || rel == ".yarn/unplugged" {
		return SkipReason{
			Code:    "package_manager_cache",
			Message: "yarn package cache is skipped by default",
		}, true
	}

	return SkipReason{}, false
}

func stateRelativePath(root, stateDir string) string {
	if stateDir == "" {
		return ""
	}
	if !filepath.IsAbs(stateDir) {
		stateDir = filepath.Join(root, stateDir)
	}
	absolute, err := filepath.Abs(stateDir)
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		absolute = resolved
	}
	rel, err := fileid.SnapshotPath(root, filepath.Clean(absolute))
	if err != nil {
		return ""
	}
	return rel
}

func indexPrevious(snapshot *Snapshot) previousIndex {
	if snapshot == nil {
		return previousIndex{files: map[string]File{}}
	}
	index := previousIndex{
		files:       make(map[string]File, len(snapshot.Files)),
		hasSnapshot: true,
	}
	for _, file := range snapshot.Files {
		index.files[file.Path] = file
	}
	return index
}

func classifyInitialState(file, previous File, hasPrevious bool, hasSnapshot bool) FileState {
	if !hasPrevious {
		if !hasSnapshot {
			return FileStatePreviouslyUnscanned
		}
		return FileStateAdded
	}
	if previous.SHA256 == "" {
		return FileStatePreviouslyUnscanned
	}
	if reusableHash(file, previous, hasPrevious) {
		return FileStateUnchanged
	}
	return FileStateModified
}

func classifyHashedState(file, previous File, hasPrevious bool, hasSnapshot bool) FileState {
	if !hasPrevious {
		if hasSnapshot {
			return FileStateAdded
		}
		return FileStatePreviouslyUnscanned
	}
	if previous.SHA256 == "" {
		return FileStatePreviouslyUnscanned
	}
	if sameReusableIdentity(file, previous) && file.SHA256 == previous.SHA256 {
		return FileStateUnchanged
	}
	return FileStateModified
}

func reusableHash(file, previous File, hasPrevious bool) bool {
	return hasPrevious &&
		file.Status == StatusScanned &&
		previous.Status == StatusScanned &&
		previous.SHA256 != "" &&
		sameReusableIdentity(file, previous)
}

func sameReusableIdentity(file, previous File) bool {
	return file.Path == previous.Path &&
		file.Size == previous.Size &&
		file.ModifiedTime.Equal(previous.ModifiedTime) &&
		file.Mode == previous.Mode &&
		file.SymlinkTarget == previous.SymlinkTarget &&
		file.PackageOwner == previous.PackageOwner
}

func scanID(t time.Time) string {
	return t.UTC().Format("2006-01-02T15-04-05.000000000Z")
}

// Classify intentionally starts with extension and path heuristics. Milestones 4
// and 8 replace these temporary limits with manifest-aware and JavaScript-aware
// classification.
func Classify(rel string) string {
	base := strings.ToLower(lastPathElement(rel))
	switch {
	case base == "package.json":
		return "node_manifest"
	case isLockfilePath(rel):
		return "lockfile"
	}

	switch strings.ToLower(filepath.Ext(base)) {
	case ".js", ".mjs", ".cjs":
		return "javascript"
	case ".jsx":
		return "javascript_react"
	case ".ts", ".mts", ".cts":
		return "typescript"
	case ".tsx":
		return "typescript_react"
	case ".json", ".jsonc":
		return "json"
	case ".yaml", ".yml":
		return "yaml"
	case ".toml":
		return "toml"
	case ".md", ".markdown":
		return "markdown"
	case ".sh", ".bash", ".zsh":
		return "shell"
	case ".env":
		return "environment"
	default:
		return "unknown"
	}
}

// PackageOwner returns node_modules ownership for common npm and pnpm layouts.
func PackageOwner(rel string) string {
	return node.PackageOwner(rel)
}

func detectPackageManagerSignal(rel string, isDir bool) (PackageManagerSignal, bool) {
	return node.DetectPackageManagerSignal(rel, isDir)
}

func isLockfilePath(rel string) bool {
	switch strings.ToLower(lastPathElement(rel)) {
	case "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", "deno.lock":
		return true
	default:
		return false
	}
}

func sortSnapshotData(
	files []File,
	skippedFiles []SkippedFile,
	skippedDirs []SkippedDirectory,
	issues []Issue,
	signals []PackageManagerSignal,
) {
	slices.SortFunc(files, func(a, b File) int {
		return cmp.Compare(a.Path, b.Path)
	})
	slices.SortFunc(skippedFiles, func(a, b SkippedFile) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Reason.Code, b.Reason.Code))
	})
	slices.SortFunc(skippedDirs, func(a, b SkippedDirectory) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Reason.Code, b.Reason.Code))
	})
	slices.SortFunc(issues, func(a, b Issue) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Code, b.Code))
	})
	slices.SortFunc(signals, func(a, b PackageManagerSignal) int {
		return cmp.Or(
			cmp.Compare(a.Manager, b.Manager),
			cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(a.Path, b.Path),
		)
	})
}

func uniqueSignals(signals []PackageManagerSignal) []PackageManagerSignal {
	if len(signals) == 0 {
		return nil
	}
	unique := signals[:0]
	var previous PackageManagerSignal
	for i, signal := range signals {
		if i > 0 && signal == previous {
			continue
		}
		unique = append(unique, signal)
		previous = signal
	}
	return unique
}

// RefreshSummary recalculates aggregate counts after scan-adjacent enrichments.
func RefreshSummary(snapshot *Snapshot) {
	if snapshot == nil {
		return
	}
	snapshot.Summary = summarize(*snapshot)
}

func summarize(snapshot Snapshot) Summary {
	summary := Summary{
		TotalFiles:         len(snapshot.Files),
		SkippedFiles:       len(snapshot.SkippedFiles),
		SkippedDirectories: len(snapshot.SkippedDirectories),
		PackageManagers:    len(snapshot.PackageManagers),
	}

	owners := map[string]struct{}{}
	for _, file := range snapshot.Files {
		switch file.Status {
		case StatusScanned:
			summary.ScannedFiles++
		case StatusError:
			summary.ErroredFiles++
		}
		if file.PackageOwner != "" {
			summary.NodeModulesFiles++
			owners[file.PackageOwner] = struct{}{}
		}
	}
	summary.NodeModulesPackages = len(owners)
	for _, finding := range snapshot.Findings {
		summary.Findings++
		if finding.Suppressed {
			summary.SuppressedFindings++
		}
		if finding.Blocking && !finding.Suppressed {
			summary.BlockingFindings++
		}
		if finding.Confidence == rules.ConfidenceWeakSignal {
			summary.WeakFindings++
		}
	}
	return summary
}

func nodeFileRefs(files []File) []node.FileRef {
	refs := make([]node.FileRef, 0, len(files))
	for _, file := range files {
		refs = append(refs, node.FileRef{
			Path:   file.Path,
			SHA256: file.SHA256,
			Status: string(file.Status),
		})
	}
	return refs
}

func ruleFileRefs(files []File) []rules.File {
	refs := make([]rules.File, 0, len(files))
	for _, file := range files {
		if file.Status != StatusScanned {
			continue
		}
		refs = append(refs, rules.File{
			Path:         file.Path,
			SHA256:       file.SHA256,
			Type:         file.Type,
			PackageOwner: file.PackageOwner,
			Size:         file.Size,
		})
	}
	return refs
}

func jsAnalysisFileRefs(files []File) []jsanalysis.File {
	refs := make([]jsanalysis.File, 0, len(files))
	for _, file := range files {
		if file.Status != StatusScanned {
			continue
		}
		refs = append(refs, jsanalysis.File{
			Path:         file.Path,
			SHA256:       file.SHA256,
			Type:         file.Type,
			PackageOwner: file.PackageOwner,
			Size:         file.Size,
		})
	}
	return refs
}

func ruleWarningIssues(warnings []rules.Warning) []Issue {
	if len(warnings) == 0 {
		return nil
	}
	issues := make([]Issue, 0, len(warnings))
	for _, warning := range warnings {
		issues = append(issues, Issue{
			Path:    warning.Path,
			Code:    "rule_" + warning.Code,
			Message: warning.Message,
		})
	}
	return issues
}

func jsAnalysisWarningIssues(warnings []rules.Warning) []Issue {
	if len(warnings) == 0 {
		return nil
	}
	issues := make([]Issue, 0, len(warnings))
	for _, warning := range warnings {
		issues = append(issues, Issue{
			Path:    warning.Path,
			Code:    warning.Code,
			Message: warning.Message,
		})
	}
	return issues
}

func buildProjectID(root string, files []File) string {
	h := sha256.New()
	writeHashPart(h, "root", filepath.Clean(root))

	for _, file := range files {
		if !isLockfilePath(file.Path) {
			continue
		}
		writeHashPart(h, "lockfile", file.Path)
		writeHashPart(h, "size", fmt.Sprintf("%d", file.Size))
		writeHashPart(h, "modified_time", file.ModifiedTime.UTC().Format(time.RFC3339Nano))
		writeHashPart(h, "mode", file.Mode)
		writeHashPart(h, "sha256", file.SHA256)
		writeHashPart(h, "status", string(file.Status))
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func writeHashPart(w io.Writer, key, value string) {
	_, _ = io.WriteString(w, key)
	_, _ = io.WriteString(w, "\x00")
	_, _ = io.WriteString(w, value)
	_, _ = io.WriteString(w, "\x00")
}

func displayPath(root, path string) string {
	rel, err := fileid.SnapshotPath(root, path)
	if err == nil {
		return rel
	}
	return filepath.ToSlash(filepath.Base(path))
}

func cleanErrorMessage(root string, err error) string {
	msg := err.Error()
	cleanRoot := filepath.Clean(root)
	msg = strings.ReplaceAll(msg, cleanRoot+string(os.PathSeparator), "")
	msg = strings.ReplaceAll(msg, cleanRoot, ".")
	return msg
}

func lastPathElement(rel string) string {
	rel = strings.TrimSuffix(filepath.ToSlash(rel), "/")
	if rel == "" {
		return "."
	}
	parts := strings.Split(rel, "/")
	return parts[len(parts)-1]
}
