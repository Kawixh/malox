// Package diff compares Malox scan snapshots.
package diff

import (
	"cmp"
	"slices"

	"malox/internal/node"
	"malox/internal/scan"
)

// SchemaVersion is the public diff report schema.
const SchemaVersion = "malox.diff.v1"

// Report describes the file and finding delta between two snapshots.
type Report struct {
	SchemaVersion         string
	FromScanID            string
	ToScanID              string
	AddedFiles            []FileChange
	RemovedFiles          []FileChange
	ModifiedFiles         []FileChange
	UnchangedFiles        []FileChange
	SkippedFiles          []FileChange
	NewDependencies       []DependencyChange
	RemovedDependencies   []DependencyChange
	UpdatedDependencies   []DependencyChange
	NewPackageScripts     []PackageScriptChange
	ChangedPackageScripts []PackageScriptChange
	NewFindings           []FindingChange
	ResolvedFindings      []FindingChange
	StillExistingFindings []FindingChange
}

// FileChange describes one file's state across two snapshots.
type FileChange struct {
	Path         string
	State        scan.FileState
	FromStatus   scan.Status
	ToStatus     scan.Status
	FromSHA256   string
	ToSHA256     string
	FromSize     int64
	ToSize       int64
	PackageOwner string
}

// FindingChange is reserved for milestone 5+ rule and threat findings.
type FindingChange struct {
	ID string
}

// Compare returns a deterministic diff from oldSnapshot to newSnapshot.
func Compare(oldSnapshot, newSnapshot scan.Snapshot) Report {
	report := Report{
		SchemaVersion:         SchemaVersion,
		FromScanID:            oldSnapshot.ScanID,
		ToScanID:              newSnapshot.ScanID,
		AddedFiles:            []FileChange{},
		RemovedFiles:          []FileChange{},
		ModifiedFiles:         []FileChange{},
		UnchangedFiles:        []FileChange{},
		SkippedFiles:          []FileChange{},
		NewDependencies:       []DependencyChange{},
		RemovedDependencies:   []DependencyChange{},
		UpdatedDependencies:   []DependencyChange{},
		NewPackageScripts:     []PackageScriptChange{},
		ChangedPackageScripts: []PackageScriptChange{},
		NewFindings:           []FindingChange{},
		ResolvedFindings:      []FindingChange{},
		StillExistingFindings: []FindingChange{},
	}

	oldFiles := indexFiles(oldSnapshot.Files)
	newFiles := indexFiles(newSnapshot.Files)
	paths := allPaths(oldFiles, newFiles)

	for _, path := range paths {
		oldFile, hadOld := oldFiles[path]
		newFile, hasNew := newFiles[path]

		switch {
		case !hadOld && hasNew:
			change := newFileChange(path, scan.File{}, newFile, scan.FileStateAdded)
			if newFile.Status == scan.StatusSkipped {
				change.State = scan.FileStateSkipped
				report.SkippedFiles = append(report.SkippedFiles, change)
				continue
			}
			report.AddedFiles = append(report.AddedFiles, change)
		case hadOld && !hasNew:
			report.RemovedFiles = append(report.RemovedFiles, newFileChange(path, oldFile, scan.File{}, scan.FileStateRemoved))
		case oldFile.Status == scan.StatusSkipped || newFile.Status == scan.StatusSkipped:
			report.SkippedFiles = append(report.SkippedFiles, newFileChange(path, oldFile, newFile, scan.FileStateSkipped))
		case sameFileIdentity(oldFile, newFile) && oldFile.SHA256 == newFile.SHA256:
			report.UnchangedFiles = append(report.UnchangedFiles, newFileChange(path, oldFile, newFile, scan.FileStateUnchanged))
		default:
			report.ModifiedFiles = append(report.ModifiedFiles, newFileChange(path, oldFile, newFile, scan.FileStateModified))
		}
	}

	compareDependencies(&report, oldSnapshot.Node.Dependencies, newSnapshot.Node.Dependencies)
	comparePackageScripts(&report, oldSnapshot.Node.PackageScripts, newSnapshot.Node.PackageScripts)
	return report
}

// HasRelevantChanges reports whether the diff should produce a non-zero result.
func (r Report) HasRelevantChanges() bool {
	return len(r.AddedFiles) > 0 ||
		len(r.RemovedFiles) > 0 ||
		len(r.ModifiedFiles) > 0 ||
		len(r.NewDependencies) > 0 ||
		len(r.RemovedDependencies) > 0 ||
		len(r.UpdatedDependencies) > 0 ||
		len(r.NewPackageScripts) > 0 ||
		len(r.ChangedPackageScripts) > 0 ||
		len(r.NewFindings) > 0 ||
		len(r.ResolvedFindings) > 0
}

// DependencyChange describes one dependency-level state transition.
type DependencyChange struct {
	Name           string
	PackageManager string
	DependencyType string
	SourcePath     string
	PackagePath    string
	FromVersion    string
	ToVersion      string
	FromPURL       string
	ToPURL         string
	FromIntegrity  string
	ToIntegrity    string
	FromResolved   string
	ToResolved     string
}

// PackageScriptChange describes a new or changed package script.
type PackageScriptChange struct {
	PackageName    string
	PackageManager string
	SourcePath     string
	PackagePath    string
	ScriptName     string
	FromCommand    string
	ToCommand      string
}

func indexFiles(files []scan.File) map[string]scan.File {
	index := make(map[string]scan.File, len(files))
	for _, file := range files {
		index[file.Path] = file
	}
	return index
}

func allPaths(oldFiles, newFiles map[string]scan.File) []string {
	seen := make(map[string]struct{}, len(oldFiles)+len(newFiles))
	paths := make([]string, 0, len(oldFiles)+len(newFiles))
	for path := range oldFiles {
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	for path := range newFiles {
		if _, ok := seen[path]; ok {
			continue
		}
		paths = append(paths, path)
	}
	slices.Sort(paths)
	return paths
}

func newFileChange(path string, oldFile, newFile scan.File, state scan.FileState) FileChange {
	owner := newFile.PackageOwner
	if owner == "" {
		owner = oldFile.PackageOwner
	}
	return FileChange{
		Path:         path,
		State:        state,
		FromStatus:   oldFile.Status,
		ToStatus:     newFile.Status,
		FromSHA256:   oldFile.SHA256,
		ToSHA256:     newFile.SHA256,
		FromSize:     oldFile.Size,
		ToSize:       newFile.Size,
		PackageOwner: owner,
	}
}

func sameFileIdentity(a, b scan.File) bool {
	return a.Path == b.Path &&
		a.Size == b.Size &&
		a.ModifiedTime.Equal(b.ModifiedTime) &&
		a.Mode == b.Mode &&
		a.SymlinkTarget == b.SymlinkTarget &&
		a.PackageOwner == b.PackageOwner &&
		a.Status == b.Status
}

func compareDependencies(report *Report, oldDeps, newDeps []node.Dependency) {
	oldIndex := indexDependencies(oldDeps)
	newIndex := indexDependencies(newDeps)
	keys := allDependencyKeys(oldIndex, newIndex)

	for _, key := range keys {
		oldDep, hadOld := oldIndex[key]
		newDep, hasNew := newIndex[key]
		switch {
		case !hadOld && hasNew:
			report.NewDependencies = append(report.NewDependencies, dependencyChange(oldDep, newDep))
		case hadOld && !hasNew:
			report.RemovedDependencies = append(report.RemovedDependencies, dependencyChange(oldDep, newDep))
		case dependencyChanged(oldDep, newDep):
			report.UpdatedDependencies = append(report.UpdatedDependencies, dependencyChange(oldDep, newDep))
		}
	}
}

func comparePackageScripts(report *Report, oldScripts, newScripts []node.PackageScript) {
	oldIndex := indexPackageScripts(oldScripts)
	newIndex := indexPackageScripts(newScripts)
	keys := allScriptKeys(oldIndex, newIndex)

	for _, key := range keys {
		oldScript, hadOld := oldIndex[key]
		newScript, hasNew := newIndex[key]
		switch {
		case !hadOld && hasNew:
			report.NewPackageScripts = append(report.NewPackageScripts, packageScriptChange(oldScript, newScript))
		case hadOld && hasNew && oldScript.Command != newScript.Command:
			report.ChangedPackageScripts = append(
				report.ChangedPackageScripts,
				packageScriptChange(oldScript, newScript),
			)
		}
	}
}

func indexDependencies(deps []node.Dependency) map[string]node.Dependency {
	index := make(map[string]node.Dependency, len(deps))
	for _, dep := range deps {
		index[dependencyIdentity(dep)] = dep
	}
	return index
}

func indexPackageScripts(scripts []node.PackageScript) map[string]node.PackageScript {
	index := make(map[string]node.PackageScript, len(scripts))
	for _, script := range scripts {
		index[packageScriptIdentity(script)] = script
	}
	return index
}

func allDependencyKeys(
	oldDeps map[string]node.Dependency,
	newDeps map[string]node.Dependency,
) []string {
	keys := make([]string, 0, len(oldDeps)+len(newDeps))
	seen := map[string]struct{}{}
	for key := range oldDeps {
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	for key := range newDeps {
		if _, ok := seen[key]; ok {
			continue
		}
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func allScriptKeys(
	oldScripts map[string]node.PackageScript,
	newScripts map[string]node.PackageScript,
) []string {
	keys := make([]string, 0, len(oldScripts)+len(newScripts))
	seen := map[string]struct{}{}
	for key := range oldScripts {
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	for key := range newScripts {
		if _, ok := seen[key]; ok {
			continue
		}
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func dependencyIdentity(dep node.Dependency) string {
	return cmp.Or(dep.PackageManager, "unknown") + "\x00" +
		dep.SourcePath + "\x00" +
		dep.PackagePath + "\x00" +
		dep.Name + "\x00" +
		dep.DependencyType
}

func packageScriptIdentity(script node.PackageScript) string {
	return cmp.Or(script.PackageManager, "unknown") + "\x00" +
		script.SourcePath + "\x00" +
		script.PackagePath + "\x00" +
		script.PackageName + "\x00" +
		script.ScriptName
}

func dependencyChanged(oldDep, newDep node.Dependency) bool {
	return oldDep.Version != newDep.Version ||
		oldDep.PURL != newDep.PURL ||
		oldDep.Integrity != newDep.Integrity ||
		oldDep.Resolved != newDep.Resolved ||
		oldDep.HasInstallScript != newDep.HasInstallScript
}

func dependencyChange(oldDep, newDep node.Dependency) DependencyChange {
	dep := newDep
	if dep.Name == "" {
		dep = oldDep
	}
	return DependencyChange{
		Name:           dep.Name,
		PackageManager: dep.PackageManager,
		DependencyType: dep.DependencyType,
		SourcePath:     dep.SourcePath,
		PackagePath:    dep.PackagePath,
		FromVersion:    oldDep.Version,
		ToVersion:      newDep.Version,
		FromPURL:       oldDep.PURL,
		ToPURL:         newDep.PURL,
		FromIntegrity:  oldDep.Integrity,
		ToIntegrity:    newDep.Integrity,
		FromResolved:   oldDep.Resolved,
		ToResolved:     newDep.Resolved,
	}
}

func packageScriptChange(oldScript, newScript node.PackageScript) PackageScriptChange {
	script := newScript
	if script.ScriptName == "" {
		script = oldScript
	}
	return PackageScriptChange{
		PackageName:    script.PackageName,
		PackageManager: script.PackageManager,
		SourcePath:     script.SourcePath,
		PackagePath:    script.PackagePath,
		ScriptName:     script.ScriptName,
		FromCommand:    oldScript.Command,
		ToCommand:      newScript.Command,
	}
}
