// Package node discovers Node.js project metadata and dependency inventories.
package node

// SchemaVersion is the public node inventory schema embedded in scan snapshots.
const SchemaVersion = "malox.node.inventory.v1"

// FileRef describes a scanned project file available to the node inventory pass.
type FileRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	Status string `json:"status,omitempty"`
}

// BuildOptions configures one node inventory pass.
type BuildOptions struct {
	Root    string
	Files   []FileRef
	Signals []PackageManagerSignal
}

// Inventory contains package-manager signals, parsed metadata, and warnings.
type Inventory struct {
	SchemaVersion  string                 `json:"schema_version"`
	Signals        []PackageManagerSignal `json:"package_manager_signals"`
	Manifests      []SourceFile           `json:"manifests"`
	Lockfiles      []SourceFile           `json:"lockfiles"`
	Dependencies   []Dependency           `json:"dependencies"`
	PackageScripts []PackageScript        `json:"package_scripts"`
	Warnings       []Warning              `json:"warnings"`
	Summary        Summary                `json:"summary"`
}

// PackageManagerSignal describes a package-manager clue discovered in a project.
type PackageManagerSignal struct {
	Manager string `json:"manager"`
	Kind    string `json:"kind"`
	Path    string `json:"path"`
}

// SourceFile identifies a manifest or lockfile participating in the inventory.
type SourceFile struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256,omitempty"`
	Manager string `json:"manager"`
	Kind    string `json:"kind"`
}

// Dependency describes one package identity discovered from manifests or lockfiles.
type Dependency struct {
	Name             string            `json:"name"`
	Version          string            `json:"version,omitempty"`
	PURL             string            `json:"purl,omitempty"`
	Maintainers      []string          `json:"maintainers,omitempty"`
	PackageManager   string            `json:"package_manager_source"`
	DependencyType   string            `json:"dependency_type,omitempty"`
	SourcePath       string            `json:"source_path"`
	PackagePath      string            `json:"package_path,omitempty"`
	Integrity        string            `json:"integrity,omitempty"`
	Resolved         string            `json:"resolved,omitempty"`
	Scripts          map[string]string `json:"scripts,omitempty"`
	HasInstallScript bool              `json:"has_install_script,omitempty"`
}

// PackageScript describes one lifecycle or package script without executing it.
type PackageScript struct {
	PackageName    string   `json:"package_name,omitempty"`
	PackageVersion string   `json:"package_version,omitempty"`
	PURL           string   `json:"purl,omitempty"`
	Maintainers    []string `json:"maintainers,omitempty"`
	PackageManager string   `json:"package_manager_source"`
	SourcePath     string   `json:"source_path"`
	PackagePath    string   `json:"package_path,omitempty"`
	ScriptName     string   `json:"script_name"`
	Command        string   `json:"command"`
}

// Warning reports a malformed or unsupported project metadata file.
type Warning struct {
	Path    string `json:"path"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Summary contains aggregate node inventory counts.
type Summary struct {
	ManifestCount   int `json:"manifest_count"`
	LockfileCount   int `json:"lockfile_count"`
	DependencyCount int `json:"dependency_count"`
	PackageScripts  int `json:"package_scripts"`
	Warnings        int `json:"warnings"`
}
