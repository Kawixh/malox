package node

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

const scannedStatus = "scanned"

// Build discovers Node.js manifests, lockfiles, dependencies, scripts, and warnings.
func Build(ctx context.Context, opts BuildOptions) (Inventory, error) {
	if err := ctx.Err(); err != nil {
		return Inventory{}, fmt.Errorf("build node inventory: %w", err)
	}
	if strings.TrimSpace(opts.Root) == "" {
		return Inventory{}, errors.New("root is required")
	}

	inv := Inventory{
		SchemaVersion:  SchemaVersion,
		Signals:        append([]PackageManagerSignal{}, opts.Signals...),
		Manifests:      []SourceFile{},
		Lockfiles:      []SourceFile{},
		Dependencies:   []Dependency{},
		PackageScripts: []PackageScript{},
		Warnings:       []Warning{},
	}

	manifestTypes := map[string]string{}
	packageScriptsByPath := map[string][]PackageScript{}
	packageMaintainersByPath := map[string][]string{}
	for _, file := range scannedFiles(opts.Files) {
		if err := ctx.Err(); err != nil {
			return Inventory{}, fmt.Errorf("build node inventory: %w", err)
		}

		signal, ok := DetectPackageManagerSignal(file.Path, false)
		if ok {
			inv.Signals = append(inv.Signals, signal)
		}

		switch strings.ToLower(filepath.Base(file.Path)) {
		case "package.json":
			source := SourceFile{
				Path:    file.Path,
				SHA256:  file.SHA256,
				Manager: "node",
				Kind:    "manifest",
			}
			inv.Manifests = append(inv.Manifests, source)

			data, err := readProjectFile(opts.Root, file.Path)
			if err != nil {
				inv.Warnings = append(inv.Warnings, warning(file.Path, "manifest_read_error", err))
				continue
			}
			doc, err := parseManifest(file.Path, data)
			if err != nil {
				inv.Warnings = append(inv.Warnings, warning(file.Path, "manifest_parse_error", err))
				continue
			}
			if !strings.Contains(filepath.ToSlash(file.Path), "/node_modules/") {
				deps := dependenciesFromManifest(file.Path, doc)
				inv.Dependencies = append(inv.Dependencies, deps...)
				for _, dep := range deps {
					if dep.DependencyType != "" {
						manifestTypes[dep.Name] = dep.DependencyType
					}
				}
			}
			scripts := packageScriptsFromManifest(file.Path, doc)
			inv.PackageScripts = append(inv.PackageScripts, scripts...)
			packageDir := packageDirFromManifest(file.Path)
			packageScriptsByPath[packageDir] = scripts
			packageMaintainersByPath[packageDir] = peopleFromManifest(doc)
		case "deno.json":
			inv.Manifests = append(inv.Manifests, SourceFile{
				Path:    file.Path,
				SHA256:  file.SHA256,
				Manager: "deno",
				Kind:    "manifest",
			})
		case "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", "deno.lock":
			inv.Lockfiles = append(inv.Lockfiles, SourceFile{
				Path:    file.Path,
				SHA256:  file.SHA256,
				Manager: managerForLockfile(file.Path),
				Kind:    kindForLockfile(file.Path),
			})
		}
	}

	for _, file := range scannedFiles(opts.Files) {
		if err := ctx.Err(); err != nil {
			return Inventory{}, fmt.Errorf("build node inventory: %w", err)
		}
		deps, scripts, warnings := parseInventoryFile(opts.Root, file, manifestTypes)
		inv.Dependencies = append(inv.Dependencies, deps...)
		inv.PackageScripts = append(inv.PackageScripts, scripts...)
		inv.Warnings = append(inv.Warnings, warnings...)
	}

	attachPackageScripts(inv.Dependencies, packageScriptsByPath)
	attachPackageMaintainers(inv.Dependencies, packageMaintainersByPath)
	sortInventory(&inv)
	inv.Signals = uniqueSignals(inv.Signals)
	inv.Dependencies = dedupeDependencies(inv.Dependencies)
	inv.PackageScripts = dedupePackageScripts(inv.PackageScripts)
	inv.Summary = Summary{
		ManifestCount:   len(inv.Manifests),
		LockfileCount:   len(inv.Lockfiles),
		DependencyCount: len(inv.Dependencies),
		PackageScripts:  len(inv.PackageScripts),
		Warnings:        len(inv.Warnings),
	}
	return inv, nil
}

// DetectPackageManagerSignal returns a package-manager clue for rel when one is known.
func DetectPackageManagerSignal(rel string, isDir bool) (PackageManagerSignal, bool) {
	if isDir {
		if path.Base(filepath.ToSlash(rel)) == "node_modules" {
			return PackageManagerSignal{Manager: "node", Kind: "dependency_directory", Path: rel}, true
		}
		return PackageManagerSignal{}, false
	}

	switch strings.ToLower(path.Base(filepath.ToSlash(rel))) {
	case "package.json":
		return PackageManagerSignal{Manager: "node", Kind: "manifest", Path: rel}, true
	case "package-lock.json", "npm-shrinkwrap.json":
		return PackageManagerSignal{Manager: "npm", Kind: "lockfile", Path: rel}, true
	case "pnpm-lock.yaml":
		return PackageManagerSignal{Manager: "pnpm", Kind: "lockfile", Path: rel}, true
	case "yarn.lock":
		return PackageManagerSignal{Manager: "yarn", Kind: "lockfile", Path: rel}, true
	case "bun.lock", "bun.lockb":
		return PackageManagerSignal{Manager: "bun", Kind: "lockfile", Path: rel}, true
	case "deno.json":
		return PackageManagerSignal{Manager: "deno", Kind: "manifest", Path: rel}, true
	case "deno.lock":
		return PackageManagerSignal{Manager: "deno", Kind: "lockfile", Path: rel}, true
	default:
		return PackageManagerSignal{}, false
	}
}

func parseInventoryFile(
	root string,
	file FileRef,
	manifestTypes map[string]string,
) ([]Dependency, []PackageScript, []Warning) {
	base := strings.ToLower(filepath.Base(file.Path))
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", "deno.json", "deno.lock":
	default:
		return nil, nil, nil
	}

	if base == "bun.lockb" {
		return nil, nil, []Warning{{
			Path:    file.Path,
			Code:    "bun_lockb_unsupported",
			Message: "binary bun.lockb parsing is not implemented; use bun.lock for dependency inventory",
		}}
	}

	data, err := readProjectFile(root, file.Path)
	if err != nil {
		return nil, nil, []Warning{warning(file.Path, "lockfile_read_error", err)}
	}

	switch base {
	case "package-lock.json":
		deps, err := parseNpmLock(file.Path, "npm", data, manifestTypes)
		return deps, nil, warningsFromError(file.Path, "npm_lock_parse_error", err)
	case "npm-shrinkwrap.json":
		deps, err := parseNpmLock(file.Path, "npm-shrinkwrap", data, manifestTypes)
		return deps, nil, warningsFromError(file.Path, "npm_shrinkwrap_parse_error", err)
	case "pnpm-lock.yaml":
		deps, err := parsePnpmLock(file.Path, data)
		return deps, nil, warningsFromError(file.Path, "pnpm_lock_parse_error", err)
	case "yarn.lock":
		deps, warnings := parseYarnLock(file.Path, data)
		return deps, nil, warnings
	case "bun.lock":
		deps, err := parseBunLock(file.Path, data)
		return deps, nil, warningsFromError(file.Path, "bun_lock_parse_error", err)
	case "deno.json":
		deps, scripts, err := parseDenoConfig(file.Path, data)
		return deps, scripts, warningsFromError(file.Path, "deno_config_parse_error", err)
	case "deno.lock":
		deps, err := parseDenoLock(file.Path, data)
		return deps, nil, warningsFromError(file.Path, "deno_lock_parse_error", err)
	default:
		return nil, nil, nil
	}
}

func scannedFiles(files []FileRef) []FileRef {
	out := make([]FileRef, 0, len(files))
	for _, file := range files {
		if file.Status != "" && file.Status != scannedStatus {
			continue
		}
		out = append(out, file)
	}
	slices.SortFunc(out, func(a, b FileRef) int {
		return cmp.Compare(a.Path, b.Path)
	})
	return out
}

func readProjectFile(root, rel string) ([]byte, error) {
	if !filepath.IsLocal(rel) {
		return nil, fmt.Errorf("unsafe relative path %q", rel)
	}
	f, err := os.OpenInRoot(root, filepath.FromSlash(rel))
	if err != nil {
		return nil, fmt.Errorf("open project file %q: %w", rel, err)
	}
	defer func() {
		_ = f.Close()
	}()
	return io.ReadAll(f)
}

func managerForLockfile(path string) string {
	switch strings.ToLower(filepath.Base(path)) {
	case "package-lock.json", "npm-shrinkwrap.json":
		return "npm"
	case "pnpm-lock.yaml":
		return "pnpm"
	case "yarn.lock":
		return "yarn"
	case "bun.lock", "bun.lockb":
		return "bun"
	case "deno.json", "deno.lock":
		return "deno"
	default:
		return "node"
	}
}

func kindForLockfile(path string) string {
	if strings.EqualFold(filepath.Base(path), "deno.json") {
		return "manifest"
	}
	return "lockfile"
}

func attachPackageScripts(deps []Dependency, scriptsByPath map[string][]PackageScript) {
	for i := range deps {
		if deps[i].PackagePath == "" {
			continue
		}
		scripts := scriptsByPath[deps[i].PackagePath]
		if len(scripts) == 0 {
			continue
		}
		deps[i].Scripts = make(map[string]string, len(scripts))
		for _, script := range scripts {
			deps[i].Scripts[script.ScriptName] = script.Command
		}
	}
}

func attachPackageMaintainers(deps []Dependency, maintainersByPath map[string][]string) {
	for i := range deps {
		if deps[i].PackagePath == "" {
			continue
		}
		maintainers := maintainersByPath[deps[i].PackagePath]
		if len(maintainers) == 0 {
			continue
		}
		deps[i].Maintainers = slices.Clone(maintainers)
	}
}

func sortInventory(inv *Inventory) {
	slices.SortFunc(inv.Manifests, func(a, b SourceFile) int {
		return cmp.Compare(a.Path, b.Path)
	})
	slices.SortFunc(inv.Lockfiles, func(a, b SourceFile) int {
		return cmp.Compare(a.Path, b.Path)
	})
	slices.SortFunc(inv.Dependencies, compareDependency)
	slices.SortFunc(inv.PackageScripts, comparePackageScript)
	slices.SortFunc(inv.Warnings, func(a, b Warning) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Code, b.Code), cmp.Compare(a.Message, b.Message))
	})
	slices.SortFunc(inv.Signals, func(a, b PackageManagerSignal) int {
		return cmp.Or(cmp.Compare(a.Manager, b.Manager), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Path, b.Path))
	})
}

func compareDependency(a, b Dependency) int {
	return cmp.Or(
		cmp.Compare(a.PackageManager, b.PackageManager),
		cmp.Compare(a.SourcePath, b.SourcePath),
		cmp.Compare(a.PackagePath, b.PackagePath),
		cmp.Compare(a.Name, b.Name),
		cmp.Compare(a.Version, b.Version),
	)
}

func comparePackageScript(a, b PackageScript) int {
	return cmp.Or(
		cmp.Compare(a.SourcePath, b.SourcePath),
		cmp.Compare(a.PackagePath, b.PackagePath),
		cmp.Compare(a.PackageName, b.PackageName),
		cmp.Compare(a.ScriptName, b.ScriptName),
	)
}

func uniqueSignals(signals []PackageManagerSignal) []PackageManagerSignal {
	if len(signals) == 0 {
		return []PackageManagerSignal{}
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

func dedupeDependencies(deps []Dependency) []Dependency {
	if len(deps) == 0 {
		return []Dependency{}
	}
	slices.SortFunc(deps, compareDependency)
	seen := map[string]struct{}{}
	out := deps[:0]
	for _, dep := range deps {
		key := dependencyKey(dep)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, dep)
	}
	return out
}

func dedupePackageScripts(scripts []PackageScript) []PackageScript {
	if len(scripts) == 0 {
		return []PackageScript{}
	}
	slices.SortFunc(scripts, comparePackageScript)
	seen := map[string]struct{}{}
	out := scripts[:0]
	for _, script := range scripts {
		key := strings.Join([]string{
			script.PackageManager,
			script.SourcePath,
			script.PackagePath,
			script.PackageName,
			script.ScriptName,
			script.Command,
		}, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, script)
	}
	return out
}

func dependencyKey(dep Dependency) string {
	return strings.Join([]string{
		dep.PackageManager,
		dep.SourcePath,
		dep.PackagePath,
		dep.Name,
		dep.Version,
		dep.DependencyType,
	}, "\x00")
}

func warning(path, code string, err error) Warning {
	return Warning{
		Path:    path,
		Code:    code,
		Message: err.Error(),
	}
}

func warningsFromError(path, code string, err error) []Warning {
	if err == nil {
		return nil
	}
	return []Warning{warning(path, code, err)}
}
