package node

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
)

type npmLock struct {
	LockfileVersion int                   `json:"lockfileVersion"`
	Packages        map[string]npmPackage `json:"packages"`
	Dependencies    map[string]npmLegacy  `json:"dependencies"`
}

type npmPackage struct {
	Name             string            `json:"name"`
	Version          string            `json:"version"`
	Resolved         string            `json:"resolved"`
	Integrity        string            `json:"integrity"`
	Link             bool              `json:"link"`
	Dev              bool              `json:"dev"`
	Optional         bool              `json:"optional"`
	DevOptional      bool              `json:"devOptional"`
	HasInstallScript bool              `json:"hasInstallScript"`
	Dependencies     map[string]string `json:"dependencies"`
	OptionalDeps     map[string]string `json:"optionalDependencies"`
}

type npmLegacy struct {
	Version      string               `json:"version"`
	Resolved     string               `json:"resolved"`
	Integrity    string               `json:"integrity"`
	Dev          bool                 `json:"dev"`
	Optional     bool                 `json:"optional"`
	Dependencies map[string]npmLegacy `json:"dependencies"`
}

func parseNpmLock(path, manager string, data []byte, manifestTypes map[string]string) ([]Dependency, error) {
	var lock npmLock
	if err := readJSONStrict(bytes.NewReader(data), &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}

	if len(lock.Packages) > 0 {
		return dependenciesFromNpmPackages(path, manager, lock.Packages, manifestTypes), nil
	}
	return dependenciesFromNpmLegacy(path, manager, lock.Dependencies, manifestTypes), nil
}

func dependenciesFromNpmPackages(
	path string,
	manager string,
	packages map[string]npmPackage,
	manifestTypes map[string]string,
) []Dependency {
	locations := sortedMapKeys(packages)
	out := make([]Dependency, 0, len(locations))
	for _, location := range locations {
		if location == "" {
			continue
		}
		pkg := packages[location]
		if pkg.Link || pkg.Version == "" {
			continue
		}
		name := pkg.Name
		if name == "" {
			name = nameFromNodeModulesPath(location)
		}
		if name == "" {
			continue
		}
		depType := npmDependencyType(name, pkg, manifestTypes)
		out = append(out, Dependency{
			Name:             name,
			Version:          pkg.Version,
			PURL:             NpmPURL(name, pkg.Version),
			PackageManager:   manager,
			DependencyType:   depType,
			SourcePath:       path,
			PackagePath:      filepath.ToSlash(location),
			Integrity:        pkg.Integrity,
			Resolved:         pkg.Resolved,
			HasInstallScript: pkg.HasInstallScript,
		})
	}
	return out
}

func dependenciesFromNpmLegacy(
	path string,
	manager string,
	deps map[string]npmLegacy,
	manifestTypes map[string]string,
) []Dependency {
	out := []Dependency{}
	var walk func(parent string, items map[string]npmLegacy)
	walk = func(parent string, items map[string]npmLegacy) {
		for _, name := range sortedMapKeys(items) {
			dep := items[name]
			location := filepath.ToSlash(filepath.Join(parent, "node_modules", name))
			depType := manifestTypes[name]
			if depType == "" {
				depType = "transitive"
			}
			if dep.Dev {
				depType = "dev"
			}
			if dep.Optional {
				depType = "optional"
			}
			out = append(out, Dependency{
				Name:           name,
				Version:        dep.Version,
				PURL:           NpmPURL(name, dep.Version),
				PackageManager: manager,
				DependencyType: depType,
				SourcePath:     path,
				PackagePath:    location,
				Integrity:      dep.Integrity,
				Resolved:       dep.Resolved,
			})
			walk(location, dep.Dependencies)
		}
	}
	walk("", deps)
	return out
}

func npmDependencyType(name string, pkg npmPackage, manifestTypes map[string]string) string {
	switch {
	case pkg.DevOptional:
		return "dev_optional"
	case pkg.Dev:
		return "dev"
	case pkg.Optional:
		return "optional"
	case manifestTypes[name] != "":
		return manifestTypes[name]
	default:
		return "transitive"
	}
}

func nameFromNodeModulesPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "node_modules" || i+1 >= len(parts) {
			continue
		}
		if strings.HasPrefix(parts[i+1], "@") && i+2 < len(parts) {
			return parts[i+1] + "/" + parts[i+2]
		}
		return parts[i+1]
	}
	return ""
}
