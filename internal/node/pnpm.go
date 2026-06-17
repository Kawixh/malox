package node

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type pnpmLock struct {
	LockfileVersion any                     `yaml:"lockfileVersion"`
	Importers       map[string]pnpmImporter `yaml:"importers"`
	Packages        map[string]pnpmPackage  `yaml:"packages"`
}

type pnpmImporter struct {
	Dependencies         map[string]pnpmImporterDependency `yaml:"dependencies"`
	DevDependencies      map[string]pnpmImporterDependency `yaml:"devDependencies"`
	OptionalDependencies map[string]pnpmImporterDependency `yaml:"optionalDependencies"`
}

type pnpmImporterDependency struct {
	Specifier string `yaml:"specifier"`
	Version   string `yaml:"version"`
}

type pnpmPackage struct {
	Resolution struct {
		Integrity string `yaml:"integrity"`
		Tarball   string `yaml:"tarball"`
	} `yaml:"resolution"`
	Dev      bool `yaml:"dev"`
	Optional bool `yaml:"optional"`
}

func parsePnpmLock(path string, data []byte) ([]Dependency, error) {
	var lock pnpmLock
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&lock); err != nil {
		return nil, fmt.Errorf("parse pnpm lockfile: %w", err)
	}

	out := []Dependency{}
	out = append(out, dependenciesFromPnpmImporters(path, lock.Importers)...)
	out = append(out, dependenciesFromPnpmPackages(path, lock.Packages)...)
	return dedupeDependencies(out), nil
}

func dependenciesFromPnpmImporters(path string, importers map[string]pnpmImporter) []Dependency {
	out := []Dependency{}
	for _, importerPath := range sortedMapKeys(importers) {
		importer := importers[importerPath]
		for _, group := range []struct {
			kind string
			deps map[string]pnpmImporterDependency
		}{
			{kind: "dependencies", deps: importer.Dependencies},
			{kind: "dev_dependencies", deps: importer.DevDependencies},
			{kind: "optional_dependencies", deps: importer.OptionalDependencies},
		} {
			for _, name := range sortedMapKeys(group.deps) {
				dep := group.deps[name]
				version := pnpmCleanVersion(dep.Version)
				out = append(out, Dependency{
					Name:           name,
					Version:        version,
					PURL:           NpmPURL(name, version),
					PackageManager: "pnpm",
					DependencyType: group.kind,
					SourcePath:     path,
					PackagePath:    filepath.ToSlash(filepath.Join(importerPath, "node_modules", name)),
				})
			}
		}
	}
	return out
}

func dependenciesFromPnpmPackages(path string, packages map[string]pnpmPackage) []Dependency {
	out := []Dependency{}
	for _, key := range sortedMapKeys(packages) {
		name, version, ok := parsePnpmPackageKey(key)
		if !ok {
			continue
		}
		pkg := packages[key]
		depType := "transitive"
		if pkg.Dev {
			depType = "dev"
		}
		if pkg.Optional {
			depType = "optional"
		}
		out = append(out, Dependency{
			Name:           name,
			Version:        version,
			PURL:           NpmPURL(name, version),
			PackageManager: "pnpm",
			DependencyType: depType,
			SourcePath:     path,
			PackagePath:    "node_modules/.pnpm/" + strings.TrimPrefix(key, "/"),
			Integrity:      pkg.Resolution.Integrity,
			Resolved:       pkg.Resolution.Tarball,
		})
	}
	return out
}

func parsePnpmPackageKey(key string) (string, string, bool) {
	key = strings.TrimPrefix(strings.TrimSpace(key), "/")
	if key == "" {
		return "", "", false
	}
	if before, _, ok := strings.Cut(key, "("); ok {
		key = before
	}
	idx := strings.LastIndex(key, "@")
	if idx <= 0 || idx == len(key)-1 {
		return "", "", false
	}
	name := key[:idx]
	version := pnpmCleanVersion(key[idx+1:])
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}

func pnpmCleanVersion(value string) string {
	value = strings.TrimSpace(value)
	if before, _, ok := strings.Cut(value, "("); ok {
		value = before
	}
	return value
}
