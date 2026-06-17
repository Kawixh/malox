package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tailscale/hujson"
)

type bunLock struct {
	Workspaces map[string]struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	} `json:"workspaces"`
	Packages map[string]json.RawMessage `json:"packages"`
}

func parseBunLock(path string, data []byte) ([]Dependency, error) {
	standard, err := hujson.Standardize(data)
	if err != nil {
		return nil, fmt.Errorf("standardize bun lockfile: %w", err)
	}

	var lock bunLock
	if err := readJSONStrict(bytes.NewReader(standard), &lock); err != nil {
		return nil, fmt.Errorf("parse bun lockfile: %w", err)
	}

	out := []Dependency{}
	for _, workspace := range sortedMapKeys(lock.Workspaces) {
		item := lock.Workspaces[workspace]
		for _, group := range []struct {
			kind string
			deps map[string]string
		}{
			{kind: "dependencies", deps: item.Dependencies},
			{kind: "dev_dependencies", deps: item.DevDependencies},
			{kind: "optional_dependencies", deps: item.OptionalDependencies},
		} {
			for _, name := range sortedMapKeys(group.deps) {
				version := group.deps[name]
				out = append(out, Dependency{
					Name:           name,
					Version:        version,
					PURL:           NpmPURL(name, version),
					PackageManager: "bun",
					DependencyType: group.kind,
					SourcePath:     path,
					PackagePath:    "node_modules/" + name,
				})
			}
		}
	}

	for _, name := range sortedMapKeys(lock.Packages) {
		dep := dependencyFromBunPackage(path, name, lock.Packages[name])
		if dep.Name == "" {
			continue
		}
		out = append(out, dep)
	}

	return dedupeDependencies(out), nil
}

func dependencyFromBunPackage(path, name string, raw json.RawMessage) Dependency {
	var parts []any
	if err := json.Unmarshal(raw, &parts); err != nil || len(parts) == 0 {
		return Dependency{}
	}

	version := ""
	if first, ok := parts[0].(string); ok {
		version = versionFromBunResolution(name, first)
	}
	if version == "" {
		return Dependency{}
	}
	return Dependency{
		Name:           name,
		Version:        version,
		PURL:           NpmPURL(name, version),
		PackageManager: "bun",
		DependencyType: "locked",
		SourcePath:     path,
		PackagePath:    "node_modules/" + name,
		Resolved:       string(raw),
	}
}

func versionFromBunResolution(name, value string) string {
	prefix := name + "@"
	if !strings.HasPrefix(value, prefix) {
		return ""
	}
	version := strings.TrimPrefix(value, prefix)
	if before, _, ok := strings.Cut(version, "#"); ok {
		version = before
	}
	if before, _, ok := strings.Cut(version, "?"); ok {
		version = before
	}
	return version
}
