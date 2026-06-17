package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

type denoConfig struct {
	Imports map[string]string `json:"imports"`
	Tasks   map[string]string `json:"tasks"`
}

type denoLock struct {
	Version  int                        `json:"version"`
	Packages map[string]denoLockPackage `json:"packages"`
	Remote   map[string]json.RawMessage `json:"remote"`
}

type denoLockPackage struct {
	Integrity    string   `json:"integrity"`
	Dependencies []string `json:"dependencies"`
}

func parseDenoConfig(path string, data []byte) ([]Dependency, []PackageScript, error) {
	var cfg denoConfig
	if err := readJSONStrict(bytes.NewReader(data), &cfg); err != nil {
		return nil, nil, fmt.Errorf("parse deno config: %w", err)
	}

	deps := []Dependency{}
	for _, name := range sortedMapKeys(cfg.Imports) {
		source := cfg.Imports[name]
		depName, version := parseDenoSpecifier(name, source)
		if depName == "" {
			continue
		}
		purl := DenoPURL(depName, version)
		if strings.HasPrefix(source, "npm:") || strings.HasPrefix(name, "npm:") {
			purl = NpmPURL(depName, version)
		}
		deps = append(deps, Dependency{
			Name:           depName,
			Version:        version,
			PURL:           purl,
			PackageManager: "deno",
			DependencyType: "imports",
			SourcePath:     path,
			Resolved:       source,
		})
	}

	scripts := []PackageScript{}
	for _, task := range sortedMapKeys(cfg.Tasks) {
		scripts = append(scripts, PackageScript{
			PackageManager: "deno",
			SourcePath:     path,
			ScriptName:     task,
			Command:        cfg.Tasks[task],
		})
	}
	return deps, scripts, nil
}

func parseDenoLock(path string, data []byte) ([]Dependency, error) {
	var lock denoLock
	if err := readJSONStrict(bytes.NewReader(data), &lock); err != nil {
		return nil, fmt.Errorf("parse deno lockfile: %w", err)
	}

	out := []Dependency{}
	for _, raw := range sortedMapKeys(lock.Packages) {
		name, version := parseDenoPackageKey(raw)
		if name == "" {
			continue
		}
		pkg := lock.Packages[raw]
		purl := DenoPURL(name, version)
		if strings.HasPrefix(raw, "npm:") {
			purl = NpmPURL(name, version)
		}
		out = append(out, Dependency{
			Name:           name,
			Version:        version,
			PURL:           purl,
			PackageManager: "deno",
			DependencyType: "locked",
			SourcePath:     path,
			Integrity:      pkg.Integrity,
			Resolved:       raw,
		})
	}
	return out, nil
}

func parseDenoSpecifier(alias, source string) (string, string) {
	if strings.HasPrefix(source, "npm:") {
		return parseDenoPackageKey(strings.TrimPrefix(source, "npm:"))
	}
	if strings.HasPrefix(alias, "npm:") {
		return parseDenoPackageKey(strings.TrimPrefix(alias, "npm:"))
	}
	return strings.TrimSuffix(alias, "/"), ""
}

func parseDenoPackageKey(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	if strings.HasPrefix(value, "npm:") {
		value = strings.TrimPrefix(value, "npm:")
	}
	idx := strings.LastIndex(value, "@")
	if idx <= 0 || idx == len(value)-1 {
		return value, ""
	}
	return value[:idx], value[idx+1:]
}
