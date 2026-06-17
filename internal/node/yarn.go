package node

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

func parseYarnLock(path string, data []byte) ([]Dependency, []Warning) {
	if bytes.Contains(data, []byte("__metadata:")) {
		deps, err := parseYarnBerryLock(path, data)
		if err != nil {
			return nil, []Warning{{
				Path:    path,
				Code:    "yarn_lock_parse_error",
				Message: err.Error(),
			}}
		}
		return deps, []Warning{{
			Path:    path,
			Code:    "yarn_berry_partial_support",
			Message: "yarn v2+ lockfile parsing is partial in this milestone",
		}}
	}

	deps, err := parseYarnClassicLock(path, data)
	if err != nil {
		return nil, []Warning{{
			Path:    path,
			Code:    "yarn_lock_parse_error",
			Message: err.Error(),
		}}
	}
	return deps, nil
}

func parseYarnClassicLock(path string, data []byte) ([]Dependency, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var current []string
	fields := map[string]string{}
	out := []Dependency{}

	flush := func() {
		if len(current) == 0 || fields["version"] == "" {
			current = nil
			fields = map[string]string{}
			return
		}
		version := fields["version"]
		for _, selector := range current {
			name := packageNameFromSelector(selector)
			if name == "" {
				continue
			}
			out = append(out, Dependency{
				Name:           name,
				Version:        version,
				PURL:           NpmPURL(name, version),
				PackageManager: "yarn",
				DependencyType: "locked",
				SourcePath:     path,
				PackagePath:    "node_modules/" + name,
				Integrity:      fields["integrity"],
				Resolved:       fields["resolved"],
			})
		}
		current = nil
		fields = map[string]string{}
	}

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(trimmed, ":") {
			flush()
			current = splitYarnSelectors(strings.TrimSuffix(trimmed, ":"))
			continue
		}
		if len(current) == 0 {
			continue
		}
		key, value, ok := strings.Cut(trimmed, " ")
		if !ok {
			continue
		}
		value = strings.Trim(value, `"`)
		switch key {
		case "version", "resolved", "integrity":
			fields[key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read yarn lockfile: %w", err)
	}
	flush()
	return dedupeDependencies(out), nil
}

type yarnBerryLock map[string]struct {
	Version    string `yaml:"version"`
	Resolution string `yaml:"resolution"`
	Checksum   string `yaml:"checksum"`
}

func parseYarnBerryLock(path string, data []byte) ([]Dependency, error) {
	var lock yarnBerryLock
	if err := yamlUnmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse yarn berry lockfile: %w", err)
	}
	out := []Dependency{}
	for _, selector := range sortedMapKeys(lock) {
		if selector == "__metadata" {
			continue
		}
		item := lock[selector]
		name := packageNameFromSelector(selector)
		version := item.Version
		if version == "" {
			_, version, _ = parseYarnResolution(item.Resolution)
		}
		if name == "" || version == "" {
			continue
		}
		out = append(out, Dependency{
			Name:           name,
			Version:        version,
			PURL:           NpmPURL(name, version),
			PackageManager: "yarn",
			DependencyType: "locked",
			SourcePath:     path,
			PackagePath:    "node_modules/" + name,
			Integrity:      item.Checksum,
			Resolved:       item.Resolution,
		})
	}
	return dedupeDependencies(out), nil
}

func splitYarnSelectors(value string) []string {
	parts := []string{}
	var b strings.Builder
	inQuote := false
	for _, r := range value {
		switch r {
		case '"':
			inQuote = !inQuote
			b.WriteRune(r)
		case ',':
			if inQuote {
				b.WriteRune(r)
				continue
			}
			parts = append(parts, strings.Trim(strings.TrimSpace(b.String()), `"`))
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		parts = append(parts, strings.Trim(strings.TrimSpace(b.String()), `"`))
	}
	return parts
}

func packageNameFromSelector(selector string) string {
	selector = strings.Trim(strings.TrimSpace(selector), `"`)
	if selector == "" {
		return ""
	}
	if strings.HasPrefix(selector, "@") {
		slash := strings.Index(selector, "/")
		if slash < 0 {
			return ""
		}
		at := strings.Index(selector[slash:], "@")
		if at < 0 {
			return selector
		}
		return selector[:slash+at]
	}
	at := strings.Index(selector, "@")
	if at < 0 {
		return selector
	}
	return selector[:at]
}

func parseYarnResolution(value string) (string, string, bool) {
	name, rest, ok := strings.Cut(value, "@npm:")
	if !ok {
		return "", "", false
	}
	return name, rest, true
}
