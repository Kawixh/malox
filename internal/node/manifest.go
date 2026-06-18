package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

type manifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	PackageManager       string            `json:"packageManager"`
	Author               json.RawMessage   `json:"author"`
	Maintainer           json.RawMessage   `json:"maintainer"`
	Maintainers          json.RawMessage   `json:"maintainers"`
	Contributors         json.RawMessage   `json:"contributors"`
	Publisher            json.RawMessage   `json:"publisher"`
	Scripts              map[string]string `json:"scripts"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

func parseManifest(path string, data []byte) (manifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	var doc manifest
	if err := decoder.Decode(&doc); err != nil {
		return manifest{}, fmt.Errorf("parse package manifest: %w", err)
	}
	return doc, nil
}

func dependenciesFromManifest(path string, doc manifest) []Dependency {
	out := []Dependency{}
	for _, group := range []struct {
		kind string
		deps map[string]string
	}{
		{kind: "dependencies", deps: doc.Dependencies},
		{kind: "dev_dependencies", deps: doc.DevDependencies},
		{kind: "optional_dependencies", deps: doc.OptionalDependencies},
		{kind: "peer_dependencies", deps: doc.PeerDependencies},
	} {
		names := sortedMapKeys(group.deps)
		for _, name := range names {
			version := group.deps[name]
			out = append(out, Dependency{
				Name:           name,
				Version:        version,
				PURL:           NpmPURL(name, version),
				PackageManager: "package.json",
				DependencyType: group.kind,
				SourcePath:     path,
			})
		}
	}
	return out
}

func packageScriptsFromManifest(path string, doc manifest) []PackageScript {
	if len(doc.Scripts) == 0 {
		return []PackageScript{}
	}

	name := doc.Name
	version := doc.Version
	if name == "" {
		if owner := PackageOwner(path); owner != "" {
			name = owner
		}
	}

	packagePath := packageDirFromManifest(path)
	purl := NpmPURL(name, version)
	maintainers := peopleFromManifest(doc)
	scripts := make([]PackageScript, 0, len(doc.Scripts))
	for _, scriptName := range sortedMapKeys(doc.Scripts) {
		scripts = append(scripts, PackageScript{
			PackageName:    name,
			PackageVersion: version,
			PURL:           purl,
			Maintainers:    maintainers,
			PackageManager: "package.json",
			SourcePath:     path,
			PackagePath:    packagePath,
			ScriptName:     scriptName,
			Command:        doc.Scripts[scriptName],
		})
	}
	return scripts
}

func peopleFromManifest(doc manifest) []string {
	people := []string{}
	for _, raw := range []json.RawMessage{
		doc.Author,
		doc.Maintainer,
		doc.Maintainers,
		doc.Contributors,
		doc.Publisher,
	} {
		people = append(people, parsePeople(raw)...)
	}
	return uniqueSortedStrings(people)
}

func parsePeople(raw json.RawMessage) []string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil
	}

	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		text = strings.TrimSpace(text)
		if text == "" {
			return nil
		}
		return []string{text}
	}

	var object struct {
		Name  string `json:"name"`
		Email string `json:"email"`
		URL   string `json:"url"`
	}
	if err := json.Unmarshal(raw, &object); err == nil {
		values := []string{}
		for _, value := range []string{object.Name, object.Email, object.URL} {
			value = strings.TrimSpace(value)
			if value != "" {
				values = append(values, value)
			}
		}
		return values
	}

	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil
	}
	people := []string{}
	for _, item := range items {
		people = append(people, parsePeople(item)...)
	}
	return people
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	slices.Sort(values)
	out := values[:0]
	var previous string
	for i, value := range values {
		if i > 0 && strings.EqualFold(value, previous) {
			continue
		}
		out = append(out, value)
		previous = value
	}
	return out
}

func readJSONStrict(r io.Reader, target any) error {
	decoder := json.NewDecoder(r)
	decoder.UseNumber()
	return decoder.Decode(target)
}

func sortedMapKeys[V any](m map[string]V) []string {
	if len(m) == 0 {
		return []string{}
	}
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
