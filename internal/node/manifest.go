package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
)

type manifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	PackageManager       string            `json:"packageManager"`
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
	scripts := make([]PackageScript, 0, len(doc.Scripts))
	for _, scriptName := range sortedMapKeys(doc.Scripts) {
		scripts = append(scripts, PackageScript{
			PackageName:    name,
			PackageVersion: version,
			PURL:           purl,
			PackageManager: "package.json",
			SourcePath:     path,
			PackagePath:    packagePath,
			ScriptName:     scriptName,
			Command:        doc.Scripts[scriptName],
		})
	}
	return scripts
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
