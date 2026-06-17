package node

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestBuildNpmInventory(t *testing.T) {
	root := fixtureRoot(t, "npm")
	inv, err := Build(t.Context(), BuildOptions{
		Root: root,
		Files: []FileRef{
			{Path: "package.json", SHA256: "manifest", Status: "scanned"},
			{Path: "package-lock.json", SHA256: "lock", Status: "scanned"},
			{Path: "node_modules/left-pad/package.json", SHA256: "pkg", Status: "scanned"},
		},
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if inv.SchemaVersion != SchemaVersion {
		t.Fatalf("SchemaVersion = %q, want %q", inv.SchemaVersion, SchemaVersion)
	}
	if inv.Summary.ManifestCount != 2 {
		t.Fatalf("ManifestCount = %d, want 2", inv.Summary.ManifestCount)
	}
	if inv.Summary.LockfileCount != 1 {
		t.Fatalf("LockfileCount = %d, want 1", inv.Summary.LockfileCount)
	}
	if inv.Summary.Warnings != 0 {
		t.Fatalf("Warnings = %#v, want none", inv.Warnings)
	}

	lockDep := findDependency(t, inv, "npm", "left-pad", "node_modules/left-pad")
	if lockDep.Version != "1.3.0" {
		t.Fatalf("left-pad version = %q, want 1.3.0", lockDep.Version)
	}
	if lockDep.PURL != "pkg:npm/left-pad@1.3.0" {
		t.Fatalf("left-pad PURL = %q", lockDep.PURL)
	}
	if lockDep.Integrity != "sha512-left" || !lockDep.HasInstallScript {
		t.Fatalf("left-pad metadata = %#v", lockDep)
	}
	if lockDep.Scripts["install"] != "node install.js" {
		t.Fatalf("left-pad scripts = %#v, want install script", lockDep.Scripts)
	}

	script := findScript(t, inv, "left-pad", "install")
	if script.Command != "node install.js" {
		t.Fatalf("script command = %q", script.Command)
	}
}

func TestBuildParsesSupportedLockfiles(t *testing.T) {
	tests := []struct {
		name    string
		files   []FileRef
		manager string
		depName string
		purl    string
	}{
		{
			name: "pnpm",
			files: []FileRef{
				{Path: "package.json", Status: "scanned"},
				{Path: "pnpm-lock.yaml", Status: "scanned"},
			},
			manager: "pnpm",
			depName: "is-odd",
			purl:    "pkg:npm/is-odd@3.0.1",
		},
		{
			name: "yarn",
			files: []FileRef{
				{Path: "package.json", Status: "scanned"},
				{Path: "yarn.lock", Status: "scanned"},
			},
			manager: "yarn",
			depName: "@scope/pkg",
			purl:    "pkg:npm/%40scope/pkg@1.2.3",
		},
		{
			name: "bun",
			files: []FileRef{
				{Path: "package.json", Status: "scanned"},
				{Path: "bun.lock", Status: "scanned"},
			},
			manager: "bun",
			depName: "debug",
			purl:    "pkg:npm/debug@4.3.7",
		},
		{
			name: "deno",
			files: []FileRef{
				{Path: "deno.json", Status: "scanned"},
				{Path: "deno.lock", Status: "scanned"},
			},
			manager: "deno",
			depName: "left-pad",
			purl:    "pkg:npm/left-pad@1.3.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv, err := Build(t.Context(), BuildOptions{
				Root:  fixtureRoot(t, tt.name),
				Files: tt.files,
			})
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			dep := findDependencyByName(t, inv, tt.manager, tt.depName)
			if dep.PURL != tt.purl {
				t.Fatalf("PURL = %q, want %q for %#v", dep.PURL, tt.purl, dep)
			}
			if inv.Summary.Warnings != 0 {
				t.Fatalf("Warnings = %#v, want none", inv.Warnings)
			}
		})
	}
}

func TestBuildReportsMalformedWarnings(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, root, "package-lock.json", "{not json")

	inv, err := Build(t.Context(), BuildOptions{
		Root:  root,
		Files: []FileRef{{Path: "package-lock.json", Status: "scanned"}},
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(inv.Warnings) != 1 {
		t.Fatalf("Warnings = %#v, want one warning", inv.Warnings)
	}
	if inv.Warnings[0].Code != "npm_lock_parse_error" {
		t.Fatalf("warning code = %q, want npm_lock_parse_error", inv.Warnings[0].Code)
	}
}

func TestBuildDetectsBunLockBAsUnsupported(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, root, "bun.lockb", "binary-ish")

	inv, err := Build(t.Context(), BuildOptions{
		Root:  root,
		Files: []FileRef{{Path: "bun.lockb", Status: "scanned"}},
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(inv.Warnings) != 1 || inv.Warnings[0].Code != "bun_lockb_unsupported" {
		t.Fatalf("Warnings = %#v, want bun_lockb_unsupported", inv.Warnings)
	}
}

func TestPackageOwnerHandlesCommonLayouts(t *testing.T) {
	tests := []struct {
		path      string
		wantOwner string
		wantRoot  string
	}{
		{
			path:      "node_modules/@scope/pkg/index.js",
			wantOwner: "@scope/pkg",
			wantRoot:  "node_modules/@scope/pkg",
		},
		{
			path:      "node_modules/a/node_modules/b/index.js",
			wantOwner: "b",
			wantRoot:  "node_modules/a/node_modules/b",
		},
		{
			path:      "node_modules/.pnpm/@scope+pkg@1.2.3/node_modules/@scope/pkg/index.js",
			wantOwner: "@scope/pkg",
			wantRoot:  "node_modules/.pnpm/@scope+pkg@1.2.3/node_modules/@scope/pkg",
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			owner, root := PackageOwnerPath(tt.path)
			if owner != tt.wantOwner || root != tt.wantRoot {
				t.Fatalf("PackageOwnerPath() = %q, %q; want %q, %q", owner, root, tt.wantOwner, tt.wantRoot)
			}
		})
	}
}

func TestDetectPackageManagerSignal(t *testing.T) {
	signals := []string{}
	for _, item := range []struct {
		path  string
		isDir bool
	}{
		{path: "package.json"},
		{path: "package-lock.json"},
		{path: "pnpm-lock.yaml"},
		{path: "yarn.lock"},
		{path: "bun.lock"},
		{path: "deno.lock"},
		{path: "node_modules", isDir: true},
	} {
		signal, ok := DetectPackageManagerSignal(item.path, item.isDir)
		if ok {
			signals = append(signals, signal.Manager+":"+signal.Kind)
		}
	}

	want := []string{
		"node:manifest",
		"npm:lockfile",
		"pnpm:lockfile",
		"yarn:lockfile",
		"bun:lockfile",
		"deno:lockfile",
		"node:dependency_directory",
	}
	if !slices.Equal(signals, want) {
		t.Fatalf("signals = %#v, want %#v", signals, want)
	}
}

func fixtureRoot(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "node", name)
}

func writeFixtureFile(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func findDependency(t *testing.T, inv Inventory, manager, name, packagePath string) Dependency {
	t.Helper()
	for _, dep := range inv.Dependencies {
		if dep.PackageManager == manager && dep.Name == name && dep.PackagePath == packagePath {
			return dep
		}
	}
	t.Fatalf("dependency %s %s at %s not found in %#v", manager, name, packagePath, inv.Dependencies)
	return Dependency{}
}

func findDependencyByName(t *testing.T, inv Inventory, manager, name string) Dependency {
	t.Helper()
	for _, dep := range inv.Dependencies {
		if dep.PackageManager == manager && dep.Name == name && dep.PURL != "" {
			return dep
		}
	}
	t.Fatalf("dependency %s %s not found in %#v", manager, name, inv.Dependencies)
	return Dependency{}
}

func findScript(t *testing.T, inv Inventory, packageName, scriptName string) PackageScript {
	t.Helper()
	for _, script := range inv.PackageScripts {
		if script.PackageName == packageName && script.ScriptName == scriptName {
			return script
		}
	}
	t.Fatalf("script %s %s not found in %#v", packageName, scriptName, inv.PackageScripts)
	return PackageScript{}
}
