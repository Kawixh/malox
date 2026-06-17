package node

import (
	"path/filepath"
	"strings"
)

// PackageOwner returns the owning npm package name for common node_modules layouts.
func PackageOwner(rel string) string {
	owner, _ := PackageOwnerPath(rel)
	return owner
}

// PackageOwnerPath returns the package owner and package root path for rel.
func PackageOwnerPath(rel string) (string, string) {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "node_modules" || i+1 >= len(parts) {
			continue
		}

		name := parts[i+1]
		end := i + 2
		if strings.HasPrefix(name, "@") && i+2 < len(parts) {
			name += "/" + parts[i+2]
			end = i + 3
		}
		if name == ".pnpm" || name == ".store" || name == ".cache" {
			continue
		}
		return name, strings.Join(parts[:end], "/")
	}
	return "", ""
}

func packageDirFromManifest(path string) string {
	path = filepath.ToSlash(path)
	if !strings.HasSuffix(path, "/package.json") {
		return ""
	}
	return strings.TrimSuffix(path, "/package.json")
}
