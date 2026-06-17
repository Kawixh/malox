// Package platform contains small cross-platform helpers used at the app boundary.
package platform

import (
	"fmt"
	"os"
	"path/filepath"
)

// DefaultCacheDir returns Malox's per-user cache directory.
func DefaultCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("find user cache dir: %w", err)
	}
	return filepath.Join(base, "malox"), nil
}

// DefaultStateDir returns the default project-local Malox state directory.
func DefaultStateDir(root string) string {
	return filepath.Join(root, ".malox")
}

// ResolvePath cleans path and resolves relative values against workDir.
func ResolvePath(workDir, path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	if workDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("find working directory: %w", err)
		}
		workDir = wd
	}
	return filepath.Clean(filepath.Join(workDir, path)), nil
}
