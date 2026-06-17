// Package fileid contains filesystem identity helpers for scan snapshots.
package fileid

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// ErrFileTooLarge reports that a file exceeded the configured scan read limit.
var ErrFileTooLarge = errors.New("file too large")

// Metadata describes stable filesystem identity fields for one path.
type Metadata struct {
	Path          string
	RelativePath  string
	Size          int64
	ModifiedTime  time.Time
	Mode          fs.FileMode
	Permissions   string
	Symlink       bool
	SymlinkTarget string
}

// NormalizeRoot resolves root into a clean absolute path with symlinks evaluated.
func NormalizeRoot(root string) (string, error) {
	if root == "" {
		return "", errors.New("root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("make root absolute: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve root symlinks: %w", err)
	}
	return filepath.Clean(resolved), nil
}

// SnapshotPath returns a slash-separated project-relative path for path.
func SnapshotPath(root, path string) (string, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", fmt.Errorf("make snapshot path relative: %w", err)
	}
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("path escapes root: %q", rel)
	}
	return filepath.ToSlash(rel), nil
}

// Inspect collects path metadata without following symlinks.
func Inspect(root, path string) (Metadata, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Metadata{}, fmt.Errorf("stat path: %w", err)
	}

	rel, err := SnapshotPath(root, path)
	if err != nil {
		return Metadata{}, err
	}

	meta := Metadata{
		Path:         path,
		RelativePath: rel,
		Size:         info.Size(),
		ModifiedTime: info.ModTime().UTC(),
		Mode:         info.Mode(),
		Permissions:  PermissionString(info.Mode()),
		Symlink:      info.Mode()&fs.ModeSymlink != 0,
	}
	if meta.Symlink {
		target, err := os.Readlink(path)
		if err != nil {
			return Metadata{}, fmt.Errorf("read symlink: %w", err)
		}
		meta.SymlinkTarget = target
	}
	return meta, nil
}

// PermissionString formats the permission bits as a four-digit octal string.
func PermissionString(mode fs.FileMode) string {
	return fmt.Sprintf("%04o", mode.Perm())
}

// HashFile computes a SHA-256 hash for rel inside root without reading past maxSize.
func HashFile(ctx context.Context, root, rel string, maxSize int64) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("hash file: %w", err)
	}
	if maxSize < 1 {
		return "", errors.New("max file size must be greater than 0")
	}
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("unsafe relative path %q", rel)
	}

	f, err := os.OpenInRoot(root, filepath.FromSlash(rel))
	if err != nil {
		return "", fmt.Errorf("open project file %q: %w", rel, err)
	}
	// This is a read-only scan path; close errors cannot improve recovery beyond
	// the open/read errors that are returned with path context below.
	defer func() {
		_ = f.Close()
	}()

	sum := sha256.New()
	if err := copyBounded(ctx, sum, f, maxSize); err != nil {
		return "", fmt.Errorf("hash project file %q: %w", rel, err)
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

func copyBounded(ctx context.Context, dst hash.Hash, src io.Reader, maxSize int64) error {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		n, err := src.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > maxSize {
				return fmt.Errorf("%w: exceeds %d bytes", ErrFileTooLarge, maxSize)
			}
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
