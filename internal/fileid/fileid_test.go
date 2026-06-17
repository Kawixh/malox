package fileid

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotPathNormalizesToSlashSeparatedLocalPath(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "src", "index.js")

	got, err := SnapshotPath(root, path)
	if err != nil {
		t.Fatalf("SnapshotPath() error = %v", err)
	}
	if got != "src/index.js" {
		t.Fatalf("SnapshotPath() = %q, want %q", got, "src/index.js")
	}
}

func TestSnapshotPathRejectsEscapes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "..", "outside.js")

	_, err := SnapshotPath(root, path)
	if err == nil {
		t.Fatal("SnapshotPath() error = nil, want escape error")
	}
}

func TestHashFileStreamsSHA256WithinLimit(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := HashFile(t.Context(), root, "package.json", 1024)
	if err != nil {
		t.Fatalf("HashFile() error = %v", err)
	}
	sum := sha256.Sum256([]byte("{}\n"))
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("HashFile() = %q, want %q", got, want)
	}
}

func TestHashFileRejectsOversizedFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "large.txt"), []byte("12345"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := HashFile(t.Context(), root, "large.txt", 4)
	if !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("HashFile() error = %v, want ErrFileTooLarge", err)
	}
}
