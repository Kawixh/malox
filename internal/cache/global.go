package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"malox/internal/rules"
)

const (
	// GlobalIndexSchemaVersion is the schema used by index-v1.json.
	GlobalIndexSchemaVersion = "malox.cache.index.v1"
	// SourceMetadataSchemaVersion is the schema used by per-source metadata.
	SourceMetadataSchemaVersion = "malox.cache.source.metadata.v1"
	// CacheReportSchemaVersion is the schema used by cache command JSON output.
	CacheReportSchemaVersion = "malox.cache.report.v1"
)

var (
	// ErrCleanAllRequiresForce reports that a full cache clean needs confirmation.
	ErrCleanAllRequiresForce = errors.New("cache clean --all requires --force")
	// ErrSourceMetadataInvalid reports malformed source metadata.
	ErrSourceMetadataInvalid = errors.New("source metadata is invalid")
)

// GlobalStore reads and writes the per-user Malox cache.
type GlobalStore struct {
	dir string
	now func() time.Time
}

// SourceMetadata records freshness and provenance for one cached source.
type SourceMetadata struct {
	SchemaVersion string    `json:"schema_version"`
	Source        string    `json:"source"`
	FetchedAt     time.Time `json:"fetched_at"`
	ETag          string    `json:"etag"`
	LastModified  string    `json:"last_modified"`
	License       string    `json:"license"`
	SourceType    string    `json:"source_type"`
	TTL           string    `json:"ttl"`
	RecordCount   int       `json:"record_count"`
}

// GlobalIndex is the root cache index document.
type GlobalIndex struct {
	SchemaVersion string            `json:"schema_version"`
	UpdatedAt     time.Time         `json:"updated_at"`
	Sources       []SourceMetadata  `json:"sources"`
	TTLs          map[string]string `json:"ttls"`
}

// UpdateOptions configures a cache update.
type UpdateOptions struct {
	Offline bool
	Source  string
	Now     time.Time
}

// CleanOptions configures a cache cleanup.
type CleanOptions struct {
	Expired bool
	All     bool
	Force   bool
	Now     time.Time
}

// CommandReport is the machine-readable output for cache commands.
type CommandReport struct {
	SchemaVersion string         `json:"schema_version"`
	Operation     string         `json:"operation"`
	Offline       bool           `json:"offline,omitempty"`
	Sources       []SourceChange `json:"sources"`
	Warnings      []string       `json:"warnings"`
}

// SourceChange describes the changed records for one cache source.
type SourceChange struct {
	Source         string   `json:"source"`
	RecordsChanged int      `json:"records_changed"`
	BytesWritten   int64    `json:"bytes_written,omitempty"`
	BytesRemoved   int64    `json:"bytes_removed,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
}

type sourceConfig struct {
	name       string
	sourceType string
	ttl        time.Duration
	license    string
	dirs       []string
}

var globalSourceConfigs = []sourceConfig{
	{
		name:       "osv",
		sourceType: "vulnerability",
		ttl:        24 * time.Hour,
		license:    "varies by OSV record",
		dirs:       []string{"querybatch", "vulns"},
	},
	{
		name:       "github-advisory-database",
		sourceType: "vulnerability",
		ttl:        24 * time.Hour,
		license:    "GitHub Advisory Database terms",
		dirs:       []string{"records"},
	},
	{
		name:       "openssf-malicious-packages",
		sourceType: "malware",
		ttl:        24 * time.Hour,
		license:    "OpenSSF malicious-packages license",
		dirs:       []string{"records", "by-purl", "by-package"},
	},
	{
		name:       "npm",
		sourceType: "registry",
		ttl:        72 * time.Hour,
		license:    "npm registry metadata terms",
		dirs:       []string{"packuments", "versions", "audit-bulk", "keys"},
	},
	{
		name:       "deps-dev",
		sourceType: "repository",
		ttl:        7 * 24 * time.Hour,
		license:    "deps.dev API terms",
		dirs:       []string{"packages", "versions", "advisories", "hash-query"},
	},
	{
		name:       "openssf-package-analysis",
		sourceType: "behavior",
		ttl:        24 * time.Hour,
		license:    "OpenSSF package-analysis license",
		dirs:       []string{"package-behavior"},
	},
	{
		name:       "scorecard",
		sourceType: "repository",
		ttl:        7 * 24 * time.Hour,
		license:    "OpenSSF Scorecard license",
		dirs:       []string{"repositories"},
	},
	{
		name:       "builtin-rules",
		sourceType: "rules",
		ttl:        24 * time.Hour,
		license:    "Malox project license",
	},
}

// NewGlobalStore returns a global cache store rooted at cacheDir.
func NewGlobalStore(cacheDir string) (GlobalStore, error) {
	if strings.TrimSpace(cacheDir) == "" {
		return GlobalStore{}, errors.New("cache dir is required")
	}
	absolute, err := filepath.Abs(cacheDir)
	if err != nil {
		return GlobalStore{}, fmt.Errorf("resolve cache dir: %w", err)
	}
	return GlobalStore{dir: filepath.Clean(absolute), now: func() time.Time {
		return time.Now().UTC()
	}}, nil
}

// Dir returns the global cache root directory.
func (s GlobalStore) Dir() string {
	return s.dir
}

// Ensure creates the expected global cache layout and root index if needed.
func (s GlobalStore) Ensure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("ensure global cache: %w", err)
	}
	for _, dir := range s.layoutDirs() {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create cache dir %q: %w", dir, err)
		}
	}

	indexPath := filepath.Join(s.dir, "index-v1.json")
	if _, err := os.Stat(indexPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat cache index: %w", err)
	}
	return s.writeIndex(ctx, GlobalIndex{
		SchemaVersion: GlobalIndexSchemaVersion,
		UpdatedAt:     s.clock(),
		Sources:       []SourceMetadata{},
		TTLs:          ttlStrings(),
	})
}

// Update refreshes local cache metadata and bundled rule documents.
func (s GlobalStore) Update(ctx context.Context, opts UpdateOptions) (CommandReport, error) {
	if err := s.Ensure(ctx); err != nil {
		return CommandReport{}, err
	}

	now := opts.Now
	if now.IsZero() {
		now = s.clock()
	}
	report := CommandReport{
		SchemaVersion: CacheReportSchemaVersion,
		Operation:     "update",
		Offline:       opts.Offline,
		Sources:       []SourceChange{},
		Warnings:      []string{},
	}
	if opts.Offline {
		report.Warnings = append(report.Warnings, "offline mode: remote source updates skipped")
	}
	source := strings.TrimSpace(opts.Source)
	if source != "" && source != "builtin-rules" {
		return report, nil
	}

	change, metadata, err := s.updateBuiltinRules(ctx, now)
	if err != nil {
		return CommandReport{}, err
	}
	report.Sources = append(report.Sources, change)

	index := GlobalIndex{
		SchemaVersion: GlobalIndexSchemaVersion,
		UpdatedAt:     now,
		Sources:       []SourceMetadata{metadata},
		TTLs:          ttlStrings(),
	}
	if err := s.writeIndex(ctx, index); err != nil {
		return CommandReport{}, err
	}
	return report, nil
}

// Clean removes expired records or, with explicit force, all cache records.
func (s GlobalStore) Clean(ctx context.Context, opts CleanOptions) (CommandReport, error) {
	if err := s.Ensure(ctx); err != nil {
		return CommandReport{}, err
	}
	if opts.All && !opts.Force {
		return CommandReport{}, ErrCleanAllRequiresForce
	}
	if !opts.All && !opts.Expired {
		opts.Expired = true
	}

	now := opts.Now
	if now.IsZero() {
		now = s.clock()
	}

	report := CommandReport{
		SchemaVersion: CacheReportSchemaVersion,
		Operation:     "clean",
		Sources:       []SourceChange{},
		Warnings:      []string{},
	}
	if opts.All {
		removed, err := dirSize(s.dir)
		if err != nil {
			return CommandReport{}, err
		}
		if err := os.RemoveAll(s.dir); err != nil {
			return CommandReport{}, fmt.Errorf("remove cache dir: %w", err)
		}
		if err := s.Ensure(ctx); err != nil {
			return CommandReport{}, err
		}
		report.Sources = append(report.Sources, SourceChange{
			Source:         "all",
			RecordsChanged: 1,
			BytesRemoved:   removed,
		})
		return report, nil
	}

	change, warnings, err := s.cleanExpired(ctx, now)
	if err != nil {
		return CommandReport{}, err
	}
	report.Sources = append(report.Sources, change...)
	report.Warnings = append(report.Warnings, warnings...)
	return report, nil
}

// ReadSourceMetadata reads and validates a source metadata file.
func ReadSourceMetadata(path string) (SourceMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SourceMetadata{}, err
	}
	var metadata SourceMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return SourceMetadata{}, fmt.Errorf("parse source metadata: %w", err)
	}
	if err := ValidateSourceMetadata(metadata); err != nil {
		return SourceMetadata{}, err
	}
	return metadata, nil
}

// ValidateSourceMetadata checks the source metadata schema.
func ValidateSourceMetadata(metadata SourceMetadata) error {
	problems := []string{}
	if metadata.SchemaVersion != SourceMetadataSchemaVersion {
		problems = append(problems, "schema_version is invalid")
	}
	if strings.TrimSpace(metadata.Source) == "" {
		problems = append(problems, "source is required")
	}
	if metadata.FetchedAt.IsZero() {
		problems = append(problems, "fetched_at is required")
	}
	if strings.TrimSpace(metadata.License) == "" {
		problems = append(problems, "license is required")
	}
	if strings.TrimSpace(metadata.SourceType) == "" {
		problems = append(problems, "source_type is required")
	}
	if _, err := time.ParseDuration(metadata.TTL); err != nil {
		problems = append(problems, "ttl is invalid")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrSourceMetadataInvalid, strings.Join(problems, "; "))
	}
	return nil
}

func (s GlobalStore) updateBuiltinRules(ctx context.Context, now time.Time) (SourceChange, SourceMetadata, error) {
	docs, err := rules.BuiltinDocuments()
	if err != nil {
		return SourceChange{}, SourceMetadata{}, err
	}

	var recordsChanged int
	var bytesWritten int64
	for _, doc := range docs {
		if err := ctx.Err(); err != nil {
			return SourceChange{}, SourceMetadata{}, fmt.Errorf("update builtin rules: %w", err)
		}
		sum := sha256.Sum256(doc.Data)
		name := hex.EncodeToString(sum[:]) + ".json"
		path := filepath.Join(s.dir, "rules", "builtin", name)
		if _, err := os.Stat(path); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return SourceChange{}, SourceMetadata{}, fmt.Errorf("stat builtin rule %q: %w", doc.Name, err)
		}
		if err := writeFileAtomic(ctx, path, append(slices.Clone(doc.Data), '\n'), 0o644); err != nil {
			return SourceChange{}, SourceMetadata{}, fmt.Errorf("write builtin rule %q: %w", doc.Name, err)
		}
		recordsChanged++
		bytesWritten += int64(len(doc.Data) + 1)
	}

	cfg := sourceConfigByName("builtin-rules")
	metadata := SourceMetadata{
		SchemaVersion: SourceMetadataSchemaVersion,
		Source:        "builtin-rules",
		FetchedAt:     now,
		ETag:          "",
		LastModified:  "",
		License:       cfg.license,
		SourceType:    cfg.sourceType,
		TTL:           cfg.ttl.String(),
		RecordCount:   len(docs),
	}
	data, err := marshalJSON(metadata)
	if err != nil {
		return SourceChange{}, SourceMetadata{}, err
	}
	if err := writeFileAtomic(ctx, filepath.Join(s.dir, "rules", "builtin", "metadata.json"), data, 0o644); err != nil {
		return SourceChange{}, SourceMetadata{}, fmt.Errorf("write builtin metadata: %w", err)
	}
	bytesWritten += int64(len(data))
	if recordsChanged == 0 {
		recordsChanged = 1
	}

	return SourceChange{
		Source:         "builtin-rules",
		RecordsChanged: recordsChanged,
		BytesWritten:   bytesWritten,
	}, metadata, nil
}

func (s GlobalStore) cleanExpired(ctx context.Context, now time.Time) ([]SourceChange, []string, error) {
	changes := []SourceChange{}
	warnings := []string{}
	metadataPaths := []string{}
	err := filepath.WalkDir(s.dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if entry.IsDir() || entry.Name() != "metadata.json" {
			return nil
		}
		metadataPaths = append(metadataPaths, path)
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("find cache metadata: %w", err)
	}

	for _, path := range metadataPaths {
		metadata, err := ReadSourceMetadata(path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skip invalid metadata %q: %v", filepath.ToSlash(path), err))
			continue
		}
		ttl, err := time.ParseDuration(metadata.TTL)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skip invalid ttl for %s: %v", metadata.Source, err))
			continue
		}
		if !now.After(metadata.FetchedAt.Add(ttl)) {
			continue
		}

		sourceDir := filepath.Dir(path)
		removed, err := dirSize(sourceDir)
		if err != nil {
			return nil, nil, fmt.Errorf("measure expired source %q: %w", metadata.Source, err)
		}
		if err := os.RemoveAll(sourceDir); err != nil {
			return nil, nil, fmt.Errorf("remove expired source %q: %w", metadata.Source, err)
		}
		changes = append(changes, SourceChange{
			Source:         metadata.Source,
			RecordsChanged: max(1, metadata.RecordCount),
			BytesRemoved:   removed,
		})
	}
	if err := s.Ensure(ctx); err != nil {
		return nil, nil, err
	}
	if len(changes) == 0 {
		changes = append(changes, SourceChange{Source: "expired", RecordsChanged: 0})
	}
	return changes, warnings, nil
}

func (s GlobalStore) writeIndex(ctx context.Context, index GlobalIndex) error {
	data, err := marshalJSON(index)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(ctx, filepath.Join(s.dir, "index-v1.json"), data, 0o644); err != nil {
		return fmt.Errorf("write cache index: %w", err)
	}
	return nil
}

func (s GlobalStore) layoutDirs() []string {
	dirs := []string{
		s.dir,
		filepath.Join(s.dir, "sources"),
		filepath.Join(s.dir, "rules", "builtin"),
		filepath.Join(s.dir, "rules", "downloaded"),
		filepath.Join(s.dir, "decoded-payloads", "sha256"),
	}
	for _, cfg := range globalSourceConfigs {
		if cfg.name == "builtin-rules" {
			continue
		}
		sourceDir := filepath.Join(s.dir, "sources", cfg.name)
		dirs = append(dirs, sourceDir)
		for _, subdir := range cfg.dirs {
			dirs = append(dirs, filepath.Join(sourceDir, subdir))
		}
	}
	return dirs
}

func (s GlobalStore) clock() time.Time {
	if s.now == nil {
		return time.Now().UTC()
	}
	return s.now().UTC()
}

func ttlStrings() map[string]string {
	out := map[string]string{}
	for _, cfg := range globalSourceConfigs {
		out[cfg.sourceType] = cfg.ttl.String()
	}
	return out
}

func sourceConfigByName(name string) sourceConfig {
	for _, cfg := range globalSourceConfigs {
		if cfg.name == name {
			return cfg
		}
	}
	return sourceConfig{
		name:       name,
		sourceType: "unknown",
		ttl:        24 * time.Hour,
		license:    "unknown",
	}
}

func marshalJSON(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal cache json: %w", err)
	}
	return append(data, '\n'), nil
}

func dirSize(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	return total, err
}
