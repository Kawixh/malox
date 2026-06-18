// Package threat queries cache-aware threat-intelligence sources.
package threat

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"malox/internal/cache"
	"malox/internal/node"
	"malox/internal/rules"
	"malox/internal/scan"
)

const (
	SourceLocalPolicy    = "local-policy"
	SourceOSV            = "osv"
	SourceOpenSSF        = "openssf-malicious-packages"
	SourceGitHubAdvisory = "github-advisory-database"
	SourceNPM            = "npm"

	defaultOSVURL         = "https://api.osv.dev"
	defaultNPMRegistryURL = "https://registry.npmjs.org"
	defaultTimeout        = 10 * time.Second
)

// ErrRequiredSourceUnavailable reports that a required source could not answer.
var ErrRequiredSourceUnavailable = errors.New("required threat source unavailable")

// Options configures one threat-intelligence pass.
type Options struct {
	Store           cache.GlobalStore
	Offline         bool
	Sources         []string
	RequiredSources []string
	HTTPClient      *http.Client
	OSVURL          string
	NPMRegistryURL  string
	Timeout         time.Duration
	Now             func() time.Time
}

// Result contains normalized threat findings and source health.
type Result struct {
	Findings []rules.Finding
	Sources  []scan.ThreatSourceStatus
}

// Evaluate queries all configured sources for the dependency inventory.
func Evaluate(ctx context.Context, inv node.Inventory, opts Options) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("evaluate threat sources: %w", err)
	}
	opts = opts.withDefaults()
	if err := opts.Store.Ensure(ctx); err != nil {
		return Result{}, fmt.Errorf("prepare threat cache: %w", err)
	}

	result := Result{
		Findings: []rules.Finding{},
		Sources:  []scan.ThreatSourceStatus{},
	}
	for _, source := range normalizeSources(opts.Sources) {
		findings, status, err := evaluateSource(ctx, source, inv, opts)
		status.Required = opts.required(source)
		result.Sources = append(result.Sources, status)
		if err != nil {
			if opts.required(source) {
				return result, fmt.Errorf("%w: %s: %v", ErrRequiredSourceUnavailable, source, err)
			}
			continue
		}
		result.Findings = append(result.Findings, findings...)
	}
	sortResult(&result)
	return result, nil
}

// UpdateSource prepares source cache state for cache update commands.
func UpdateSource(ctx context.Context, opts Options, source string) ([]cache.SourceChange, []string, error) {
	opts = opts.withDefaults()
	if err := opts.Store.Ensure(ctx); err != nil {
		return nil, nil, err
	}
	source = normalizeSource(source)
	if source == "" || source == "builtin-rules" {
		return nil, nil, nil
	}
	warnings := []string{}
	change := cache.SourceChange{Source: source}
	if opts.Offline {
		change.Warnings = append(change.Warnings, "offline mode: remote source update skipped")
		return []cache.SourceChange{change}, warnings, nil
	}
	switch source {
	case SourceOSV, SourceNPM:
		change.Warnings = append(change.Warnings, "source is package-specific and is refreshed during scan")
	case SourceOpenSSF, SourceGitHubAdvisory:
		change.Warnings = append(change.Warnings, "source reads cached mirror records; configure or populate the cache before scanning")
	case SourceLocalPolicy:
		change.Warnings = append(change.Warnings, "local policy source is evaluated from configured rule files during scan")
	default:
		return nil, nil, fmt.Errorf("unknown threat source %q", source)
	}
	return []cache.SourceChange{change}, warnings, nil
}

func evaluateSource(
	ctx context.Context,
	source string,
	inv node.Inventory,
	opts Options,
) ([]rules.Finding, scan.ThreatSourceStatus, error) {
	status := newStatus(source, opts)
	switch source {
	case SourceLocalPolicy:
		status.Status = "available"
		status.Records = len(inv.Dependencies)
		return nil, status, nil
	case SourceOSV:
		return evaluateOSV(ctx, inv, opts, status)
	case SourceOpenSSF:
		return evaluateCachedOSVRecords(ctx, inv, opts, status, SourceOpenSSF, rules.ConfidenceConfirmedMalicious)
	case SourceGitHubAdvisory:
		return evaluateCachedOSVRecords(ctx, inv, opts, status, SourceGitHubAdvisory, rules.ConfidenceKnownVulnerable)
	case SourceNPM:
		return evaluateNPM(ctx, inv, opts, status)
	default:
		status.Status = "unavailable"
		status.Warning = "unknown threat source"
		return nil, status, fmt.Errorf("unknown threat source %q", source)
	}
}

func evaluateOSV(
	ctx context.Context,
	inv node.Inventory,
	opts Options,
	status scan.ThreatSourceStatus,
) ([]rules.Finding, scan.ThreatSourceStatus, error) {
	deps := exactPURLDeps(inv.Dependencies)
	if len(deps) == 0 {
		status.Status = "available"
		status.Warning = "no exact package URLs to query"
		return nil, status, nil
	}

	cachePath := filepath.Join(opts.Store.Dir(), "sources", SourceOSV, "querybatch", batchKey(deps)+".json")
	var response osvQueryBatchResponse
	var metadata cache.SourceMetadata
	if opts.Offline {
		if err := readJSON(cachePath, &response); err != nil {
			status.Status = "missing"
			status.Warning = "cached OSV querybatch result is unavailable"
			return nil, status, err
		}
		status.Status = "cached"
		status.Mode = "offline"
	} else {
		reqBody := newOSVRequest(deps)
		body, err := json.Marshal(reqBody)
		if err != nil {
			status.Status = "unavailable"
			status.Warning = err.Error()
			return nil, status, err
		}
		data, err := postJSON(ctx, opts, opts.osvURL()+"/v1/querybatch", body)
		if err != nil {
			status.Status = "unavailable"
			status.Warning = err.Error()
			return nil, status, err
		}
		if err := json.Unmarshal(data, &response); err != nil {
			status.Status = "unavailable"
			status.Warning = "invalid OSV response"
			return nil, status, err
		}
		if err := cache.WriteFileAtomic(ctx, cachePath, append(data, '\n'), 0o644); err != nil {
			return nil, status, err
		}
		metadata = sourceMetadata(SourceOSV, "vulnerability", "varies by OSV record", len(response.Results), opts.now())
		if err := writeSourceMetadata(ctx, opts.Store.Dir(), SourceOSV, metadata); err != nil {
			return nil, status, err
		}
		status.Status = "updated"
	}
	if metadata.Source == "" {
		metadata = readSourceMetadata(opts.Store.Dir(), SourceOSV)
	}
	applyMetadata(&status, metadata, opts.now())
	findings := osvFindings(SourceOSV, deps, response.Results, rules.ConfidenceKnownVulnerable)
	status.Records = len(findings)
	return findings, status, nil
}

func evaluateCachedOSVRecords(
	ctx context.Context,
	inv node.Inventory,
	opts Options,
	status scan.ThreatSourceStatus,
	source string,
	confidence rules.Confidence,
) ([]rules.Finding, scan.ThreatSourceStatus, error) {
	_ = ctx
	deps := exactPURLDeps(inv.Dependencies)
	records, err := readCachedOSVRecords(opts.Store.Dir(), source)
	if err != nil {
		status.Status = "missing"
		status.Warning = "cached source records are unavailable"
		return nil, status, err
	}
	findings := []rules.Finding{}
	for _, record := range records {
		for _, dep := range deps {
			if !record.affects(dep) {
				continue
			}
			findings = append(findings, recordFinding(source, dep, record.ID, record.summary(), confidence))
		}
	}
	metadata := readSourceMetadata(opts.Store.Dir(), source)
	status.Status = "cached"
	applyMetadata(&status, metadata, opts.now())
	status.Records = len(records)
	return findings, status, nil
}

func evaluateNPM(
	ctx context.Context,
	inv node.Inventory,
	opts Options,
	status scan.ThreatSourceStatus,
) ([]rules.Finding, scan.ThreatSourceStatus, error) {
	deps := npmDeps(inv.Dependencies)
	if len(deps) == 0 {
		status.Status = "available"
		status.Warning = "no npm dependencies to query"
		return nil, status, nil
	}
	findings := []rules.Finding{}
	updated := 0
	var etag, lastModified string
	for _, dep := range deps {
		packument, headers, err := loadNPMPackument(ctx, opts, dep)
		if err != nil {
			if opts.Offline {
				status.Status = "missing"
				status.Warning = "cached npm metadata is unavailable"
			} else {
				status.Status = "unavailable"
				status.Warning = err.Error()
			}
			return findings, status, err
		}
		if !opts.Offline {
			updated++
			etag = cmp.Or(headers.Get("ETag"), etag)
			lastModified = cmp.Or(headers.Get("Last-Modified"), lastModified)
		}
		if finding, ok := npmDeprecatedFinding(dep, packument); ok {
			findings = append(findings, finding)
		}
	}
	if !opts.Offline {
		metadata := sourceMetadata(SourceNPM, "registry", "npm registry metadata terms", updated, opts.now())
		metadata.ETag = etag
		metadata.LastModified = lastModified
		if err := writeSourceMetadata(ctx, opts.Store.Dir(), SourceNPM, metadata); err != nil {
			return nil, status, err
		}
		status.Status = "updated"
		applyMetadata(&status, metadata, opts.now())
	} else {
		status.Status = "cached"
		applyMetadata(&status, readSourceMetadata(opts.Store.Dir(), SourceNPM), opts.now())
	}
	status.Records = len(deps)
	return findings, status, nil
}

func loadNPMPackument(ctx context.Context, opts Options, dep node.Dependency) (npmPackument, http.Header, error) {
	path := filepath.Join(opts.Store.Dir(), "sources", SourceNPM, "packuments", packageKey(dep.Name)+".json")
	var packument npmPackument
	if opts.Offline {
		return packument, nil, readJSON(path, &packument)
	}
	data, headers, err := get(ctx, opts, opts.npmRegistryURL()+"/"+escapeNPMName(dep.Name))
	if err != nil {
		return packument, nil, err
	}
	if err := json.Unmarshal(data, &packument); err != nil {
		return packument, nil, err
	}
	if err := cache.WriteFileAtomic(ctx, path, append(data, '\n'), 0o644); err != nil {
		return packument, nil, err
	}
	return packument, headers, nil
}

func postJSON(ctx context.Context, opts Options, endpoint string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	data, _, err := do(ctx, opts, req)
	return data, err
}

func get(ctx context.Context, opts Options, endpoint string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, nil, err
	}
	data, headers, err := do(ctx, opts, req)
	if err != nil {
		return nil, nil, err
	}
	return data, headers, nil
}

func do(ctx context.Context, opts Options, req *http.Request) ([]byte, http.Header, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(req.Context(), timeout)
	defer cancel()
	req = req.WithContext(ctx)

	var lastErr error
	for attempt := range 2 {
		resp, err := opts.httpClient().Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, readErr := readHTTPResponse(resp)
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode >= http.StatusInternalServerError && attempt == 0 {
			lastErr = fmt.Errorf("server returned %s", resp.Status)
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, nil, fmt.Errorf("server returned %s", resp.Status)
		}
		return data, resp.Header, nil
	}
	return nil, nil, lastErr
}

func readHTTPResponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func sortResult(result *Result) {
	slices.SortFunc(result.Findings, func(a, b rules.Finding) int {
		return strings.Compare(rules.FindingIdentity(a)+"\x00"+a.ID, rules.FindingIdentity(b)+"\x00"+b.ID)
	})
	slices.SortFunc(result.Sources, func(a, b scan.ThreatSourceStatus) int {
		return strings.Compare(a.Source, b.Source)
	})
}

func normalizeSources(sources []string) []string {
	if len(sources) == 0 {
		sources = []string{SourceLocalPolicy}
	}
	out := make([]string, 0, len(sources))
	seen := map[string]struct{}{}
	for _, source := range sources {
		source = normalizeSource(source)
		if source == "" {
			continue
		}
		if _, ok := seen[source]; ok {
			continue
		}
		seen[source] = struct{}{}
		out = append(out, source)
	}
	return out
}

func normalizeSource(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", "builtin-rules":
		return strings.ToLower(strings.TrimSpace(source))
	case "local", "local-rules", "local-policy":
		return SourceLocalPolicy
	case "osv", "osv.dev":
		return SourceOSV
	case "openssf", "openssf-malicious", "openssf-malicious-packages":
		return SourceOpenSSF
	case "github", "github-advisory", "github-advisory-database", "ghsa":
		return SourceGitHubAdvisory
	case "npm", "npm-registry":
		return SourceNPM
	default:
		return strings.ToLower(strings.TrimSpace(source))
	}
}

func (opts Options) withDefaults() Options {
	if opts.Sources == nil {
		opts.Sources = []string{SourceLocalPolicy}
	}
	return opts
}

func (opts Options) httpClient() *http.Client {
	if opts.HTTPClient != nil {
		return opts.HTTPClient
	}
	return &http.Client{Timeout: opts.Timeout}
}

func (opts Options) osvURL() string {
	if opts.OSVURL != "" {
		return strings.TrimRight(opts.OSVURL, "/")
	}
	return defaultOSVURL
}

func (opts Options) npmRegistryURL() string {
	if opts.NPMRegistryURL != "" {
		return strings.TrimRight(opts.NPMRegistryURL, "/")
	}
	return defaultNPMRegistryURL
}

func (opts Options) now() time.Time {
	if opts.Now != nil {
		return opts.Now().UTC()
	}
	return time.Now().UTC()
}

func (opts Options) required(source string) bool {
	source = normalizeSource(source)
	for _, required := range opts.RequiredSources {
		if normalizeSource(required) == source {
			return true
		}
	}
	return false
}

func newStatus(source string, opts Options) scan.ThreatSourceStatus {
	mode := "online"
	if opts.Offline {
		mode = "offline"
	}
	return scan.ThreatSourceStatus{
		SchemaVersion: cache.SourceMetadataSchemaVersion,
		Source:        source,
		Status:        "unknown",
		Mode:          mode,
	}
}

func exactPURLDeps(deps []node.Dependency) []node.Dependency {
	out := make([]node.Dependency, 0, len(deps))
	for _, dep := range deps {
		if dep.PURL == "" || dep.Version == "" {
			continue
		}
		out = append(out, dep)
	}
	slices.SortFunc(out, func(a, b node.Dependency) int {
		return strings.Compare(a.PURL, b.PURL)
	})
	return out
}

func npmDeps(deps []node.Dependency) []node.Dependency {
	out := make([]node.Dependency, 0, len(deps))
	for _, dep := range deps {
		if strings.HasPrefix(dep.PURL, "pkg:npm/") && dep.Name != "" {
			out = append(out, dep)
		}
	}
	slices.SortFunc(out, func(a, b node.Dependency) int {
		return strings.Compare(a.Name+"\x00"+a.Version, b.Name+"\x00"+b.Version)
	})
	return out
}

func batchKey(deps []node.Dependency) string {
	h := sha256.New()
	for _, dep := range deps {
		_, _ = io.WriteString(h, dep.PURL+"\n")
	}
	return hex.EncodeToString(h.Sum(nil))
}

func packageKey(name string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(name)))
	return hex.EncodeToString(sum[:])
}

func readJSON(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("parse %q: %w", path, err)
	}
	return nil
}

func writeSourceMetadata(ctx context.Context, root, source string, metadata cache.SourceMetadata) error {
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return cache.WriteFileAtomic(ctx, filepath.Join(root, "sources", source, "metadata.json"), data, 0o644)
}

func readSourceMetadata(root, source string) cache.SourceMetadata {
	metadata, err := cache.ReadSourceMetadata(filepath.Join(root, "sources", source, "metadata.json"))
	if err != nil {
		return cache.SourceMetadata{}
	}
	return metadata
}

func sourceMetadata(source, sourceType, license string, records int, now time.Time) cache.SourceMetadata {
	return cache.SourceMetadata{
		SchemaVersion: cache.SourceMetadataSchemaVersion,
		Source:        source,
		FetchedAt:     now,
		License:       license,
		SourceType:    sourceType,
		TTL:           (24 * time.Hour).String(),
		RecordCount:   records,
	}
}

func applyMetadata(status *scan.ThreatSourceStatus, metadata cache.SourceMetadata, now time.Time) {
	if metadata.Source == "" {
		return
	}
	status.FetchedAt = metadata.FetchedAt
	status.Records = metadata.RecordCount
	if !metadata.FetchedAt.IsZero() {
		status.CacheAge = now.Sub(metadata.FetchedAt).Round(time.Second).String()
	}
}

func escapeNPMName(name string) string {
	if strings.HasPrefix(name, "@") {
		return strings.ReplaceAll(url.PathEscape(name), "%2F", "%2f")
	}
	return url.PathEscape(name)
}
