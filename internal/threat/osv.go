package threat

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"malox/internal/node"
	"malox/internal/rules"
)

type osvQueryBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
}

type osvPackage struct {
	PURL      string `json:"purl,omitempty"`
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

type osvQueryBatchResponse struct {
	Results []osvQueryResult `json:"results"`
}

type osvQueryResult struct {
	Vulns []osvRecord `json:"vulns"`
}

type osvRecord struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details"`
	Affected []osvAffected `json:"affected"`
	Aliases  []string      `json:"aliases"`
	Severity []osvSeverity `json:"severity"`
}

type osvAffected struct {
	Package   osvPackage `json:"package"`
	Versions  []string   `json:"versions"`
	Ranges    []osvRange `json:"ranges"`
	Database  any        `json:"database_specific,omitempty"`
	Ecosystem any        `json:"ecosystem_specific,omitempty"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

func newOSVRequest(deps []node.Dependency) osvQueryBatchRequest {
	req := osvQueryBatchRequest{Queries: make([]osvQuery, 0, len(deps))}
	for _, dep := range deps {
		req.Queries = append(req.Queries, osvQuery{Package: osvPackage{PURL: dep.PURL}})
	}
	return req
}

func osvFindings(
	source string,
	deps []node.Dependency,
	results []osvQueryResult,
	confidence rules.Confidence,
) []rules.Finding {
	findings := []rules.Finding{}
	for i, result := range results {
		if i >= len(deps) {
			break
		}
		for _, vuln := range result.Vulns {
			findings = append(findings, recordFinding(source, deps[i], vuln.ID, vuln.summary(), confidence))
		}
	}
	return findings
}

func readCachedOSVRecords(root, source string) ([]osvRecord, error) {
	recordsDir := filepath.Join(root, "sources", source, "records")
	records := []osvRecord{}
	err := filepath.WalkDir(recordsDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var record osvRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return fmt.Errorf("parse %q: %w", path, err)
		}
		records = append(records, record)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, os.ErrNotExist
	}
	return records, nil
}

func (r osvRecord) affects(dep node.Dependency) bool {
	for _, affected := range r.Affected {
		if !affectedPackageMatches(affected.Package, dep) {
			continue
		}
		if len(affected.Versions) == 0 && len(affected.Ranges) == 0 {
			return true
		}
		for _, version := range affected.Versions {
			if version == dep.Version {
				return true
			}
		}
		for _, versionRange := range affected.Ranges {
			if rangeAffects(versionRange, dep.Version) {
				return true
			}
		}
	}
	return false
}

func affectedPackageMatches(pkg osvPackage, dep node.Dependency) bool {
	if pkg.PURL != "" {
		return pkg.PURL == dep.PURL || strings.TrimSuffix(pkg.PURL, "@"+dep.Version) == strings.TrimSuffix(dep.PURL, "@"+dep.Version)
	}
	if pkg.Name == "" {
		return false
	}
	if !strings.EqualFold(pkg.Name, dep.Name) {
		return false
	}
	return pkg.Ecosystem == "" || strings.EqualFold(pkg.Ecosystem, "npm")
}

func rangeAffects(r osvRange, version string) bool {
	if !strings.EqualFold(r.Type, "SEMVER") && r.Type != "" {
		return false
	}
	introduced := "0"
	for _, event := range r.Events {
		if event.Introduced != "" {
			introduced = event.Introduced
		}
		if event.Fixed != "" && compareVersion(version, event.Fixed) < 0 && compareVersion(version, introduced) >= 0 {
			return true
		}
	}
	return introduced != "" && compareVersion(version, introduced) >= 0
}

func compareVersion(a, b string) int {
	aa := versionParts(a)
	bb := versionParts(b)
	for i := range max(len(aa), len(bb)) {
		var av, bv int
		if i < len(aa) {
			av = aa[i]
		}
		if i < len(bb) {
			bv = bb[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func versionParts(version string) []int {
	version = strings.TrimPrefix(version, "v")
	version, _, _ = strings.Cut(version, "-")
	chunks := strings.Split(version, ".")
	out := make([]int, 0, len(chunks))
	for _, chunk := range chunks {
		var value int
		for _, r := range chunk {
			if r < '0' || r > '9' {
				break
			}
			value = value*10 + int(r-'0')
		}
		out = append(out, value)
	}
	return out
}

func (r osvRecord) summary() string {
	if strings.TrimSpace(r.Summary) != "" {
		return r.Summary
	}
	if strings.TrimSpace(r.Details) != "" {
		details := strings.TrimSpace(r.Details)
		if len(details) > 140 {
			return details[:140]
		}
		return details
	}
	return "upstream advisory matched dependency"
}

func recordFinding(
	source string,
	dep node.Dependency,
	advisoryID string,
	summary string,
	confidence rules.Confidence,
) rules.Finding {
	severity := rules.SeverityHigh
	if confidence == rules.ConfidenceConfirmedMalicious {
		severity = rules.SeverityCritical
	}
	finding := rules.Finding{
		SchemaVersion:  rules.FindingSchemaVersion,
		Severity:       severity,
		Confidence:     confidence,
		Source:         source,
		RuleID:         source + ":" + advisoryID,
		RuleType:       "threat-intelligence",
		Summary:        summary,
		Path:           dep.PackagePath,
		PackageName:    dep.Name,
		PackageVersion: dep.Version,
		PURL:           dep.PURL,
		RegistryURL:    dep.Resolved,
		Location:       &rules.Location{Path: dep.SourcePath},
		Blocking:       confidence == rules.ConfidenceConfirmedMalicious,
		Evidence: []rules.Evidence{{
			Kind:           "advisory",
			Value:          advisoryID,
			PackageName:    dep.Name,
			PackageVersion: dep.Version,
			PURL:           dep.PURL,
			RegistryURL:    dep.Resolved,
		}},
	}
	finding.ID = threatFindingID(finding)
	return finding
}

func threatFindingID(finding rules.Finding) string {
	sum := sha256.Sum256([]byte(rules.FindingIdentity(finding)))
	return "sha256:" + hex.EncodeToString(sum[:])
}
