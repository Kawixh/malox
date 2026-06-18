package threat

import (
	"crypto/sha256"
	"encoding/hex"

	"malox/internal/node"
	"malox/internal/rules"
)

type npmPackument struct {
	Name     string                `json:"name"`
	Versions map[string]npmVersion `json:"versions"`
	Time     map[string]string     `json:"time,omitempty"`
}

type npmVersion struct {
	Name       string            `json:"name"`
	Version    string            `json:"version"`
	Deprecated string            `json:"deprecated,omitempty"`
	Scripts    map[string]string `json:"scripts,omitempty"`
	Dist       npmDist           `json:"dist,omitempty"`
}

type npmDist struct {
	Tarball string `json:"tarball,omitempty"`
	Shasum  string `json:"shasum,omitempty"`
}

func npmDeprecatedFinding(dep node.Dependency, packument npmPackument) (rules.Finding, bool) {
	version, ok := packument.Versions[dep.Version]
	if !ok || version.Deprecated == "" {
		return rules.Finding{}, false
	}
	finding := rules.Finding{
		SchemaVersion:  rules.FindingSchemaVersion,
		Severity:       rules.SeverityMedium,
		Confidence:     rules.ConfidenceSuspiciousHistory,
		Source:         SourceNPM,
		RuleID:         SourceNPM + ":deprecated-version",
		RuleType:       "threat-intelligence",
		Summary:        "npm registry marks this package version as deprecated",
		Path:           dep.PackagePath,
		PackageName:    dep.Name,
		PackageVersion: dep.Version,
		PURL:           dep.PURL,
		RegistryURL:    version.Dist.Tarball,
		Location:       &rules.Location{Path: dep.SourcePath},
		Evidence: []rules.Evidence{{
			Kind:           "npm_deprecated",
			Value:          version.Deprecated,
			PackageName:    dep.Name,
			PackageVersion: dep.Version,
			PURL:           dep.PURL,
			RegistryURL:    version.Dist.Tarball,
		}},
	}
	finding.ID = npmFindingID(finding)
	return finding, true
}

func npmFindingID(finding rules.Finding) string {
	sum := sha256.Sum256([]byte(rules.FindingIdentity(finding)))
	return "sha256:" + hex.EncodeToString(sum[:])
}
