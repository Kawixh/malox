package rules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"malox/internal/node"
)

const (
	ruleTypeDetection = "detection"
	ruleTypeBlocklist = "blocklist"
)

// Evaluate applies all policies to a snapshot-shaped scan input.
func Evaluate(ctx context.Context, opts EvaluateOptions) (EvaluateResult, error) {
	if err := ctx.Err(); err != nil {
		return EvaluateResult{}, fmt.Errorf("evaluate rules: %w", err)
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	findings := []Finding{}
	warnings := []Warning{}
	for _, policy := range opts.Policies {
		policyFindings, policyWarnings := evaluatePolicy(ctx, opts, policy)
		findings = append(findings, policyFindings...)
		warnings = append(warnings, policyWarnings...)
	}

	applyAllowlists(findings, opts.Policies, now)
	sortFindings(findings)
	slices.SortFunc(warnings, func(a, b Warning) int {
		return strings.Compare(a.Path+"\x00"+a.Code+"\x00"+a.Message, b.Path+"\x00"+b.Code+"\x00"+b.Message)
	})
	return EvaluateResult{Findings: findings, Warnings: warnings}, nil
}

// HasBlockingFindings reports whether scan findings should produce exit code 1.
func HasBlockingFindings(findings []Finding) bool {
	for _, finding := range findings {
		if finding.Blocking && !finding.Suppressed {
			return true
		}
	}
	return false
}

// FindingIdentity returns a stable identity for finding diffing.
func FindingIdentity(finding Finding) string {
	return strings.Join([]string{
		finding.RuleID,
		finding.RuleType,
		finding.Path,
		finding.FileHash,
		finding.PackageName,
		finding.PackageVersion,
		finding.PURL,
		finding.RegistryURL,
		finding.Maintainer,
		finding.ScriptName,
	}, "\x00")
}

func evaluatePolicy(ctx context.Context, opts EvaluateOptions, policy Policy) ([]Finding, []Warning) {
	findings := []Finding{}
	warnings := []Warning{}
	for _, block := range policy.Blocklist {
		findings = append(findings, blocklistFindings(policy, block, opts.Files, opts.Node)...)
	}
	for _, rule := range policy.Rules {
		nextFindings, nextWarnings := ruleFindings(ctx, opts, policy, rule)
		findings = append(findings, nextFindings...)
		warnings = append(warnings, nextWarnings...)
	}
	return findings, warnings
}

func blocklistFindings(policy Policy, block BlocklistEntry, files []File, inv node.Inventory) []Finding {
	findings := []Finding{}
	for _, file := range files {
		switch {
		case block.Hash != "" && strings.EqualFold(block.Hash, file.SHA256):
			findings = append(findings, newBlocklistFileFinding(policy, block, file, "file hash"))
		case block.Path != "" && block.Path == file.Path:
			findings = append(findings, newBlocklistFileFinding(policy, block, file, "path"))
		case block.PathPattern != "" && matchGlob(block.PathPattern, file.Path):
			findings = append(findings, newBlocklistFileFinding(policy, block, file, "path pattern"))
		}
	}
	for _, dep := range inv.Dependencies {
		switch {
		case block.Package != "" && strings.EqualFold(block.Package, dep.Name) && blockVersionMatches(block, dep.Version):
			findings = append(findings, newBlocklistDependencyFinding(policy, block, dep, "package"))
		case block.PURL != "" && block.PURL == dep.PURL:
			findings = append(findings, newBlocklistDependencyFinding(policy, block, dep, "purl"))
		case block.URL != "" && block.URL == dep.Resolved:
			findings = append(findings, newBlocklistDependencyFinding(policy, block, dep, "url"))
		case block.Maintainer != "" && matchAnyFold(dep.Maintainers, block.Maintainer):
			findings = append(findings, newBlocklistDependencyFinding(policy, block, dep, "maintainer"))
		}
	}
	return findings
}

func ruleFindings(
	ctx context.Context,
	opts EvaluateOptions,
	policy Policy,
	rule Rule,
) ([]Finding, []Warning) {
	findings := []Finding{}
	warnings := []Warning{}
	for _, file := range opts.Files {
		if matchAnyGlob(rule.PathPatterns, file.Path) {
			findings = append(findings, newFileRuleFinding(policy, rule, file, Evidence{
				Kind:     "path_pattern",
				Pattern:  strings.Join(rule.PathPatterns, ","),
				Path:     file.Path,
				FileHash: file.SHA256,
			}))
		}
		if file.SHA256 != "" && matchAnyFold(rule.FileSHA256, file.SHA256) {
			findings = append(findings, newFileRuleFinding(policy, rule, file, Evidence{
				Kind:     "file_sha256",
				Value:    file.SHA256,
				Path:     file.Path,
				FileHash: file.SHA256,
			}))
		}
	}

	for _, dep := range opts.Node.Dependencies {
		findings = append(findings, dependencyRuleFindings(policy, rule, dep)...)
	}
	for _, script := range opts.Node.PackageScripts {
		findings = append(findings, scriptRuleFindings(policy, rule, script)...)
	}

	filePatternFindings, filePatternWarnings := fileRuleFindings(ctx, opts, policy, rule)
	findings = append(findings, filePatternFindings...)
	warnings = append(warnings, filePatternWarnings...)
	return findings, warnings
}

func dependencyRuleFindings(policy Policy, rule Rule, dep node.Dependency) []Finding {
	findings := []Finding{}
	if matchAnyFold(rule.PackageNames, dep.Name) {
		findings = append(findings, newDependencyRuleFinding(policy, rule, dep, Evidence{
			Kind:           "package_name",
			Value:          dep.Name,
			PackageName:    dep.Name,
			PackageVersion: dep.Version,
			PURL:           dep.PURL,
		}))
	}
	for _, versionRange := range rule.PackageVersionRanges {
		if versionRange.Package != "" && !strings.EqualFold(versionRange.Package, dep.Name) {
			continue
		}
		ok, err := matchesRange(dep.Version, versionRange.Range)
		if err != nil || !ok {
			continue
		}
		findings = append(findings, newDependencyRuleFinding(policy, rule, dep, Evidence{
			Kind:           "package_version_range",
			Pattern:        versionRange.Range,
			PackageName:    dep.Name,
			PackageVersion: dep.Version,
			PURL:           dep.PURL,
		}))
	}
	if matchAnyExact(rule.PURLs, dep.PURL) {
		findings = append(findings, newDependencyRuleFinding(policy, rule, dep, Evidence{
			Kind:           "purl",
			Value:          dep.PURL,
			PackageName:    dep.Name,
			PackageVersion: dep.Version,
			PURL:           dep.PURL,
		}))
	}
	if matchAnyExact(rule.RegistryURLs, dep.Resolved) {
		findings = append(findings, newDependencyRuleFinding(policy, rule, dep, Evidence{
			Kind:           "registry_url",
			Value:          dep.Resolved,
			PackageName:    dep.Name,
			PackageVersion: dep.Version,
			PURL:           dep.PURL,
			RegistryURL:    dep.Resolved,
		}))
	}
	for _, maintainer := range dep.Maintainers {
		if !matchAnyFold(rule.Maintainers, maintainer) {
			continue
		}
		findings = append(findings, newDependencyRuleFinding(policy, rule, dep, Evidence{
			Kind:           "maintainer",
			Value:          maintainer,
			PackageName:    dep.Name,
			PackageVersion: dep.Version,
			PURL:           dep.PURL,
			Maintainer:     maintainer,
		}))
	}
	return findings
}

func scriptRuleFindings(policy Policy, rule Rule, script node.PackageScript) []Finding {
	if len(rule.ScriptNames) == 0 &&
		len(rule.ScriptPatterns) == 0 &&
		!rule.SuspiciousLifecycleHooks {
		return nil
	}
	if len(rule.ScriptNames) > 0 && !matchAnyFold(rule.ScriptNames, script.ScriptName) {
		return nil
	}
	if rule.SuspiciousLifecycleHooks && !isLifecycleHook(script.ScriptName) {
		return nil
	}

	findings := []Finding{}
	for _, pattern := range rule.ScriptPatterns {
		re := regexp.MustCompile(pattern)
		if !re.MatchString(script.Command) {
			continue
		}
		findings = append(findings, newScriptRuleFinding(policy, rule, script, Evidence{
			Kind:           "script_pattern",
			Pattern:        pattern,
			PackageName:    script.PackageName,
			PackageVersion: script.PackageVersion,
			PURL:           script.PURL,
			ScriptName:     script.ScriptName,
			Command:        script.Command,
		}))
	}
	if rule.SuspiciousLifecycleHooks && len(rule.ScriptPatterns) == 0 {
		findings = append(findings, newScriptRuleFinding(policy, rule, script, Evidence{
			Kind:           "suspicious_lifecycle_hook",
			PackageName:    script.PackageName,
			PackageVersion: script.PackageVersion,
			PURL:           script.PURL,
			ScriptName:     script.ScriptName,
			Command:        script.Command,
		}))
	}
	return findings
}

func fileRuleFindings(
	ctx context.Context,
	opts EvaluateOptions,
	policy Policy,
	rule Rule,
) ([]Finding, []Warning) {
	findings := []Finding{}
	warnings := []Warning{}
	if len(rule.FilePatterns) == 0 {
		return nil, nil
	}

	for _, pattern := range rule.FilePatterns {
		re := regexp.MustCompile(pattern.Pattern)
		for _, file := range opts.Files {
			if err := ctx.Err(); err != nil {
				warnings = append(warnings, Warning{Path: file.Path, Code: "rule_context_canceled", Message: err.Error()})
				return findings, warnings
			}
			if len(pattern.FileTypes) > 0 && !matchAnyFold(pattern.FileTypes, file.Type) {
				continue
			}
			if len(pattern.PathPatterns) > 0 && !matchAnyGlob(pattern.PathPatterns, file.Path) {
				continue
			}
			data, err := readRuleFile(opts.Root, file.Path, filePatternLimit(opts.MaxFileSize, pattern.MaxBytes))
			if err != nil {
				warnings = append(warnings, Warning{Path: file.Path, Code: "file_pattern_read_error", Message: err.Error()})
				continue
			}
			match := re.Find(data)
			if len(match) == 0 {
				continue
			}
			evidenceValue := string(match)
			if len(evidenceValue) > 80 {
				evidenceValue = evidenceValue[:80]
			}
			findings = append(findings, newFileRuleFinding(policy, rule, file, Evidence{
				Kind:     "file_pattern",
				Value:    evidenceValue,
				Pattern:  pattern.Pattern,
				Path:     file.Path,
				FileHash: file.SHA256,
			}))
		}
	}
	return findings, warnings
}

func readRuleFile(root, rel string, maxBytes int64) ([]byte, error) {
	if !filepath.IsLocal(rel) {
		return nil, fmt.Errorf("unsafe relative path %q", rel)
	}
	f, err := os.OpenInRoot(root, filepath.FromSlash(rel))
	if err != nil {
		return nil, fmt.Errorf("open rule target %q: %w", rel, err)
	}
	defer func() {
		_ = f.Close()
	}()
	limited := io.LimitReader(f, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read rule target %q: %w", rel, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("rule target %q exceeds %d bytes", rel, maxBytes)
	}
	return data, nil
}

func filePatternLimit(scanMax, patternMax int64) int64 {
	const fallback = 1024 * 1024
	limit := scanMax
	if limit <= 0 {
		limit = fallback
	}
	if patternMax > 0 && patternMax < limit {
		return patternMax
	}
	return limit
}

func blockVersionMatches(block BlocklistEntry, version string) bool {
	if block.VersionRange == "" {
		return true
	}
	ok, err := matchesRange(version, block.VersionRange)
	return err == nil && ok
}

func newBlocklistFileFinding(policy Policy, block BlocklistEntry, file File, matched string) Finding {
	severity := block.Severity
	if severity == "" {
		severity = SeverityCritical
	}
	confidence := block.Confidence
	if confidence == "" {
		confidence = ConfidenceConfirmedMalicious
	}
	finding := Finding{
		SchemaVersion: FindingSchemaVersion,
		Severity:      severity,
		Confidence:    confidence,
		Source:        policy.Source,
		RuleID:        block.ID,
		RuleType:      ruleTypeBlocklist,
		Summary:       "local blocklist matched " + matched,
		Path:          file.Path,
		FileHash:      file.SHA256,
		PackageOwner:  file.PackageOwner,
		Location:      &Location{Path: file.Path},
		Blocking:      true,
		Evidence: []Evidence{{
			Kind:     matched,
			Path:     file.Path,
			FileHash: file.SHA256,
			Pattern:  block.PathPattern,
			Value:    firstNonEmpty(block.Hash, block.Path),
		}},
	}
	finding.ID = findingID(finding)
	return finding
}

func newBlocklistDependencyFinding(policy Policy, block BlocklistEntry, dep node.Dependency, matched string) Finding {
	severity := block.Severity
	if severity == "" {
		severity = SeverityCritical
	}
	confidence := block.Confidence
	if confidence == "" {
		confidence = ConfidenceConfirmedMalicious
	}
	finding := Finding{
		SchemaVersion:  FindingSchemaVersion,
		Severity:       severity,
		Confidence:     confidence,
		Source:         policy.Source,
		RuleID:         block.ID,
		RuleType:       ruleTypeBlocklist,
		Summary:        "local blocklist matched " + matched,
		Path:           dep.PackagePath,
		PackageName:    dep.Name,
		PackageVersion: dep.Version,
		PURL:           dep.PURL,
		RegistryURL:    dep.Resolved,
		Maintainer:     matchedMaintainer(block, dep),
		Location:       &Location{Path: dep.SourcePath},
		Blocking:       true,
		Evidence: []Evidence{{
			Kind:           matched,
			Value:          firstNonEmpty(block.Package, block.PURL, block.URL, block.Maintainer),
			PackageName:    dep.Name,
			PackageVersion: dep.Version,
			PURL:           dep.PURL,
			RegistryURL:    dep.Resolved,
			Maintainer:     matchedMaintainer(block, dep),
		}},
	}
	finding.ID = findingID(finding)
	return finding
}

func newFileRuleFinding(policy Policy, rule Rule, file File, evidence Evidence) Finding {
	finding := Finding{
		SchemaVersion: FindingSchemaVersion,
		Severity:      rule.Severity,
		Confidence:    rule.Confidence,
		Source:        policy.Source,
		RuleID:        rule.ID,
		RuleType:      ruleTypeDetection,
		Summary:       firstNonEmpty(rule.Description, "local rule matched file"),
		Evidence:      []Evidence{evidence},
		Path:          file.Path,
		FileHash:      file.SHA256,
		PackageOwner:  file.PackageOwner,
		Location:      &Location{Path: file.Path},
		Blocking:      false,
	}
	finding.ID = findingID(finding)
	return finding
}

func newDependencyRuleFinding(policy Policy, rule Rule, dep node.Dependency, evidence Evidence) Finding {
	finding := Finding{
		SchemaVersion:  FindingSchemaVersion,
		Severity:       rule.Severity,
		Confidence:     rule.Confidence,
		Source:         policy.Source,
		RuleID:         rule.ID,
		RuleType:       ruleTypeDetection,
		Summary:        firstNonEmpty(rule.Description, "local rule matched dependency"),
		Evidence:       []Evidence{evidence},
		Path:           dep.PackagePath,
		PackageName:    dep.Name,
		PackageVersion: dep.Version,
		PURL:           dep.PURL,
		RegistryURL:    dep.Resolved,
		Maintainer:     evidence.Maintainer,
		Location:       &Location{Path: dep.SourcePath},
		Blocking:       false,
	}
	finding.ID = findingID(finding)
	return finding
}

func matchedMaintainer(block BlocklistEntry, dep node.Dependency) string {
	if block.Maintainer == "" {
		return ""
	}
	for _, maintainer := range dep.Maintainers {
		if strings.EqualFold(maintainer, block.Maintainer) {
			return maintainer
		}
	}
	return block.Maintainer
}

func newScriptRuleFinding(policy Policy, rule Rule, script node.PackageScript, evidence Evidence) Finding {
	finding := Finding{
		SchemaVersion:  FindingSchemaVersion,
		Severity:       rule.Severity,
		Confidence:     rule.Confidence,
		Source:         policy.Source,
		RuleID:         rule.ID,
		RuleType:       ruleTypeDetection,
		Summary:        firstNonEmpty(rule.Description, "local rule matched package script"),
		Evidence:       []Evidence{evidence},
		Path:           script.PackagePath,
		PackageName:    script.PackageName,
		PackageVersion: script.PackageVersion,
		PURL:           script.PURL,
		ScriptName:     script.ScriptName,
		Location:       &Location{Path: script.SourcePath, ScriptName: script.ScriptName},
		Blocking:       false,
	}
	finding.ID = findingID(finding)
	return finding
}

func applyAllowlists(findings []Finding, policies []Policy, now time.Time) {
	for i := range findings {
		for _, policy := range policies {
			for _, entry := range policy.Allowlist {
				suppression, ok := allowlistMatch(entry, findings[i], now)
				if !ok {
					continue
				}
				findings[i].Suppressed = true
				findings[i].Suppression = &suppression
				break
			}
			if findings[i].Suppressed {
				break
			}
		}
	}
}

func sortFindings(findings []Finding) {
	slices.SortFunc(findings, func(a, b Finding) int {
		return strings.Compare(FindingIdentity(a)+"\x00"+a.ID, FindingIdentity(b)+"\x00"+b.ID)
	})
}

func findingID(finding Finding) string {
	sum := sha256.Sum256([]byte(FindingIdentity(finding)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
