package rules

import (
	"regexp"
	"strings"
	"time"
)

func compilePattern(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile(pattern)
}

func matchAnyExact(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func matchAnyFold(values []string, candidate string) bool {
	for _, value := range values {
		if strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

func matchAnyGlob(patterns []string, candidate string) bool {
	for _, pattern := range patterns {
		if matchGlob(pattern, candidate) {
			return true
		}
	}
	return false
}

func matchGlob(pattern, value string) bool {
	pattern = strings.TrimSpace(strings.ReplaceAll(pattern, "\\", "/"))
	value = strings.ReplaceAll(value, "\\", "/")
	if pattern == "" {
		return false
	}
	if pattern == value {
		return true
	}

	regex := globRegexp(pattern)
	return regex.MatchString(value)
}

func globRegexp(pattern string) *regexp.Regexp {
	var builder strings.Builder
	builder.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		switch ch {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				builder.WriteString(".*")
				i++
				continue
			}
			builder.WriteString("[^/]*")
		case '?':
			builder.WriteString("[^/]")
		default:
			builder.WriteString(regexp.QuoteMeta(string(ch)))
		}
	}
	builder.WriteString("$")
	return regexp.MustCompile(builder.String())
}

func allowlistMatch(entry AllowlistEntry, finding Finding, now time.Time) (Suppression, bool) {
	expiresAt, err := time.Parse(time.RFC3339, entry.ExpiresAt)
	if err != nil || !now.Before(expiresAt) {
		return Suppression{}, false
	}
	scope := entry.Scope
	if scope.FindingID != "" && scope.FindingID != finding.ID {
		return Suppression{}, false
	}
	if scope.RuleID != "" && scope.RuleID != finding.RuleID {
		return Suppression{}, false
	}
	if scope.Package != "" && scope.Package != finding.PackageName {
		return Suppression{}, false
	}
	if scope.Version != "" && scope.Version != finding.PackageVersion {
		return Suppression{}, false
	}
	if scope.PURL != "" && scope.PURL != finding.PURL {
		return Suppression{}, false
	}
	if scope.Path != "" && scope.Path != finding.Path {
		return Suppression{}, false
	}
	if scope.Hash != "" && scope.Hash != finding.FileHash {
		return Suppression{}, false
	}
	if scope.Maintainer != "" && scope.Maintainer != finding.Maintainer {
		return Suppression{}, false
	}
	if scope.URL != "" && scope.URL != finding.RegistryURL {
		return Suppression{}, false
	}
	if scope.ScriptName != "" && scope.ScriptName != finding.ScriptName {
		return Suppression{}, false
	}
	return Suppression{
		AllowlistID: entry.ID,
		Reason:      entry.Reason,
		Owner:       entry.Owner,
		ExpiresAt:   entry.ExpiresAt,
	}, true
}

func isLifecycleHook(name string) bool {
	switch name {
	case "preinstall", "install", "postinstall", "prepare":
		return true
	default:
		return false
	}
}
