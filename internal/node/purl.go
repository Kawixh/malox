package node

import (
	"net/url"
	"strings"
)

// NpmPURL returns a Package URL for an npm package when the name and version are exact.
func NpmPURL(name, version string) string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" || !isExactVersion(version) {
		return ""
	}
	if strings.HasPrefix(name, "@") {
		scope, pkg, ok := strings.Cut(name, "/")
		if !ok || pkg == "" {
			return ""
		}
		return "pkg:npm/" + escapePURLPath(scope) + "/" + escapePURLPath(pkg) + "@" + escapePURLVersion(version)
	}
	return "pkg:npm/" + escapePURLPath(name) + "@" + escapePURLVersion(version)
}

// DenoPURL returns a Package URL for a Deno dependency when an exact version is available.
func DenoPURL(name, version string) string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" || !isExactVersion(version) {
		return ""
	}
	return "pkg:deno/" + escapePURLPath(name) + "@" + escapePURLVersion(version)
}

func escapePURLPath(value string) string {
	escaped := strings.ReplaceAll(url.PathEscape(value), "+", "%20")
	return strings.ReplaceAll(escaped, "@", "%40")
}

func escapePURLVersion(value string) string {
	return strings.ReplaceAll(url.PathEscape(value), "+", "%20")
}

func isExactVersion(version string) bool {
	if version == "" {
		return false
	}
	if strings.ContainsAny(version, " <>|*~^") {
		return false
	}
	for _, prefix := range []string{"npm:", "workspace:", "file:", "link:", "git:", "github:", "http://", "https://"} {
		if strings.HasPrefix(version, prefix) {
			return false
		}
	}
	return true
}
