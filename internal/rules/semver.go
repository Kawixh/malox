package rules

import (
	"fmt"
	"strconv"
	"strings"
)

type semver struct {
	major int
	minor int
	patch int
	pre   string
}

type comparator struct {
	op      string
	version semver
}

func matchesRange(version, rawRange string) (bool, error) {
	parsedVersion, err := parseSemver(version)
	if err != nil {
		return false, err
	}
	comparators, err := parseRange(rawRange)
	if err != nil {
		return false, err
	}
	for _, cmp := range comparators {
		if !cmp.matches(parsedVersion) {
			return false, nil
		}
	}
	return true, nil
}

func parseRange(raw string) ([]comparator, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "*" {
		return nil, nil
	}

	tokens := strings.Fields(strings.ReplaceAll(raw, ",", " "))
	comparators := []comparator{}
	for _, token := range tokens {
		next, err := parseComparator(token)
		if err != nil {
			return nil, err
		}
		comparators = append(comparators, next...)
	}
	return comparators, nil
}

func parseComparator(token string) ([]comparator, error) {
	if strings.HasPrefix(token, "^") {
		base, err := parseSemver(strings.TrimPrefix(token, "^"))
		if err != nil {
			return nil, err
		}
		upper := semver{major: base.major + 1}
		if base.major == 0 {
			upper = semver{minor: base.minor + 1}
			if base.minor == 0 {
				upper = semver{patch: base.patch + 1}
			}
		}
		return []comparator{{op: ">=", version: base}, {op: "<", version: upper}}, nil
	}
	if strings.HasPrefix(token, "~") {
		base, err := parseSemver(strings.TrimPrefix(token, "~"))
		if err != nil {
			return nil, err
		}
		upper := semver{major: base.major, minor: base.minor + 1}
		return []comparator{{op: ">=", version: base}, {op: "<", version: upper}}, nil
	}
	if strings.ContainsAny(token, "*xX") {
		return wildcardComparators(token)
	}

	for _, op := range []string{">=", "<=", "!=", ">", "<", "="} {
		if strings.HasPrefix(token, op) {
			version, err := parseSemver(strings.TrimPrefix(token, op))
			if err != nil {
				return nil, err
			}
			return []comparator{{op: op, version: version}}, nil
		}
	}

	version, err := parseSemver(token)
	if err != nil {
		return nil, err
	}
	return []comparator{{op: "=", version: version}}, nil
}

func wildcardComparators(token string) ([]comparator, error) {
	parts := strings.Split(strings.TrimPrefix(token, "v"), ".")
	if len(parts) > 3 {
		return nil, fmt.Errorf("invalid wildcard range %q", token)
	}
	nums := []int{0, 0, 0}
	wildcardAt := -1
	for i, part := range parts {
		if part == "*" || strings.EqualFold(part, "x") {
			wildcardAt = i
			break
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid wildcard range %q", token)
		}
		nums[i] = n
	}
	if wildcardAt == -1 {
		return nil, fmt.Errorf("invalid wildcard range %q", token)
	}
	lower := semver{major: nums[0], minor: nums[1], patch: nums[2]}
	upper := lower
	switch wildcardAt {
	case 0:
		return nil, nil
	case 1:
		upper.major++
		upper.minor = 0
		upper.patch = 0
	default:
		upper.minor++
		upper.patch = 0
	}
	return []comparator{{op: ">=", version: lower}, {op: "<", version: upper}}, nil
}

func parseSemver(raw string) (semver, error) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "v"))
	if raw == "" {
		return semver{}, fmt.Errorf("empty semantic version")
	}
	if main, _, ok := strings.Cut(raw, "+"); ok {
		raw = main
	}

	main := raw
	pre := ""
	if before, after, ok := strings.Cut(raw, "-"); ok {
		main = before
		pre = after
	}

	parts := strings.Split(main, ".")
	if len(parts) != 3 {
		return semver{}, fmt.Errorf("semantic version %q must have major.minor.patch", raw)
	}
	nums := [3]int{}
	for i, part := range parts {
		if part == "" {
			return semver{}, fmt.Errorf("semantic version %q has an empty numeric part", raw)
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return semver{}, fmt.Errorf("semantic version %q has invalid numeric part %q", raw, part)
		}
		nums[i] = n
	}
	return semver{major: nums[0], minor: nums[1], patch: nums[2], pre: pre}, nil
}

func compareSemver(a, b semver) int {
	switch {
	case a.major != b.major:
		return compareInt(a.major, b.major)
	case a.minor != b.minor:
		return compareInt(a.minor, b.minor)
	case a.patch != b.patch:
		return compareInt(a.patch, b.patch)
	case a.pre == b.pre:
		return 0
	case a.pre == "":
		return 1
	case b.pre == "":
		return -1
	default:
		return strings.Compare(a.pre, b.pre)
	}
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func (c comparator) matches(version semver) bool {
	order := compareSemver(version, c.version)
	switch c.op {
	case "=":
		return order == 0
	case "!=":
		return order != 0
	case ">":
		return order > 0
	case ">=":
		return order >= 0
	case "<":
		return order < 0
	case "<=":
		return order <= 0
	default:
		return false
	}
}
