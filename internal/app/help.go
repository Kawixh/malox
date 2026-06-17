package app

import (
	"fmt"
	"io"
)

func writeHelp(w io.Writer, command command) int {
	var err error
	switch command {
	case commandRoot:
		err = rootHelp(w)
	case commandScan:
		err = scanHelp(w)
	case commandDiff:
		err = diffHelp(w)
	case commandRules, commandRulesTest:
		err = rulesHelp(w)
	case commandCache, commandCacheUpdate, commandCacheClean:
		err = cacheHelp(w)
	case commandVersion:
		err = versionHelp(w)
	default:
		err = rootHelp(w)
	}
	if err != nil {
		return ExitScanFailed
	}
	return ExitOK
}

func rootHelp(w io.Writer) error {
	_, err := fmt.Fprint(w, `Malox scans open source projects for suspicious dependency changes, risky files, known vulnerabilities, and malware signals.

Usage:
  malox [global flags] <command> [flags]

Commands:
  scan          Scan a project and produce a report
  diff          Compare scan snapshots
  rules test    Test local rules against fixtures
  cache update  Update local threat intelligence caches
  cache clean   Remove expired cache entries
  version       Print build and Go version information

Global flags:
  --help          Show help
  --version       Print version information
  --config        Path to a JSON config file
  --state-dir     Project state directory (default: <root>/.malox)
  --cache-dir     Global cache directory
  --offline       Use cached data only
  --no-color      Disable color output
  --quiet         Suppress logs
  --verbose       Enable debug logs

Examples:
  malox scan
  malox scan --root ./app --output json
  malox diff
  malox cache update --offline
`)
	return err
}

func scanHelp(w io.Writer) error {
	_, err := fmt.Fprint(w, `Scan a project and produce a report.

Usage:
  malox scan [flags]

Flags:
  --root           Project root to scan (default: current directory)
  --json           Shortcut for --output json
  --output         Output format: table, json, or plain (default: table)
  --strict-hash    Rehash every candidate file
  --max-workers    Maximum worker count for scan work
  --max-file-size  Maximum file size in bytes

Global flags:
  --config --state-dir --cache-dir --offline --no-color --quiet --verbose

Examples:
  malox scan
  malox scan --root ./frontend --max-workers 4
  malox scan --json
`)
	return err
}

func diffHelp(w io.Writer) error {
	_, err := fmt.Fprint(w, `Compare scan snapshots.

Usage:
  malox diff [global flags]

Global flags:
  --config --state-dir --cache-dir --offline --no-color --quiet --verbose

Examples:
  malox diff
  malox diff --state-dir ./.malox
`)
	return err
}

func rulesHelp(w io.Writer) error {
	_, err := fmt.Fprint(w, `Test local Malox rules against fixtures.

Usage:
  malox rules test [global flags]

Global flags:
  --config --state-dir --cache-dir --offline --no-color --quiet --verbose

Examples:
  malox rules test
  malox rules test --config ./malox.json
`)
	return err
}

func cacheHelp(w io.Writer) error {
	_, err := fmt.Fprint(w, `Manage Malox cache data.

Usage:
  malox cache update [global flags]
  malox cache clean [global flags]

Global flags:
  --config --state-dir --cache-dir --offline --no-color --quiet --verbose

Examples:
  malox cache update
  malox cache clean --cache-dir ~/.cache/malox
`)
	return err
}

func versionHelp(w io.Writer) error {
	_, err := fmt.Fprint(w, `Print Malox build metadata.

Usage:
  malox version
  malox --version

Fields:
  version     Release version, or unknown
  commit      Source commit, or unknown
  build_date  Build date, or unknown
  go_version  Go runtime version

Examples:
  malox version
  malox --version
`)
	return err
}
