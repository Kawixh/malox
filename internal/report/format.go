// Package report defines stable output contracts for Malox reports.
package report

import "fmt"

// Format identifies a supported command output format.
type Format string

const (
	// FormatTable renders compact human-readable tables.
	FormatTable Format = "table"
	// FormatJSON renders machine-readable JSON without decorative output.
	FormatJSON Format = "json"
	// FormatPlain renders plain human-readable text.
	FormatPlain Format = "plain"
)

// ParseFormat converts a user-supplied format string into a Format.
func ParseFormat(value string) (Format, error) {
	switch Format(value) {
	case FormatTable, FormatJSON, FormatPlain:
		return Format(value), nil
	default:
		return "", fmt.Errorf("unsupported output format %q", value)
	}
}

// String returns the CLI spelling for f.
func (f Format) String() string {
	return string(f)
}

// Valid reports whether f is a known output format.
func (f Format) Valid() bool {
	switch f {
	case FormatTable, FormatJSON, FormatPlain:
		return true
	default:
		return false
	}
}
