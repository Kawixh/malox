package report

import (
	"encoding/json"
	"fmt"
	"io"

	"malox/internal/rules"
)

// WriteRulesTest writes a rules test result in the requested output format.
func WriteRulesTest(w io.Writer, result rules.TestResult, format Format) error {
	switch format {
	case FormatJSON:
		return writeRulesTestJSON(w, result)
	case FormatTable:
		return writeRulesTestTable(w, result)
	case FormatPlain:
		return writeRulesTestPlain(w, result)
	default:
		return fmt.Errorf("unsupported rules test output format %q", format)
	}
}

func writeRulesTestJSON(w io.Writer, result rules.TestResult) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func writeRulesTestTable(w io.Writer, result rules.TestResult) error {
	status := "passed"
	if !result.Passed {
		status = "failed"
	}
	_, err := fmt.Fprintf(
		w,
		"Rules test %s\nRule file: %s\nFixture: %s\nFindings: %d\nWarnings: %d\nErrors: %d\n",
		status,
		result.RuleFile,
		result.Fixture,
		result.MatchCount,
		len(result.Warnings),
		len(result.Errors),
	)
	return err
}

func writeRulesTestPlain(w io.Writer, result rules.TestResult) error {
	_, err := fmt.Fprintf(
		w,
		"passed=%t valid=%t findings=%d warnings=%d errors=%d\n",
		result.Passed,
		result.Valid,
		result.MatchCount,
		len(result.Warnings),
		len(result.Errors),
	)
	return err
}
