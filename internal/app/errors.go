package app

import (
	"errors"
	"fmt"
)

const (
	// ExitOK means no findings above threshold.
	ExitOK = 0
	// ExitFindings means findings at or above threshold were found.
	ExitFindings = 1
	// ExitUsage means the user supplied invalid arguments or configuration.
	ExitUsage = 2
	// ExitScanFailed means scanning or a scan-adjacent operation failed.
	ExitScanFailed = 3
	// ExitThreatUnavailable means a required threat source is unavailable.
	ExitThreatUnavailable = 4
)

// ExitError attaches a Malox process exit code to an error.
type ExitError struct {
	Code int
	Err  error
}

// Error returns the wrapped error message.
func (e *ExitError) Error() string {
	return e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ExitError) Unwrap() error {
	return e.Err
}

func withExitCode(code int, err error) error {
	if err == nil {
		return nil
	}
	return &ExitError{
		Code: code,
		Err:  err,
	}
}

// ExitCode maps err to a Malox process exit code.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		return exitErr.Code
	}
	return ExitScanFailed
}

func usageError(format string, args ...any) error {
	return withExitCode(ExitUsage, fmt.Errorf(format, args...))
}
