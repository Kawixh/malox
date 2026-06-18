package report

import (
	"encoding/json"
	"fmt"
	"io"

	"malox/internal/cache"
)

// WriteCache writes a cache command report in the requested output format.
func WriteCache(w io.Writer, result cache.CommandReport, format Format) error {
	switch format {
	case FormatJSON:
		return writeCacheJSON(w, result)
	case FormatTable:
		return writeCacheTable(w, result)
	case FormatPlain:
		return writeCachePlain(w, result)
	default:
		return fmt.Errorf("unsupported cache output format %q", format)
	}
}

func writeCacheJSON(w io.Writer, result cache.CommandReport) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func writeCacheTable(w io.Writer, result cache.CommandReport) error {
	if _, err := fmt.Fprintf(w, "Cache %s\n", result.Operation); err != nil {
		return err
	}
	for _, source := range result.Sources {
		if _, err := fmt.Fprintf(
			w,
			"  %s: records_changed=%d bytes_written=%d bytes_removed=%d\n",
			source.Source,
			source.RecordsChanged,
			source.BytesWritten,
			source.BytesRemoved,
		); err != nil {
			return err
		}
		for _, warning := range source.Warnings {
			if _, err := fmt.Fprintf(w, "    warning: %s\n", warning); err != nil {
				return err
			}
		}
	}
	for _, warning := range result.Warnings {
		if _, err := fmt.Fprintf(w, "Warning: %s\n", warning); err != nil {
			return err
		}
	}
	return nil
}

func writeCachePlain(w io.Writer, result cache.CommandReport) error {
	var recordsChanged int
	var bytesWritten int64
	var bytesRemoved int64
	for _, source := range result.Sources {
		recordsChanged += source.RecordsChanged
		bytesWritten += source.BytesWritten
		bytesRemoved += source.BytesRemoved
	}
	_, err := fmt.Fprintf(
		w,
		"operation=%s records_changed=%d bytes_written=%d bytes_removed=%d warnings=%d\n",
		result.Operation,
		recordsChanged,
		bytesWritten,
		bytesRemoved,
		len(result.Warnings),
	)
	return err
}
