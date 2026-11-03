package normalizer

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"time"
)

// Record preserves rejected lines for callers' parse-error and non-event counters.
type Record struct {
	Line       string
	Path       string
	LineNumber int
	Event      Event
	Err        error
}

// ReadBatch parses all files once and stably merges events by timestamp.
// Batch memory grows with input size; live tailing does not use this path.
func ReadBatch(paths []string) ([]Record, error) {
	var records []Record
	reference := time.Now()
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		lineNumber := 0
		for scanner.Scan() {
			lineNumber++
			line := scanner.Text()
			ev, err := ParseLineAt(line, reference)
			if err != nil {
				err = fmt.Errorf("%s:%d: %w", path, lineNumber, err)
			}
			records = append(records, Record{Line: line, Event: ev, Err: err, Path: path, LineNumber: lineNumber})
		}
		scanErr := scanner.Err()
		closeErr := file.Close()
		if scanErr != nil {
			return nil, fmt.Errorf("scan %s: %w", path, scanErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close %s: %w", path, closeErr)
		}
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Err != nil {
			return false
		}
		if records[j].Err != nil {
			return true
		}
		return records[i].Event.TS.Before(records[j].Event.TS)
	})
	return records, nil
}
