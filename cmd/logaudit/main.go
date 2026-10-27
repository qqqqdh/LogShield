// logaudit measures parsing and detection coverage without exposing raw log lines.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"go-logshield/internal/analyzer"
	"go-logshield/internal/normalizer"
)

type auditReport struct {
	Source               string         `json:"source"`
	SourceSHA256         string         `json:"source_sha256"`
	Lines                int            `json:"lines"`
	NormalizedEvents     int            `json:"normalized_events"`
	NonEventRecords      int            `json:"non_event_records"`
	ParseErrors          int            `json:"parse_errors"`
	IPAttributedEvents   int            `json:"ip_attributed_events"`
	MissingIPEvents      int            `json:"missing_ip_events"`
	HTTPStatuses         map[string]int `json:"http_status_counts"`
	AlertCount           int            `json:"alert_count"`
	FirstEventTime       string         `json:"first_event_time,omitempty"`
	LastEventTime        string         `json:"last_event_time,omitempty"`
	GroundTruthAvailable bool           `json:"ground_truth_available"`
	AccuracyComputed     bool           `json:"accuracy_computed"`
}

func auditFile(path string) (auditReport, error) {
	report := auditReport{Source: path, HTTPStatuses: make(map[string]int)}
	file, err := os.Open(path)
	if err != nil {
		return report, err
	}
	defer file.Close()
	hash := sha256.New()
	scan := bufio.NewScanner(io.TeeReader(file, hash))
	scan.Buffer(make([]byte, 64*1024), 1024*1024)
	engine := analyzer.NewDefault()
	var first, last time.Time
	for scan.Scan() {
		report.Lines++
		ev, alerts, err := engine.ProcessLine(scan.Text())
		if errors.Is(err, normalizer.ErrNonEvent) {
			report.NonEventRecords++
			continue
		}
		if err != nil {
			report.ParseErrors++
			continue
		}
		report.NormalizedEvents++
		if ev.IP == "" {
			report.MissingIPEvents++
		} else {
			report.IPAttributedEvents++
		}
		if ev.Service == "web" {
			report.HTTPStatuses[ev.Status]++
		}
		report.AlertCount += len(alerts)
		if first.IsZero() || ev.TS.Before(first) {
			first = ev.TS
		}
		if last.IsZero() || ev.TS.After(last) {
			last = ev.TS
		}
	}
	if err := scan.Err(); err != nil {
		return report, err
	}
	report.SourceSHA256 = fmt.Sprintf("%x", hash.Sum(nil))
	if !first.IsZero() {
		report.FirstEventTime = first.Format(time.RFC3339Nano)
		report.LastEventTime = last.Format(time.RFC3339Nano)
	}
	return report, nil
}

func main() {
	input := flag.String("input", "", "Exact log or JSONL file to audit")
	output := flag.String("output", "", "Aggregate JSON report path (default: stdout)")
	flag.Parse()
	if *input == "" {
		log.Fatal("-input is required")
	}
	report, err := auditFile(*input)
	if err != nil {
		log.Fatal(err)
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	data = append(data, '\n')
	if *output == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			log.Fatal(err)
		}
	} else if err := os.WriteFile(*output, data, 0600); err != nil {
		log.Fatal(err)
	}
}
