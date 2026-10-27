package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditSeparatesRequestsNonEventsAndMalformedRecords(t *testing.T) {
	data := []byte(`{"timestamp":"2026-10-28T10:00:00Z","message":"INFO [200] GET / (1ms)"}
{"timestamp":"2026-10-28T10:00:01Z","message":"INFO Starting init"}
{"timestamp":
`)
	path := filepath.Join(t.TempDir(), "fly.jsonl")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	report, err := auditFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if report.Lines != 3 || report.NormalizedEvents != 1 || report.NonEventRecords != 1 || report.ParseErrors != 1 || report.MissingIPEvents != 1 || report.IPAttributedEvents != 0 || report.AlertCount != 0 || report.HTTPStatuses["200"] != 1 {
		t.Fatalf("incorrect audit: %+v", report)
	}
	if report.GroundTruthAvailable || report.AccuracyComputed {
		t.Fatal("unlabeled source received accuracy claims")
	}
	if report.SourceSHA256 != fmt.Sprintf("%x", sha256.Sum256(data)) {
		t.Fatal("source hash mismatch")
	}
}
