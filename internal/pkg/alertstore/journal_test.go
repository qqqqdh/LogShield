package alertstore

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go-logshield/internal/detector"
)

func TestJournalKeepsEveryAlertBeyondDisplayLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 101; i++ {
		alert := detector.Result{TS: time.Unix(int64(i), 0), Severity: "높음", Title: "test"}
		if err := journal.Append(alert); err != nil {
			t.Fatal(err)
		}
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scan := bufio.NewScanner(file)
	count := 0
	for scan.Scan() {
		var entry Entry
		if err := json.Unmarshal(scan.Bytes(), &entry); err != nil {
			t.Fatal(err)
		}
		if entry.RecordedAt.IsZero() || entry.Alert.Title != "test" {
			t.Fatalf("bad entry: %+v", entry)
		}
		count++
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 101 {
		t.Fatalf("journal entries=%d, want 101", count)
	}
	if err := journal.Append(detector.Result{}); err == nil {
		t.Fatal("append after close succeeded")
	}
}
