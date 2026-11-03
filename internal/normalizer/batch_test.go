package normalizer_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-logshield/internal/analyzer"
	"go-logshield/internal/normalizer"
)

func TestReadBatchMergesAttackFragmentsAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	paths := []string{}
	for i, seconds := range [][]int{{0, 1, 100, 101, 102}, {2, 3, 4, 103, 104}} {
		var lines strings.Builder
		for _, s := range seconds {
			fmt.Fprintf(&lines, "%s service=auth action=login status=FAIL ip=203.0.113.5\n", time.Unix(1700000000+int64(s), 0).UTC().Format(time.RFC3339))
		}
		path := filepath.Join(dir, fmt.Sprintf("%d.log", i))
		if err := os.WriteFile(path, []byte(lines.String()), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	records, err := normalizer.ReadBatch(paths)
	if err != nil {
		t.Fatal(err)
	}
	engine := analyzer.NewDefault()
	count := 0
	for i, r := range records {
		if r.Err != nil {
			t.Fatal(r.Err)
		}
		if i > 0 && r.Event.TS.Before(records[i-1].Event.TS) {
			t.Fatal("not chronological")
		}
		count += len(engine.Process(r.Event))
	}
	if len(records) != 10 || count != 2 {
		t.Fatalf("records=%d alerts=%d, want 10 / 2", len(records), count)
	}
}

func TestReadBatchPreservesEqualTimesAndRejectedRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.log")
	lines := []string{
		"2026-01-01T00:00:00Z service=auth action=login status=FAIL ip=203.0.113.1",
		"2026-01-01T09:00:00+09:00 service=auth action=login status=FAIL ip=203.0.113.2",
		"malformed",
		`{"timestamp":"2026-01-01T00:00:00Z","message":"platform startup"}`,
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	records, err := normalizer.ReadBatch([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 4 || records[0].Event.IP != "203.0.113.1" || records[1].Event.IP != "203.0.113.2" || records[2].Err == nil || errors.Is(records[2].Err, normalizer.ErrNonEvent) || !errors.Is(records[3].Err, normalizer.ErrNonEvent) {
		t.Fatalf("records=%+v", records)
	}
}

func TestReadBatchPropagatesReadErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := normalizer.ReadBatch([]string{filepath.Join(dir, "missing.log")}); err == nil {
		t.Fatal("missing file accepted")
	}
	path := filepath.Join(dir, "long.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 1024*1024+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := normalizer.ReadBatch([]string{path}); err == nil {
		t.Fatal("scanner error ignored")
	}
}
