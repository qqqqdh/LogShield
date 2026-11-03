package normalizer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommonEventValidation(t *testing.T) {
	for _, line := range []string{
		"2026-01-01T00:00:00Z service=auth action=login status=FAIL ip=not-an-ip",
		"2026-01-01T00:00:00Z service=web status=999 ip=203.0.113.1",
		"2026-01-01T00:00:00Z service=web status=099",
		"2026-01-01T00:00:00Z service=web status=bad",
		"203.0.113.1 - - [01/Jan/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 999 0 \"-\" \"test\"",
	} {
		if _, err := ParseLine(line); err == nil {
			t.Errorf("accepted invalid input: %s", line)
		}
	}
	for _, status := range []string{"100", "599"} {
		if _, err := ParseLine("2026-01-01T00:00:00Z service=web status=" + status); err != nil {
			t.Fatal(err)
		}
	}
	for _, address := range []string{"2001:0db8:0:0:0:0:0:1", "2001:db8::1"} {
		ev, err := ParseLine("2026-01-01T00:00:00Z service=auth status=failed ip=" + address)
		if err != nil || ev.IP != "2001:db8::1" || ev.Status != "FAIL" {
			t.Errorf("canonical event=%+v err=%v", ev, err)
		}
	}
	ev, err := ParseLine("2026-01-01T00:00:00Z service=auth status=FAIL ip=::ffff:203.0.113.1")
	if err != nil || ev.IP != "203.0.113.1" {
		t.Errorf("mapped IPv4=%+v err=%v", ev, err)
	}
	for _, status := range []string{"", "unexpected"} {
		ev, err := ParseLine("2026-01-01T00:00:00Z service=auth status=" + status)
		if err != nil || ev.IP != "" || ev.Status != "UNKNOWN" {
			t.Errorf("partial event=%+v err=%v", ev, err)
		}
	}
	ev, err = ParseLine(`{"timestamp":"2026-01-01T00:00:00Z","message":"INFO [200] GET / (1ms)"}`)
	if err != nil || ev.IP != "" {
		t.Errorf("missing-IP Fly event=%+v err=%v", ev, err)
	}
	_, err = ParseLine(`{"timestamp":"2026-01-01T00:00:00Z","message":"INFO Starting init"}`)
	if !errors.Is(err, ErrNonEvent) {
		t.Errorf("non-event changed: %v", err)
	}
}

func TestBatchErrorPreservesOriginalLocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.log")
	input := "2026-01-01T00:00:02Z service=web status=200\nbad line\n2026-01-01T00:00:01Z service=web status=200\n"
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	records, err := ReadBatch([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	// Sorting must not change the original error location.
	for _, r := range records {
		if r.Err != nil && !strings.Contains(r.Err.Error(), path+":2") {
			t.Fatalf("missing original source location: %v", r.Err)
		}
	}
}
