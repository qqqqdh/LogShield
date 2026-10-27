package normalizer

import "testing"

func TestParseLinePreservesQuotedFields(t *testing.T) {
	ev, err := ParseLine(`2026-01-01T00:00:00Z service=web path="/admin panel" ip=198.51.100.1 status=404 ua="scan bot/1.0"`)
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}
	if ev.Path != "/admin panel" {
		t.Fatalf("Path = %q, want /admin panel", ev.Path)
	}
}

func TestParseLineRejectsUnterminatedQuotedField(t *testing.T) {
	if _, err := ParseLine(`2026-01-01T00:00:00Z service=web path="/admin`); err == nil {
		t.Fatal("expected an unterminated quoted field error")
	}
}

func TestParseLineNormalizesAuthenticationFields(t *testing.T) {
	ev, err := ParseLine(`2026-01-01T00:00:00Z service=SSH action=login user=root ip="198.51.100.23" status="failed"`)
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}
	if ev.Service != "ssh" || ev.Action != "auth" || ev.Status != "FAIL" || ev.IP != "198.51.100.23" {
		t.Fatalf("normalized event = %+v", ev)
	}
}
