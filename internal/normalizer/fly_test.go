package normalizer

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestParseFlyHTTPRequest(t *testing.T) {
	attrs := map[string]any{
		"timestamp": "2026-10-28T10:00:00.123456789Z",
		"message":   "\x1b[32mINFO\x1b[0m [200] GET /api/items?q=redacted (1.2ms)",
		"instance":  "not-a-client-ip",
	}
	for _, input := range []any{attrs, map[string]any{"id": "synthetic", "attributes": attrs}} {
		data, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		ev, err := ParseLine(string(data))
		if err != nil {
			t.Fatal(err)
		}
		want, _ := time.Parse(time.RFC3339Nano, attrs["timestamp"].(string))
		if ev.Service != "web" || ev.Action != "get" || ev.Status != "200" || ev.Path != "/api/items" || ev.IP != "" || !ev.TS.Equal(want) {
			t.Fatalf("Fly request parsed incorrectly: %+v", ev)
		}
	}
}

func TestFlyPlatformRecordIsNotAParseFailure(t *testing.T) {
	_, err := ParseLine(`{"timestamp":"2026-10-28T10:00:00Z","message":"INFO Starting init"}`)
	if !errors.Is(err, ErrNonEvent) {
		t.Fatalf("platform record: %v", err)
	}
	for _, input := range []string{
		`{"timestamp":"2026-10-28T10:00:00Z","message":"INFO [999] GET / (1ms)"}`,
		`{"timestamp":"2026-10-28T10:00:00Z","message":"INFO [200] GET / (1ms)","attributes":{}}`,
		`{"timestamp":`,
	} {
		if _, err := ParseLine(input); err == nil || errors.Is(err, ErrNonEvent) {
			t.Fatalf("malformed record classified as non-event: %s", input)
		}
	}
}

func TestFlyHTTPRequestRequiresTimestamp(t *testing.T) {
	for _, input := range []string{
		`{"message":"INFO [200] GET / (1ms)"}`,
		`{"timestamp":"bad","message":"INFO [200] GET / (1ms)"}`,
		"INFO [200] GET / (1ms)",
	} {
		if _, err := ParseLine(input); err == nil {
			t.Fatalf("request without valid timestamp was accepted: %s", input)
		}
	}
}
