package normalizer_test

import (
	"fmt"
	"testing"

	"go-logshield/internal/analyzer"
	"go-logshield/internal/normalizer"
)

func TestCanonicalIPVariantsShareDetectorState(t *testing.T) {
	engine := analyzer.NewDefault()
	addresses := []string{"2001:db8::1", "2001:0db8:0:0:0:0:0:1", "2001:db8::1", "2001:0db8::1", "2001:db8::1"}
	alerts := 0
	for i, ip := range addresses {
		event, err := normalizer.ParseLine(fmt.Sprintf("2026-11-03T10:00:0%dZ service=auth action=login status=FAIL ip=%s", i, ip))
		if err != nil {
			t.Fatal(err)
		}
		alerts += len(engine.Process(event))
	}
	if alerts != 1 {
		t.Fatalf("canonical source attack alerts=%d, want1", alerts)
	}
}
