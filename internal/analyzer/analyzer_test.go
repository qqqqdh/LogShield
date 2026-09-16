package analyzer

import "testing"

func TestDefaultAnalyzerDetectsLoginBruteForce(t *testing.T) {
	engine := NewDefault()
	lines := []string{
		"2026-01-01T00:00:00Z service=auth action=login user=alice ip=203.0.113.10 status=FAIL",
		"2026-01-01T00:00:01Z service=auth action=login user=alice ip=203.0.113.10 status=FAIL",
		"2026-01-01T00:00:02Z service=auth action=login user=alice ip=203.0.113.10 status=FAIL",
		"2026-01-01T00:00:03Z service=auth action=login user=alice ip=203.0.113.10 status=FAIL",
		"2026-01-01T00:00:04Z service=auth action=login user=alice ip=203.0.113.10 status=FAIL",
	}

	var results int
	for _, line := range lines {
		_, alerts, err := engine.ProcessLine(line)
		if err != nil {
			t.Fatalf("ProcessLine() error = %v", err)
		}
		results += len(alerts)
	}

	if results != 1 {
		t.Fatalf("got %d alerts, want 1", results)
	}
}
