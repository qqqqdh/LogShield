package analyzer

import (
	"fmt"
	"testing"
	"time"

	"go-logshield/internal/normalizer"
)

func TestDefaultAnalyzerDetectsNativeSSHAndWebLogs(t *testing.T) {
	engine := NewDefault()
	reference := time.Date(2026, 10, 28, 12, 0, 0, 0, time.FixedZone("KST", 9*3600))
	sshTemplate := "Oct 28 10:00:%02d host sshd[12]: Failed password for root from 203.0.113.1 port 22 ssh2"
	webTemplate := `203.0.113.2 - - [28/Oct/2026:10:01:%02d +0900] "GET /.env?x=1 HTTP/1.1" 404 12 "-" "scanner"`
	counts := map[string]int{}
	for i := 0; i < 6; i++ {
		ev, err := normalizer.ParseLineAt(fmt.Sprintf(sshTemplate, i), reference)
		if err != nil {
			t.Fatal(err)
		}
		for _, result := range engine.Process(ev) {
			counts[result.RuleID]++
		}
	}
	for i := 0; i < 4; i++ {
		ev, err := normalizer.ParseLineAt(fmt.Sprintf(webTemplate, i), reference)
		if err != nil {
			t.Fatal(err)
		}
		for _, result := range engine.Process(ev) {
			counts[result.RuleID]++
		}
	}
	if counts["SSH_BRUTE_FORCE"] != 1 || counts["WEB_ENUMERATION"] != 1 {
		t.Fatalf("native log detections = %+v, want one SSH and one web alert", counts)
	}
}

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
