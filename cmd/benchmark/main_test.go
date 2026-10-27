package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go-logshield/internal/benchmark"
	"go-logshield/internal/detector/llm"
)

type benignClient struct{}

func (benignClient) Generate(context.Context, string) (string, error) {
	return `{"is_attack":false,"confidence":0.9,"findings":[]}`, nil
}

func TestHybridKeepsRuleAlertWhenLLMIsBenign(t *testing.T) {
	reference := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	sample := benchmark.Sample{ID: "rule-alert", IsAttackGround: true, GroundTechnique: "T1110", BehaviorContext: "normal", Events: []string{
		"2026-10-28T10:00:00Z service=auth action=login ip=203.0.113.5 status=FAIL",
		"2026-10-28T10:00:01Z service=auth action=login ip=203.0.113.5 status=FAIL",
		"2026-10-28T10:00:02Z service=auth action=login ip=203.0.113.5 status=FAIL",
		"2026-10-28T10:00:03Z service=auth action=login ip=203.0.113.5 status=FAIL",
		"2026-10-28T10:00:04Z service=auth action=login ip=203.0.113.5 status=FAIL",
	}}
	detector := llm.NewICLDetectorWithClient(llm.ICLDetectorConfig{Timeout: time.Second}, benignClient{})
	got := evaluateHybridPipeline([]benchmark.Sample{sample}, detector, reference)
	if len(got) != 1 || !got[0].IsAttack || got[0].TechniqueID != "T1110" {
		t.Fatalf("hybrid discarded rule alert: %+v", got)
	}
}

func TestRuleBaselineUsesParsedEventsNotNarrative(t *testing.T) {
	ref := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	sample := benchmark.Sample{
		ID: "positive", IsAttackGround: true, GroundTechnique: "T1110",
		BehaviorContext: "normal text",
		Events: []string{
			"2026-10-28T10:00:00Z service=auth action=login ip=203.0.113.5 status=FAIL",
			"2026-10-28T10:00:01Z service=auth action=login ip=203.0.113.5 status=FAIL",
			"2026-10-28T10:00:02Z service=auth action=login ip=203.0.113.5 status=FAIL",
			"2026-10-28T10:00:03Z service=auth action=login ip=203.0.113.5 status=FAIL",
			"2026-10-28T10:00:04Z service=auth action=login ip=203.0.113.5 status=FAIL",
		},
	}
	spoof := benchmark.Sample{ID: "negative", BehaviorContext: "status=FAIL status=FAIL status=FAIL status=FAIL", IsAttackGround: false}
	got := evaluateRuleOnly([]benchmark.Sample{sample, spoof}, ref)
	if !got[0].IsAttack || got[0].TechniqueID != "T1110" || got[1].IsAttack {
		t.Fatalf("rule predictions = %+v", got)
	}
}

func TestLoadDatasetValidatesLabeledEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dataset.json")
	fixture := map[string]any{
		"reference_time": "2026-10-28T12:00:00+09:00",
		"samples":        []benchmark.Sample{{ID: "one", IsAttackGround: true, GroundTechnique: "T1110", BehaviorContext: "untrusted narrative", Events: []string{"2026-10-28T10:00:00+09:00 service=auth action=login ip=203.0.113.5 status=FAIL"}}},
	}
	data, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	samples, ref, err := loadDataset(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 || samples[0].BehaviorContext == "" || samples[0].BehaviorContext == "untrusted narrative" || ref.Year() != 2026 {
		t.Fatalf("loaded samples = %+v, reference=%s", samples, ref)
	}
	fixture["samples"] = []benchmark.Sample{{ID: "bad", Events: []string{"not a log"}}}
	data, _ = json.Marshal(fixture)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadDataset(path); err == nil {
		t.Fatal("malformed log accepted")
	}
}
