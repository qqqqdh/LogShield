package main

import (
	"context"
	"go-logshield/internal/benchmark"
	"go-logshield/internal/detector/llm"
	"strings"
	"testing"
	"time"
)

type groundedBenchmarkClient struct{ t *testing.T }

func (c groundedBenchmarkClient) Generate(_ context.Context, prompt string) (string, error) {
	if !strings.Contains(prompt, "- Total Events in Context: 5") || !strings.Contains(prompt, "- Failed Authentication Attempts: 5") {
		c.t.Error("benchmark omitted actual counts/stats")
	}
	return `{"is_attack":true,"confidence":0.9,"findings":[{"technique_id":"T1110","attack_name":"Brute Force","severity":"high","evidence_event_ids":[1,5],"reasoning":"Repeated authentication failures"}]}`, nil
}

func TestBenchmarkPassesGroundedInput(t *testing.T) {
	sample := benchmark.Sample{ID: "attack", IsAttackGround: true, GroundTechnique: "T1110"}
	sample.Events = syntheticLines("auth", "login", "FAIL", "203.0.113.5", nil, 5)
	d := llm.NewICLDetectorWithClient(llm.ICLDetectorConfig{Timeout: time.Second}, groundedBenchmarkClient{t})
	pure := evaluateLLMOnly([]benchmark.Sample{sample}, d, time.Now())
	if len(pure) != 1 || !pure[0].IsAttack || pure[0].IsInvalid || pure[0].IsDegraded {
		t.Fatalf("pure LLM omitted grounded input: %+v", pure)
	}
	got := evaluateHybridPipeline([]benchmark.Sample{sample}, d, time.Now())
	if len(got) != 1 || got[0].IsInvalid || got[0].IsDegraded {
		t.Fatalf("grounded sample invalid: %+v", got)
	}
}
