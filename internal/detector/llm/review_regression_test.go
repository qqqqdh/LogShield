package llm

import (
	"context"
	"testing"
	"time"
)

type deadlineClient struct {
	t       *testing.T
	timeout time.Duration
}

func (c deadlineClient) Generate(ctx context.Context, _ string) (string, error) {
	deadline, ok := ctx.Deadline()
	remaining := time.Until(deadline)
	if !ok || remaining <= 0 || remaining > c.timeout || remaining < c.timeout-time.Second {
		c.t.Errorf("deadline remaining=%v, want near %v", remaining, c.timeout)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return `{"is_attack":false,"confidence":0,"findings":[]}`, nil
}

func TestRequiredJSONFields(t *testing.T) {
	for _, raw := range []string{
		`{}`, `null`,
		`{"confidence":0,"findings":[]}`,
		`{"is_attack":false,"findings":[]}`,
		`{"is_attack":false,"confidence":0}`,
		`{"is_attack":null,"confidence":0,"findings":[]}`,
		`{"is_attack":false,"confidence":null,"findings":[]}`,
		`{"is_attack":false,"confidence":0,"findings":null}`,
	} {
		t.Run(raw, func(t *testing.T) {
			client := &mockInferenceClient{responses: []string{raw, raw}}
			d := NewICLDetectorWithClient(ICLDetectorConfig{Timeout: time.Second}, client)
			r, err := d.EvaluateContext("test")
			if err != nil {
				t.Fatal(err)
			}
			if r.Engine != EngineInvalid || r.EvaluationStatus != StatusSchemaError || r.AttemptCount != 1 || client.callCount != 1 {
				t.Fatalf("invalid response accepted: %+v calls=%d", r, client.callCount)
			}
		})
	}
	valid := `{"is_attack":false,"confidence":0,"findings":[]}`
	client := &mockInferenceClient{responses: []string{"{}", valid}}
	r, err := NewICLDetectorWithClient(ICLDetectorConfig{Timeout: time.Second}, client).EvaluateContext("test")
	if err != nil || r.Engine != EngineInvalid || r.AttemptCount != 1 {
		t.Fatalf("invalid response must not be reclassified: %+v err=%v", r, err)
	}
}

func TestICLTimeoutDefaults(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second, 3 * time.Second} {
		expected := timeout
		if expected <= 0 {
			expected = 10 * time.Second
		}
		d := NewICLDetectorWithClient(ICLDetectorConfig{Timeout: timeout}, deadlineClient{t, expected})
		r, err := d.EvaluateContext("test")
		if err != nil || r.Engine != EngineLLM {
			t.Fatalf("default client failed: %+v err=%v", r, err)
		}
		standard := NewICLDetector(ICLDetectorConfig{Timeout: timeout})
		client := standard.client.(*OllamaClient)
		if standard.config.Timeout != expected || client.config.Timeout != expected || standard.config.ModelName != client.config.ModelName || standard.config.OllamaURL != client.config.OllamaURL {
			t.Fatalf("inconsistent defaults: %+v / %+v", standard.config, client.config)
		}
	}
}
