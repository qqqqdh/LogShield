package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const groundedAttack = `{"is_attack":true,"confidence":0.9,"findings":[{"technique_id":"T1110","attack_name":"Brute Force","severity":"high","evidence_event_ids":[1,2],"reasoning":"Two authentication failures"}]}`

func TestOllamaRequestsSchemaAndDeterministicGeneration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		var schema struct {
			Type       string
			Required   []string
			Properties map[string]json.RawMessage
		}
		if err := json.Unmarshal(req["format"], &schema); err != nil || schema.Type != "object" || len(schema.Required) < 3 {
			t.Errorf("missing response schema: %s", req["format"])
		}
		var options map[string]float64
		if err := json.Unmarshal(req["options"], &options); err != nil || options["temperature"] != 0 {
			t.Errorf("generation options=%s", req["options"])
		}
		if _, exists := options["temperature"]; !exists {
			t.Error("temperature must be explicit")
		}
		json.NewEncoder(w).Encode(map[string]any{"done": true, "response": `{"is_attack":false,"confidence":0.9,"findings":[]}`})
	}))
	defer server.Close()
	client := NewOllamaClient(OllamaClientConfig{OllamaURL: server.URL, Timeout: time.Second})
	if _, err := client.Generate(context.Background(), "test"); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidResponseIsNotReclassified(t *testing.T) {
	data, readErr := os.ReadFile("testdata/auth_prose_response.txt")
	if readErr != nil {
		t.Fatal(readErr)
	}
	raw := string(data)
	client := &mockInferenceClient{responses: []string{raw, `{"is_attack":false,"confidence":0.75,"findings":[]}`}}
	d := NewICLDetectorWithClient(ICLDetectorConfig{Timeout: time.Second}, client)
	result, err := d.EvaluateContextWithInput(PromptInput{BehaviorContext: "five authentication failures", TotalEvents: 5})
	if err != nil {
		t.Fatal(err)
	}
	if result.Engine != EngineInvalid || result.EvaluationStatus != StatusParseError || result.AttemptCount != 1 || client.callCount != 1 {
		t.Fatalf("unexpected reclassification: engine=%s status=%s attempts=%d calls=%d", result.Engine, result.EvaluationStatus, result.AttemptCount, client.callCount)
	}
	// The raw malformed response must be retained in the invalid envelope.
	encoded, _ := json.Marshal(result)
	if !strings.Contains(string(encoded), "Based on the provided context") {
		t.Error("raw invalid response was not retained")
	}
}

func TestGroundedResponseValidation(t *testing.T) {
	cases := map[string]string{
		"null optional string": `{"is_attack":false,"confidence":0.9,"findings":[],"recommended_action":null}`,
		"zero":                 strings.Replace(groundedAttack, "[1,2]", "[0]", 1),
		"negative":             strings.Replace(groundedAttack, "[1,2]", "[-1]", 1),
		"outside":              strings.Replace(groundedAttack, "[1,2]", "[6]", 1),
		"duplicate evidence":   strings.Replace(groundedAttack, "[1,2]", "[1,1]", 1),
		"unknown technique":    strings.Replace(groundedAttack, "T1110", "T9999", 1),
		"empty technique":      strings.Replace(groundedAttack, "T1110", "", 1),
		"empty reasoning":      strings.Replace(groundedAttack, "Two authentication failures", "", 1),
		"unknown field":        strings.Replace(groundedAttack, `"confidence":0.9`, `"confidence":0.9,"unexpected":true`, 1),
		"noncanonical key":     strings.Replace(groundedAttack, `"confidence":0.9`, `"confidence":0.9,"CONFIDENCE":0.1`, 1),
		"duplicate key":        `{"is_attack":true,"is_attack":false,"confidence":0.9,"findings":[]}`,
		"trailing JSON":        groundedAttack + " {}",
		"fenced":               "```json\n" + groundedAttack + "\n```",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			client := &mockInferenceClient{responses: []string{raw, raw}}
			result, err := NewICLDetectorWithClient(ICLDetectorConfig{Timeout: time.Second}, client).EvaluateContextWithInput(PromptInput{TotalEvents: 5, BehaviorContext: "test"})
			if err != nil {
				t.Fatal(err)
			}
			if result.Engine != EngineInvalid || client.callCount != 1 {
				t.Errorf("accepted invalid response: engine=%s status=%s calls=%d", result.Engine, result.EvaluationStatus, client.callCount)
			}
		})
	}
	client := &mockInferenceClient{responses: []string{groundedAttack}}
	result, err := NewICLDetectorWithClient(ICLDetectorConfig{Timeout: time.Second}, client).EvaluateContextWithInput(PromptInput{TotalEvents: 2, BehaviorContext: "test"})
	if err != nil || result.Engine != EngineLLM {
		t.Fatalf("valid evidence rejected: engine=%s status=%s err=%v", result.Engine, result.EvaluationStatus, err)
	}
	client = &mockInferenceClient{responses: []string{groundedAttack}}
	result, err = NewICLDetectorWithClient(ICLDetectorConfig{Timeout: time.Second}, client).EvaluateContext("unknown number of events")
	if err != nil || result.Engine != EngineInvalid {
		t.Errorf("ungrounded legacy result accepted: engine=%s err=%v", result.Engine, err)
	}
}

func TestNetworkFailureRetainsFailureStatus(t *testing.T) {
	client := &mockInferenceClient{errors: []error{context.DeadlineExceeded}}
	result, err := NewICLDetectorWithClient(ICLDetectorConfig{Timeout: time.Second}, client).EvaluateContext("test")
	if err != nil {
		t.Fatal(err)
	}
	if result.Engine != EngineFallbackRule || !result.DegradedMode || result.EvaluationStatus != StatusTimeout || result.ParseError == "" {
		t.Fatalf("timeout hidden: engine=%s status=%s detail=%q", result.Engine, result.EvaluationStatus, result.ParseError)
	}
}
