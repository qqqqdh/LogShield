package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSchemaTechniqueIDsMatchPrompt(t *testing.T) {
	var schema struct {
		Properties struct {
			Findings struct {
				Items struct {
					Properties struct {
						TechniqueID struct{ Enum []string } `json:"technique_id"`
					}
				}
			}
		}
	}
	if err := json.Unmarshal(responseSchema, &schema); err != nil {
		t.Fatal(err)
	}
	ids := schema.Properties.Findings.Items.Properties.TechniqueID.Enum
	if len(ids) != len(NewPromptGenerator().Techniques) {
		t.Fatalf("schema techniques=%v", ids)
	}
	for _, tech := range NewPromptGenerator().Techniques {
		found := false
		for _, id := range ids {
			if id == tech.ID {
				found = true
			}
		}
		if !found {
			t.Errorf("prompt technique %s absent from schema", tech.ID)
		}
	}
}

func TestNestedDuplicateKeysAndUnicodeBounds(t *testing.T) {
	duplicate := strings.Replace(groundedAttack, `"severity":"high"`, `"severity":"high","severity":"low"`, 1)
	d := NewICLDetectorWithClient(ICLDetectorConfig{Timeout: time.Second}, &mockInferenceClient{responses: []string{duplicate}})
	result, err := d.EvaluateContextWithInput(PromptInput{TotalEvents: 2})
	if err != nil || result.Engine != EngineInvalid {
		t.Fatalf("duplicate field accepted: %s err=%v", result.Engine, err)
	}
	valid := strings.Replace(groundedAttack, "Two authentication failures", strings.Repeat("가", 1024), 1)
	d = NewICLDetectorWithClient(ICLDetectorConfig{Timeout: time.Second}, &mockInferenceClient{responses: []string{valid}})
	result, err = d.EvaluateContextWithInput(PromptInput{TotalEvents: 2})
	if err != nil || result.Engine != EngineLLM {
		t.Fatalf("Unicode character bound mismatch: %s %s err=%v", result.Engine, result.ParseError, err)
	}
}

func TestOllamaRejectsIncompleteAndOversizedEnvelope(t *testing.T) {
	for _, body := range []string{`{"done":false,"response":"{}"}`, strings.Repeat("x", (1<<20)+1)} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		client := NewOllamaClient(OllamaClientConfig{OllamaURL: server.URL, Timeout: time.Second})
		if _, err := client.Generate(context.Background(), "test"); err == nil {
			t.Error("invalid envelope accepted")
		}
		server.Close()
	}
}
