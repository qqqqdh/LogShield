package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go-logshield/internal/detector/llm"
)

func TestCLIValidationFailuresKeepRuleAlerts(t *testing.T) {
	for _, mode := range []string{"invalid", "timeout", "normal"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if mode == "timeout" {
					select {
					case <-r.Context().Done():
						return
					case <-time.After(time.Second):
					}
				}
				raw := `{"is_attack":false,"confidence":0.9,"findings":[]}`
				if mode == "invalid" {
					raw = "explanation before " + raw
				}
				json.NewEncoder(w).Encode(map[string]any{"done": true, "response": raw})
			}))
			defer server.Close()
			dir := t.TempDir()
			var input strings.Builder
			for i := 0; i < 5; i++ {
				fmt.Fprintf(&input, "2026-11-03T10:00:0%dZ service=auth action=login status=FAIL ip=203.0.113.5\n", i)
			}
			if err := os.WriteFile(filepath.Join(dir, "auth.log"), []byte(input.String()), 0600); err != nil {
				t.Fatal(err)
			}
			timeout := "2s"
			if mode == "timeout" {
				timeout = "30ms"
			}
			reportPath := filepath.Join(dir, "report.json")
			cmd := exec.Command("go", "run", ".", "-log-dir", dir, "-llm=true", "-ollama-url", server.URL, "-llm-timeout", timeout, "-anomaly-threshold", "32", "-report", reportPath, "-alerts-file", filepath.Join(dir, "alerts.jsonl"))
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("CLI failed: %v\n%s", err, output)
			}
			data, err := os.ReadFile(reportPath)
			if err != nil {
				t.Fatal(err)
			}
			var report FinalReport
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 1 || len(report.LLMICLEvaluations) != 1 || len(report.RuleBasedAlerts) != 1 {
				t.Fatalf("calls=%d evals=%d rules=%d", calls.Load(), len(report.LLMICLEvaluations), len(report.RuleBasedAlerts))
			}
			result := report.LLMICLEvaluations[0]
			switch mode {
			case "invalid":
				if result.Engine != llm.EngineInvalid || result.EvaluationStatus != llm.StatusParseError || result.AttemptCount != 1 || result.RawResponse == "" {
					t.Errorf("invalid envelope: engine=%s status=%s", result.Engine, result.EvaluationStatus)
				}
			case "timeout":
				if result.Engine != llm.EngineFallbackRule || result.EvaluationStatus != llm.StatusTimeout {
					t.Errorf("timeout envelope: engine=%s status=%s", result.Engine, result.EvaluationStatus)
				}
			case "normal":
				if result.Engine != llm.EngineLLM || result.EvaluationStatus != llm.StatusValid {
					t.Errorf("normal envelope: engine=%s status=%s", result.Engine, result.EvaluationStatus)
				}
			}
			if mode != "normal" && (!strings.Contains(string(output), "LLM EVALUATION FAILED") || strings.Contains(string(output), "LLM ICL NORMAL")) {
				t.Errorf("failure printed as normal: %s", output)
			}
		})
	}
}

func TestCLIRejectsNonpositiveTimeoutBeforeOpeningFiles(t *testing.T) {
	for _, value := range []string{"0s", "-1s"} {
		cmd := exec.Command("go", "run", ".", "-llm-timeout", value, "-log-dir", filepath.Join(t.TempDir(), "missing"))
		output, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "llm-timeout must be positive") {
			t.Fatalf("invalid timeout accepted: %v %s", err, output)
		}
	}
}
