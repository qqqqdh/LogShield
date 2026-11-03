package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

type Engine string

const (
	EngineLLM          Engine = "llm"
	EngineFallbackRule Engine = "fallback_rule"
	EngineInvalid      Engine = "invalid"
)

type EvaluationStatus string

const (
	StatusValid       EvaluationStatus = "valid"
	StatusParseError  EvaluationStatus = "parse_error"
	StatusSchemaError EvaluationStatus = "schema_error"
	StatusTimeout     EvaluationStatus = "timeout"
	StatusUnavailable EvaluationStatus = "unavailable"
)

type Finding struct {
	TechniqueID      string `json:"technique_id"`
	AttackName       string `json:"attack_name"`
	Severity         string `json:"severity"`           // low, medium, high, critical
	EvidenceEventIDs []int  `json:"evidence_event_ids"` // unique indices 1..TotalEvents when attack
	Reasoning        string `json:"reasoning"`
}

type LLMResponsePayload struct {
	IsAttack          bool      `json:"is_attack"`
	Confidence        float64   `json:"confidence"`
	Findings          []Finding `json:"findings"`
	RecommendedAction string    `json:"recommended_action,omitempty"`
}

type ICLResult struct {
	Engine           Engine             `json:"engine"`
	DegradedMode     bool               `json:"degraded_mode"`
	EvaluationStatus EvaluationStatus   `json:"evaluation_status"`
	AttemptCount     int                `json:"attempt_count"`
	ModelUsed        string             `json:"model_used,omitempty"`
	ParseError       string             `json:"parse_error,omitempty"`
	RawResponse      string             `json:"raw_response,omitempty"`
	Prompt           string             `json:"prompt_used,omitempty"`
	Result           LLMResponsePayload `json:"result"`
}

// InferenceClient abstracts LLM execution for decoupling (Ollama, OpenAI, etc.).
type InferenceClient interface {
	Generate(ctx context.Context, prompt string) (string, error)
}

type OllamaClientConfig struct {
	OllamaURL string
	ModelName string
	Timeout   time.Duration
}

type OllamaClient struct {
	config OllamaClientConfig
	client *http.Client
}

func NewOllamaClient(config OllamaClientConfig) *OllamaClient {
	if config.OllamaURL == "" {
		config.OllamaURL = "http://localhost:11434"
	}
	if config.ModelName == "" {
		config.ModelName = "llama3.1:8b"
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	return &OllamaClient{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

var responseSchema = json.RawMessage(`{
 "type":"object","additionalProperties":false,
 "required":["is_attack","confidence","findings"],
 "properties":{
  "is_attack":{"type":"boolean"},
  "confidence":{"type":"number","minimum":0,"maximum":1},
  "findings":{"type":"array","maxItems":20,"items":{
   "type":"object","additionalProperties":false,
   "required":["technique_id","attack_name","severity","evidence_event_ids","reasoning"],
   "properties":{
    "technique_id":{"type":"string","enum":["T1110","T1595","T1078","T1499","T1059"]},
    "attack_name":{"type":"string","minLength":1,"maxLength":128},
    "severity":{"type":"string","enum":["low","medium","high","critical"]},
    "evidence_event_ids":{"type":"array","minItems":1,"uniqueItems":true,"items":{"type":"integer","minimum":1}},
    "reasoning":{"type":"string","minLength":1,"maxLength":1024}
   }
  }},
  "recommended_action":{"type":"string","maxLength":256}
 }
}`)

type ollamaRequest struct {
	Model   string             `json:"model"`
	Prompt  string             `json:"prompt"`
	Stream  bool               `json:"stream"`
	Format  json.RawMessage    `json:"format"`
	Options map[string]float64 `json:"options"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

func (c *OllamaClient) Generate(ctx context.Context, prompt string) (string, error) {
	reqBody := ollamaRequest{
		Model:   c.config.ModelName,
		Prompt:  prompt,
		Stream:  false,
		Format:  responseSchema,
		Options: map[string]float64{"temperature": 0},
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request error: %w", err)
	}

	apiURL := fmt.Sprintf("%s/api/generate", strings.TrimRight(c.config.OllamaURL, "/"))
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(data))
	if err != nil {
		return "", fmt.Errorf("create request error: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama API status %d", resp.StatusCode)
	}

	data, err = io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return "", err
	}
	if len(data) > 1<<20 {
		return "", errors.New("Ollama response exceeds 1 MiB")
	}
	var ollamaResp ollamaResponse
	if err := json.Unmarshal(data, &ollamaResp); err != nil {
		return "", fmt.Errorf("decode response error: %w", err)
	}

	if !ollamaResp.Done {
		return "", errors.New("Ollama generation is incomplete")
	}
	return ollamaResp.Response, nil
}

type ICLDetectorConfig struct {
	OllamaURL  string
	ModelName  string
	Timeout    time.Duration
	EnableMock bool
}

type ICLDetector struct {
	config    ICLDetectorConfig
	generator *PromptGenerator
	client    InferenceClient
}

func NewICLDetector(config ICLDetectorConfig) *ICLDetector {
	ollamaClient := NewOllamaClient(OllamaClientConfig{
		OllamaURL: config.OllamaURL,
		ModelName: config.ModelName,
		Timeout:   config.Timeout,
	})
	config.OllamaURL = ollamaClient.config.OllamaURL
	config.ModelName = ollamaClient.config.ModelName
	config.Timeout = ollamaClient.config.Timeout
	return NewICLDetectorWithClient(config, ollamaClient)
}

func NewICLDetectorWithClient(config ICLDetectorConfig, client InferenceClient) *ICLDetector {
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	return &ICLDetector{
		config:    config,
		generator: NewPromptGenerator(),
		client:    client,
	}
}

// EvaluateContext is a legacy text-only path; attack evidence needs TotalEvents via EvaluateContextWithInput.
func (d *ICLDetector) EvaluateContext(behaviorContext string) (ICLResult, error) {
	return d.EvaluateContextWithInput(PromptInput{
		BehaviorContext: behaviorContext,
	})
}

// EvaluateContextWithInput evaluates a full PromptInput including computed statistical features.
func (d *ICLDetector) EvaluateContextWithInput(input PromptInput) (ICLResult, error) {
	prompt := d.generator.GeneratePromptWithInput(input)
	ctx, cancel := context.WithTimeout(context.Background(), d.config.Timeout)
	defer cancel()
	raw, err := d.client.Generate(ctx, prompt)
	if err != nil {
		status := StatusUnavailable
		var netErr net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
			status = StatusTimeout
		}
		return d.fallbackEvaluate(input.BehaviorContext, err, status)
	}
	payload, parseErr, schemaErr := d.parseAndValidate(raw, input.TotalEvents)
	result := ICLResult{Engine: EngineLLM, EvaluationStatus: StatusValid, AttemptCount: 1, ModelUsed: d.config.ModelName, Prompt: prompt, Result: payload}
	if parseErr != nil || schemaErr != nil {
		result.Engine = EngineInvalid
		result.DegradedMode = true
		result.EvaluationStatus = StatusParseError
		if schemaErr != nil {
			result.EvaluationStatus = StatusSchemaError
			parseErr = schemaErr
		}
		result.ParseError = parseErr.Error()
		result.RawResponse = raw
		result.Result = LLMResponsePayload{Findings: []Finding{}, RecommendedAction: "evaluation failed"}
	}
	return result, nil
}

func (d *ICLDetector) parseAndValidate(raw string, eventCount int) (LLMResponsePayload, error, error) {
	var payload LLMResponsePayload
	if !json.Valid([]byte(raw)) {
		return payload, errors.New("response is not a single valid JSON value"), nil
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return payload, nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, nil, fmt.Errorf("schema validation error: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return payload, nil, err
	}
	for _, key := range []string{"is_attack", "confidence", "findings"} {
		value, exists := fields[key]
		if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return payload, nil, fmt.Errorf("%s is required and must not be null", key)
		}
	}
	if value, exists := fields["recommended_action"]; exists && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return payload, nil, errors.New("recommended_action must be a string when present")
	}
	if err := validatePayload(payload, eventCount); err != nil {
		return payload, nil, err
	}
	return payload, nil, nil
}

// JSON object duplicates are ambiguous even when encoding/json accepts them.
func rejectDuplicateKeys(raw string) error {
	decoder := json.NewDecoder(strings.NewReader(raw))
	var visit func() error
	visit = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]bool)
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name := key.(string)
				if name != strings.ToLower(name) {
					return fmt.Errorf("noncanonical JSON field %q", name)
				}
				if seen[name] {
					return fmt.Errorf("duplicate JSON field %q", name)
				}
				seen[name] = true
				if err := visit(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := visit(); err != nil {
					return err
				}
			}
		}
		_, err = decoder.Token()
		return err
	}
	return visit()
}

func validatePayload(p LLMResponsePayload, eventCount int) error {
	if p.Confidence < 0 || p.Confidence > 1 {
		return errors.New("confidence outside [0,1]")
	}
	if utf8.RuneCountInString(p.RecommendedAction) > 256 {
		return errors.New("recommended_action too long")
	}
	if !p.IsAttack {
		if len(p.Findings) > 0 {
			return errors.New("is_attack=false requires empty findings")
		}
		return nil
	}
	if len(p.Findings) == 0 || len(p.Findings) > 20 {
		return errors.New("attack requires 1..20 findings")
	}
	if eventCount <= 0 {
		return errors.New("attack evidence requires the input event count")
	}
	for _, f := range p.Findings {
		switch f.TechniqueID {
		case "T1110", "T1595", "T1078", "T1499", "T1059":
		default:
			return fmt.Errorf("unsupported technique %q", f.TechniqueID)
		}
		switch f.Severity {
		case "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("invalid severity %q", f.Severity)
		}
		if strings.TrimSpace(f.AttackName) == "" || utf8.RuneCountInString(f.AttackName) > 128 || strings.TrimSpace(f.Reasoning) == "" || utf8.RuneCountInString(f.Reasoning) > 1024 {
			return errors.New("finding requires bounded attack_name and reasoning")
		}
		if len(f.EvidenceEventIDs) == 0 {
			return errors.New("finding requires evidence")
		}
		seen := make(map[int]bool)
		for _, id := range f.EvidenceEventIDs {
			if id < 1 || id > eventCount || seen[id] {
				return fmt.Errorf("invalid or duplicate evidence ID %d for %d input events", id, eventCount)
			}
			seen[id] = true
		}
	}
	return nil
}

// Count signals by service so HTTP 401 responses do not become login failures.
func fallbackSignalCounts(contextText string) (failed, scans int) {
	for _, line := range strings.Split(strings.ToLower(contextText), "\n") {
		var service, status, path string
		for _, field := range strings.Fields(line) {
			field = strings.Trim(field, ",;")
			switch {
			case strings.HasPrefix(field, "service="):
				service = strings.TrimPrefix(field, "service=")
			case strings.HasPrefix(field, "status="):
				status = strings.TrimPrefix(field, "status=")
			case strings.HasPrefix(field, "path="):
				path = strings.TrimPrefix(field, "path=")
			}
		}
		if (service == "auth" || service == "ssh") && (status == "fail" || status == "failed" || status == "failure" || status == "401") {
			failed++
		}
		if service == "web" && (status == "404" || strings.HasPrefix(path, "/.env") || strings.HasPrefix(path, "/admin")) {
			scans++
		}
	}
	return failed, scans
}

// Fallback heuristic evaluator for degraded execution when LLM is unavailable.
func (d *ICLDetector) fallbackEvaluate(behaviorContext string, cause error, status EvaluationStatus) (ICLResult, error) {
	resPayload := LLMResponsePayload{}
	failedCount, notfoundCount := fallbackSignalCounts(behaviorContext)

	if failedCount >= 3 {
		resPayload.IsAttack = true
		resPayload.Confidence = 0.85
		resPayload.RecommendedAction = "Temporarily rate-limit or block source IP"
		resPayload.Findings = []Finding{
			{
				TechniqueID:      "T1110",
				AttackName:       "Brute Force / Credential Access",
				Severity:         "high",
				EvidenceEventIDs: []int{1, 2, 3},
				Reasoning:        fmt.Sprintf("[In-Context Evaluation] Multiple authentication failures (%d events) observed in sliding window context, matching MITRE T1110.", failedCount),
			},
		}
	} else if notfoundCount >= 2 {
		resPayload.IsAttack = true
		resPayload.Confidence = 0.80
		resPayload.RecommendedAction = "Block scanner IP and inspect web server logs"
		resPayload.Findings = []Finding{
			{
				TechniqueID:      "T1595",
				AttackName:       "Active Scanning / Web Enumeration",
				Severity:         "medium",
				EvidenceEventIDs: []int{1, 2},
				Reasoning:        fmt.Sprintf("[In-Context Evaluation] Sensitive path probing or repeated 404 errors (%d events) detected in sliding window context, matching MITRE T1595.", notfoundCount),
			},
		}
	} else {
		resPayload.IsAttack = false
		resPayload.Confidence = 0.90
		resPayload.RecommendedAction = "monitor"
		resPayload.Findings = []Finding{}
	}

	return ICLResult{
		Engine:           EngineFallbackRule,
		DegradedMode:     true,
		EvaluationStatus: status,
		AttemptCount:     1,
		ParseError:       cause.Error(),
		ModelUsed:        fmt.Sprintf("%s (ICL Fallback Engine: %v)", d.config.ModelName, cause),
		Result:           resPayload,
	}, nil
}
