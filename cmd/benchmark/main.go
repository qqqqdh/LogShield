package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"go-logshield/internal/analyzer"
	"go-logshield/internal/benchmark"
	"go-logshield/internal/detector/llm"
	"go-logshield/internal/normalizer"
)

func main() {
	ollamaURL := flag.String("ollama-url", "http://localhost:11434", "Ollama API Endpoint URL")
	llmModel := flag.String("llm-model", "llama3.1:8b", "LLM Model Name for Evaluation")
	reportPath := flag.String("output", "benchmark_report.json", "Output JSON report path")
	datasetPath := flag.String("dataset", "", "Labeled JSON dataset; empty uses seven synthetic examples")
	flag.Parse()

	fmt.Printf("🚀 [LogShield Benchmark] Running 4-Mode Independent Evaluation (Model: %s)...\n", *llmModel)

	dataset, reference, err := loadDataset(*datasetPath)
	if err != nil {
		log.Fatalf("load dataset: %v", err)
	}
	datasetKind := "synthetic_demo"
	datasetSource := "built-in seven examples"
	if *datasetPath != "" {
		datasetKind, datasetSource = "user_labeled", *datasetPath
	}
	fmt.Printf("Dataset: %s (%s, %d samples)\n", datasetSource, datasetKind, len(dataset))
	evaluator := benchmark.NewEvaluator()

	detector := llm.NewICLDetector(llm.ICLDetectorConfig{
		OllamaURL: *ollamaURL,
		ModelName: *llmModel,
		Timeout:   5 * time.Second,
	})

	// 1. Mode 1: Rule-Only Baseline
	fmt.Println("\n🔍 [Mode 1/4] Running Rule-Only Detector Evaluation...")
	ruleDetails := evaluateRuleOnly(dataset, reference)
	ruleResult := evaluator.ComputeDetailed("Rule-Only Baseline", ruleDetails, dataset)

	// 2. Mode 2: Fallback-Only Heuristic Baseline
	fmt.Println("🔍 [Mode 2/4] Running Fallback-Only Heuristic Evaluation...")
	fallbackDetails := evaluateFallbackOnly(dataset)
	fallbackResult := evaluator.ComputeDetailed("Fallback-Only Baseline", fallbackDetails, dataset)

	// 3. Mode 3: LLM-Only Pure Evaluation (Without Anomaly Pre-filter)
	fmt.Println("🔍 [Mode 3/4] Running LLM attempts with fallback on model failure...")
	llmDetails := evaluateLLMOnly(dataset, detector)
	llmResult := evaluator.ComputeDetailed("LLM Attempt/Fallback", llmDetails, dataset)

	// 4. Mode 4: Rule alerts plus anomaly-score-gated LLM evaluation.
	fmt.Println("🔍 [Mode 4/4] Running Hybrid Pipeline (Rule/Anomaly Filter + LLM)...")
	hybridDetails := evaluateHybridPipeline(dataset, detector, reference)
	hybridResult := evaluator.ComputeDetailed("Rule+Score+LLM", hybridDetails, dataset)

	// Create Multi-Mode Benchmark Report
	multiReport := benchmark.MultiModeBenchmarkReport{
		ModelName:      *llmModel,
		DatasetSource:  datasetSource,
		DatasetKind:    datasetKind,
		ReferenceTime:  reference.Format(time.RFC3339),
		Timestamp:      time.Now().Format(time.RFC3339),
		RuleOnly:       ruleResult,
		FallbackOnly:   fallbackResult,
		LLMOnly:        llmResult,
		HybridPipeline: hybridResult,
	}

	// Print comparison summary
	multiReport.PrintComparisonSummary()

	// Print detailed summary for Hybrid Pipeline
	hybridResult.PrintSummary()

	// Save JSON report
	reportData, err := json.MarshalIndent(multiReport, "", "  ")
	if err != nil {
		log.Fatalf("marshal benchmark report: %v", err)
	}
	if err := os.WriteFile(*reportPath, reportData, 0600); err != nil {
		log.Fatalf("write benchmark report: %v", err)
	}
	fmt.Printf("\n📄 Multi-mode benchmark metric report saved to '%s'\n", *reportPath)
}

func evaluateRuleOnly(dataset []benchmark.Sample, reference time.Time) []benchmark.PredictionDetail {
	details := make([]benchmark.PredictionDetail, len(dataset))
	for i, sample := range dataset {
		start := time.Now()
		isAttack, techID, _ := evaluateRules(sample, reference)
		details[i] = benchmark.PredictionDetail{SampleID: sample.ID, IsAttack: isAttack, TechniqueID: techID, Latency: time.Since(start)}
	}
	return details
}

func evaluateRules(sample benchmark.Sample, reference time.Time) (bool, string, []normalizer.Event) {
	engine := analyzer.NewDefault()
	events := make([]normalizer.Event, 0, len(sample.Events))
	attack := false
	technique := "None"
	for _, raw := range sample.Events {
		ev, err := normalizer.ParseLineAt(raw, reference)
		if err != nil {
			continue
		}
		events = append(events, ev)
		for _, result := range engine.Process(ev) {
			if attack {
				continue
			}
			attack = true
			switch result.RuleID {
			case "BRUTE_FORCE_LOGIN", "SSH_BRUTE_FORCE":
				technique = "T1110"
			case "WEB_ENUMERATION":
				technique = "T1595"
			default:
				technique = result.RuleID
			}
		}
	}
	return attack, technique, events
}

type offlineClient struct{}

func (offlineClient) Generate(context.Context, string) (string, error) {
	return "", errors.New("intentional offline baseline")
}

func evaluateFallbackOnly(dataset []benchmark.Sample) []benchmark.PredictionDetail {
	detector := llm.NewICLDetectorWithClient(llm.ICLDetectorConfig{ModelName: "offline-baseline", Timeout: time.Second}, offlineClient{})
	details := make([]benchmark.PredictionDetail, len(dataset))
	for i, sample := range dataset {
		start := time.Now()
		result, err := detector.EvaluateContext(sample.BehaviorContext)
		if err != nil {
			log.Printf("fallback sample %s: %v", sample.ID, err)
		}
		techID := "None"
		if len(result.Result.Findings) > 0 {
			techID = result.Result.Findings[0].TechniqueID
		}
		details[i] = benchmark.PredictionDetail{SampleID: sample.ID, IsAttack: result.Result.IsAttack, TechniqueID: techID, IsDegraded: result.DegradedMode, Latency: time.Since(start)}
	}
	return details
}

func evaluateLLMOnly(dataset []benchmark.Sample, detector *llm.ICLDetector) []benchmark.PredictionDetail {
	details := make([]benchmark.PredictionDetail, len(dataset))
	for i, sample := range dataset {
		start := time.Now()
		result, err := detector.EvaluateContext(sample.BehaviorContext)
		lat := time.Since(start)

		if err != nil {
			log.Printf("Sample %s evaluation error: %v", sample.ID, err)
		}

		techID := "None"
		if len(result.Result.Findings) > 0 {
			techID = result.Result.Findings[0].TechniqueID
		}

		details[i] = benchmark.PredictionDetail{
			SampleID:    sample.ID,
			IsAttack:    result.Result.IsAttack,
			TechniqueID: techID,
			IsDegraded:  result.DegradedMode,
			IsInvalid:   result.Engine == llm.EngineInvalid,
			Latency:     lat,
			ExecutedLLM: true,
		}
	}
	return details
}

func evaluateHybridPipeline(dataset []benchmark.Sample, detector *llm.ICLDetector, reference time.Time) []benchmark.PredictionDetail {
	details := make([]benchmark.PredictionDetail, len(dataset))
	for i, sample := range dataset {
		start := time.Now()
		ruleAttack, techID, events := evaluateRules(sample, reference)
		stats := llm.CalculateAnomalyScore(events)
		isAttack := ruleAttack
		executedLLM, isDegraded, isInvalid := false, false, false
		if ruleAttack || stats.TotalScore >= 7 {
			executedLLM = true
			result, err := detector.EvaluateContext(sample.BehaviorContext)
			if err != nil {
				log.Printf("hybrid sample %s: %v", sample.ID, err)
			} else {
				isDegraded = result.DegradedMode
				isInvalid = result.Engine == llm.EngineInvalid
				if result.Result.IsAttack {
					isAttack = true
					if !ruleAttack && len(result.Result.Findings) > 0 {
						techID = result.Result.Findings[0].TechniqueID
					}
				}
			}
		}
		details[i] = benchmark.PredictionDetail{SampleID: sample.ID, IsAttack: isAttack, TechniqueID: techID, IsDegraded: isDegraded, IsInvalid: isInvalid, Latency: time.Since(start), ExecutedLLM: executedLLM}
	}
	return details
}

func prepareDataset() []benchmark.Sample {
	return []benchmark.Sample{
		{ID: "N1", GroundTechnique: "None"},
		{ID: "N2", GroundTechnique: "None"},
		{ID: "N3", GroundTechnique: "None"},
		{ID: "A1_T1110", IsAttackGround: true, GroundTechnique: "T1110"},
		{ID: "A2_T1110", IsAttackGround: true, GroundTechnique: "T1110"},
		{ID: "A3_T1595", IsAttackGround: true, GroundTechnique: "T1595"},
		{ID: "A4_T1595", IsAttackGround: true, GroundTechnique: "T1595"},
	}
}
