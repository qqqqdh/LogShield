package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"go-logshield/internal/detector"
	"go-logshield/internal/detector/llm"
	"go-logshield/internal/normalizer"
	"go-logshield/internal/pkg/alertstore"
	"go-logshield/internal/pkg/watcher"
)

type FinalReport struct {
	Timestamp             string            `json:"timestamp"`
	RuleBasedAlerts       []detector.Result `json:"rule_based_alerts"`
	LLMICLEvaluations     []llm.ICLResult   `json:"llm_icl_evaluations"`
	TotalLogsAnalyzed     int               `json:"total_logs_analyzed"`
	TotalLogsRead         int               `json:"total_logs_read"`
	ParseErrors           int               `json:"parse_errors"`
	ActiveSessions        int               `json:"active_sessions_count"`
	RuleAlertsOmitted     int               `json:"rule_alerts_omitted_from_report"`
	LLMEvaluationsOmitted int               `json:"llm_evaluations_omitted_from_report"`
	WatchFailures         int               `json:"watch_failures"`
}

const maxReportEntries = 100

func appendRuleReport(report *FinalReport, alert detector.Result) {
	if len(report.RuleBasedAlerts) < maxReportEntries {
		report.RuleBasedAlerts = append(report.RuleBasedAlerts, alert)
		return
	}
	copy(report.RuleBasedAlerts, report.RuleBasedAlerts[1:])
	report.RuleBasedAlerts[len(report.RuleBasedAlerts)-1] = alert
	report.RuleAlertsOmitted++
}

func appendLLMReport(report *FinalReport, evaluation llm.ICLResult) {
	if len(report.LLMICLEvaluations) < maxReportEntries {
		report.LLMICLEvaluations = append(report.LLMICLEvaluations, evaluation)
		return
	}
	copy(report.LLMICLEvaluations, report.LLMICLEvaluations[1:])
	report.LLMICLEvaluations[len(report.LLMICLEvaluations)-1] = evaluation
	report.LLMEvaluationsOmitted++
}

// processWatchStream drains queued lines after tailers stop, including on Ctrl+C.
func processWatchStream(logs <-chan string, workerDone <-chan struct{}, stop chan struct{}, signals <-chan os.Signal, process func(string)) {
	stopping := false
	for {
		select {
		case line := <-logs:
			process(line)
		case <-signals:
			if !stopping {
				close(stop)
				stopping = true
			}
		case <-workerDone:
			if !stopping {
				close(stop)
			}
			for {
				select {
				case line := <-logs:
					process(line)
				default:
					return
				}
			}
		}
	}
}

func main() {
	logDir := flag.String("log-dir", "./logs", "Path to log directory containing .log files")
	enableLLM := flag.Bool("llm", true, "Enable LLaMA 3.1 8B In-Context Learning (ICL) Detector")
	ollamaURL := flag.String("ollama-url", "http://localhost:11434", "Ollama API Endpoint URL")
	llmModel := flag.String("llm-model", "llama3.1:8b", "LLM Model Name for In-Context Learning")
	anomalyThreshold := flag.Int("anomaly-threshold", 7, "Anomaly Score threshold (0-32) to trigger 2nd-stage LLM evaluation")
	idleTTL := flag.Duration("session-idle-ttl", 10*time.Minute, "Session Idle TTL before expiration")
	hardTTL := flag.Duration("session-hard-ttl", 30*time.Minute, "Session Hard TTL before Epoch Rollover")
	maxSessions := flag.Int("max-sessions", 1000, "Maximum active session contexts (LRU Eviction)")
	printPrompt := flag.Bool("print-prompt", false, "Print the full generated LLM prompt to stdout for verification")
	watchMode := flag.Bool("watch", false, "Enable real-time log file tailing mode")
	reportFile := flag.String("report", "report.json", "Output JSON report file path")
	alertsFile := flag.String("alerts-file", "alerts.jsonl", "Append-only JSONL file for every detected alert")
	flag.Parse()

	// 1. Locate log files
	pattern := filepath.Join(*logDir, "*.log")
	files, err := filepath.Glob(pattern)
	if err != nil {
		log.Fatal(err)
	}
	if len(files) == 0 {
		log.Fatalf("No log files found in %s", *logDir)
	}

	journal, err := alertstore.Open(*alertsFile)
	if err != nil {
		log.Fatalf("open alert journal: %v", err)
	}

	// 2. Initialize Rule-Based Detectors
	bruteForceDetector := detector.NewBruteForceDetector(detector.BruteForceConfig{
		Window:    20 * time.Second,
		Threshold: 5,
	})
	sshBruteForceDetector := detector.NewSSHBruteForceDetector(30*time.Second, 6)
	webEnumDetector := detector.NewWebEnumDetector(30*time.Second, 4)

	// 3. Initialize Paper-Based LLM In-Context Learning (ICL) Engine & Session Context Manager
	var sessionManager *llm.SessionContextManager
	var anomalyEvaluator *llm.AnomalyEvaluator
	var iclDetector *llm.ICLDetector

	if *enableLLM {
		sessionManager = llm.NewSessionContextManager(llm.SessionContextManagerConfig{
			IdleTTL:             *idleTTL,
			HardTTL:             *hardTTL,
			MaxSessions:         *maxSessions,
			MaxEventsPerSession: 20,
		})
		anomalyEvaluator = llm.NewAnomalyEvaluator(llm.AnomalyEvaluatorConfig{
			Threshold:         *anomalyThreshold,
			PreInferenceTTL:   30 * time.Second,
			PostAlertCooldown: 60 * time.Second,
		})
		iclDetector = llm.NewICLDetector(llm.ICLDetectorConfig{
			OllamaURL: *ollamaURL,
			ModelName: *llmModel,
			Timeout:   5 * time.Second,
		})
		fmt.Printf("🤖 [LogShield Phase 3 & 4] Hybrid LLM Engine Initialized (Model: %s, Anomaly Threshold: %d/32)\n", *llmModel, *anomalyThreshold)
		fmt.Printf("   ⚙️ Session Key: IP|Service, Idle TTL: %v, Hard TTL: %v, Max Sessions: %d\n\n", *idleTTL, *hardTTL, *maxSessions)
	}

	report := FinalReport{
		Timestamp:         time.Now().Format(time.RFC3339),
		RuleBasedAlerts:   make([]detector.Result, 0),
		LLMICLEvaluations: make([]llm.ICLResult, 0),
	}

	totalLogs := 0
	totalLogsRead := 0
	parseErrors := 0
	promptCount := 0
	recordRuleAlert := func(r detector.Result) {
		if err := journal.Append(r); err != nil {
			log.Fatalf("write alert journal: %v", err)
		}
		fmt.Printf("⚠️  [RULE DETECTED] %s\n", r.Message)
		appendRuleReport(&report, r)
	}

	processLogLine := func(line string) {
		totalLogsRead++
		ev, err := normalizer.ParseLine(line)
		if err != nil {
			parseErrors++
			if parseErrors <= 10 {
				log.Printf("unsupported or malformed log line %d: %v", totalLogsRead, err)
			}
			return
		}
		totalLogs++

		ruleTriggered := false

		// A) Rule-Based Detection
		if r, ok := bruteForceDetector.Process(ev); ok {
			recordRuleAlert(r)
			ruleTriggered = true
		}
		if r, ok := sshBruteForceDetector.Process(ev); ok {
			recordRuleAlert(r)
			ruleTriggered = true
		}
		if r, ok := webEnumDetector.Process(ev); ok {
			recordRuleAlert(r)
			ruleTriggered = true
		}

		// B) Session Context Aggregation & Smart LLM Triggering
		if *enableLLM {
			session := sessionManager.ProcessEvent(ev, ev.TS)
			shouldEval, stats, fingerprint := anomalyEvaluator.ShouldEvaluate(session, ruleTriggered, ev.TS)

			if shouldEval {
				behaviorCtx := session.BuildContext()
				promptInput := llm.PromptInput{
					CorrelationKey:  session.CorrelationKey(),
					Service:         session.Service,
					SourceIP:        session.IP,
					TotalEvents:     len(session.Events),
					Stats:           stats,
					BehaviorContext: behaviorCtx,
				}
				promptCount++

				if *printPrompt && promptCount == 1 {
					generator := llm.NewPromptGenerator()
					fullPrompt := generator.GeneratePromptWithInput(promptInput)
					fmt.Println("==================== [GENERATED LLM PROMPT (PROTOTYPE VERIFICATION)] ====================")
					fmt.Println(fullPrompt)
					fmt.Println("=========================================================================================")
				}

				iclResult, err := iclDetector.EvaluateContextWithInput(promptInput)
				if err == nil {
					appendLLMReport(&report, iclResult)

					if iclResult.Result.IsAttack {
						techID := "TXXXX"
						severity := "high"
						techSummary := "Multiple"
						if len(iclResult.Result.Findings) > 0 {
							techID = iclResult.Result.Findings[0].TechniqueID
							severity = iclResult.Result.Findings[0].Severity
							techSummary = fmt.Sprintf("%s (%s)", techID, iclResult.Result.Findings[0].AttackName)
						}

						// Check Stage 2 Alert Cooldown
						if anomalyEvaluator.ShouldAlert(session.CorrelationKey(), techID, severity, ev.TS) {
							reasoning := ""
							if len(iclResult.Result.Findings) > 0 {
								reasoning = iclResult.Result.Findings[0].Reasoning
							}
							llmAlert := detector.Result{TS: ev.TS, RuleID: "LLM_" + string(iclResult.Engine) + "_" + techID, Title: techSummary, Severity: severity, Message: fmt.Sprintf("%s (engine=%s, confidence=%.2f, score=%d/32)", reasoning, iclResult.Engine, iclResult.Result.Confidence, stats.TotalScore), IP: session.IP, Service: session.Service}
							if err := journal.Append(llmAlert); err != nil {
								log.Fatalf("write LLM alert journal: %v", err)
							}
							fmt.Printf("\n🤖 [LLM ICL ALERT] Key: %s | Engine: %s (Status: %s) | Anomaly Score: %d/32\n", session.CorrelationKey(), iclResult.Engine, iclResult.EvaluationStatus, stats.TotalScore)
							fmt.Printf("   🎯 Technique: %s | Severity: %s\n", techSummary, severity)
							if len(iclResult.Result.Findings) > 0 {
								fmt.Printf("   💡 Reasoning: %s\n", iclResult.Result.Findings[0].Reasoning)
							}
							fmt.Printf("   ⚙️  Model: %s (Fingerprint: %s)\n\n", iclResult.ModelUsed, fingerprint)
						}
					} else {
						fmt.Printf("🟢 [LLM ICL NORMAL] Key: %s | Engine: %s | Anomaly Score: %d/32\n", session.CorrelationKey(), iclResult.Engine, stats.TotalScore)
					}
				}
			}
		}
	}

	watchFailures := 0
	if *watchMode {
		fmt.Printf("📡 [Real-Time Watcher] Tailing %d log files in real-time (Press Ctrl+C to stop)...\n", len(files))
		logChan := make(chan string, 1000)
		stopChan := make(chan struct{})
		watchErrors := make(chan error, len(files))
		workerDone := make(chan struct{})
		var workers sync.WaitGroup
		for _, file := range files {
			path := file
			workers.Add(1)
			go func() {
				defer workers.Done()
				if err := watcher.TailFile(path, logChan, stopChan); err != nil {
					watchErrors <- fmt.Errorf("tail %s: %w", path, err)
				}
			}()
		}
		go func() { workers.Wait(); close(workerDone) }()
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		processWatchStream(logChan, workerDone, stopChan, sigChan, processLogLine)
		signal.Stop(sigChan)
		close(watchErrors)
		for err := range watchErrors {
			watchFailures++
			log.Print(err)
		}
	} else {
		// Batch processing mode
		for _, file := range files {
			fmt.Printf("🔍 === Analyzing Log File: %s ===\n", file)
			fp, err := os.Open(file)
			if err != nil {
				log.Fatal(err)
			}
			scanner := bufio.NewScanner(fp)
			scanner.Buffer(make([]byte, 64*1024), 1024*1024)
			for scanner.Scan() {
				processLogLine(scanner.Text())
			}
			if err := scanner.Err(); err != nil {
				_ = fp.Close()
				log.Fatalf("scan %s: %v", file, err)
			}
			if err := fp.Close(); err != nil {
				log.Fatalf("close %s: %v", file, err)
			}
		}
	}

	report.WatchFailures = watchFailures
	report.TotalLogsRead = totalLogsRead
	report.ParseErrors = parseErrors
	report.TotalLogsAnalyzed = totalLogs
	if sessionManager != nil {
		report.ActiveSessions = sessionManager.ActiveSessionsCount()
	}

	// Save JSON report
	reportData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("marshal report: %v", err)
	}
	if err := os.WriteFile(*reportFile, reportData, 0600); err != nil {
		log.Fatalf("write report: %v", err)
	}
	if err := journal.Close(); err != nil {
		log.Fatalf("close alert journal: %v", err)
	}
	fmt.Printf("\n📊 Analysis complete. Parsed: %d/%d lines; parse errors: %d. Report saved to %s\n", totalLogs, totalLogsRead, parseErrors, *reportFile)
	if totalLogsRead > 0 && totalLogs == 0 {
		log.Fatal("no supported log lines were parsed")
	}
	if watchFailures > 0 {
		log.Fatalf("%d log watcher(s) failed", watchFailures)
	}
}
