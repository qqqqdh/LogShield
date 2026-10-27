package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go-logshield/internal/detector"
	"go-logshield/internal/detector/llm"
	"go-logshield/internal/pkg/alertstore"
)

func TestCLIFlyLogsDoNotCreateUnattributedLLMSessions(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.Mkdir(logs, 0700); err != nil {
		t.Fatal(err)
	}
	lines := []string{`{"timestamp":"2026-10-28T10:00:00Z","message":"INFO Starting init"}`}
	for i := 0; i < 4; i++ {
		lines = append(lines, fmt.Sprintf(`{"timestamp":"2026-10-28T10:00:0%dZ","message":"WARN [404] GET /.env (1ms)"}`, i))
	}
	if err := os.WriteFile(filepath.Join(logs, "fly.log"), []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(dir, "report.json")
	cmd := exec.Command("go", "run", ".", "-log-dir", logs, "-llm=true", "-ollama-url", "http://127.0.0.1:1", "-alerts-file", filepath.Join(dir, "alerts.jsonl"), "-report", reportPath)
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
	if report.TotalLogsAnalyzed != 4 || report.NonEventRecords != 1 || report.MissingIPEvents != 4 || report.ParseErrors != 0 || report.ActiveSessions != 0 || len(report.LLMICLEvaluations) != 0 {
		t.Fatalf("unattributed/platform records incorrectly evaluated: %+v", report)
	}
}

func TestReportSnapshotIsBounded(t *testing.T) {
	report := FinalReport{}
	for i := 0; i < 101; i++ {
		appendRuleReport(&report, detector.Result{RuleID: fmt.Sprintf("rule-%d", i)})
		appendLLMReport(&report, llm.ICLResult{ModelUsed: fmt.Sprintf("model-%d", i)})
	}
	if len(report.RuleBasedAlerts) != 100 || report.RuleAlertsOmitted != 1 || report.RuleBasedAlerts[0].RuleID != "rule-1" {
		t.Fatalf("rule snapshot=%d omitted=%d first=%+v", len(report.RuleBasedAlerts), report.RuleAlertsOmitted, report.RuleBasedAlerts[0])
	}
	if len(report.LLMICLEvaluations) != 100 || report.LLMEvaluationsOmitted != 1 {
		t.Fatalf("LLM snapshot=%d omitted=%d", len(report.LLMICLEvaluations), report.LLMEvaluationsOmitted)
	}
}

func TestCLIReportsUnsupportedLines(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.Mkdir(logs, 0700); err != nil {
		t.Fatal(err)
	}
	content := "not a supported log\n2026-10-28T10:00:00Z service=auth action=login ip=203.0.113.5 status=SUCCESS\n"
	if err := os.WriteFile(filepath.Join(logs, "mixed.log"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(dir, "report.json")
	cmd := exec.Command("go", "run", ".", "-log-dir", logs, "-llm=false", "-alerts-file", filepath.Join(dir, "alerts.jsonl"), "-report", reportPath)
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
	if report.TotalLogsRead != 2 || report.TotalLogsAnalyzed != 1 || report.ParseErrors != 1 {
		t.Fatalf("report counts = %+v", report)
	}
}

func TestWatchStreamDrainsBufferedLinesOnStop(t *testing.T) {
	logs := make(chan string, 3)
	logs <- "one"
	logs <- "two"
	workerDone := make(chan struct{})
	close(workerDone)
	stop := make(chan struct{})
	signals := make(chan os.Signal, 1)
	signals <- os.Interrupt
	var got []string
	processWatchStream(logs, workerDone, stop, signals, func(line string) { got = append(got, line) })
	if len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("drained lines = %+v", got)
	}
	select {
	case <-stop:
	default:
		t.Fatal("tailers were not asked to stop")
	}
}

func TestCLIParsesNativeSSHAndWebLogs(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.Mkdir(logs, 0700); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for i := 0; i < 6; i++ {
		lines = append(lines, fmt.Sprintf("Oct 28 10:00:%02d host sshd[12]: Failed password for root from 203.0.113.1 port 22 ssh2", i))
	}
	for i := 0; i < 4; i++ {
		lines = append(lines, fmt.Sprintf(`203.0.113.2 - - [28/Oct/2026:10:01:%02d +0900] "GET /.env HTTP/1.1" 404 12 "-" "scanner"`, i))
	}
	if err := os.WriteFile(filepath.Join(logs, "mixed.log"), []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(dir, "report.json")
	cmd := exec.Command("go", "run", ".", "-log-dir", logs, "-llm=false", "-alerts-file", filepath.Join(dir, "alerts.jsonl"), "-report", reportPath)
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
	counts := map[string]int{}
	for _, alert := range report.RuleBasedAlerts {
		counts[alert.RuleID]++
	}
	if counts["SSH_BRUTE_FORCE"] != 1 || counts["WEB_ENUMERATION"] != 1 {
		t.Fatalf("native log alerts = %+v", counts)
	}
}

func TestCLIRecordsRuleAlertAndReport(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.Mkdir(logs, 0700); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for i := 0; i < 5; i++ {
		lines = append(lines, fmt.Sprintf("2026-10-28T10:00:%02dZ service=auth action=login user=alice ip=203.0.113.5 status=FAIL", i))
	}
	if err := os.WriteFile(filepath.Join(logs, "auth.log"), []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(dir, "alerts.jsonl")
	reportPath := filepath.Join(dir, "report.json")
	cmd := exec.Command("go", "run", ".", "-log-dir", logs, "-llm=false", "-alerts-file", journalPath, "-report", reportPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI failed: %v\n%s", err, output)
	}
	data, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	var entry alertstore.Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Alert.RuleID != "BRUTE_FORCE_LOGIN" {
		t.Fatalf("journal alert = %+v", entry.Alert)
	}
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report FinalReport
	if err := json.Unmarshal(reportData, &report); err != nil {
		t.Fatal(err)
	}
	if report.TotalLogsAnalyzed != 5 || len(report.RuleBasedAlerts) != 1 {
		t.Fatalf("report = %+v", report)
	}
}
