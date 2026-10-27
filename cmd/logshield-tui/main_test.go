package main

import (
	"encoding/json"
	"fmt"
	"go-logshield/internal/analyzer"
	"go-logshield/internal/pkg/alertstore"
	"os"
	"path/filepath"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestVisibleAlertsStayBounded(t *testing.T) {
	m := initialModel(make(chan Alert))
	for i := 0; i < 101; i++ {
		updated, _ := m.Update(alertMsg{a: Alert{TS: time.Unix(int64(i), 0), Title: fmt.Sprintf("alert-%d", i)}})
		m = updated.(model)
	}
	if len(m.alerts) != 100 || m.alerts[0].Title != "alert-1" {
		t.Fatalf("visible alerts=%d first=%s, want 100 and alert-1", len(m.alerts), m.alerts[0].Title)
	}
}

func TestRealtimeWorkerMergesFilesAndPersistsAlert(t *testing.T) {
	lines := make(chan rawLine, 5)
	for i := 0; i < 5; i++ {
		path := "auth-a.log"
		if i%2 == 1 {
			path = "auth-b.log"
		}
		lines <- rawLine{path: path, text: fmt.Sprintf("2026-10-28T10:00:%02dZ service=auth action=login user=alice ip=203.0.113.5 status=FAIL", i)}
	}
	close(lines)
	journalPath := filepath.Join(t.TempDir(), "alerts.jsonl")
	journal, err := alertstore.Open(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	var alerts []Alert
	runRealtimeWorker(lines, analyzer.NewDefault(), journal, func(a Alert) { alerts = append(alerts, a) }, func(err error) { t.Error(err) })
	if len(alerts) != 1 {
		t.Fatalf("alerts=%d, want 1", len(alerts))
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
		t.Fatalf("journal alert=%+v", entry.Alert)
	}
}

func TestPausedAlertsAppearOnceInOrderAfterResume(t *testing.T) {
	m := initialModel(make(chan Alert))
	pause := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}}
	updated, _ := m.Update(pause)
	m = updated.(model)

	for _, title := range []string{"first", "second"} {
		updated, _ = m.Update(alertMsg{a: Alert{TS: time.Unix(0, 0), Title: title}})
		m = updated.(model)
	}
	if len(m.alerts) != 0 {
		t.Fatalf("paused display has %d alerts, want 0", len(m.alerts))
	}

	updated, _ = m.Update(pause)
	m = updated.(model)
	if len(m.alerts) != 2 || m.alerts[0].Title != "first" || m.alerts[1].Title != "second" {
		t.Fatalf("alerts after resume = %+v, want first then second", m.alerts)
	}
	if m.alertCount != 2 {
		t.Fatalf("alert count after resume = %d, want 2", m.alertCount)
	}

	updated, _ = m.Update(alertMsg{a: Alert{TS: time.Unix(0, 0), Title: "third"}})
	m = updated.(model)
	if len(m.alerts) != 3 || m.alertCount != 3 {
		t.Fatalf("alerts after next event = %d, count = %d; want 3 each", len(m.alerts), m.alertCount)
	}
}

func TestClearDiscardsPausedAlerts(t *testing.T) {
	m := initialModel(make(chan Alert))
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	m = updated.(model)
	updated, _ = m.Update(alertMsg{a: Alert{Title: "queued"}})
	m = updated.(model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	m = updated.(model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	m = updated.(model)
	if len(m.alerts) != 0 || m.alertCount != 0 {
		t.Fatalf("clear should discard paused alerts: alerts=%d count=%d", len(m.alerts), m.alertCount)
	}
}

func TestPausedBufferKeepsImportantAlertsAndResumesByTime(t *testing.T) {
	m := initialModel(make(chan Alert))
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	m = updated.(model)
	for _, a := range []Alert{
		{TS: time.Unix(50, 0), Severity: "치명", Title: "critical"},
		{TS: time.Unix(300, 0), Severity: "높음", Title: "high"},
	} {
		updated, _ = m.Update(alertMsg{a: a})
		m = updated.(model)
	}
	for i := 0; i < 100; i++ {
		updated, _ = m.Update(alertMsg{a: Alert{
			TS: time.Unix(int64(100+i), 0), Severity: "낮음", Title: fmt.Sprintf("low-%d", i),
		}})
		m = updated.(model)
	}
	if len(m.pending) != 100 || m.droppedAlerts != 2 {
		t.Fatalf("pending = %d, dropped = %d; want 100 and 2", len(m.pending), m.droppedAlerts)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	m = updated.(model)
	if len(m.alerts) != 100 {
		t.Fatalf("resumed alerts = %d, want 100", len(m.alerts))
	}
	if m.alerts[0].Title != "critical" || m.alerts[len(m.alerts)-1].Title != "high" {
		t.Fatalf("unexpected order: first=%+v last=%+v", m.alerts[0], m.alerts[len(m.alerts)-1])
	}
	for i := 1; i < len(m.alerts); i++ {
		if m.alerts[i].TS.Before(m.alerts[i-1].TS) {
			t.Fatalf("alerts are not chronological at %d", i)
		}
	}
	for _, a := range m.alerts {
		if a.Title == "low-0" || a.Title == "low-1" {
			t.Fatalf("old low-severity alert survived: %s", a.Title)
		}
	}
}

func TestPausedBufferPrefersRecentWithinSeverity(t *testing.T) {
	m := initialModel(make(chan Alert))
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	m = updated.(model)
	for i := 0; i <= 100; i++ {
		updated, _ = m.Update(alertMsg{a: Alert{
			TS: time.Unix(int64(i), 0), Severity: "높음", Title: fmt.Sprintf("high-%d", i),
		}})
		m = updated.(model)
	}
	updated, _ = m.Update(alertMsg{a: Alert{TS: time.Unix(-1, 0), Severity: "높음", Title: "older"}})
	m = updated.(model)
	if len(m.pending) != 100 || m.droppedAlerts != 2 {
		t.Fatalf("pending = %d, dropped = %d; want 100 and 2", len(m.pending), m.droppedAlerts)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	m = updated.(model)
	if m.alerts[0].Title != "high-1" || m.alerts[len(m.alerts)-1].Title != "high-100" {
		t.Fatalf("same-severity retention wrong: first=%s last=%s", m.alerts[0].Title, m.alerts[len(m.alerts)-1].Title)
	}
}

func TestPausedBufferUsesArrivalOrderForEqualTimestamp(t *testing.T) {
	m := initialModel(make(chan Alert))
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	m = updated.(model)
	for i := 0; i <= 100; i++ {
		updated, _ = m.Update(alertMsg{a: Alert{
			TS: time.Unix(1, 0), Severity: "높음", Title: fmt.Sprintf("same-%d", i),
		}})
		m = updated.(model)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	m = updated.(model)
	if len(m.alerts) != 100 || m.alerts[0].Title != "same-1" || m.alerts[len(m.alerts)-1].Title != "same-100" {
		t.Fatalf("equal-time retention wrong: count=%d first=%s last=%s", len(m.alerts), m.alerts[0].Title, m.alerts[len(m.alerts)-1].Title)
	}
}
