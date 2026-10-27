package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestPausedAlertsAreShownAfterResume(t *testing.T) {
	m := initialModel()
	m.paused = true

	updated, _ := m.Update(alertMsg{a: Alert{
		TS:       time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		Title:    "테스트 경고",
		Severity: "높음",
	}})
	m = updated.(model)
	if len(m.alerts) != 0 || len(m.pending) != 1 || m.totalAlerts != 1 {
		t.Fatalf("paused alert was handled incorrectly: alerts=%d pending=%d total=%d", len(m.alerts), len(m.pending), m.totalAlerts)
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	m = updated.(model)
	if len(m.alerts) != 1 || len(m.pending) != 0 {
		t.Fatalf("pending alert was not released on resume: alerts=%d pending=%d", len(m.alerts), len(m.pending))
	}
}

func TestPausedBufferKeepsImportantAlertsAndResumesByTime(t *testing.T) {
	m := initialModel()
	m.paused = true
	for _, a := range []Alert{
		{TS: time.Unix(50, 0), Severity: "치명", Title: "critical"},
		{TS: time.Unix(300, 0), Severity: "높음", Title: "high"},
	} {
		updated, _ := m.Update(alertMsg{a: a})
		m = updated.(model)
	}
	for i := 0; i < 100; i++ {
		updated, _ := m.Update(alertMsg{a: Alert{
			TS: time.Unix(int64(100+i), 0), Severity: "낮음", Title: fmt.Sprintf("low-%d", i),
		}})
		m = updated.(model)
	}
	if len(m.pending) != 100 || m.droppedAlerts != 2 {
		t.Fatalf("pending = %d, dropped = %d; want 100 and 2", len(m.pending), m.droppedAlerts)
	}
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	m = updated.(model)
	if len(m.alerts) != 100 {
		t.Fatalf("resumed alerts = %d, want 100", len(m.alerts))
	}
	if m.alerts[0].Title != "critical" || m.alerts[len(m.alerts)-1].Title != "high" {
		t.Fatalf("important alerts missing: first=%s last=%s", m.alerts[0].Title, m.alerts[len(m.alerts)-1].Title)
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
	m := initialModel()
	m.paused = true
	for i := 0; i <= 100; i++ {
		updated, _ := m.Update(alertMsg{a: Alert{
			TS: time.Unix(int64(i), 0), Severity: "높음", Title: fmt.Sprintf("high-%d", i),
		}})
		m = updated.(model)
	}
	updated, _ := m.Update(alertMsg{a: Alert{TS: time.Unix(-1, 0), Severity: "높음", Title: "older"}})
	m = updated.(model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	m = updated.(model)
	if len(m.alerts) != 100 || m.alerts[0].Title != "high-1" || m.alerts[len(m.alerts)-1].Title != "high-100" {
		t.Fatalf("same-severity retention wrong: count=%d", len(m.alerts))
	}
}

func TestPausedBufferUsesArrivalOrderForEqualTimestamp(t *testing.T) {
	m := initialModel()
	m.paused = true
	for i := 0; i <= 100; i++ {
		updated, _ := m.Update(alertMsg{a: Alert{
			TS: time.Unix(1, 0), Severity: "높음", Title: fmt.Sprintf("same-%d", i),
		}})
		m = updated.(model)
	}
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	m = updated.(model)
	if len(m.alerts) != 100 || m.alerts[0].Title != "same-1" || m.alerts[len(m.alerts)-1].Title != "same-100" {
		t.Fatalf("equal-time retention wrong: count=%d", len(m.alerts))
	}
}

func TestSaveWhilePausedIncludesPendingAlerts(t *testing.T) {
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalDir) })

	m := initialModel()
	m.paused = true
	updated, _ := m.Update(alertMsg{a: Alert{TS: time.Unix(1, 0), Severity: "높음", Title: "queued"}})
	m = updated.(model)
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	if cmd == nil {
		t.Fatal("save command missing while only queued alerts exist")
	}
	if msg := cmd(); msg == nil {
		t.Fatal("save command returned no result")
	}
	data, err := os.ReadFile("report.json")
	if err != nil {
		t.Fatal(err)
	}
	var alerts []Alert
	if err := json.Unmarshal(data, &alerts); err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Title != "queued" {
		t.Fatalf("report alerts = %+v, want queued alert", alerts)
	}
}
