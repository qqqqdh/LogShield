package main

import (
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
