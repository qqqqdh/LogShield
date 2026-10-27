package main

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

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
