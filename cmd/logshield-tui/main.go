package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go-logshield/internal/analyzer"
	"go-logshield/internal/pkg/alertstore"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nxadm/tail"
)

type Alert struct {
	TS       time.Time `json:"ts"`
	Severity string    `json:"severity"`
	Title    string    `json:"title"`
	Message  string    `json:"message"`

	IP      string `json:"ip,omitempty"`
	Service string `json:"service,omitempty"`
	RuleID  string `json:"rule_id,omitempty"`
}

type alertMsg struct{ a Alert }

type rawLine struct{ path, text string }
type errMsg struct{ err error }

// The single worker owns detector state for every tailed file.
func runRealtimeWorker(lines <-chan rawLine, engine *analyzer.Analyzer, journal *alertstore.Journal, emit func(Alert), reportError func(error)) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			engine.Prune(time.Now())
		case item, ok := <-lines:
			if !ok {
				return
			}
			_, results, err := engine.ProcessLine(item.text)
			if err != nil {
				reportError(fmt.Errorf("parse error (%s): %w", item.path, err))
				continue
			}
			for _, result := range results {
				if err := journal.Append(result); err != nil {
					reportError(fmt.Errorf("alert journal: %w", err))
				}
				emit(Alert{TS: result.TS, Severity: result.Severity, Title: result.Title, Message: result.Message, IP: result.IP, RuleID: result.RuleID, Service: result.Service})
			}
		}
	}
}

type viewMode int

const (
	viewList viewMode = iota
	viewDetail
)

type model struct {
	alerts        []Alert
	pending       []Alert
	selectedIdx   int
	mode          viewMode
	err           error
	paused        bool
	showHelp      bool
	eventCount    int
	alertCount    int
	droppedAlerts int
	subChan       chan Alert
}

func initialModel(subChan chan Alert) model {
	return model{
		alerts:      make([]Alert, 0),
		selectedIdx: 0,
		mode:        viewList,
		subChan:     subChan,
	}
}

func (m model) Init() tea.Cmd {
	return waitForNextAlert(m.subChan)
}

func waitForNextAlert(subChan chan Alert) tea.Cmd {
	return func() tea.Msg {
		a := <-subChan
		return alertMsg{a: a}
	}
}

func (m *model) appendAlert(a Alert) {
	followLatest := len(m.alerts) == 0 || m.selectedIdx == len(m.alerts)-1
	if len(m.alerts) >= maxPausedAlerts {
		m.alerts = m.alerts[1:]
		if m.selectedIdx > 0 {
			m.selectedIdx--
		}
	}
	m.alerts = append(m.alerts, a)
	if followLatest {
		m.selectedIdx = len(m.alerts) - 1
	}
}

const maxPausedAlerts = 100

func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "치명", "critical":
		return 4
	case "높음", "high":
		return 3
	case "중간", "medium":
		return 2
	case "낮음", "low":
		return 1
	default:
		return 0
	}
}

// Keep the most severe alerts. Within one severity, retain newer event times;
// equal timestamps prefer the alert received later.
func (m *model) queueAlert(a Alert) {
	if len(m.pending) < maxPausedAlerts {
		m.pending = append(m.pending, a)
		return
	}
	worst := 0
	for i := 1; i < len(m.pending); i++ {
		candidate, current := m.pending[i], m.pending[worst]
		if severityRank(candidate.Severity) < severityRank(current.Severity) ||
			(severityRank(candidate.Severity) == severityRank(current.Severity) && candidate.TS.Before(current.TS)) {
			worst = i
		}
	}
	current := m.pending[worst]
	if severityRank(a.Severity) > severityRank(current.Severity) ||
		(severityRank(a.Severity) == severityRank(current.Severity) && !a.TS.Before(current.TS)) {
		copy(m.pending[worst:], m.pending[worst+1:])
		m.pending[len(m.pending)-1] = a
	}
	m.droppedAlerts++
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "p":
			m.paused = !m.paused
			if !m.paused {
				sort.SliceStable(m.pending, func(i, j int) bool {
					return m.pending[i].TS.Before(m.pending[j].TS)
				})
				for _, a := range m.pending {
					m.appendAlert(a)
				}
				m.pending = nil
			}
		case "c":
			m.alerts = nil
			m.pending = nil
			m.selectedIdx = 0
			m.alertCount = 0
			m.droppedAlerts = 0
		case "h", "?":
			m.showHelp = !m.showHelp
		case "down", "j":
			if m.selectedIdx < len(m.alerts)-1 {
				m.selectedIdx++
			}
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
		case "enter":
			if len(m.alerts) > 0 {
				if m.mode == viewList {
					m.mode = viewDetail
				} else {
					m.mode = viewList
				}
			}
		case "esc":
			m.mode = viewList
		}

	case errMsg:
		m.err = msg.err
		return m, nil
	case alertMsg:
		m.alertCount++
		if m.paused {
			m.queueAlert(msg.a)
		} else {
			m.appendAlert(msg.a)
		}
		return m, waitForNextAlert(m.subChan)
	}

	return m, nil
}

func (m model) View() string {
	s := "🛡️  Go-LogShield Real-time TUI Monitoring Dashboard\n"
	s += fmt.Sprintf("Alerts Detected: %d | Queued: %d/%d | Dropped: %d | Paused: %v\n", m.alertCount, len(m.pending), maxPausedAlerts, m.droppedAlerts, m.paused)
	s += "--------------------------------------------------\n"
	if m.err != nil {
		s += fmt.Sprintf("Error: %v\n", m.err)
	}

	if len(m.alerts) == 0 {
		s += "Waiting for incoming log stream and security alerts...\n"
	} else if m.mode == viewList {
		for i, a := range m.alerts {
			cursor := " "
			if i == m.selectedIdx {
				cursor = ">"
			}
			s += fmt.Sprintf("%s [%s] %s (%s) IP:%s\n", cursor, a.Severity, a.Title, a.TS.Format("15:04:05"), a.IP)
		}
	} else if m.mode == viewDetail && m.selectedIdx < len(m.alerts) {
		a := m.alerts[m.selectedIdx]
		s += fmt.Sprintf("=== Alert Detail [%s] ===\nTitle: %s\nTime: %s\nIP: %s\nRule: %s\nMessage: %s\n",
			a.Severity, a.Title, a.TS.Format(time.RFC3339), a.IP, a.RuleID, a.Message)
		s += "\n(Press ESC or ENTER to return to list)\n"
	}

	s += "\nKeys: q: Quit | p: Pause | c: Clear | ↑/↓: Navigate | ENTER: Details\n"
	return s
}

func main() {
	logDir := flag.String("log-dir", "./logs", "Directory containing log files to tail")
	alertPath := flag.String("alerts-file", "alerts.jsonl", "Append-only JSONL alert journal")
	flag.Parse()

	pattern := filepath.Join(*logDir, "*.log")
	files, err := filepath.Glob(pattern)
	if err != nil || len(files) == 0 {
		fmt.Fprintf(os.Stderr, "no log files found for %s: %v\n", pattern, err)
		os.Exit(1)
	}
	journal, err := alertstore.Open(*alertPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open alert journal: %v\n", err)
		os.Exit(1)
	}

	tailers := make([]*tail.Tail, 0, len(files))
	tailerPaths := make([]string, 0, len(files))
	for _, path := range files {
		t, err := tail.TailFile(path, tail.Config{Follow: true, ReOpen: true, Poll: true, Logger: tail.DiscardingLogger})
		if err != nil {
			fmt.Fprintf(os.Stderr, "tail %s: %v\n", path, err)
			continue
		}
		tailers = append(tailers, t)
		tailerPaths = append(tailerPaths, path)
	}
	if len(tailers) == 0 {
		_ = journal.Close()
		fmt.Fprintln(os.Stderr, "no readable log files")
		os.Exit(1)
	}

	subChan := make(chan Alert, 100)
	p := tea.NewProgram(initialModel(subChan))
	lines := make(chan rawLine, 1024)
	uiDone := make(chan struct{})
	var producers sync.WaitGroup
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		runRealtimeWorker(lines, analyzer.NewDefault(), journal,
			func(a Alert) {
				select {
				case subChan <- a:
				case <-uiDone:
				}
			},
			func(err error) {
				fmt.Fprintln(os.Stderr, err)
				p.Send(errMsg{err: err})
			})
	}()
	for i, t := range tailers {
		path := tailerPaths[i]
		producers.Add(1)
		go func() {
			defer producers.Done()
			for line := range t.Lines {
				if line == nil {
					continue
				}
				raw := strings.TrimSpace(line.Text)
				if raw == "" {
					continue
				}
				select {
				case lines <- rawLine{path: path, text: raw}:
				case <-uiDone:
					return
				}
			}
		}()
	}

	_, runErr := p.Run()
	close(uiDone)
	for _, t := range tailers {
		_ = t.Stop()
		t.Cleanup()
	}
	producers.Wait()
	close(lines)
	<-workerDone
	closeErr := journal.Close()
	if closeErr != nil {
		fmt.Fprintf(os.Stderr, "close alert journal: %v\n", closeErr)
	}
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", runErr)
	}
	if closeErr != nil || runErr != nil {
		os.Exit(1)
	}
}
