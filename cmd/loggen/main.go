package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go-logshield/internal/analyzer"
	"go-logshield/internal/detector"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nxadm/tail"
)

type Alert = detector.Result

type alertMsg struct{ a Alert }

type viewMode int

const (
	viewList viewMode = iota
	viewDetail
)

type model struct {
	paused   bool
	showHelp bool
	mode     viewMode

	alerts   []Alert
	pending  []Alert
	selected int

	statusLine string

	// 통계(있으면 보기 좋음)
	totalEvents   int
	totalAlerts   int
	droppedAlerts int
}

func initialModel() model {
	return model{
		paused:     false,
		showHelp:   true,
		mode:       viewList,
		alerts:     make([]Alert, 0, 100),
		pending:    make([]Alert, 0, maxStoredAlerts),
		selected:   0,
		statusLine: "실시간 로그 분석 시작됨 (q 종료, p 일시정지)",
	}
}

type savedMsg struct{ path string }
type errMsg struct{ err error }
type eventCountMsg struct{ n int }
type statusMsg struct{ text string }

const maxStoredAlerts = 100

func saveReportCmd(alerts []Alert) tea.Cmd {
	snapshot := make([]Alert, len(alerts))
	copy(snapshot, alerts)

	return func() tea.Msg {
		b, err := json.MarshalIndent(snapshot, "", "  ")
		if err != nil {
			return errMsg{err: err}
		}
		path := "report.json"
		if err := os.WriteFile(path, b, 0600); err != nil {
			return errMsg{err: err}
		}
		return savedMsg{path: path}
	}
}

func (m model) Init() tea.Cmd { return nil }

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func (m *model) appendAlert(a Alert) {
	if len(m.alerts) >= maxStoredAlerts {
		m.alerts = m.alerts[1:]
		m.selected = clamp(m.selected-1, 0, len(m.alerts)-1)
	}
	m.alerts = append(m.alerts, a)
	m.selected = clamp(m.selected, 0, len(m.alerts)-1)
}

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
	if len(m.pending) < maxStoredAlerts {
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
	switch x := msg.(type) {

	case tea.KeyMsg:
		k := x.String()

		switch k {
		case "q", "ctrl+c":
			return m, tea.Quit

		case "h", "?":
			m.showHelp = !m.showHelp
			return m, nil

		case "p":
			m.paused = !m.paused
			if m.paused {
				m.statusLine = "⏸ 일시정지됨 (p로 재개) — 경고는 잠깐 멈춤"
			} else {
				sort.SliceStable(m.pending, func(i, j int) bool {
					return m.pending[i].TS.Before(m.pending[j].TS)
				})
				for _, alert := range m.pending {
					m.appendAlert(alert)
				}
				m.pending = nil
				m.statusLine = "▶ 분석 재개됨"
			}
			return m, nil

		case "c":
			m.alerts = nil
			m.pending = nil
			m.selected = 0
			m.mode = viewList
			m.totalEvents = 0
			m.totalAlerts = 0
			m.droppedAlerts = 0
			m.statusLine = "🧹 초기화 완료"
			return m, nil

		case "s":
			if len(m.alerts)+len(m.pending) == 0 {
				m.statusLine = "저장할 경고가 없습니다."
				return m, nil
			}
			reportAlerts := make([]Alert, 0, len(m.alerts)+len(m.pending))
			reportAlerts = append(reportAlerts, m.alerts...)
			reportAlerts = append(reportAlerts, m.pending...)
			sort.SliceStable(reportAlerts, func(i, j int) bool {
				return reportAlerts[i].TS.Before(reportAlerts[j].TS)
			})
			m.statusLine = "💾 report.json 저장 중..."
			return m, saveReportCmd(reportAlerts)

		case "esc":
			if m.mode == viewDetail {
				m.mode = viewList
				m.statusLine = "리스트로 돌아옴"
			}
			return m, nil

		case "enter":
			if len(m.alerts) == 0 {
				return m, nil
			}
			if m.mode == viewList {
				m.mode = viewDetail
			} else {
				m.mode = viewList
			}
			return m, nil
		}

		if m.mode == viewList && len(m.alerts) > 0 {
			switch k {
			case "up", "k":
				// 화면은 역순(최신=맨위=높은 인덱스)이므로 위쪽 = 인덱스 증가
				m.selected = clamp(m.selected+1, 0, len(m.alerts)-1)
				return m, nil
			case "down", "j":
				m.selected = clamp(m.selected-1, 0, len(m.alerts)-1)
				return m, nil
			case "g":
				// 화면 맨 위 = 가장 높은 인덱스
				m.selected = len(m.alerts) - 1
				return m, nil
			case "G":
				// 화면 맨 아래 = 인덱스 0
				m.selected = 0
				return m, nil
			}
		}

	case alertMsg:
		m.totalAlerts++
		if m.paused {
			m.queueAlert(x.a)
			return m, nil
		}
		m.appendAlert(x.a)
		m.statusLine = fmt.Sprintf("🚨 새 경고: %s", x.a.Title)
		return m, nil

	case eventCountMsg:
		m.totalEvents += x.n
		return m, nil

	case savedMsg:
		m.statusLine = fmt.Sprintf("✅ 저장 완료: %s", x.path)
		return m, nil

	case errMsg:
		m.statusLine = fmt.Sprintf("❌ 오류: %v", x.err)
		return m, nil

	case statusMsg:
		m.statusLine = x.text
		return m, nil
	}

	return m, nil
}

func (m model) View() string {
	state := "RUNNING"
	if m.paused {
		state = "PAUSED"
	}

	header := ""
	header += "Go-LogShield TUI (실시간 로그 분석)\n"
	header += fmt.Sprintf("상태: %s | 이벤트: %d | 경고: %d | 대기: %d/%d | 버림: %d | 모드: %s\n",
		state, m.totalEvents, m.totalAlerts, len(m.pending), maxStoredAlerts, m.droppedAlerts,
		map[viewMode]string{viewList: "LIST", viewDetail: "DETAIL"}[m.mode],
	)
	if m.statusLine != "" {
		header += m.statusLine + "\n"
	}
	header += "--------------------------------------------------\n"

	help := ""
	if m.showHelp {
		help += "단축키\n"
		help += "  q: 종료   p: 일시정지/재개   c: 초기화   s: report.json 저장\n"
		help += "  h/?: 도움말 토글   ↑/k ↓/j: 이동   enter: 상세보기 토글   esc: 리스트로\n"
		help += "  g: 맨위   G: 맨아래\n"
		help += "--------------------------------------------------\n"
	}

	if len(m.alerts) == 0 {
		return header + help + "(아직 경고 없음 — 로그를 계속 따라가는 중)\n"
	}

	if m.mode == viewList {
		out := header + help
		out += "최근 경고 목록 (enter로 상세보기)\n\n"

		// 최신이 아래에 쌓이지만 보기 편하게 최근순 역순 출력
		for i := 0; i < len(m.alerts); i++ {
			idx := len(m.alerts) - 1 - i
			a := m.alerts[idx]

			cursor := "  "
			if idx == m.selected {
				cursor = "> "
			}

			out += fmt.Sprintf("%s[%s] %s  (%s)\n",
				cursor, a.Severity, a.Title, a.TS.Format("15:04:05"),
			)
		}
		out += "\n"
		return out
	}

	// DETAIL
	a := m.alerts[m.selected]
	out := header + help
	out += "상세 보기 (esc 또는 enter로 돌아가기)\n\n"
	out += fmt.Sprintf("🚨 제목: %s\n", a.Title)
	out += fmt.Sprintf("등급: %s\n", a.Severity)
	out += fmt.Sprintf("시간: %s\n", a.TS.Format(time.RFC3339))
	if a.IP != "" {
		out += fmt.Sprintf("IP: %s\n", a.IP)
	}
	if a.Service != "" {
		out += fmt.Sprintf("서비스: %s\n", a.Service)
	}
	if a.RuleID != "" {
		out += fmt.Sprintf("RuleID: %s\n", a.RuleID)
	}
	out += "\n원문 메시지\n"
	out += a.Message + "\n"
	return out
}

// --- 실시간 tail + 분석 파이프라인 ---
// stopFn()을 호출하면 모든 tailer goroutine이 정리됩니다.
func startRealtimePipeline(p *tea.Program, logDir string) (stopFn func(), err error) {
	pattern := filepath.Join(logDir, "*.log")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return func() {}, err
	}
	if len(paths) == 0 {
		p.Send(errMsg{err: fmt.Errorf("%s 파일을 찾지 못했습니다. 로그 디렉터리를 확인하세요.", pattern)})
		return func() {}, nil
	}

	engine := analyzer.NewDefault()

	tailers := make([]*tail.Tail, 0, len(paths))

	for _, path := range paths {
		path := path
		t, err := tail.TailFile(path, tail.Config{
			Follow:    true,
			ReOpen:    true,
			MustExist: false,
			Poll:      true,
			Logger:    tail.DiscardingLogger,
		})
		if err != nil {
			p.Send(errMsg{err: fmt.Errorf("tail 실패 (%s): %w", path, err)})
			continue
		}
		tailers = append(tailers, t)

		go func() {
			for line := range t.Lines {
				if line == nil {
					continue
				}
				raw := strings.TrimSpace(line.Text)
				if raw == "" {
					continue
				}

				p.Send(eventCountMsg{n: 1})

				_, results, err := engine.ProcessLine(raw)
				if err != nil {
					p.Send(errMsg{err: fmt.Errorf("parse error (%s): %v", path, err)})
					continue
				}

				for _, result := range results {
					p.Send(alertMsg{a: result})
				}
			}
		}()
	}

	p.Send(statusMsg{text: fmt.Sprintf("실시간 tail 시작: %d개 파일 (%s)", len(tailers), pattern)})

	// 모든 tailer를 정리하는 함수 반환
	return func() {
		for _, t := range tailers {
			_ = t.Stop()
			t.Cleanup()
		}
	}, nil
}

func main() {
	logDir := flag.String("log-dir", "./logs", "분석할 로그 파일이 위치한 디렉터리")
	flag.Parse()

	p := tea.NewProgram(initialModel(), tea.WithAltScreen())

	pipelineReady := make(chan func(), 1)
	go func() {
		stop, err := startRealtimePipeline(p, *logDir)
		if err != nil {
			p.Send(errMsg{err: err})
			stop = func() {}
		}
		pipelineReady <- stop
	}()

	_, runErr := p.Run()
	// TUI 종료 후 tailer goroutine 정리. 시작 goroutine이 아직 준비 중이어도
	// 채널에서 cleanup 함수를 받은 뒤 반드시 정리한다.
	(<-pipelineReady)()
	if runErr != nil {
		panic(runErr)
	}
}
