package detector

import (
	"fmt"
	"sync"
	"time"

	"go-logshield/internal/normalizer"
)

type SSHBruteForceDetector struct {
	mu      sync.Mutex
	tracker *WindowTracker
}

func NewSSHBruteForceDetector(window time.Duration, threshold int) *SSHBruteForceDetector {
	return &SSHBruteForceDetector{
		tracker: NewWindowTracker(window, threshold, maxTrackedIPs),
	}
}

func (d *SSHBruteForceDetector) Process(ev normalizer.Event) (Result, bool) {
	if ev.Service != "ssh" || ev.Action != "auth" || ev.Status != "FAIL" {
		return Result{}, false
	}
	if ev.IP == "" {
		return Result{}, false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	ip := ev.IP
	now := ev.TS

	match, ok := d.tracker.Add(ip, now)
	if ok {
		first := match.First
		last := match.Last

		const ruleID = "SSH_BRUTE_FORCE"
		msg := fmt.Sprintf(
			"🚨 [경고][높음] SSH 브루트포스 공격 의심\n"+
				"- IP: %s\n"+
				"- 실패 횟수: %d회 (%d초 윈도우)\n"+
				"- 최초 시각: %s\n"+
				"- 마지막 시각: %s\n"+
				"- 설명: 동일 IP에서 SSH 인증 실패가 짧은 시간에 반복되었습니다.",
			ip,
			match.Count,
			int(d.tracker.window.Seconds()),
			first.Format(time.RFC3339),
			last.Format(time.RFC3339),
		)

		return Result{
			TS:       now,
			RuleID:   ruleID,
			Title:    "SSH 브루트포스 공격 의심",
			Severity: "높음",
			Message:  msg,
			IP:       ip,
			Service:  ev.Service,
		}, true
	}

	return Result{}, false
}
