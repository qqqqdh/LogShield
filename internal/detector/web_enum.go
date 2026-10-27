package detector

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"go-logshield/internal/normalizer"
)

type WebEnumDetector struct {
	mu      sync.Mutex
	tracker *WindowTracker
}

func NewWebEnumDetector(window time.Duration, threshold int) *WebEnumDetector {
	return &WebEnumDetector{
		tracker: NewWindowTracker(window, threshold, maxTrackedIPs),
	}
}

func isSensitivePath(path string) bool {
	targets := []string{
		"/wp-login",
		"/admin",
		"/.env",
		"phpmyadmin",
		"/.git",
		"/backup",
		"/config",
		"/api/v1",
		"/actuator",
		"/server-status",
	}
	for _, t := range targets {
		if strings.Contains(path, t) {
			return true
		}
	}
	return false
}

func isErrorStatus(status string) bool {
	return status == "401" || status == "403" || status == "404"
}

func (d *WebEnumDetector) Prune(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tracker.Prune(now)
}

func (d *WebEnumDetector) Process(ev normalizer.Event) (Result, bool) {
	if ev.Service != "web" {
		return Result{}, false
	}
	if ev.IP == "" || ev.Path == "" {
		return Result{}, false
	}
	if !isSensitivePath(ev.Path) || !isErrorStatus(ev.Status) {
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

		const ruleID = "WEB_ENUMERATION"
		msg := fmt.Sprintf(
			"⚠️ [경고][중간] 웹 경로 스캐닝(열거) 공격 의심\n"+
				"- IP: %s\n"+
				"- 시도 횟수: %d회 (%d초 윈도우)\n"+
				"- 최초 시각: %s\n"+
				"- 마지막 시각: %s\n"+
				"- 설명: 관리자/환경 파일 등 민감 경로에 대한 접근이 반복되었습니다.",
			ip,
			match.Count,
			int(d.tracker.window.Seconds()),
			first.Format(time.RFC3339),
			last.Format(time.RFC3339),
		)

		return Result{
			TS:       now,
			RuleID:   ruleID,
			Title:    "웹 경로 스캐닝(열거) 공격 의심",
			Severity: "중간",
			Message:  msg,
			IP:       ip,
			Service:  ev.Service,
		}, true
	}

	return Result{}, false
}
