package normalizer

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
)

type Event struct {
	TS      time.Time
	Service string
	Action  string
	User    string
	IP      string
	Status  string
	Path    string
	RawLine string
}

func ParseLine(line string) (Event, error) {
	return ParseLineAt(line, time.Now())
}

// ParseLineAt uses the supplied clock to infer the year and timezone of
// traditional syslog timestamps, which contain neither.
func ParseLineAt(line string, reference time.Time) (Event, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Event{}, errors.New("empty line")
	}
	if ev, matched, err := parseOpenSSH(line, reference); matched {
		return ev, err
	}
	if ev, matched, err := parseWebAccess(line); matched {
		return ev, err
	}
	if !strings.Contains(line, "service=") {
		return Event{}, errors.New("unsupported log format")
	}
	return parseProjectLine(line)
}

func parseProjectLine(line string) (Event, error) {
	parts, err := splitFields(line)
	if err != nil {
		return Event{}, err
	}
	if len(parts) < 2 {
		return Event{}, errors.New("invalid line format")
	}

	// 1) timestamp (첫 토큰)
	ts, err := time.Parse(time.RFC3339, parts[0])
	if err != nil {
		return Event{}, err
	}

	ev := Event{
		TS:      ts,
		RawLine: line,
	}

	// 2) key=value 토큰 파싱
	for _, tok := range parts[1:] {
		kv := strings.SplitN(tok, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := kv[0], kv[1]

		switch k {
		case "service":
			ev.Service = v
		case "action":
			ev.Action = v
		case "user":
			ev.User = v
		case "ip":
			ev.IP = v
		case "status":
			ev.Status = v
		case "path":
			ev.Path = v
			// web.log에는 method, ua도 있지만 Step 1에서는 무시해도 OK
		}
	}

	// Keep one Event vocabulary across quoted and unquoted project logs.
	ev.Service = strings.ToLower(ev.Service)
	ev.Action = strings.ToLower(ev.Action)
	if ev.Service == "" {
		return Event{}, errors.New("missing service field")
	}
	if ev.Service == "ssh" && ev.Action == "login" {
		ev.Action = "auth"
	}
	if ev.Service == "auth" || ev.Service == "ssh" {
		switch strings.ToUpper(ev.Status) {
		case "FAIL", "FAILED", "FAILURE":
			ev.Status = "FAIL"
		case "SUCCESS", "SUCCEEDED":
			ev.Status = "SUCCESS"
		}
	}

	return ev, nil
}

var openSSHLine = regexp.MustCompile("^(\\w{3}\\s+\\d{1,2}\\s+\\d\\d:\\d\\d:\\d\\d)\\s+\\S+\\s+sshd(?:\\[\\d+\\])?:\\s+(Failed|Accepted)\\s+(?:password|publickey|keyboard-interactive/pam)\\s+for\\s+(?:invalid user\\s+)?(\\S+)\\s+from\\s+(\\S+)\\s+port\\s+\\d+")
var webAccessLine = regexp.MustCompile("^(\\S+)\\s+\\S+\\s+\\S+\\s+\\[([^]]+)\\]\\s+\"(\\S+)\\s+(\\S+)\\s+HTTP/[0-9.]+\"\\s+(\\d{3})\\s+\\S+(?:\\s+.*)?$")

func parseOpenSSH(line string, reference time.Time) (Event, bool, error) {
	match := openSSHLine.FindStringSubmatch(line)
	if match == nil {
		return Event{}, false, nil
	}
	if net.ParseIP(match[4]) == nil {
		return Event{}, true, errors.New("invalid OpenSSH source IP")
	}
	if reference.IsZero() {
		return Event{}, true, errors.New("missing reference time for syslog")
	}
	parsed, err := time.ParseInLocation("Jan _2 15:04:05", match[1], reference.Location())
	if err != nil {
		return Event{}, true, err
	}
	ts := time.Date(reference.Year(), parsed.Month(), parsed.Day(), parsed.Hour(), parsed.Minute(), parsed.Second(), 0, reference.Location())
	if ts.After(reference.Add(24 * time.Hour)) {
		ts = ts.AddDate(-1, 0, 0)
	}
	status := "FAIL"
	if match[2] == "Accepted" {
		status = "SUCCESS"
	}
	return Event{TS: ts, Service: "ssh", Action: "auth", User: match[3], IP: match[4], Status: status, RawLine: line}, true, nil
}

func parseWebAccess(line string) (Event, bool, error) {
	match := webAccessLine.FindStringSubmatch(line)
	if match == nil {
		return Event{}, false, nil
	}
	if net.ParseIP(match[1]) == nil {
		return Event{}, true, errors.New("invalid web source IP")
	}
	ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", match[2])
	if err != nil {
		return Event{}, true, err
	}
	uri, err := url.ParseRequestURI(match[4])
	if err != nil {
		return Event{}, true, err
	}
	return Event{TS: ts, Service: "web", Action: strings.ToLower(match[3]), IP: match[1], Status: match[5], Path: uri.Path, RawLine: line}, true, nil
}

// splitFields keeps quoted values, including spaces, within one key=value token.
func splitFields(line string) ([]string, error) {
	fields := make([]string, 0, 8)
	var field strings.Builder
	inQuotes := false
	escaped := false

	flush := func() {
		if field.Len() == 0 {
			return
		}
		fields = append(fields, field.String())
		field.Reset()
	}

	for _, r := range line {
		if escaped {
			field.WriteRune(r)
			escaped = false
			continue
		}
		if inQuotes && r == '\\' {
			escaped = true
			continue
		}
		if r == '"' {
			inQuotes = !inQuotes
			continue
		}
		if unicode.IsSpace(r) && !inQuotes {
			flush()
			continue
		}
		field.WriteRune(r)
	}

	if escaped {
		field.WriteRune('\\')
	}
	if inQuotes {
		return nil, errors.New("unterminated quoted field")
	}
	flush()
	return fields, nil
}
