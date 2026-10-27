package normalizer

import (
	"testing"
	"time"
)

func TestParseLinePreservesQuotedFields(t *testing.T) {
	ev, err := ParseLine(`2026-01-01T00:00:00Z service=web path="/admin panel" ip=198.51.100.1 status=404 ua="scan bot/1.0"`)
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}
	if ev.Path != "/admin panel" {
		t.Fatalf("Path = %q, want %q", ev.Path, "/admin panel")
	}
}

func TestParseLineRejectsUnterminatedQuotedField(t *testing.T) {
	if _, err := ParseLine(`2026-01-01T00:00:00Z service=web path="/admin`); err == nil {
		t.Fatal("expected an unterminated quoted field error")
	}
}

func TestParseOpenSSHAndWebAccessFormats(t *testing.T) {
	reference := time.Date(2026, 10, 28, 12, 0, 0, 0, time.FixedZone("KST", 9*3600))
	cases := []struct {
		name, line, service, action, user, ip, status, path string
		want                                                time.Time
	}{
		{
			name:    "openssh failed invalid user",
			line:    "Oct 28 10:00:00 host sshd[12]: Failed password for invalid user root from 203.0.113.1 port 22 ssh2",
			service: "ssh", action: "auth", user: "root", ip: "203.0.113.1", status: "FAIL",
			want: time.Date(2026, 10, 28, 10, 0, 0, 0, reference.Location()),
		},
		{
			name:    "openssh accepted",
			line:    "Oct 28 10:00:01 host sshd[12]: Accepted publickey for alice from 203.0.113.1 port 22 ssh2",
			service: "ssh", action: "auth", user: "alice", ip: "203.0.113.1", status: "SUCCESS",
			want: time.Date(2026, 10, 28, 10, 0, 1, 0, reference.Location()),
		},
		{
			name:    "web combined",
			line:    `203.0.113.2 - - [28/Oct/2026:10:00:00 +0900] "GET /.env?x=1 HTTP/1.1" 404 12 "-" "scanner"`,
			service: "web", action: "get", ip: "203.0.113.2", status: "404", path: "/.env",
			want: time.Date(2026, 10, 28, 10, 0, 0, 0, reference.Location()),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseLineAt(tc.line, reference)
			if err != nil {
				t.Fatal(err)
			}
			if got.Service != tc.service || got.Action != tc.action || got.User != tc.user || got.IP != tc.ip || got.Status != tc.status || got.Path != tc.path || !got.TS.Equal(tc.want) {
				t.Fatalf("got %+v, want service=%s action=%s user=%s ip=%s status=%s path=%s ts=%s", got, tc.service, tc.action, tc.user, tc.ip, tc.status, tc.path, tc.want)
			}
		})
	}
}

func TestParseRejectsUnsupportedSyslog(t *testing.T) {
	reference := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	if _, err := ParseLineAt("Oct 28 10:00:00 host cron[12]: job completed", reference); err == nil {
		t.Fatal("unsupported syslog was accepted")
	}
}

func TestParseLineNormalizesAuthenticationFields(t *testing.T) {
	ev, err := ParseLine(`2026-01-01T00:00:00Z service=SSH action=login user=root ip="198.51.100.23" status="failed"`)
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}
	if ev.Service != "ssh" || ev.Action != "auth" || ev.Status != "FAIL" || ev.IP != "198.51.100.23" {
		t.Fatalf("normalized event = %+v", ev)
	}
}
