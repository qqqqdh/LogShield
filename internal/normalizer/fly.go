package normalizer

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ErrNonEvent distinguishes a valid log envelope from a supported security event.
var ErrNonEvent = errors.New("log record is not a supported event")

type flyRecord struct {
	Timestamp  string          `json:"timestamp"`
	Message    *string         `json:"message"`
	Attributes json.RawMessage `json:"attributes"`
}

var ansiSequence = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
var flyHTTPRequest = regexp.MustCompile(`^(?:TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+\[([0-9]{3})\]\s+(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+\([^\r\n]*\)$`)

func parseFlyLine(line string) (Event, error) {
	var record flyRecord
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		return Event{}, fmt.Errorf("invalid Fly JSON: %w", err)
	}
	if len(record.Attributes) > 0 {
		attributes := record.Attributes
		record = flyRecord{}
		if err := json.Unmarshal(attributes, &record); err != nil {
			return Event{}, fmt.Errorf("invalid Fly attributes: %w", err)
		}
	}
	if record.Message == nil {
		return Event{}, errors.New("Fly log has no message")
	}
	ts, err := time.Parse(time.RFC3339Nano, record.Timestamp)
	if err != nil {
		return Event{}, fmt.Errorf("invalid Fly timestamp: %w", err)
	}
	message := strings.TrimSpace(ansiSequence.ReplaceAllString(*record.Message, ""))
	match := flyHTTPRequest.FindStringSubmatch(message)
	if match == nil {
		return Event{}, ErrNonEvent
	}
	status, _ := strconv.Atoi(match[1])
	if status < 100 || status > 599 {
		return Event{}, errors.New("invalid Fly HTTP status")
	}
	uri, err := url.ParseRequestURI(match[3])
	if err != nil {
		return Event{}, fmt.Errorf("invalid Fly request target: %w", err)
	}
	// The current skueat request format has no client IP; instance metadata is not one.
	return Event{TS: ts, Service: "web", Action: strings.ToLower(match[2]), Status: match[1], Path: uri.Path, RawLine: line}, nil
}
