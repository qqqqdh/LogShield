package detector

import (
	"sort"
	"time"
)

// WindowMatch describes the events that reached a rule's threshold.
type WindowMatch struct {
	Count int
	First time.Time
	Last  time.Time
}

// WindowTracker keeps bounded, per-key event history for detectors that use
// the same sliding-window rule.
type WindowTracker struct {
	window    time.Duration
	threshold int
	maxKeys   int
	events    map[string][]time.Time
	lastSeen  map[string]time.Time
	lastPrune time.Time
}

func NewWindowTracker(window time.Duration, threshold, maxKeys int) *WindowTracker {
	return &WindowTracker{
		window:    window,
		threshold: threshold,
		maxKeys:   maxKeys,
		events:    make(map[string][]time.Time),
		lastSeen:  make(map[string]time.Time),
	}
}

// Add records an event and reports when the key reaches the configured
// threshold. Old entries are removed before the threshold is evaluated.
func (t *WindowTracker) Add(key string, now time.Time) (WindowMatch, bool) {
	if key == "" || now.IsZero() || t.window <= 0 || t.threshold <= 0 {
		return WindowMatch{}, false
	}

	if t.lastPrune.IsZero() || !now.Before(t.lastPrune.Add(t.window)) {
		t.Prune(now)
	}

	if _, exists := t.events[key]; !exists {
		if t.maxKeys > 0 && len(t.events) >= t.maxKeys {
			t.evictExpired(now.Add(-t.window))
			if len(t.events) >= t.maxKeys {
				t.evictOldest()
			}
		}
	}

	list := append(t.events[key], now)
	if seen, exists := t.lastSeen[key]; !exists || now.After(seen) {
		t.lastSeen[key] = now
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].Before(list[j])
	})
	cutoff := now.Add(-t.window)
	latest := now.Add(t.window)
	kept := list[:0]
	// shortcut: retain one window on either side of this arrival; sort historical
	// replays first when events can jump between distant time segments.
	for _, ts := range list {
		if !ts.Before(cutoff) && !ts.After(latest) {
			kept = append(kept, ts)
		}
	}

	var match WindowMatch
	start := 0
	for end, ts := range kept {
		for ts.Sub(kept[start]) > t.window {
			start++
		}
		if end-start+1 >= t.threshold {
			match = WindowMatch{Count: end - start + 1, First: kept[start], Last: ts}
			kept = append(kept[:start], kept[end+1:]...)
			break
		}
	}
	if len(kept) == 0 {
		delete(t.events, key)
		delete(t.lastSeen, key)
	} else {
		t.events[key] = kept
		t.lastSeen[key] = kept[len(kept)-1]
	}
	return match, match.Count > 0
}

// Prune removes expired history, including keys that have gone idle.
func (t *WindowTracker) Prune(now time.Time) {
	if now.IsZero() || t.window <= 0 {
		return
	}
	t.evictExpired(now.Add(-t.window))
	t.lastPrune = now
}

func (t *WindowTracker) evictExpired(cutoff time.Time) {
	for key, list := range t.events {
		kept := list[:0]
		for _, ts := range list {
			if !ts.Before(cutoff) {
				kept = append(kept, ts)
			}
		}
		if len(kept) == 0 {
			delete(t.events, key)
			delete(t.lastSeen, key)
			continue
		}
		t.events[key] = kept
	}
}

func (t *WindowTracker) evictOldest() {
	var oldestKey string
	var oldest time.Time
	for key, seen := range t.lastSeen {
		if oldestKey == "" || seen.Before(oldest) {
			oldestKey = key
			oldest = seen
		}
	}
	if oldestKey != "" {
		delete(t.events, oldestKey)
		delete(t.lastSeen, oldestKey)
	}
}
