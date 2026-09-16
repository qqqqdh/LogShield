package detector

import (
	"testing"
	"time"
)

func TestWindowTrackerMatchesAndResets(t *testing.T) {
	tracker := NewWindowTracker(10*time.Second, 3, 10)
	base := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

	for i := 0; i < 2; i++ {
		if _, matched := tracker.Add("198.51.100.1", base.Add(time.Duration(i)*time.Second)); matched {
			t.Fatalf("matched before threshold on event %d", i+1)
		}
	}

	match, matched := tracker.Add("198.51.100.1", base.Add(2*time.Second))
	if !matched {
		t.Fatal("expected the third event to match")
	}
	if match.Count != 3 || !match.First.Equal(base) || !match.Last.Equal(base.Add(2*time.Second)) {
		t.Fatalf("unexpected match: %+v", match)
	}

	if _, matched := tracker.Add("198.51.100.1", base.Add(3*time.Second)); matched {
		t.Fatal("tracker should reset after a match")
	}
}

func TestWindowTrackerExpiresEventsAndBoundsKeys(t *testing.T) {
	tracker := NewWindowTracker(5*time.Second, 2, 1)
	base := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

	tracker.Add("198.51.100.1", base)
	if _, matched := tracker.Add("198.51.100.1", base.Add(6*time.Second)); matched {
		t.Fatal("an expired event must not count toward the threshold")
	}
	if _, matched := tracker.Add("198.51.100.2", base.Add(time.Second)); matched {
		t.Fatal("the replacement key should not match after one event")
	}
	if _, matched := tracker.Add("198.51.100.2", base.Add(2*time.Second)); !matched {
		t.Fatal("the replacement key should be tracked at the key limit")
	}
}

func TestWindowTrackerIgnoresFutureEventsForLateRecords(t *testing.T) {
	tracker := NewWindowTracker(10*time.Second, 3, 10)
	base := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

	tracker.Add("198.51.100.3", base.Add(20*time.Second))
	tracker.Add("198.51.100.3", base.Add(21*time.Second))
	tracker.Add("198.51.100.3", base)
	tracker.Add("198.51.100.3", base.Add(time.Second))

	match, matched := tracker.Add("198.51.100.3", base.Add(2*time.Second))
	if !matched || match.Count != 3 || !match.First.Equal(base) || !match.Last.Equal(base.Add(2*time.Second)) {
		t.Fatalf("late records were handled incorrectly: matched=%v match=%+v", matched, match)
	}
}
