package detector

import (
	"go-logshield/internal/normalizer"
	"testing"
	"time"
)

func TestLateIndependentAttack(t *testing.T) {
	d := NewBruteForceDetector(BruteForceConfig{Window: 20 * time.Second, Threshold: 5})
	base := time.Unix(1700000000, 0)
	alerts := 0
	for _, start := range []int{100, 0} {
		for i := 0; i < 5; i++ {
			_, ok := d.Process(normalizer.Event{TS: base.Add(time.Duration(start+i) * time.Second), Service: "auth", Action: "login", Status: "FAIL", IP: "203.0.113.5"})
			if ok {
				alerts++
			}
		}
	}
	if alerts != 2 {
		t.Fatalf("independent clusters: alerts=%d, want 2", alerts)
	}
	// The older alert's neighboring late records remain in cooldown.
	for i := 0; i < 5; i++ {
		if _, ok := d.Process(normalizer.Event{TS: base.Add(time.Duration(i) * time.Second), Service: "auth", Action: "login", Status: "FAIL", IP: "203.0.113.5"}); ok {
			t.Fatal("duplicate within cooldown")
		}
	}
}

func TestReverseTimeHistoryIsBounded(t *testing.T) {
	for _, step := range []time.Duration{time.Second, 31 * time.Second} {
		t.Run(step.String(), func(t *testing.T) {
			tracker := NewWindowTracker(30*time.Second, 6, 10000)
			base := time.Unix(1700000000, 0)
			alerts := 0
			for i := 1000; i > 0; i-- {
				if _, ok := tracker.Add("one-ip", base.Add(time.Duration(i)*step)); ok {
					alerts++
				}
				if n := len(tracker.events["one-ip"]); n > 10 {
					t.Fatalf("retained=%d after input %d, limit 10", n, 1001-i)
				}
			}
			if step == time.Second && alerts == 0 {
				t.Fatal("reverse ordered attack missed")
			}
			if step > 30*time.Second && alerts != 0 {
				t.Fatal("unrelated events counted together")
			}
		})
	}
}

func TestWindowMatchAtBoundaryInEitherOrder(t *testing.T) {
	for _, order := range [][]int{{0, 5, 10}, {10, 5, 0}, {5, 0, 10}} {
		tracker := NewWindowTracker(10*time.Second, 3, 10)
		base := time.Unix(1700000000, 0)
		for i, sec := range order {
			match, ok := tracker.Add("ip", base.Add(time.Duration(sec)*time.Second))
			if ok != (i == 2) {
				t.Fatalf("order=%v event=%d match=%v", order, i, ok)
			}
			if ok && (match.Count != 3 || !match.First.Equal(base) || !match.Last.Equal(base.Add(10*time.Second))) {
				t.Fatalf("match=%+v", match)
			}
		}
	}
}
