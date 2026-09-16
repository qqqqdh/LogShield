package analyzer

import (
	"time"

	"go-logshield/internal/detector"
	"go-logshield/internal/normalizer"
)

// Detector is the small contract shared by all event detectors.
type Detector interface {
	Process(normalizer.Event) (detector.Result, bool)
}

// Analyzer normalizes log lines and runs the configured detectors in order.
// Keeping this orchestration in one package makes the batch CLI, log generator,
// and TUI use exactly the same detection rules.
type Analyzer struct {
	detectors []Detector
}

func New(detectors ...Detector) *Analyzer {
	configured := make([]Detector, len(detectors))
	copy(configured, detectors)
	return &Analyzer{detectors: configured}
}

// NewDefault creates the detector set used by the LogShield commands.
func NewDefault() *Analyzer {
	return New(
		detector.NewBruteForceDetector(detector.BruteForceConfig{
			Window:    20 * time.Second,
			Threshold: 5,
		}),
		detector.NewSSHBruteForceDetector(30*time.Second, 6),
		detector.NewWebEnumDetector(30*time.Second, 4),
	)
}

// Process runs every detector against an already normalized event.
func (a *Analyzer) Process(ev normalizer.Event) []detector.Result {
	results := make([]detector.Result, 0, len(a.detectors))
	for _, d := range a.detectors {
		if result, ok := d.Process(ev); ok {
			results = append(results, result)
		}
	}
	return results
}

// ProcessLine parses one raw line and runs every detector against it.
func (a *Analyzer) ProcessLine(line string) (normalizer.Event, []detector.Result, error) {
	ev, err := normalizer.ParseLine(line)
	if err != nil {
		return normalizer.Event{}, nil, err
	}
	return ev, a.Process(ev), nil
}
