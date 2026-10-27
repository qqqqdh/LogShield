package benchmark

import "testing"

func TestComputeDetailedSeparatesAttemptsFromValidLLMResponses(t *testing.T) {
	predictions := []PredictionDetail{
		{ExecutedLLM: true, IsDegraded: true},
		{ExecutedLLM: true, IsInvalid: true},
		{ExecutedLLM: true},
	}
	dataset := []Sample{{}, {}, {}}
	result := NewEvaluator().ComputeDetailed("test", predictions, dataset)
	if result.LLMCallCount != 3 || result.LLMValidCount != 1 {
		t.Fatalf("attempts=%d valid=%d, want 3 and 1", result.LLMCallCount, result.LLMValidCount)
	}
}
