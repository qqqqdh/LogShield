package benchmark

import "testing"

func TestTechniqueConfusionAccounting(t *testing.T) {
	cases := []struct {
		name       string
		truth      Sample
		prediction PredictionDetail
		want       map[string]TechMetric
	}{
		{"wrong technique", Sample{IsAttackGround: true, GroundTechnique: "T1595"}, PredictionDetail{IsAttack: true, TechniqueID: "T1110"}, map[string]TechMetric{"T1595": {FN: 1}, "T1110": {FP: 1}}},
		{"normal false alarm", Sample{GroundTechnique: "None"}, PredictionDetail{IsAttack: true, TechniqueID: "T1110"}, map[string]TechMetric{"T1110": {FP: 1}}},
		{"correct", Sample{IsAttackGround: true, GroundTechnique: "T1110"}, PredictionDetail{IsAttack: true, TechniqueID: "T1110"}, map[string]TechMetric{"T1110": {TP: 1, Precision: 1, Recall: 1, F1Score: 1}}},
		{"missed", Sample{IsAttackGround: true, GroundTechnique: "T1595"}, PredictionDetail{}, map[string]TechMetric{"T1595": {FN: 1}}},
		{"normal", Sample{GroundTechnique: "None"}, PredictionDetail{}, map[string]TechMetric{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NewEvaluator().ComputeDetailed("test", []PredictionDetail{tc.prediction}, []Sample{tc.truth}).TechniqueMetrics
			if len(got) != len(tc.want) {
				t.Fatalf("metrics=%+v want %+v", got, tc.want)
			}
			for tech, want := range tc.want {
				if got[tech] != want {
					t.Fatalf("%s=%+v want %+v", tech, got[tech], want)
				}
			}
		})
	}
}
