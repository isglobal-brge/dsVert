package linearaccel

import "testing"

func BenchmarkLinear63TwoRolesOnline(b *testing.B) {
	b.StopTimer()
	experiment, err := NewExperiment(Signed63, 2)
	if err != nil {
		b.Fatal(err)
	}
	input := smallInput()
	b.ReportAllocs()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		result, err := experiment.Run(input)
		if err != nil {
			b.Fatal(err)
		}
		if i == 0 {
			b.ReportMetric(float64(result.Metrics.InputCiphertextBytes), "input-wire-B/op")
			b.ReportMetric(float64(result.Metrics.OutputCiphertextBytes), "output-ct-B/op")
			b.ReportMetric(float64(result.Metrics.SignedEnvelopeBytes), "share-wire-B/op")
		}
	}
}

func BenchmarkSetup63TwoRoles(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		experiment, err := NewExperiment(Signed63, 2)
		if err != nil {
			b.Fatal(err)
		}
		if i == 0 {
			b.ReportMetric(float64(experiment.setupPublicBytes), "setup-wire-B/op")
		}
	}
}
