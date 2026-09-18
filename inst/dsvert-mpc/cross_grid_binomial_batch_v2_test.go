package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/markkurossi/mpc/circuit"
)

// Use the already certified binomial polynomial unchanged. Widen only the
// output-share container so both component probes use the same transport ABI.
func crossGridBinomialBatchCompile(t testing.TB, p crossGridPWProfile, n int) *circuit.Circuit {
	source := crossGridPWSource(p)
	source = strings.Replace(source, "func main(g [2]uint32, e uint32) (uint32, bool)", "func main(g [2]uint64, e uint32) (uint64, bool)", 1)
	source = strings.Replace(source, "x := g[0] + e", "x := uint32(g[0]) + e", 1)
	source = strings.Replace(source, "return v - g[1], valid", "return uint64(v) - g[1], valid", 1)
	return crossGridProfileBatchCompile(t, source, n)
}

func TestCrossGridBinomialV2BatchProtocol(t *testing.T) {
	for _, p := range crossGridPWProfiles(t) {
		if p.Family != "binomial" || p.Pieces != 64 || (p.A != 4 && p.A != 16) {
			continue
		}
		c := crossGridBinomialBatchCompile(t, p, 32)
		oracle := func(x int32) (uint64, bool) { v, ok := crossGridPWOracle(p, uint32(x)); return uint64(v), ok }
		for _, invalid := range []bool{false, true} {
			values := make([]int32, 32)
			for i := range values {
				values[i] = int32(2 * p.A * 65536 * i / 31)
			}
			if invalid {
				values[0] = int32(2*p.A*65536 + 1)
			}
			bytes := crossGridProfileProtocol(t, c, p.Identity, values, true, oracle)
			t.Logf("A=%d invalid=%t AND/eval=%.3f wire-B/eval=%.3f", p.A, invalid, float64(c.Stats[circuit.AND])/32, float64(bytes)/32)
		}
	}
}

func BenchmarkCrossGridBinomialV2BatchProtocol(b *testing.B) {
	for _, p := range crossGridPWProfiles(b) {
		if p.Family != "binomial" || p.Pieces != 64 || (p.A != 4 && p.A != 16) {
			continue
		}
		b.Run(fmt.Sprintf("A%d/batch32/compact", p.A), func(b *testing.B) {
			c := crossGridBinomialBatchCompile(b, p, 32)
			values := make([]int32, 32)
			for i := range values {
				values[i] = int32(2 * p.A * 65536 * i / 31)
			}
			oracle := func(x int32) (uint64, bool) { v, ok := crossGridPWOracle(p, uint32(x)); return uint64(v), ok }
			b.ResetTimer()
			var bytes uint64
			for i := 0; i < b.N; i++ {
				bytes += crossGridProfileProtocol(b, c, p.Identity, values, true, oracle)
			}
			b.StopTimer()
			b.ReportMetric(float64(bytes)/float64(b.N*32), "wire-B/eval")
			b.ReportMetric(float64(c.Stats[circuit.AND])/32, "AND/eval")
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*32), "ns/eval")
		})
	}
}
