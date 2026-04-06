package main

import (
	"math"
	"testing"
)

func TestN100SigmoidIter2(t *testing.T) {
	ring := NewRing63(20)
	params := DefaultSigmoidParams()

	n := 100
	// Standardized eta values from iteration 2 (small, in [-0.5, 0.5])
	eta := make([]float64, n)
	for i := 0; i < n; i++ {
		eta[i] = math.Sin(float64(i)*0.73) * 0.3 // small standardized values
	}

	etaFP := make([]uint64, n)
	for i, v := range eta { etaFP[i] = ring.FromDouble(v) }
	e0 := make([]uint64, n); e1 := make([]uint64, n)
	for i := range etaFP { e0[i], e1[i] = ring.SplitShare(etaFP[i]) }

	dmu0, dmu1 := DistributedSigmoidLocalMhe(ring, e0, e1)
	pmu0, pmu1 := SecureSigmoidLocal(params, e0, e1)

	maxDiff := 0.0
	worstI := -1
	for i := 0; i < n; i++ {
		dv := ring.ToDouble(ring.Add(dmu0[i], dmu1[i]))
		pv := ring.ToDouble(ring.Add(pmu0[i], pmu1[i]))
		d := math.Abs(dv - pv)
		if d > maxDiff { maxDiff = d; worstI = i }
	}
	t.Logf("n=100 sigmoid: maxDiff=%.2e worstI=%d", maxDiff, worstI)
	if maxDiff > 0.01 {
		dv := ring.ToDouble(ring.Add(dmu0[worstI], dmu1[worstI]))
		pv := ring.ToDouble(ring.Add(pmu0[worstI], pmu1[worstI]))
		t.Logf("  worst: eta=%.6f dist=%.6f local=%.6f", eta[worstI], dv, pv)
		t.Errorf("maxDiff %.2e > 0.01", maxDiff)
	}
}
