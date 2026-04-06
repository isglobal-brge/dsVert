package main

import (
	"math"
	"testing"
)

func TestDistributedCmpMheTool(t *testing.T) {
	ring := NewRing63(20)

	testX := []float64{-5.0, -1.5, -0.5, 0.0, 0.3, 0.99, 1.0, 2.5, 10.0}
	n := len(testX)

	xFP := make([]uint64, n)
	for i, v := range testX { xFP[i] = ring.FromDouble(v) }
	x0 := make([]uint64, n); x1 := make([]uint64, n)
	for i := range xFP { x0[i], x1[i] = ring.SplitShare(xFP[i]) }

	lfLn2 := float64(20) * math.Ln2
	thresholds := []float64{0.0, 1.0, lfLn2}

	for _, tf := range thresholds {
		threshFP := ring.FromDouble(tf)
		p0Pre, p1Pre := cmpGeneratePreprocess(ring, n, threshFP)

		p0R1 := cmpRound1(ring, 0, x0, p0Pre)
		p1R1 := cmpRound1(ring, 1, x1, p1Pre)

		p0Res := cmpRound2(ring, 0, p0Pre, p0R1, p1R1)
		p1Res := cmpRound2(ring, 1, p1Pre, p1R1, p0R1)

		for i, xv := range testX {
			sum := ring.Add(p0Res.Shares[i], p1Res.Shares[i])
			want := uint64(0)
			if xv < tf { want = 1 }
			if sum != want {
				t.Errorf("[%.1f < %.1f]: got %d, want %d", xv, tf, sum, want)
			}
		}
	}
	t.Log("All comparisons correct")
}

func TestDistributedCmpLargeN(t *testing.T) {
	ring := NewRing63(20)
	n := 155

	testX := make([]float64, n)
	for i := range testX { testX[i] = math.Sin(float64(i)*1.37) * 3.0 }

	xFP := make([]uint64, n)
	for i, v := range testX { xFP[i] = ring.FromDouble(v) }
	x0 := make([]uint64, n); x1 := make([]uint64, n)
	for i := range xFP { x0[i], x1[i] = ring.SplitShare(xFP[i]) }

	lfLn2 := float64(20) * math.Ln2
	thresholds := []float64{-lfLn2, -1.0, 0.0, 1.0, lfLn2}

	errors := 0
	total := 0
	for _, tf := range thresholds {
		threshFP := ring.FromDouble(tf)
		p0Pre, p1Pre := cmpGeneratePreprocess(ring, n, threshFP)
		p0R1 := cmpRound1(ring, 0, x0, p0Pre)
		p1R1 := cmpRound1(ring, 1, x1, p1Pre)
		p0Res := cmpRound2(ring, 0, p0Pre, p0R1, p1R1)
		p1Res := cmpRound2(ring, 1, p1Pre, p1R1, p0R1)

		for i, xv := range testX {
			sum := ring.Add(p0Res.Shares[i], p1Res.Shares[i])
			want := uint64(0)
			if xv < tf { want = 1 }
			if sum != want { errors++ }
			total++
		}
	}
	t.Logf("Comparison: %d/%d correct", total-errors, total)
	if errors > 0 { t.Errorf("%d errors", errors) }
}
