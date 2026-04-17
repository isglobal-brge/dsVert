// k2_fp_ops_test.go: unit tests for the local Ring63 FP helper ops
// that underpin Cox (cumsum + permutation) and weighted GLM (vec-mul).
package main

import (
	"math"
	"testing"
)

// TestFPCumsumShares verifies that cumsum on additive shares equals
// the cumsum of the true vector after reconstruction, both forward
// and reverse. This is the kernel of the Cox reverse-cumsum gradient.
func TestFPCumsumShares(t *testing.T) {
	ring := NewRing63(K2DefaultFracBits)

	truth := []float64{1.2, -0.5, 0.3, 0.7, -1.1, 0.9, 0.4, 1.5, -0.8, 0.6}
	n := len(truth)

	a0 := make([]uint64, n)
	a1 := make([]uint64, n)
	for i, v := range truth {
		fp := ring.FromDouble(v)
		s0, s1 := ring.SplitShare(fp)
		a0[i] = s0
		a1[i] = s1
	}

	out0 := make([]uint64, n)
	out1 := make([]uint64, n)
	acc0 := uint64(0)
	acc1 := uint64(0)
	for i := 0; i < n; i++ {
		acc0 = ring.Add(acc0, a0[i])
		acc1 = ring.Add(acc1, a1[i])
		out0[i] = acc0
		out1[i] = acc1
	}
	trueForward := make([]float64, n)
	acc := 0.0
	for i, v := range truth {
		acc += v
		trueForward[i] = acc
	}
	for i := 0; i < n; i++ {
		got := ring.ToDouble(ring.Add(out0[i], out1[i]))
		if math.Abs(got-trueForward[i]) > 1e-5 {
			t.Errorf("forward cumsum[%d] = %f, want %f", i, got, trueForward[i])
		}
	}

	out0 = make([]uint64, n)
	out1 = make([]uint64, n)
	acc0, acc1 = 0, 0
	for i := n - 1; i >= 0; i-- {
		acc0 = ring.Add(acc0, a0[i])
		acc1 = ring.Add(acc1, a1[i])
		out0[i] = acc0
		out1[i] = acc1
	}
	trueReverse := make([]float64, n)
	acc = 0.0
	for i := n - 1; i >= 0; i-- {
		acc += truth[i]
		trueReverse[i] = acc
	}
	for i := 0; i < n; i++ {
		got := ring.ToDouble(ring.Add(out0[i], out1[i]))
		if math.Abs(got-trueReverse[i]) > 1e-5 {
			t.Errorf("reverse cumsum[%d] = %f, want %f", i, got, trueReverse[i])
		}
	}
}

// TestFPVecMulPlaintextShare verifies element-wise FP multiplication
// of a share by a plaintext vector preserves additive sharing:
// (a0 + a1) * w element-wise == a0*w + a1*w, reconstructed.
func TestFPVecMulPlaintextShare(t *testing.T) {
	ring := NewRing63(K2DefaultFracBits)
	truth := []float64{1.5, 2.7, -0.3, 4.1}
	w := []float64{0.5, 1.2, 3.0, 0.8}
	n := len(truth)

	a0 := make([]uint64, n)
	a1 := make([]uint64, n)
	wFP := make([]uint64, n)
	for i, v := range truth {
		fp := ring.FromDouble(v)
		s0, s1 := ring.SplitShare(fp)
		a0[i] = s0
		a1[i] = s1
		wFP[i] = ring.FromDouble(w[i])
	}

	p0 := make([]uint64, n)
	p1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		p0[i] = ring.TruncMulSigned(a0[i], wFP[i])
		p1[i] = ring.TruncMulSigned(a1[i], wFP[i])
	}

	for i := 0; i < n; i++ {
		got := ring.ToDouble(ring.Add(p0[i], p1[i]))
		want := truth[i] * w[i]
		if math.Abs(got-want) > 1e-5 {
			t.Errorf("vec-mul[%d]: got %f, want %f", i, got, want)
		}
	}
}
