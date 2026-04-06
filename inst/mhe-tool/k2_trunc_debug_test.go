package main

import (
	"math"
	"testing"
)

func TestDebugIdealTruncSigmoid(t *testing.T) {
	ring := NewRing63(20)

	// Test sigmoid at eta=0 with both floor and ideal truncation
	n := 5
	eta := make([]float64, n)
	eta[0] = 0.0
	eta[1] = 0.5
	eta[2] = -0.5
	eta[3] = 1.5
	eta[4] = -1.5

	for _, tf := range []struct {
		name string
		fn   truncFn
	}{
		{"FLOOR", floorTruncBoth},
		{"IDEAL", idealTruncBoth},
		{"TRUNCPR", truncPrBoth},
	} {
		etaFP := make([]uint64, n)
		for i, v := range eta {
			etaFP[i] = ring.FromDouble(v)
		}
		eta0 := make([]uint64, n)
		eta1 := make([]uint64, n)
		for i := range etaFP {
			eta0[i], eta1[i] = ring.SplitShare(etaFP[i])
		}

		mu0, mu1 := distributedSigmoidFn(ring, eta0, eta1, tf.fn)

		for i := 0; i < n; i++ {
			mu := ring.ToDouble(ring.Add(mu0[i], mu1[i]))
			want := 1.0 / (1.0 + math.Exp(-eta[i]))
			t.Logf("[%s] eta=%.1f: mu=%.6f (want %.6f, err=%.2e)", tf.name, eta[i], mu, want, math.Abs(mu-want))
		}
	}
}

func TestDebugIdealTruncSpline(t *testing.T) {
	ring := NewRing63(20)
	params := DefaultSigmoidParams()

	// Test spline only at a few x values
	for _, x := range []float64{0.15, 0.35, 0.55, 0.75, 0.95} {
		xFP := ring.FromDouble(x)
		localVal := ring.FromDouble(evalSpline(x, params))
		wantF := evalSpline(x, params)

		for _, tf := range []struct {
			name string
			fn   truncFn
		}{
			{"FLOOR", floorTruncBoth},
			{"IDEAL", idealTruncBoth},
		} {
			x0, x1 := ring.SplitShare(xFP)
			r0, r1 := evalSplineOnSharesFn(ring, params, []uint64{x0}, []uint64{x1}, tf.fn)
			distVal := ring.Add(r0[0], r1[0])
			distF := ring.ToDouble(distVal)
			bias := float64(int64(distVal) - int64(localVal))
			t.Logf("[%s] x=%.2f: dist=%.6f local=%.6f want=%.6f bias=%.1f ULP err=%.2e",
				tf.name, x, distF, ring.ToDouble(localVal), wantF, bias, math.Abs(distF-wantF))
		}
	}
}

func TestDebugIdealHadamard(t *testing.T) {
	ring := NewRing63(20)

	// Simple Hadamard test: 0.5 * 0.3 = 0.15
	a := ring.FromDouble(0.5)
	b := ring.FromDouble(0.3)
	want := ring.FromDouble(0.15)

	for _, tf := range []struct {
		name string
		fn   truncFn
	}{
		{"FLOOR", floorTruncBoth},
		{"IDEAL", idealTruncBoth},
	} {
		sumBias := 0.0
		N := 100
		for trial := 0; trial < N; trial++ {
			a0, a1 := ring.SplitShare(a)
			b0, b1 := ring.SplitShare(b)
			r0, r1 := hadamardBothFn([]uint64{a0}, []uint64{b0}, []uint64{a1}, []uint64{b1}, ring.FracBits, ring, tf.fn)
			result := ring.Add(r0[0], r1[0])
			sumBias += float64(int64(result) - int64(want))
		}
		t.Logf("[%s] 0.5*0.3: mean bias = %+.3f ULP", tf.name, sumBias/float64(N))
	}
}

func TestDebugWideSplineBulk(t *testing.T) {
	// Test sigmoid at eta=0 for 155 elements (full Pima size)
	for _, fb := range []int{20, 30} {
		ring := NewRing63(fb)
		n := 155
		eta0 := make([]uint64, n)
		eta1 := make([]uint64, n)
		// eta = 0 for all elements
		for i := 0; i < n; i++ {
			eta0[i], eta1[i] = ring.SplitShare(ring.FromDouble(0.0))
		}
		mu0, mu1 := wideSplineSigmoidFn(ring, eta0, eta1, floorTruncBoth, 100, 5.0)

		// Check sum of mu (should be 155 * 0.5 = 77.5)
		var smu0, smu1 uint64
		for i := 0; i < n; i++ {
			smu0 = ring.Add(smu0, mu0[i])
			smu1 = ring.Add(smu1, mu1[i])
		}
		sumMu := ring.ToDouble(ring.Add(smu0, smu1))
		t.Logf("[fb=%d] sum(mu) for 155 elements at eta=0: %.4f (want 77.5, err=%.2e)", fb, sumMu, math.Abs(sumMu-77.5))

		// Check a few individual elements
		for i := 0; i < 3; i++ {
			mu := ring.ToDouble(ring.Add(mu0[i], mu1[i]))
			t.Logf("[fb=%d]   elem %d: mu=%.6f (want 0.5)", fb, i, mu)
		}
	}
}

func TestDebugWideSplineFrac30(t *testing.T) {
	for _, fb := range []int{20, 30} {
		ring := NewRing63(fb)
		n := 5
		etas := []float64{0.0, 0.5, -0.5, 1.5, -1.5}
		etaFP := make([]uint64, n)
		for i, v := range etas {
			etaFP[i] = ring.FromDouble(v)
		}
		eta0 := make([]uint64, n)
		eta1 := make([]uint64, n)
		for i := range etaFP {
			eta0[i], eta1[i] = ring.SplitShare(etaFP[i])
		}

		mu0, mu1 := wideSplineSigmoidFn(ring, eta0, eta1, floorTruncBoth, 100, 5.0)

		for i := 0; i < n; i++ {
			mu := ring.ToDouble(ring.Add(mu0[i], mu1[i]))
			want := 1.0 / (1.0 + math.Exp(-etas[i]))
			t.Logf("[fb=%d] eta=%.1f: mu=%.6f (want %.6f, err=%.2e)", fb, etas[i], mu, want, math.Abs(mu-want))
		}
	}
}

func TestDebugGradientHadamardFracBits(t *testing.T) {
	for _, fb := range []int{20, 25, 30} {
		ring := NewRing63(fb)
		n := 10
		xVals := []float64{0.5, -0.3, 1.2, -0.8, 0.1, 0.7, -1.1, 0.4, -0.6, 0.9}
		rVals := []float64{0.2, -0.3, 0.1, 0.4, -0.2, 0.15, -0.1, 0.3, -0.05, 0.25}

		// Check individual Hadamard products
		for i := 0; i < 3; i++ {
			a := ring.FromDouble(xVals[i])
			b := ring.FromDouble(rVals[i])
			want := xVals[i] * rVals[i]
			a0, a1 := ring.SplitShare(a)
			b0, b1 := ring.SplitShare(b)
			r0, r1 := HadamardProductLocal([]uint64{a0}, []uint64{b0}, []uint64{a1}, []uint64{b1}, ring.FracBits, ring)
			got := ring.ToDouble(ring.Add(r0[0], r1[0]))
			t.Logf("[fb=%d] elem %d: %.4f * %.4f = %.6f (want %.6f, err=%.2e)", fb, i, xVals[i], rVals[i], got, want, math.Abs(got-want))
		}
		// Also test a negative product
		a := ring.FromDouble(-0.8)
		b := ring.FromDouble(0.4)
		want := -0.32
		a0, a1 := ring.SplitShare(a)
		b0, b1 := ring.SplitShare(b)
		r0, r1 := HadamardProductLocal([]uint64{a0}, []uint64{b0}, []uint64{a1}, []uint64{b1}, ring.FracBits, ring)
		got := ring.ToDouble(ring.Add(r0[0], r1[0]))
		t.Logf("[fb=%d] -0.8*0.4 = %.6f (want %.6f, err=%.2e)", fb, got, want, math.Abs(got-want))

		xFP2 := make([]uint64, n)
		rFP2 := make([]uint64, n)
		for i := range xVals {
			xFP2[i] = ring.FromDouble(xVals[i])
			rFP2[i] = ring.FromDouble(rVals[i])
		}

		wantSum := 0.0
		for i := range xVals {
			wantSum += xVals[i] * rVals[i]
		}

		xx0 := make([]uint64, n)
		xx1 := make([]uint64, n)
		rr0 := make([]uint64, n)
		rr1 := make([]uint64, n)
		for i := range xFP2 {
			xx0[i], xx1[i] = ring.SplitShare(xFP2[i])
			rr0[i], rr1[i] = ring.SplitShare(rFP2[i])
		}

		bt0, bt1 := SampleBeaverTripleVector(n, ring)
		st0, msg0 := GenerateBatchedMultiplicationGateMessage(xx0, rr0, bt0, ring)
		st1, msg1 := GenerateBatchedMultiplicationGateMessage(xx1, rr1, bt1, ring)
		pr0 := HadamardProductPartyZero(st0, bt0, msg1, ring.FracBits, ring)
		pr1 := HadamardProductPartyOne(st1, bt1, msg0, ring.FracBits, ring)
		var s0, s1 uint64
		for i := 0; i < n; i++ {
			s0 = ring.Add(s0, pr0[i])
			s1 = ring.Add(s1, pr1[i])
		}
		gotSum := ring.ToDouble(ring.Add(s0, s1))
		t.Logf("[fb=%d] sum(x*r) = %.6f (want %.6f, err=%.2e)", fb, gotSum, wantSum, math.Abs(gotSum-wantSum))
	}
}

func TestDebugGradientHadamard(t *testing.T) {
	ring := NewRing63(20)
	n := 10

	// Simulate: x_j * r where x_j and r are moderate values
	xVals := []float64{0.5, -0.3, 1.2, -0.8, 0.1, 0.7, -1.1, 0.4, -0.6, 0.9}
	rVals := []float64{0.2, -0.3, 0.1, 0.4, -0.2, 0.15, -0.1, 0.3, -0.05, 0.25}

	xFP := make([]uint64, n)
	rFP := make([]uint64, n)
	for i := range xVals {
		xFP[i] = ring.FromDouble(xVals[i])
		rFP[i] = ring.FromDouble(rVals[i])
	}

	wantSum := 0.0
	for i := range xVals {
		wantSum += xVals[i] * rVals[i]
	}

	for _, tf := range []struct {
		name string
		fn   truncFn
	}{
		{"FLOOR", floorTruncBoth},
		{"IDEAL", idealTruncBoth},
	} {
		x0 := make([]uint64, n)
		x1 := make([]uint64, n)
		r0 := make([]uint64, n)
		r1 := make([]uint64, n)
		for i := range xFP {
			x0[i], x1[i] = ring.SplitShare(xFP[i])
			r0[i], r1[i] = ring.SplitShare(rFP[i])
		}

		pr0, pr1 := hadamardBothFn(x0, r0, x1, r1, ring.FracBits, ring, tf.fn)

		// Sum and convert
		var s0, s1 uint64
		for i := 0; i < n; i++ {
			s0 = ring.Add(s0, pr0[i])
			s1 = ring.Add(s1, pr1[i])
		}
		gotSum := ring.ToDouble(ring.Add(s0, s1))
		t.Logf("[%s] sum(x*r) = %.6f (want %.6f, err=%.2e)", tf.name, gotSum, wantSum, math.Abs(gotSum-wantSum))

		// Also check individual elements
		for i := 0; i < 3; i++ {
			val := ring.ToDouble(ring.Add(pr0[i], pr1[i]))
			want := xVals[i] * rVals[i]
			t.Logf("  [%s] elem %d: %.6f (want %.6f)", tf.name, i, val, want)
		}
	}
}
