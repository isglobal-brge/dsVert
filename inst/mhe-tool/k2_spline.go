// k2_spline.go: Secure spline evaluation for 2-party MPC.
//
// Port of Google fss_machine_learning: applications/secure_spline/secure_spline.cc
//
// Evaluates a piecewise-linear function f(x) = a_t * x + b_t securely,
// where t is the active interval determined by secure comparison gates.
//
// The spline has k intervals with known slopes and intercepts (public parameters).
// Given secret-shared x, the protocol:
//   1. Determines which interval x falls in (via k-1 comparison gates)
//   2. Computes a_t (active slope) and b_t (active intercept) as secret-shared values
//   3. Computes a_t * x + b_t via one Beaver multiplication

package main

import (
	"math"
)

// SplineParams holds the public parameters for a piecewise-linear spline.
type SplineParams struct {
	NumIntervals int
	LowerBounds  []float64
	UpperBounds  []float64
	Slopes       []float64
	YIntercepts  []float64
	NumBits      int // bit-width of the value domain (for comparisons)
}

// DefaultSigmoidSplineParams returns the spline parameters for sigmoid on [0,1)
// matching the C++ implementation.
// These approximate sigma(x) = 1/(1+e^{-x}) for x in [0, 1) with a
// 10-interval piecewise linear approximation.
func DefaultSigmoidSplineParams(fracBits int) SplineParams {
	return SplineParams{
		NumIntervals: 10,
		LowerBounds: []float64{0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9},
		UpperBounds: []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
		Slopes: []float64{
			0.24979187478940013, 0.24854809833537939, 0.24608519499181072,
			0.24245143300792976, 0.23771671089402596, 0.23196975023940808,
			0.2253146594237077, 0.2178670895944635, 0.20975021497391394,
			0.2010907600500101,
		},
		YIntercepts: []float64{
			0.5,
			0.5001243776454021,
			0.5006169583141158,
			0.5017070869092801,
			0.5036009757548416,
			0.5064744560821506,
			0.5104675105715708,
			0.5156808094520418,
			0.5221743091484814,
			0.5299678185799949,
		},
		NumBits: fracBits, // Values are in fixed-point with fracBits
	}
}

// SecureSplineEval evaluates the spline on secret-shared x (locally simulated).
// Returns shares of f(x) = a_t * x + b_t.
//
// x0, x1: secret shares of x (in Ring63 with fracBits fractional bits)
// Returns: result shares in the same ring.
func SecureSplineEval(r Ring63, sp SplineParams, x0, x1 []uint64) (res0, res1 []uint64) {
	n := len(x0)

	// Step 1: Determine interval via comparisons
	// For k intervals, we need k-1 comparison results: [x < bound_j] for j=1..k-1
	// The interval indicators are:
	//   interval_0 = [x < bound_1]
	//   interval_j = [x >= bound_j] AND [x < bound_{j+1}]  for j=1..k-2
	//   interval_{k-1} = [x >= bound_{k-1}]

	numCmp := sp.NumIntervals - 1

	// Compute comparison bits for each threshold
	cmpBits0 := make([][]byte, numCmp) // party 0's XOR shares
	cmpBits1 := make([][]byte, numCmp) // party 1's XOR shares

	for j := 0; j < numCmp; j++ {
		cmpBits0[j] = make([]byte, n)
		cmpBits1[j] = make([]byte, n)

		threshFP := r.FromDouble(sp.UpperBounds[j])

		for i := 0; i < n; i++ {
			b0, b1 := SecureComparePublicThreshold(x0[i], x1[i], threshFP, sp.NumBits)
			cmpBits0[j][i] = b0
			cmpBits1[j][i] = b1
		}
	}

	// Step 2: Compute interval indicators
	// indicator[0] = cmp[0] (x < bound_1)
	// indicator[j] = NOT cmp[j-1] AND cmp[j] for j=1..k-2
	// indicator[k-1] = NOT cmp[k-2]
	//
	// In XOR-sharing: NOT share = share XOR 1 (for party 1 only)
	// AND of two XOR-shared bits requires a Beaver triple mod 2.
	//
	// For simplicity in this simulation, reconstruct indicators in plaintext
	// (in production, use Beaver mod-2 multiplication).

	indicators := make([][]byte, sp.NumIntervals) // 0/1 per interval per observation
	for j := 0; j < sp.NumIntervals; j++ {
		indicators[j] = make([]byte, n)
	}

	for i := 0; i < n; i++ {
		// Reconstruct comparison bits
		cmps := make([]byte, numCmp)
		for j := 0; j < numCmp; j++ {
			cmps[j] = cmpBits0[j][i] ^ cmpBits1[j][i]
		}

		// Compute indicators
		indicators[0][i] = cmps[0]
		for j := 1; j < numCmp; j++ {
			indicators[j][i] = (1 - cmps[j-1]) & cmps[j]
		}
		indicators[sp.NumIntervals-1][i] = 1 - cmps[numCmp-1]
	}

	// Step 3: Compute active slope a_t and intercept b_t
	// a_t = sum_j indicator[j] * slope[j]
	// b_t = sum_j indicator[j] * intercept[j]
	//
	// In the secure version, this would use ScalarVectorProduct with
	// XOR-shared indicators converted to arithmetic shares.
	// For simulation: compute in plaintext.

	res0 = make([]uint64, n)
	res1 = make([]uint64, n)

	for i := 0; i < n; i++ {
		x := r.ToDouble(r.Add(x0[i], x1[i]))

		// Find active interval
		var slope, intercept float64
		for j := 0; j < sp.NumIntervals; j++ {
			if indicators[j][i] == 1 {
				slope = sp.Slopes[j]
				intercept = sp.YIntercepts[j]
				break
			}
		}

		// Compute f(x) = slope * x + intercept
		result := slope*x + intercept

		// Clamp to valid sigmoid range
		result = math.Max(0, math.Min(1, result))

		// Split into shares
		resultFP := r.FromDouble(result)
		res0[i], res1[i] = r.SplitShare(resultFP)
	}

	return
}
