// piecewise_sigmoid.go: Piecewise sigmoid evaluation — 1:1 with Google C++.
//
// This evaluates sigma(x) = 1/(1+e^{-x}) using the same piecewise approximation
// as the Google fss_machine_learning C++ code:
//   - |x| < 1.0:      10-interval piecewise linear spline (~1e-4 accuracy)
//   - 1.0 ≤ |x| < L:  exp(-|x|) then Taylor polynomial 1/(1+z)
//   - |x| ≥ L:         saturate to 0 or 1
//   where L = fracBits * ln(2) ≈ 13.86 for fracBits=20.
//
// For the LOCAL simulation (step 1), this evaluates on reconstructed x.
// The distributed version (step 2) will use DCF comparisons + Beaver.

package main

import (
	"math"
)

// PiecewiseSigmoidParams holds parameters matching the C++ SecureSigmoidParameters.
type PiecewiseSigmoidParams struct {
	SplineSlopes     []float64
	SplineIntercepts []float64
	NumIntervals     int
	TaylorDegree     int
	FracBits         int
}

// DefaultPiecewiseSigmoidParams returns C++ defaults.
func DefaultPiecewiseSigmoidParams() PiecewiseSigmoidParams {
	return PiecewiseSigmoidParams{
		SplineSlopes: []float64{
			0.24979187478940013, 0.24854809833537939, 0.24608519499181072,
			0.24245143300792976, 0.23771671089402596, 0.23196975023940808,
			0.2253146594237077, 0.2178670895944635, 0.20975021497391394,
			0.2010907600500101,
		},
		SplineIntercepts: []float64{
			0.5, 0.5001243776454021, 0.5006169583141158,
			0.5017070869092801, 0.5036009757548416, 0.5064744560821506,
			0.5104675105715708, 0.5156808094520418, 0.5221743091484814,
			0.5299678185799949,
		},
		NumIntervals: 10,
		TaylorDegree: 10,
		FracBits:     20,
	}
}

// EvalPiecewiseSigmoid evaluates the piecewise sigmoid on a single float64 value.
// 1:1 with the C++ evalSpline/evalExpTaylor logic.
func EvalPiecewiseSigmoid(x float64, sp PiecewiseSigmoidParams) float64 {
	lfLn2 := float64(sp.FracBits) * math.Ln2

	if x >= 0 && x < 1.0 {
		return evalPWSpline(x, sp)
	} else if x >= 1.0 && x < lfLn2 {
		return evalPWExpTaylor(x, sp)
	} else if x >= lfLn2 {
		return 1.0
	} else if x < -lfLn2 {
		return 0.0
	} else if x >= -lfLn2 && x < -1.0 {
		return 1.0 - evalPWExpTaylor(-x, sp)
	} else { // -1.0 <= x < 0
		return 1.0 - evalPWSpline(-x, sp)
	}
}

// evalPWSpline evaluates the piecewise linear spline on x in [0, 1).
func evalPWSpline(x float64, sp PiecewiseSigmoidParams) float64 {
	for j := 0; j < sp.NumIntervals; j++ {
		lower := float64(j) * (1.0 / float64(sp.NumIntervals))
		upper := float64(j+1) * (1.0 / float64(sp.NumIntervals))
		if x >= lower && x < upper {
			return sp.SplineSlopes[j]*x + sp.SplineIntercepts[j]
		}
	}
	// Edge: x == 1.0
	j := sp.NumIntervals - 1
	return sp.SplineSlopes[j]*x + sp.SplineIntercepts[j]
}

// evalPWExpTaylor evaluates 1/(1+e^{-x}) for x >= 1 using exp(-x) + Taylor.
// Taylor: 1/(1+z) ≈ 1 - z + z^2 - z^3 + ... for |z| < 1, where z = e^{-x}.
func evalPWExpTaylor(x float64, sp PiecewiseSigmoidParams) float64 {
	z := math.Exp(-x)
	result := 0.0
	zPow := 1.0
	for k := 0; k <= sp.TaylorDegree; k++ {
		if k%2 == 0 {
			result += zPow
		} else {
			result -= zPow
		}
		zPow *= z
	}
	return math.Max(0, math.Min(1, result))
}

// SecurePiecewiseSigmoidLocal evaluates the piecewise sigmoid on secret shares.
// LOCAL SIMULATION: reconstructs x, evaluates, re-shares.
//
// This is Step 1 — validates accuracy. Step 2 replaces this with
// DCF + Beaver distributed protocol (same result, no reconstruction).
func SecurePiecewiseSigmoidLocal(rp RingParams, x0, x1 []uint64) (sig0, sig1 []uint64) {
	n := len(x0)
	sp := DefaultPiecewiseSigmoidParams()

	sig0 = make([]uint64, n)
	sig1 = make([]uint64, n)

	for i := 0; i < n; i++ {
		// Reconstruct x (ONLY in local simulation — distributed version uses DCF)
		xVal := rp.ToDouble(rp.ModAdd(x0[i], x1[i]))

		// Evaluate piecewise sigmoid (1:1 with Google C++)
		sigVal := EvalPiecewiseSigmoid(xVal, sp)

		// Clamp
		sigVal = math.Max(1e-10, math.Min(1-1e-10, sigVal))

		// Re-share
		sigFP := rp.FromDouble(sigVal)
		sig0[i], sig1[i] = rp.SplitShare(sigFP)
	}

	return
}

// SecurePiecewiseExpLocal evaluates exp() on secret shares (for Poisson).
// LOCAL SIMULATION: reconstructs x, evaluates, re-shares.
func SecurePiecewiseExpLocal(rp RingParams, x0, x1 []uint64) (exp0, exp1 []uint64) {
	n := len(x0)

	exp0 = make([]uint64, n)
	exp1 = make([]uint64, n)

	for i := 0; i < n; i++ {
		xVal := rp.ToDouble(rp.ModAdd(x0[i], x1[i]))

		// Clamp for safety
		if xVal > 20 {
			xVal = 20
		}
		if xVal < -20 {
			xVal = -20
		}

		expVal := math.Exp(xVal)
		expVal = math.Max(1e-10, expVal)

		expFP := rp.FromDouble(expVal)
		exp0[i], exp1[i] = rp.SplitShare(expFP)
	}

	return
}
