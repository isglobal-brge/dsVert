// distributed_exp_taylor.go: Secure sigmoid for medium |x| via Kelkar exp + Taylor.
//
// For x in [1, L): sigmoid(x) = 1/(1 + exp(-x))
//   1. Compute [z] = exp(-[x]) via Kelkar (1 comm round)
//   2. Evaluate Taylor polynomial: 1/(1+z) = 1 - z + z^2 - z^3 + ... (Beaver powers)
//
// For x in [-L, -1): sigmoid(x) = 1 - 1/(1 + exp(x))
//   1. Compute [z] = exp([x]) via Kelkar
//   2. Taylor: 1/(1+z)
//   3. Result: 1 - Taylor output
//
// Reference: secure_sigmoid.cc lines 556-809, 962-1050

package main

// TaylorDegree is the degree of the Taylor polynomial for 1/(1+z).
// Matches C++ sigmoid_params_.taylor_polynomial_degree = 10.
const TaylorDegree = 10

// ExpTaylorSigmoidLocal computes sigmoid(x) for x in [1, L) on secret shares.
// LOCAL SIMULATION — uses KelkarExpLocal for exp, SecurePolyEval for Taylor.
//
// Returns shares of sigmoid(x) for both parties.
func ExpTaylorSigmoidLocal(rp RingParams, x0, x1 []uint64) (sig0, sig1 []uint64) {
	// Step 1: Negate x (we need exp(-x))
	negOne := rp.ModSub(0, 1)
	negX0 := rp.VecScale(negOne, x0)
	negX1 := rp.VecScale(negOne, x1)

	// Step 2: [z] = exp(-[x]) via Kelkar (1 communication round)
	z0, z1 := KelkarExpLocalV2(rp, negX0, negX1)

	// Step 3: Taylor polynomial 1/(1+z) = sum_{k=0}^{degree} (-1)^k * z^k
	// Coefficients: [1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1] for degree 10
	taylorCoeffs := make([]float64, TaylorDegree+1)
	for k := 0; k <= TaylorDegree; k++ {
		if k%2 == 0 {
			taylorCoeffs[k] = 1.0
		} else {
			taylorCoeffs[k] = -1.0
		}
	}

	// Step 4: Evaluate Taylor on [z] shares via Beaver power chain
	sig0, sig1 = SecurePolyEval(rp, taylorCoeffs, z0, z1)

	// Clamp: in practice z < 0.37 for x >= 1, so Taylor converges well
	// No explicit clamping needed — the polynomial handles it

	return
}

// ExpTaylorSigmoidNegLocal computes sigmoid(x) for x in [-L, -1) on shares.
// sigmoid(x) = 1 - sigmoid(-x) = 1 - 1/(1+exp(x))
//
// LOCAL SIMULATION.
func ExpTaylorSigmoidNegLocal(rp RingParams, x0, x1 []uint64) (sig0, sig1 []uint64) {
	n := len(x0)

	// Step 1: exp(x) for negative x → exp is small for x < -1
	z0, z1 := KelkarExpLocalV2(rp, x0, x1)

	// Step 2: Taylor 1/(1+z)
	taylorCoeffs := make([]float64, TaylorDegree+1)
	for k := 0; k <= TaylorDegree; k++ {
		if k%2 == 0 {
			taylorCoeffs[k] = 1.0
		} else {
			taylorCoeffs[k] = -1.0
		}
	}
	taylor0, taylor1 := SecurePolyEval(rp, taylorCoeffs, z0, z1)

	// Step 3: sigmoid(x) = 1 - taylor
	oneFP := rp.FromDouble(1.0)
	sig0 = make([]uint64, n)
	sig1 = make([]uint64, n)
	for i := 0; i < n; i++ {
		sig0[i] = rp.ModSub(oneFP, taylor0[i]) // party 0: 1 - share
		sig1[i] = rp.ModSub(0, taylor1[i])      // party 1: 0 - share
	}

	return
}
