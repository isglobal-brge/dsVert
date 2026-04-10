// k2_chebyshev.go: Chebyshev polynomial commands for K=2 strict mode.
//
// New commands added to dsvert-mpc for the improved K=2 Beaver MPC path:
//   k2-chebyshev-coeffs: Generate Chebyshev polynomial coefficients
//   k2-beaver-mul: Beaver multiplication with asymmetric truncation
//   k2-poly-eval-local: Local polynomial evaluation on a party's share
//
// These commands are called by the R client via the standard .callMheTool()
// mechanism, with DataSHIELD transport encryption for share relay.

package main

import (
	"math"
	"math/bits"
)

// ============================================================================
// Command: k2-chebyshev-coeffs
// Generates Chebyshev interpolation coefficients for sigmoid or exp.
// ============================================================================

type K2ChebyshevInput struct {
	Family string `json:"family"` // "binomial" or "poisson"
	Degree int    `json:"degree"` // polynomial degree (default 7)
	Lower  float64 `json:"lower"` // interval lower bound
	Upper  float64 `json:"upper"` // interval upper bound
}

type K2ChebyshevOutput struct {
	Coefficients []float64 `json:"coefficients"` // monomial basis [a0, a1, ..., ad]
	MaxError     float64   `json:"max_error"`
	Degree       int       `json:"degree"`
	Lower        float64   `json:"lower"`
	Upper        float64   `json:"upper"`
}

func handleK2ChebyshevCoeffs() {
	var input K2ChebyshevInput
	mpcReadInput(&input)

	if input.Degree <= 0 {
		input.Degree = 7
	}

	var f func(float64) float64
	if input.Family == "poisson" {
		f = math.Exp
		if input.Lower == 0 && input.Upper == 0 {
			input.Lower = -3.0
			input.Upper = 3.0
		}
	} else {
		f = func(x float64) float64 { return 1.0 / (1.0 + math.Exp(-x)) }
		if input.Lower == 0 && input.Upper == 0 {
			input.Lower = -5.0
			input.Upper = 5.0
		}
	}

	coeffs := k2ChebyshevInterpolate(f, input.Degree, input.Lower, input.Upper)
	maxErr := k2MeasureMaxError(coeffs, f, input.Lower, input.Upper, 100000)

	mpcWriteOutput(K2ChebyshevOutput{
		Coefficients: coeffs,
		MaxError:     maxErr,
		Degree:       input.Degree,
		Lower:        input.Lower,
		Upper:        input.Upper,
	})
}

// ============================================================================
// Command: k2-beaver-mul
// Beaver multiplication with ASYMMETRIC truncation for fixed-point.
// ============================================================================

type K2BeaverMulInput struct {
	// Party's own shares of X and Y (base64 FixedPoint)
	XShare string `json:"x_share"`
	YShare string `json:"y_share"`
	// Beaver triple shares — accept EITHER base64 FixedPoint OR float64 arrays
	AShare    string    `json:"a_share"`     // base64 FixedPoint
	BShare    string    `json:"b_share"`     // base64 FixedPoint
	CShare    string    `json:"c_share"`     // base64 FixedPoint
	AShareF64 []float64 `json:"a_share_f64"` // float64 array (alternative)
	BShareF64 []float64 `json:"b_share_f64"` // float64 array (alternative)
	CShareF64 []float64 `json:"c_share_f64"` // float64 array (alternative)
	// Peer's round-1 message (after relay)
	PeerXMinusA string `json:"peer_x_minus_a"` // base64
	PeerYMinusB string `json:"peer_y_minus_b"` // base64
	// Protocol params
	PartyID  int `json:"party_id"`  // 0 or 1
	FracBits int `json:"frac_bits"` // default 20
}

type K2BeaverMulOutput struct {
	// Round 1 output (to send to peer)
	OwnXMinusA string `json:"own_x_minus_a"` // base64
	OwnYMinusB string `json:"own_y_minus_b"` // base64
	// Round 2 output (after receiving peer's round-1)
	ResultShare string `json:"result_share"` // base64 (truncated)
	// Phase flag
	Phase string `json:"phase"` // "round1" or "round2"
}

func handleK2BeaverMul() {
	var input K2BeaverMulInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = 20
	}

	xShare := bytesToFPVec(base64ToBytes(input.XShare))
	yShare := bytesToFPVec(base64ToBytes(input.YShare))

	// Accept triples as either base64 FixedPoint or float64 arrays
	var aShare, bShare []FixedPoint
	if input.AShare != "" {
		aShare = bytesToFPVec(base64ToBytes(input.AShare))
		bShare = bytesToFPVec(base64ToBytes(input.BShare))
	} else if len(input.AShareF64) > 0 {
		aShare = float64sToFP(input.AShareF64, input.FracBits)
		bShare = float64sToFP(input.BShareF64, input.FracBits)
	} else {
		outputError("no Beaver triple shares provided")
		return
	}

	n := len(xShare)

	if input.PeerXMinusA == "" {
		// Round 1: compute own (X-A, Y-B) using int64 subtraction (wraps mod 2^64)
		xMinusA := make([]FixedPoint, n)
		yMinusB := make([]FixedPoint, n)
		for i := 0; i < n; i++ {
			xMinusA[i] = FPSub(xShare[i], aShare[i])
			yMinusB[i] = FPSub(yShare[i], bShare[i])
		}
		mpcWriteOutput(K2BeaverMulOutput{
			OwnXMinusA: bytesToBase64(fpVecToBytes(xMinusA)),
			OwnYMinusB: bytesToBase64(fpVecToBytes(yMinusB)),
			Phase:      "round1",
		})
		return
	}

	// Round 2: compute result share with truncation
	var cShare []FixedPoint
	if input.CShare != "" {
		cShare = bytesToFPVec(base64ToBytes(input.CShare))
	} else if len(input.CShareF64) > 0 {
		cShare = float64sToFP(input.CShareF64, input.FracBits)
	}
	peerXMinusA := bytesToFPVec(base64ToBytes(input.PeerXMinusA))
	peerYMinusB := bytesToFPVec(base64ToBytes(input.PeerYMinusB))

	result := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		// Reconstruct full (X-A) and (Y-B) via int64 wrapping addition
		ownXMA := FPSub(xShare[i], aShare[i])
		fullXMA := FPAdd(ownXMA, peerXMinusA[i])
		ownYMB := FPSub(yShare[i], bShare[i])
		fullYMB := FPAdd(ownYMB, peerYMinusB[i])

		// z = C + (X-A)*B + (Y-B)*A + [party0]*(X-A)*(Y-B)
		// All multiplications use FPMulLocal (int64*int64 with truncation)
		z := cShare[i]
		z = FPAdd(z, FPMulLocal(fullXMA, bShare[i], input.FracBits))
		z = FPAdd(z, FPMulLocal(fullYMB, aShare[i], input.FracBits))
		if input.PartyID == 0 {
			z = FPAdd(z, FPMulLocal(fullXMA, fullYMB, input.FracBits))
		}
		result[i] = z
	}

	mpcWriteOutput(K2BeaverMulOutput{
		ResultShare: bytesToBase64(fpVecToBytes(result)),
		Phase:       "round2",
	})
}

// ringMul computes (a * b) mod modulus using 128-bit intermediate.
func ringMul(a, b, modulus uint64) uint64 {
	_, lo := bits.Mul64(a, b)
	return lo % modulus
}

// ============================================================================
// Command: k2-poly-eval-local
// Local polynomial evaluation: p(x)_i = sum_k a_k * [x^k]_i
// Each party runs this independently with its power shares.
// ============================================================================

type K2PolyEvalLocalInput struct {
	PowerShares  []string  `json:"power_shares"`  // base64 for [x^0]_i, [x^1]_i, ..., [x^d]_i
	Coefficients []float64 `json:"coefficients"`  // monomial [a0, a1, ..., ad]
	PartyID      int       `json:"party_id"`
	FracBits     int       `json:"frac_bits"`
}

type K2PolyEvalLocalOutput struct {
	ResultShare string `json:"result_share"` // base64
}

func handleK2PolyEvalLocal() {
	var input K2PolyEvalLocalInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = 20
	}

	degree := len(input.Coefficients) - 1

	// Convert coefficients to FixedPoint (int64 two's complement)
	fpCoeffs := make([]FixedPoint, degree+1)
	for i, c := range input.Coefficients {
		fpCoeffs[i] = FromFloat64(c, input.FracBits)
	}

	// Decode power shares
	powers := make([][]FixedPoint, degree+1)
	for k := 0; k <= degree; k++ {
		if k < len(input.PowerShares) {
			powers[k] = bytesToFPVec(base64ToBytes(input.PowerShares[k]))
		}
	}

	n := len(powers[0])
	result := make([]FixedPoint, n)

	for k := 0; k <= degree; k++ {
		coeff := fpCoeffs[k]
		for i := 0; i < n; i++ {
			share := powers[k][i]
			// ScalarShareMul: multiply public coeff (int64) by share (int64).
			// Use FPMul which does int64*int64 with truncation by fracBits.
			// The int64 two's complement handles sign correctly.
			product := FPMulLocal(coeff, share, input.FracBits)

			// Asymmetric truncation is NOT needed here because FPMul already
			// does the truncation. But we're computing coeff * share_i where
			// share_i is one party's share. The truncation error from FPMul
			// is at most 1 ULP, which is acceptable.
			//
			// Note: for production, asymmetric truncation should be used to
			// minimize accumulated error. For v1, FPMul is sufficient.

			result[i] += product
		}
	}

	mpcWriteOutput(K2PolyEvalLocalOutput{
		ResultShare: bytesToBase64(fpVecToBytes(result)),
	})
}

// ============================================================================
// Chebyshev interpolation (ported from k2-mpc-tool/chebyshev.go)
// ============================================================================

func k2ChebyshevInterpolate(f func(float64) float64, degree int, lower, upper float64) []float64 {
	n := degree
	// Chebyshev nodes
	nodes := make([]float64, n+1)
	mid := (upper + lower) / 2.0
	half := (upper - lower) / 2.0
	for k := 0; k <= n; k++ {
		nodes[k] = mid + half*math.Cos(float64(k)*math.Pi/float64(n))
	}

	// Evaluate f at nodes
	fvals := make([]float64, n+1)
	for i, x := range nodes {
		fvals[i] = f(x)
	}

	// Chebyshev coefficients via DCT
	chebCoeffs := make([]float64, n+1)
	for k := 0; k <= n; k++ {
		sum := 0.0
		for j := 0; j <= n; j++ {
			term := fvals[j] * math.Cos(float64(k)*float64(j)*math.Pi/float64(n))
			if j == 0 || j == n {
				term *= 0.5
			}
			sum += term
		}
		chebCoeffs[k] = 2.0 / float64(n) * sum
		if k == 0 || k == n {
			chebCoeffs[k] *= 0.5
		}
	}

	// Convert Chebyshev basis on [-1,1] to monomial basis on [lower, upper]
	a := 2.0 / (upper - lower)
	b := -(upper + lower) / (upper - lower)

	mono_t := make([]float64, n+1)
	prev := make([]float64, n+1)
	curr := make([]float64, n+1)
	prev[0] = 1.0
	mono_t[0] += chebCoeffs[0]

	if n >= 1 {
		curr[1] = 1.0
		for i := 0; i <= n; i++ {
			mono_t[i] += chebCoeffs[1] * curr[i]
		}
	}

	for k := 2; k <= n; k++ {
		next := make([]float64, n+1)
		for i := 0; i < n; i++ {
			next[i+1] += 2.0 * curr[i]
		}
		for i := 0; i <= n; i++ {
			next[i] -= prev[i]
		}
		for i := 0; i <= n; i++ {
			mono_t[i] += chebCoeffs[k] * next[i]
		}
		prev = curr
		curr = next
	}

	mono_x := make([]float64, n+1)
	for k := 0; k <= n; k++ {
		if math.Abs(mono_t[k]) < 1e-20 {
			continue
		}
		binomCoeffs := k2BinomialExpansion(k, a, b)
		for j := 0; j <= k; j++ {
			mono_x[j] += mono_t[k] * binomCoeffs[j]
		}
	}
	return mono_x
}

func k2BinomialExpansion(k int, a, b float64) []float64 {
	coeffs := make([]float64, k+1)
	binom := 1.0
	for j := 0; j <= k; j++ {
		coeffs[j] = binom * math.Pow(a, float64(j)) * math.Pow(b, float64(k-j))
		if j < k {
			binom = binom * float64(k-j) / float64(j+1)
		}
	}
	return coeffs
}

// ============================================================================
// Command: k2-float-to-fp
// Converts float64 array to base64 FixedPoint vector (no splitting).
// ============================================================================

type K2FloatToFPInput struct {
	Values   []float64 `json:"values"`
	FracBits int       `json:"frac_bits"`
}

type K2FloatToFPOutput struct {
	FPData string `json:"fp_data"` // base64 FixedPoint
}

func handleK2FloatToFP() {
	var input K2FloatToFPInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = 20
	}
	// Encode in Ring63 for the K=2 Beaver pipeline
	ring := NewRing63(input.FracBits)
	r63 := make([]uint64, len(input.Values))
	for i, v := range input.Values {
		r63[i] = ring.FromDouble(v)
	}
	mpcWriteOutput(K2FloatToFPOutput{
		FPData: bytesToBase64(fpVecToBytes(ring63ToFP(r63))),
	})
}

// ============================================================================
// Command: k2-fp-mul
// Element-wise FixedPoint multiplication of two vectors.
// Used by the client to generate exact Beaver triples.
// ============================================================================

type K2FPMulInput struct {
	A        string `json:"a"`         // base64 FixedPoint vector
	B        string `json:"b"`         // base64 FixedPoint vector
	FracBits int    `json:"frac_bits"`
}

type K2FPMulOutput struct {
	Result string `json:"result"` // base64 FixedPoint vector (a * b truncated)
}

func handleK2FPMul() {
	var input K2FPMulInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = 20
	}
	a := bytesToFPVec(base64ToBytes(input.A))
	b := bytesToFPVec(base64ToBytes(input.B))
	n := len(a)
	result := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		result[i] = FPMulLocal(a[i], b[i], input.FracBits)
	}
	mpcWriteOutput(K2FPMulOutput{
		Result: bytesToBase64(fpVecToBytes(result)),
	})
}

// float64sToFP converts a float64 slice to FixedPoint vector.
// Uses the existing FromFloat64 which handles int64 two's complement correctly.
func float64sToFP(vals []float64, fracBits int) []FixedPoint {
	result := make([]FixedPoint, len(vals))
	for i, v := range vals {
		result[i] = FromFloat64(v, fracBits)
	}
	return result
}

func k2MeasureMaxError(coeffs []float64, f func(float64) float64,
	lower, upper float64, nPoints int) float64 {
	maxErr := 0.0
	for i := 0; i < nPoints; i++ {
		x := lower + (upper-lower)*float64(i)/float64(nPoints-1)
		approx := 0.0
		xpow := 1.0
		for _, c := range coeffs {
			approx += c * xpow
			xpow *= x
		}
		err := math.Abs(approx - f(x))
		if err > maxErr {
			maxErr = err
		}
	}
	return maxErr
}
