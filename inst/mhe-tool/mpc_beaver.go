package main

// Beaver-triple–based secure multiplication for 2-party additive secret sharing.
//
// Protocol (per multiplication of shared vectors [a] and [b]):
//   Pre: Client generates triple (u, v, w=u*v) in float64, splits into shares,
//        distributes via transport encryption.  Client never sees d,e.
//   Open:  Party i computes d_i = a_i − u_i,  e_i = b_i − v_i.
//          Exchange d,e (transport-encrypted) so both learn d, e.
//   Close: Party i computes c_i = w_i + e·u_i + d·v_i + [i==0]·d·e.
//          Then c_0 + c_1 = a·b (in fixed-point, with truncation).

import (
	"fmt"
	"math"
	"os"
)

// ============================================================================
// Command: mpc-beaver-open
// ============================================================================

type BeaverOpenInput struct {
	AShares  string    `json:"a_shares"`  // base64 FixedPoint vector (for polynomial rounds)
	BShares  string    `json:"b_shares"`  // base64 FixedPoint vector (for polynomial rounds)
	AValues  []float64 `json:"a_values"`  // float64 alternative (for cross-gradient)
	BValues  []float64 `json:"b_values"`  // float64 alternative (for cross-gradient)
	UValues  []float64 `json:"u_values"`  // float64 triple shares
	VValues  []float64 `json:"v_values"`  // float64 triple shares
	PeerPK   string    `json:"peer_pk"`   // peer transport PK (base64)
	FracBits int       `json:"frac_bits"`
}

type BeaverOpenOutput struct {
	OwnDE     string `json:"own_de"`      // base64, (d_i, e_i) concatenated
	PeerDEEnc string `json:"peer_de_enc"` // transport-encrypted for peer
}

func handleMpcBeaverOpen() {
	var input BeaverOpenInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = 20
	}

	var a, b []FixedPoint
	if len(input.AValues) > 0 {
		a = FloatVecToFP(input.AValues, input.FracBits)
	} else {
		a = bytesToFPVec(base64ToBytes(input.AShares))
	}
	if len(input.BValues) > 0 {
		b = FloatVecToFP(input.BValues, input.FracBits)
	} else {
		b = bytesToFPVec(base64ToBytes(input.BShares))
	}
	u := FloatVecToFP(input.UValues, input.FracBits)
	v := FloatVecToFP(input.VValues, input.FracBits)
	n := len(a)

	d := make([]FixedPoint, n)
	e := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		d[i] = FPSub(a[i], u[i])
		e[i] = FPSub(b[i], v[i])
	}

	de := append(fpVecToBytes(d), fpVecToBytes(e)...)
	ownDE := bytesToBase64(de)

	peerPK := base64ToBytes(input.PeerPK)
	sealed, err := transportEncryptRaw(de, peerPK)
	if err != nil {
		outputError(fmt.Sprintf("transport encrypt failed: %v", err))
		os.Exit(1)
	}

	mpcWriteOutput(BeaverOpenOutput{
		OwnDE:     ownDE,
		PeerDEEnc: bytesToBase64(sealed),
	})
}

// ============================================================================
// Command: mpc-beaver-close
// ============================================================================

type BeaverCloseInput struct {
	OwnDE     string    `json:"own_de"`     // base64, own (d_i, e_i)
	PeerDE    string    `json:"peer_de"`    // base64, peer's (d_j, e_j) — decrypted by R
	WValues   []float64 `json:"w_values"`   // float64 triple w shares
	UValues   []float64 `json:"u_values"`   // float64 triple u shares
	VValues   []float64 `json:"v_values"`   // float64 triple v shares
	AValues   []float64 `json:"a_values"`   // float64 a values (for cross-gradient close)
	BValues   []float64 `json:"b_values"`   // float64 b values (for cross-gradient close)
	PartyID   int       `json:"party_id"`   // 0 or 1
	FracBits  int       `json:"frac_bits"`
}

type BeaverCloseOutput struct {
	ResultShares string `json:"result_shares"` // base64, party's share of a*b
}

func handleMpcBeaverClose() {
	var input BeaverCloseInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = 20
	}

	ownDEBytes := base64ToBytes(input.OwnDE)
	n := len(ownDEBytes) / 16
	ownD := bytesToFPVec(ownDEBytes[:n*8])
	ownE := bytesToFPVec(ownDEBytes[n*8:])

	peerDEBytes := base64ToBytes(input.PeerDE)
	nPeer := len(peerDEBytes) / 16
	if nPeer != n {
		outputError(fmt.Sprintf("DE size mismatch: own=%d peer=%d", n, nPeer))
		os.Exit(1)
	}
	peerD := bytesToFPVec(peerDEBytes[:nPeer*8])
	peerE := bytesToFPVec(peerDEBytes[nPeer*8:])

	dFull := make([]FixedPoint, n)
	eFull := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		dFull[i] = FPAdd(ownD[i], peerD[i])
		eFull[i] = FPAdd(ownE[i], peerE[i])
	}

	w := FloatVecToFP(input.WValues, input.FracBits)
	u := FloatVecToFP(input.UValues, input.FracBits)
	v := FloatVecToFP(input.VValues, input.FracBits)

	result := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		ci := w[i]
		ci = FPAdd(ci, FPMulLocal(eFull[i], u[i], input.FracBits))
		ci = FPAdd(ci, FPMulLocal(dFull[i], v[i], input.FracBits))
		if input.PartyID == 0 {
			ci = FPAdd(ci, FPMulLocal(dFull[i], eFull[i], input.FracBits))
		}
		result[i] = ci
	}

	mpcWriteOutput(BeaverCloseOutput{
		ResultShares: bytesToBase64(fpVecToBytes(result)),
	})
}

// ============================================================================
// Command: mpc-secure-poly-eval
// Local step: given shares of x, x^2, ..., x^d, compute share of p(x).
// ============================================================================

type SecurePolyEvalInput struct {
	PowerShares  []string  `json:"power_shares"`  // base64 shares of [x], [x^2], ...
	Coefficients []float64 `json:"coefficients"`  // c0, c1, ..., cd
	PartyID      int       `json:"party_id"`
	FracBits     int       `json:"frac_bits"`
}

type SecurePolyEvalOutput struct {
	ResultShare string `json:"result_share"` // base64, share of p(x)
}

func handleMpcSecurePolyEval() {
	var input SecurePolyEvalInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = 20
	}

	ring := NewRing63(input.FracBits)

	degree := len(input.Coefficients) - 1
	if degree < 1 || len(input.PowerShares) < degree {
		outputError("need at least degree power shares")
		os.Exit(1)
	}

	// Decode power shares (FP) and convert to Ring63
	powersR63 := make([][]uint64, degree)
	for k := 0; k < degree; k++ {
		powersR63[k] = fpToRing63(bytesToFPVec(base64ToBytes(input.PowerShares[k])))
	}
	n := len(powersR63[0])

	// Initialize result in Ring63
	resultR63 := make([]uint64, n)

	// Party 0 adds the constant term c0
	if input.PartyID == 0 {
		c0R63 := ring.FromDouble(input.Coefficients[0])
		for i := 0; i < n; i++ {
			resultR63[i] = c0R63
		}
	}

	// Multiply public coefficients by secret-shared power values using
	// validated Ring63 ScalarVectorProduct from k2_beaver_google.go.
	// This correctly handles asymmetric P0/P1 truncation with explicit modulus.
	for k := 1; k <= degree; k++ {
		var termR63 []uint64
		if input.PartyID == 0 {
			termR63 = ScalarVectorProductPartyZero(input.Coefficients[k], powersR63[k-1], ring)
		} else {
			termR63 = ScalarVectorProductPartyOne(input.Coefficients[k], powersR63[k-1], ring)
		}
		for i := 0; i < n; i++ {
			resultR63[i] = ring.Add(resultR63[i], termR63[i])
		}
	}

	mpcWriteOutput(SecurePolyEvalOutput{
		ResultShare: bytesToBase64(fpVecToBytes(ring63ToFP(resultR63))),
	})
}

// ============================================================================
// Command: mpc-get-poly-coeffs
// ============================================================================

type GetPolyCoeffsInput struct {
	Family string `json:"family"`
	Degree int    `json:"degree"`
}

type GetPolyCoeffsOutput struct {
	Coefficients []float64 `json:"coefficients"`
	MaxError     float64   `json:"max_error"`
}

func handleMpcGetPolyCoeffs() {
	var input GetPolyCoeffsInput
	mpcReadInput(&input)
	if input.Degree <= 0 {
		input.Degree = 7
	}

	var coeffs []float64
	var maxErr float64

	switch input.Family {
	case "binomial":
		coeffs = SigmoidGlobalPoly(input.Degree)
		maxErr = measurePolyError(sigmoid, coeffs, -8.0, 8.0, 0.0, 1.0, 100000)
	case "poisson":
		coeffs = ExpGlobalPoly(input.Degree)
		maxErr = measurePolyError(math.Exp, coeffs, -3.0, 3.0,
			math.Exp(-3.0), math.Exp(3.0), 100000)
	default:
		outputError(fmt.Sprintf("unsupported family: %s", input.Family))
		os.Exit(1)
	}

	mpcWriteOutput(GetPolyCoeffsOutput{
		Coefficients: coeffs,
		MaxError:     maxErr,
	})
}

// ============================================================================
// Command: mpc-residual-share
// Computes residual share from mu share: label → (y - mu_share), nonlabel → (-mu_share).
// Stores the residual share and returns it as base64.
// ============================================================================

type ResidualShareInput struct {
	MuShare  string    `json:"mu_share"` // base64 FixedPoint
	Y        []float64 `json:"y"`        // response (label only, empty for nonlabel)
	Role     string    `json:"role"`     // "label" or "nonlabel"
	FracBits int       `json:"frac_bits"`
}

type ResidualShareOutput struct {
	ResidualShare string `json:"residual_share"` // base64 FixedPoint
}

func handleMpcResidualShare() {
	var input ResidualShareInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = 20
	}

	muShare := bytesToFPVec(base64ToBytes(input.MuShare))
	n := len(muShare)

	residualShare := make([]FixedPoint, n)
	if input.Role == "label" && len(input.Y) > 0 {
		yFP := FloatVecToFP(input.Y, input.FracBits)
		for i := 0; i < n; i++ {
			residualShare[i] = FPSub(yFP[i], muShare[i])
		}
	} else {
		for i := 0; i < n; i++ {
			residualShare[i] = FPNeg(muShare[i])
		}
	}

	mpcWriteOutput(ResidualShareOutput{
		ResidualShare: bytesToBase64(fpVecToBytes(residualShare)),
	})
}

// ============================================================================
// Command: mpc-secure-cross-gradient
// Securely computes X_k^T * peer_residual_share using Beaver triples,
// where X_k is private to THIS party and peer_residual_share is private to
// the OTHER party. Neither party sees the other's input.
//
// Protocol (for one column j of X_k):
//   This party has: x_j[i] for all i (plaintext).
//   Peer has: r[i] for all i (residual share, plaintext to peer).
//   Need: sum_i x_j[i] * r[i] = gradient element g_k[j].
//
//   Step 1 (share inputs): This party creates shares of x_j:
//     x_j_own[i] = random, x_j_peer[i] = x_j[i] - x_j_own[i]
//     Send x_j_peer to peer (transport-encrypted).
//     Peer creates shares of r:
//     r_own[i] = random, r_peer[i] = r[i] - r_own[i]
//     Send r_peer to this party.
//
//   Step 2 (Beaver multiply): Use Beaver triples on the shares.
//     a[i] = x_j_own[i] + x_j_peer[i] = x_j[i] (shared)
//     b[i] = r_own[i] + r_peer[i] = r[i] (shared)
//     Beaver protocol gives shares of a[i]*b[i] = x_j[i]*r[i]
//
//   Step 3 (sum): Sum shares over i → shares of gradient element g_k[j].
//
// This command handles the "open" phase (compute d,e from shares).
// A separate "close" phase completes the multiplication.
//
// For efficiency, ALL n×p_k multiplications are batched into one command.
// ============================================================================

// mpc-share-private-input: Creates additive shares of private inputs (X columns
// or residual) and transport-encrypts the peer's shares.
// Accepts EITHER float64 values OR base64 FixedPoint (for sharing FP residuals).
type SharePrivateInput struct {
	Values    []float64 `json:"values"`     // float64 values (used if fp_values is empty)
	FPValues  string    `json:"fp_values"`  // base64 FixedPoint (alternative to values)
	PeerPK    string    `json:"peer_pk"`    // peer transport PK
	FracBits  int       `json:"frac_bits"`
}

type SharePrivateOutput struct {
	OwnShare    string `json:"own_share"`     // base64 FixedPoint, this party's share
	PeerShareEnc string `json:"peer_share_enc"` // transport-encrypted peer's share
}

func handleMpcSharePrivateInput() {
	var input SharePrivateInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = 20
	}

	var valsFP []FixedPoint
	if input.FPValues != "" {
		// Use pre-encoded FixedPoint values
		valsFP = bytesToFPVec(base64ToBytes(input.FPValues))
	} else {
		valsFP = FloatVecToFP(input.Values, input.FracBits)
	}
	ownShare, peerShare := SplitVec(valsFP)

	ownB64 := bytesToBase64(fpVecToBytes(ownShare))
	peerBytes := fpVecToBytes(peerShare)
	peerPK := base64ToBytes(input.PeerPK)
	sealed, err := transportEncryptRaw(peerBytes, peerPK)
	if err != nil {
		outputError(fmt.Sprintf("transport encrypt failed: %v", err))
		os.Exit(1)
	}

	mpcWriteOutput(SharePrivateOutput{
		OwnShare:     ownB64,
		PeerShareEnc: bytesToBase64(sealed),
	})
}

// mpc-local-gradient-share: Computes this party's share of its own gradient.
// g_k_own_share = X_k^T * own_residual_share (plaintext × own share, local).
type LocalGradientShareInput struct {
	X             [][]float64 `json:"x"`              // feature matrix n x p_k
	ResidualShare string      `json:"residual_share"`  // base64 FixedPoint, this party's residual share
	FracBits      int         `json:"frac_bits"`
}

type LocalGradientShareOutput struct {
	GradientShare string `json:"gradient_share"` // base64 FixedPoint, p_k elements
}

func handleMpcLocalGradientShare() {
	var input LocalGradientShareInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = 20
	}

	n := len(input.X)
	residualShare := bytesToFPVec(base64ToBytes(input.ResidualShare))

	XFP := make([][]FixedPoint, n)
	for i := 0; i < n; i++ {
		XFP[i] = FloatVecToFP(input.X[i], input.FracBits)
	}

	// g_k_own = X_k^T * own_residual_share (plaintext × own share, local)
	gradShare := PlaintextMatTVecMul(XFP, residualShare, input.FracBits)

	mpcWriteOutput(LocalGradientShareOutput{
		GradientShare: bytesToBase64(fpVecToBytes(gradShare)),
	})
}

// ============================================================================
// Command: mpc-sum-beaver-products
// Sums Beaver product shares over observations to get p_k gradient elements.
// Input: product shares of length n*p_k (flattened column-major:
//   [x_col0_obs0, x_col0_obs1, ..., x_col0_obsN, x_col1_obs0, ...])
// Output: gradient shares of length p_k (sum over n obs per column)
// ============================================================================

type SumBeaverProductsInput struct {
	ProductShares string `json:"product_shares"` // base64 FixedPoint, n*p_k elements
	NObs          int    `json:"n_obs"`
	NPred         int    `json:"n_pred"`
}

type SumBeaverProductsOutput struct {
	GradientShare string `json:"gradient_share"` // base64 FixedPoint, p_k elements
}

func handleMpcSumBeaverProducts() {
	var input SumBeaverProductsInput
	mpcReadInput(&input)

	products := bytesToFPVec(base64ToBytes(input.ProductShares))
	n := input.NObs
	p := input.NPred

	gradient := make([]FixedPoint, p)
	for j := 0; j < p; j++ {
		var sum FixedPoint
		for i := 0; i < n; i++ {
			sum = FPAdd(sum, products[j*n+i])
		}
		gradient[j] = sum
	}

	mpcWriteOutput(SumBeaverProductsOutput{
		GradientShare: bytesToBase64(fpVecToBytes(gradient)),
	})
}

// ============================================================================
// Polynomial fitting helpers
// ============================================================================

func SigmoidGlobalPoly(degree int) []float64 {
	return fitGlobalPoly(sigmoid, -8.0, 8.0, degree, 10000)
}

func ExpGlobalPoly(degree int) []float64 {
	return fitGlobalPoly(math.Exp, -3.0, 3.0, degree, 10000)
}

func fitGlobalPoly(f func(float64) float64, lower, upper float64, degree, nPoints int) []float64 {
	d := degree + 1
	AtA := make([][]float64, d)
	for i := range AtA {
		AtA[i] = make([]float64, d)
	}
	Atb := make([]float64, d)

	for k := 0; k < nPoints; k++ {
		x := lower + (upper-lower)*float64(k)/float64(nPoints-1)
		y := f(x)
		pow := make([]float64, d)
		pow[0] = 1
		for j := 1; j < d; j++ {
			pow[j] = pow[j-1] * x
		}
		for i := 0; i < d; i++ {
			Atb[i] += pow[i] * y
			for j := 0; j < d; j++ {
				AtA[i][j] += pow[i] * pow[j]
			}
		}
	}
	return solveNxN(AtA, Atb, d)
}

func solveNxN(A [][]float64, b []float64, n int) []float64 {
	aug := make([][]float64, n)
	for i := 0; i < n; i++ {
		aug[i] = make([]float64, n+1)
		copy(aug[i][:n], A[i])
		aug[i][n] = b[i]
	}
	for col := 0; col < n; col++ {
		maxVal := math.Abs(aug[col][col])
		maxRow := col
		for row := col + 1; row < n; row++ {
			if math.Abs(aug[row][col]) > maxVal {
				maxVal = math.Abs(aug[row][col])
				maxRow = row
			}
		}
		aug[col], aug[maxRow] = aug[maxRow], aug[col]
		for row := col + 1; row < n; row++ {
			factor := aug[row][col] / aug[col][col]
			for j := col; j <= n; j++ {
				aug[row][j] -= factor * aug[col][j]
			}
		}
	}
	x := make([]float64, n)
	for i := n - 1; i >= 0; i-- {
		x[i] = aug[i][n]
		for j := i + 1; j < n; j++ {
			x[i] -= aug[i][j] * x[j]
		}
		x[i] /= aug[i][i]
	}
	return x
}

func measurePolyError(f func(float64) float64, coeffs []float64,
	lower, upper, clampLow, clampHigh float64, nPoints int) float64 {
	maxErr := 0.0
	for k := 0; k < nPoints; k++ {
		x := lower + (upper-lower)*float64(k)/float64(nPoints-1)
		exact := f(x)
		if exact < clampLow {
			exact = clampLow
		}
		if exact > clampHigh {
			exact = clampHigh
		}
		approx := evalPoly(x, coeffs)
		if approx < clampLow {
			approx = clampLow
		}
		if approx > clampHigh {
			approx = clampHigh
		}
		if err := math.Abs(exact - approx); err > maxErr {
			maxErr = err
		}
	}
	return maxErr
}

func evalPoly(x float64, coeffs []float64) float64 {
	result := 0.0
	xpow := 1.0
	for _, c := range coeffs {
		result += c * xpow
		xpow *= x
	}
	return result
}

// ============================================================================
// Command: mpc-vec-add
// Adds two base64-encoded FixedPoint vectors, returns base64 result.
// Used for combining eta shares: total_share = own_share + peer_share.
// ============================================================================

type VecAddInput struct {
	A string `json:"a"` // base64 FixedPoint vector
	B string `json:"b"` // base64 FixedPoint vector
}

type VecAddOutput struct {
	Result string `json:"result"` // base64 FixedPoint vector
}

func handleMpcVecAdd() {
	var input VecAddInput
	mpcReadInput(&input)
	a := bytesToFPVec(base64ToBytes(input.A))
	b := bytesToFPVec(base64ToBytes(input.B))
	r := FPVecAdd(a, b)
	mpcWriteOutput(VecAddOutput{Result: bytesToBase64(fpVecToBytes(r))})
}

// ============================================================================
// Command: mpc-fp-to-float
// Converts base64-encoded FixedPoint vector to float64 array.
// ============================================================================

type FPToFloatInput struct {
	FPData   string `json:"fp_data"`   // base64 FixedPoint
	FracBits int    `json:"frac_bits"`
}

type FPToFloatOutput struct {
	Values []float64 `json:"values"` // float64 array
}

func handleMpcFPToFloat() {
	var input FPToFloatInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = 20
	}
	fp := bytesToFPVec(base64ToBytes(input.FPData))
	mpcWriteOutput(FPToFloatOutput{Values: FPVecToFloat(fp, input.FracBits)})
}

// ============================================================================
// Command: mpc-sum-share
// Sums a FixedPoint share vector to produce a single scalar share.
// Used for secure aggregation: sum(w_i) or sum(mu_i - y_i).
// ============================================================================

type SumShareInput struct {
	Share    string `json:"share"`     // base64 FixedPoint vector
	FracBits int    `json:"frac_bits"`
}

type SumShareOutput struct {
	SumShare string  `json:"sum_share"` // base64 FixedPoint (1 element)
	SumFloat float64 `json:"sum_float"` // float64 for convenience
}

func handleMpcSumShare() {
	var input SumShareInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = 20
	}
	shares := bytesToFPVec(base64ToBytes(input.Share))
	var sum FixedPoint
	for _, s := range shares {
		sum = FPAdd(sum, s)
	}
	result := make([]FixedPoint, 1)
	result[0] = sum
	mpcWriteOutput(SumShareOutput{
		SumShare: bytesToBase64(fpVecToBytes(result)),
		SumFloat: sum.ToFloat64(input.FracBits),
	})
}

// ============================================================================
// Command: mpc-add-fp-shares
// Adds two FixedPoint share vectors element-wise (modular int64 addition)
// and converts the result to float. Used for reconstructing mu from Ring63
// shares: mu_total = share_A + share_B (mod 2^63) → float.
// ============================================================================

type AddFPSharesInput struct {
	ShareA   string `json:"share_a"`   // base64 FixedPoint vector
	ShareB   string `json:"share_b"`   // base64 FixedPoint vector
	FracBits int    `json:"frac_bits"`
}

type AddFPSharesOutput struct {
	Values []float64 `json:"values"` // float64 array of reconstructed values
	N      int       `json:"n"`      // number of values
	SumA   float64   `json:"sum_a"`  // debug: sum of share A as float (before Ring63 sum)
	SumB   float64   `json:"sum_b"`  // debug: sum of share B as float (before Ring63 sum)
}

func handleMpcAddFPShares() {
	var input AddFPSharesInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = 20
	}
	// Convert FP (int64) back to Ring63 (uint64 mod 2^63) for correct modular addition
	a := bytesToFPVec(base64ToBytes(input.ShareA))
	b := bytesToFPVec(base64ToBytes(input.ShareB))
	ring := NewRing63(input.FracBits)
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	sumR63 := make([]uint64, n)
	for i := 0; i < n; i++ {
		ar63 := fpToRing63([]FixedPoint{a[i]})[0]
		br63 := fpToRing63([]FixedPoint{b[i]})[0]
		sumR63[i] = ring.Add(ar63, br63)
	}
	// Convert Ring63 sum back to float
	sumFP := ring63ToFP(sumR63)
	// Debug sums
	var sumAf, sumBf float64
	for i := 0; i < n; i++ {
		sumAf += a[i].ToFloat64(input.FracBits)
		sumBf += b[i].ToFloat64(input.FracBits)
	}
	mpcWriteOutput(AddFPSharesOutput{
		Values: FPVecToFloat(sumFP, input.FracBits),
		N:      n,
		SumA:   sumAf,
		SumB:   sumBf,
	})
}
