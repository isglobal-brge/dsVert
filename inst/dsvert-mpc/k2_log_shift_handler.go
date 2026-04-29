// k2_log_shift_handler.go — dispatch handler `k2-log-shift-coeffs`.
//
// Exposes the public Ring127 Chebyshev-log coefficients on the [1, 10] core
// domain plus the affine mapping constants (oneOverHalfRange, negMidOverHalfRange)
// needed to transform x into the Chebyshev domain t ∈ [-1, 1]. All values
// are public (deterministic constants computed at init from the domain
// [Ring127LogShiftMin, Ring127LogShiftMax]), so distributing them leaks
// nothing — exactly analogous to k2-exp127-get-coeffs and
// k2-recip127-get-coeffs.
//
// R client orchestration (dsVertClient:::.ring127_log_round_keyed):
//  1. Fetch (once per session) via .callMpcTool("k2-log-shift-coeffs", ...).
//  2. Apply LocalScale + AffineCombine to map x → t ∈ [-1, 1].
//  3. Run (degree+1) Beaver vecmul rounds via Clenshaw recurrence,
//     identical to the .ring127_exp_round_keyed pipeline.
//  4. Argument reduction onto [1, 10] core handled in R via DCF (the
//     extended wrapper .ring127_log_round_keyed_extended), out of scope
//     for this handler (pure data dump).
//
// NB full-regression θ MLE pipeline (dsvertNBFullScoreDS): once log on
// shares is available, the score Σψ(y_i+θ) − n·ψ(θ) + n·log(θ) − Σlog(μ_i+θ)
// can be assembled in shares without revealing η^nl or per-patient μ_i —
// closing the K=2 disclosure budget violation in the prior full_reg path
// (Lawless 1987; Venables–Ripley 2002 §7.4).
//
// No new cryptographic primitives; pure data dump. The underlying
// Chebyshev evaluator Ring127LogShiftPlaintext + accuracy proof live
// in k2_log_shift127.go.

package main

// K2LogShiftGetCoeffsInput carries the FP precision for coefficient encoding.
// Optional ring127 fracBits override (default 50).
type K2LogShiftGetCoeffsInput struct {
	FracBits int `json:"frac_bits"`
}

// K2LogShiftGetCoeffsOutput carries the base64-encoded constants.
//
//	OneOverHalfRange     : single Uint128, the affine slope 2/(b−a) applied
//	                        to (x − mid) via LocalScale.
//	NegMidOverHalfRange  : single Uint128, the composed constant
//	                        −(a+b)/(b−a) added as party-0 public constant
//	                        in the AffineCombine step that produces t.
//	Coeffs               : (degree+1) Uint128 values, c_0..c_N in degree
//	                        order. Layout matches Uint128VecToB64.
//	Degree               : Chebyshev polynomial degree (40).
//	FracBits             : Ring127 fracBits used for FP encoding (50).
//	DomainMin / DomainMax: core Chebyshev domain bounds [1, 10] — the R
//	                        client uses these to plan DCF arg-reduction.
type K2LogShiftGetCoeffsOutput struct {
	OneOverHalfRange    string  `json:"one_over_half_range"`
	NegMidOverHalfRange string  `json:"neg_mid_over_half_range"`
	Coeffs              string  `json:"coeffs"`
	Degree              int     `json:"degree"`
	FracBits            int     `json:"frac_bits"`
	DomainMin           float64 `json:"domain_min"`
	DomainMax           float64 `json:"domain_max"`
}

// handleK2LogShiftGetCoeffs serializes the Chebyshev log-shift constants.
// Mirrors handleK2Exp127GetCoeffs / handleK2Recip127GetCoeffs encoding.
func handleK2LogShiftGetCoeffs() {
	var input K2LogShiftGetCoeffsInput
	mpcReadInput(&input)
	fb := input.FracBits
	if fb <= 0 {
		fb = K2DefaultFracBits127
	}
	r := NewRing127(fb)
	oneOverHalf, _, coeffs, degree := Ring127LogShiftCoeffsFP(r)

	// Compose negMidOverHalfRange = −(a+b)/(b−a) directly from the public
	// domain constants. The Go primitive Ring127LogShiftCoeffsFP returns
	// midShift = (a+b)/2 and oneOverHalf = 2/(b−a) separately (caller's
	// affine-combine plan: y = (x − midShift) · oneOverHalf). The R client
	// uses the standard Recip-style fused constant (negMidOverHalf =
	// −(a+b)/(b−a) added after a single LocalScale by oneOverHalf), which
	// matches the .ring127_recip_round_keyed orchestration exactly.
	a := Ring127LogShiftMin
	b := Ring127LogShiftMax
	negMidOverHalf := r.FromDouble(-(a + b) / (b - a))

	mpcWriteOutput(K2LogShiftGetCoeffsOutput{
		OneOverHalfRange:    Uint128VecToB64([]Uint128{oneOverHalf}),
		NegMidOverHalfRange: Uint128VecToB64([]Uint128{negMidOverHalf}),
		Coeffs:              Uint128VecToB64(coeffs[:]),
		Degree:              degree,
		FracBits:            fb,
		DomainMin:           a,
		DomainMax:           b,
	})
}
