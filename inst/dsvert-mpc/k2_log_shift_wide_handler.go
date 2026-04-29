// k2_log_shift_wide_handler.go — dispatch handler `k2-log-shift-coeffs-wide`.
//
// Exposes the public Ring127 wide-Chebyshev log coefficients on the
// [0.1, 1000] domain plus the affine mapping constants required to
// transform x → t ∈ [-1, 1] before share-side Clenshaw evaluation.
// All values are public deterministic constants computed at init()
// from the domain bounds; distributing them leaks nothing.
//
// R-client orchestration (dsVertClient:::.ring127_log_round_keyed_nr):
//   1. Fetch coefficients (once per session) via .callMpcTool(
//      "k2-log-shift-coeffs-wide", ...).
//   2. LocalScale + AffineCombine to map x_share into t_share ∈ [-1, 1].
//   3. Run (degree + 1) Beaver vecmul rounds via Clenshaw recurrence,
//      identical to the [1, 10] core orchestrator but with degree 60
//      coefficients and wider domain constants.
//   4. NR refinement: 5 iterations of y_{n+1} = y_n + x·exp(-y_n) - 1
//      via .ring127_exp_round_keyed_extended + .ring127_vecmul +
//      k2Ring127AffineCombineDS. Quadratic convergence drives the
//      rel error from ~30% (Bernstein-ellipse ρ=1.020 at degree 60
//      on this wide domain) to ~7.8e-27 (well below ULP 2^-50).
//
// Mirror of k2_log_shift_handler.go (which ships the [1, 10] core);
// no new cryptographic primitives, pure data dump.
//
// Refs: Goldschmidt 1964 (NR division); Trefethen & Bau §16 (NR);
//       Pugh 2004 PhD §3 (NR-on-Chebyshev for log); Catrina-Saxena
//       2010 §3.3 (fixed-point ULP).

package main

// K2LogShiftWideGetCoeffsInput carries the FP precision for coefficient
// encoding. Optional ring127 fracBits override (default 50).
type K2LogShiftWideGetCoeffsInput struct {
	FracBits int `json:"frac_bits"`
}

// K2LogShiftWideGetCoeffsOutput carries the base64-encoded constants
// for the wide [0.1, 1000] domain.
type K2LogShiftWideGetCoeffsOutput struct {
	OneOverHalfRange    string  `json:"one_over_half_range"`
	NegMidOverHalfRange string  `json:"neg_mid_over_half_range"`
	Coeffs              string  `json:"coeffs"`
	Degree              int     `json:"degree"`
	FracBits            int     `json:"frac_bits"`
	DomainMin           float64 `json:"domain_min"`
	DomainMax           float64 `json:"domain_max"`
}

// handleK2LogShiftWideGetCoeffs serializes the wide-Chebyshev log
// constants. Encoding mirrors handleK2LogShiftGetCoeffs.
func handleK2LogShiftWideGetCoeffs() {
	var input K2LogShiftWideGetCoeffsInput
	mpcReadInput(&input)
	fb := input.FracBits
	if fb <= 0 {
		fb = K2DefaultFracBits127
	}
	r := NewRing127(fb)
	oneOverHalf, _, coeffs, degree := Ring127LogShiftWideCoeffsFP(r)
	a := Ring127LogShiftWideMin
	b := Ring127LogShiftWideMax
	negMidOverHalf := r.FromDouble(-(a + b) / (b - a))

	mpcWriteOutput(K2LogShiftWideGetCoeffsOutput{
		OneOverHalfRange:    Uint128VecToB64([]Uint128{oneOverHalf}),
		NegMidOverHalfRange: Uint128VecToB64([]Uint128{negMidOverHalf}),
		Coeffs:              Uint128VecToB64(coeffs[:]),
		Degree:              degree,
		FracBits:            fb,
		DomainMin:           a,
		DomainMax:           b,
	})
}
