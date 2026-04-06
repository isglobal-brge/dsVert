// distributed_spline.go: Distributed spline evaluation on secret shares.
//
// Port of Google C++ secure_spline.cc. Evaluates f(x) = a_t * x + b_t where
// t is the active sub-interval, determined by DCF comparisons.
//
// For the sigmoid, this is called for:
//   I0: x in [0, 1)  → f(x) = spline(x)
//   I5: x in [-1, 0) → f(x) = 1 - spline(-x)
//
// The spline has 10 sub-intervals of width 0.1 in [0, 1).
// 9 DCF comparisons determine the sub-interval.
// ScalarVectorProduct computes a_t and b_t from indicators.
// One Beaver Hadamard computes a_t * x.

package main

// SplineDistPreprocess holds preprocessing for distributed spline evaluation.
type SplineDistPreprocess struct {
	// 9 comparisons for sub-interval boundaries [0.1, 0.2, ..., 0.9]
	CmpP0 []CmpPreprocessParty
	CmpP1 []CmpPreprocessParty
	// 1 Beaver Hadamard for a_t * x (per element)
	HadP0 BeaverTriple
	HadP1 BeaverTriple
}

// SplineDistPreprocessGen generates spline preprocessing for n elements.
// The spline evaluates on x in [0, 1) with 10 sub-intervals.
func SplineDistPreprocessGen(rp RingParams, n int) SplineDistPreprocess {
	// 9 sub-interval boundaries: 0.1, 0.2, ..., 0.9
	thresholds := make([]uint64, 9)
	for j := 0; j < 9; j++ {
		thresholds[j] = rp.FromDouble(float64(j+1) * 0.1)
	}

	cmpP0, cmpP1 := CmpPreprocessBatch(rp, n, thresholds)
	hadP0, hadP1 := GenerateBeaverTriples(rp, n)

	return SplineDistPreprocess{
		CmpP0: cmpP0, CmpP1: cmpP1,
		HadP0: hadP0, HadP1: hadP1,
	}
}

// SplineR1Message contains masked values for spline comparison.
type SplineR1Message struct {
	CmpMsg CmpRound1Message
}

// SplineRound1 computes round 1 for spline comparisons.
// xShare is the party's share of x (already in [0,1) range, non-negative).
func SplineRound1(rp RingParams, partyID int, xShare []uint64,
	preproc SplineDistPreprocess) SplineR1Message {

	var cmpPreproc []CmpPreprocessParty
	if partyID == 0 {
		cmpPreproc = preproc.CmpP0
	} else {
		cmpPreproc = preproc.CmpP1
	}

	return SplineR1Message{
		CmpMsg: CmpRound1(rp, partyID, xShare, cmpPreproc),
	}
}

// SplineR2Message contains Beaver Hadamard round 1 for a_t * x.
type SplineR2Message struct {
	HadMsg BeaverMulMessage
}

// SplineR2State stores state between rounds.
type SplineR2State struct {
	ActiveSlopeShare     []uint64 // [a_t] share in FP
	ActiveInterceptShare []uint64 // [b_t] share in FP
}

// SplineRound2 evaluates DCF → indicators → a_t, b_t → Hadamard round 1.
// Returns Hadamard message + state for round 3.
func SplineRound2(rp RingParams, partyID int, xShare []uint64,
	preproc SplineDistPreprocess,
	ownR1, peerR1 SplineR1Message) (SplineR2Message, SplineR2State) {

	n := len(xShare)
	sp := DefaultPiecewiseSigmoidParams()

	var cmpPreproc []CmpPreprocessParty
	if partyID == 0 {
		cmpPreproc = preproc.CmpP0
	} else {
		cmpPreproc = preproc.CmpP1
	}

	// Evaluate 9 DCF comparisons → arithmetic shares
	cmpArith := make([][]uint64, 9)
	for j := 0; j < 9; j++ {
		cmpArith[j] = make([]uint64, n)
		numBits := cmpPreproc[j].NumBits
		extMod := uint64(1) << numBits

		for i := 0; i < n; i++ {
			m := (ownR1.CmpMsg.MaskedValues[j][i] + peerR1.CmpMsg.MaskedValues[j][i]) % extMod
			v := DCFEval(partyID, cmpPreproc[j].Keys[i], m)
			cmpArith[j][i] = uint64(v) % rp.Modulus
		}
	}

	// Compute 10 sub-interval indicators from 9 comparisons:
	// indicator[0] = cmp[0]                    (x < 0.1)
	// indicator[j] = cmp[j] - cmp[j-1]         (0.j <= x < 0.(j+1)) for j=1..8
	// indicator[9] = 1 - cmp[8]                (x >= 0.9)
	//
	// These are arithmetic shares: sum of shares = 0 or 1.
	// indicator[j] = cmp[j] - cmp[j-1] works because:
	//   cmp[j] = [x < 0.(j+1)] and cmp[j-1] = [x < 0.j]
	//   If x is in interval j: cmp[j]=1, cmp[j-1]=0 → 1-0=1
	//   Otherwise: both same → 0

	indicators := make([][]uint64, 10)
	for k := 0; k < 10; k++ {
		indicators[k] = make([]uint64, n)
	}

	for i := 0; i < n; i++ {
		// indicator[0] = cmp[0]
		indicators[0][i] = cmpArith[0][i]

		// indicator[j] = cmp[j] - cmp[j-1] for j=1..8
		for j := 1; j < 9; j++ {
			indicators[j][i] = rp.ModSub(cmpArith[j][i], cmpArith[j-1][i])
		}

		// indicator[9] = 1 - cmp[8]
		if partyID == 0 {
			indicators[9][i] = rp.ModSub(1, cmpArith[8][i])
		} else {
			indicators[9][i] = rp.ModSub(0, cmpArith[8][i])
		}
	}

	// Scale indicators to FP: multiply by FracMultiplier
	// (matching C++ line 448: BatchedModMul with fractional_multiplier_vector)
	for k := 0; k < 10; k++ {
		for i := 0; i < n; i++ {
			indicators[k][i] = rp.ModMul(indicators[k][i], rp.FracMultiplier)
		}
	}

	// Compute [a_t] = sum_j slope_j * [indicator_j_fp] (ScalarShareMul, NO communication)
	// Compute [b_t] = sum_j intercept_j * [indicator_j_fp]
	activeSlopeShare := make([]uint64, n)
	activeInterceptShare := make([]uint64, n)

	for j := 0; j < 10; j++ {
		slopeFP := rp.FromDouble(sp.SplineSlopes[j])
		interceptFP := rp.FromDouble(sp.SplineIntercepts[j])

		for i := 0; i < n; i++ {
			var slopeTerm, interceptTerm uint64
			if partyID == 0 {
				slopeTerm = rp.ScalarShareMulP0(slopeFP, indicators[j][i])
				interceptTerm = rp.ScalarShareMulP0(interceptFP, indicators[j][i])
			} else {
				slopeTerm = rp.ScalarShareMulP1(slopeFP, indicators[j][i])
				interceptTerm = rp.ScalarShareMulP1(interceptFP, indicators[j][i])
			}
			activeSlopeShare[i] = rp.ModAdd(activeSlopeShare[i], slopeTerm)
			activeInterceptShare[i] = rp.ModAdd(activeInterceptShare[i], interceptTerm)
		}
	}

	// Beaver Hadamard round 1: [a_t] * [x]
	var hadTriple BeaverTriple
	if partyID == 0 {
		hadTriple = preproc.HadP0
	} else {
		hadTriple = preproc.HadP1
	}
	hadMsg := BeaverMulRound1(rp, activeSlopeShare, xShare, hadTriple)

	return SplineR2Message{HadMsg: hadMsg},
		SplineR2State{
			ActiveSlopeShare:     activeSlopeShare,
			ActiveInterceptShare: activeInterceptShare,
		}
}

// SplineRound3 completes the Hadamard product and returns the spline result.
// result = [a_t * x + b_t] in FP.
func SplineRound3(rp RingParams, partyID int,
	preproc SplineDistPreprocess,
	r2State SplineR2State,
	ownR2, peerR2 SplineR2Message) []uint64 {

	n := len(r2State.ActiveSlopeShare)

	var hadTriple BeaverTriple
	if partyID == 0 {
		hadTriple = preproc.HadP0
	} else {
		hadTriple = preproc.HadP1
	}

	// Complete Hadamard: [a_t * x]
	raw := BeaverMulRound2(rp, ownR2.HadMsg, peerR2.HadMsg, hadTriple, partyID)
	atTimesX := rp.TruncateVecShare(raw, partyID)

	// Result = [a_t * x] + [b_t]
	result := make([]uint64, n)
	for i := 0; i < n; i++ {
		result[i] = rp.ModAdd(atTimesX[i], r2State.ActiveInterceptShare[i])
	}

	return result
}
