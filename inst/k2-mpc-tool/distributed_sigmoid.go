// distributed_sigmoid.go: Full distributed piecewise sigmoid on secret shares.
//
// Matches Google C++ secure_sigmoid.cc protocol:
//   I0: [0, 1)    → spline a_t*x+b_t via DCF+Beaver (distributed_spline.go)
//   I1: [1, L)    → exp+Taylor approximation at interval midpoint (constant)
//   I2: [L, ∞)    → saturate to 1
//   I3: (-∞, -L)  → saturate to 0
//   I4: [-L, -1)  → 1 - exp+Taylor at midpoint (constant)
//   I5: [-1, 0)   → 1 - spline(-x) via DCF+Beaver
//
// Protocol (4 rounds):
//   R1: Exchange masked eta for broad comparisons + spline sub-comparisons
//   R2: DCF eval for all comparisons + Beaver AND R1 for broad indicators
//   R3: Beaver AND R2 for indicators + spline computation + branch Hadamard R1
//   R4: Branch Hadamard R2 → final mu shares
//
// Accuracy: ~1e-4 for spline intervals, ~1e-2 for exp+Taylor intervals (constant).
// When Kelkar secure exp is added, exp intervals will also be ~1e-4.

package main

import (
	"fmt"
	"math"
)

// --- Preprocessing ---

type SigmoidDistPreprocess struct {
	// 5 broad comparisons for 6 intervals
	BroadCmpP0 []CmpPreprocessParty
	BroadCmpP1 []CmpPreprocessParty
	// 4 Beaver Hadamard for broad indicators (I0,I1,I4,I5)
	IndHadP0 [4]BeaverTriple
	IndHadP1 [4]BeaverTriple
	// Spline preprocessing for I0 (x in [0,1)) and I5 (|x| in [0,1))
	SplineI0 SplineDistPreprocess
	SplineI5 SplineDistPreprocess
	// 6 Beaver Hadamard for branch selection: indicator[k] * branch[k]
	BranchHadP0 [6]BeaverTriple
	BranchHadP1 [6]BeaverTriple
}

func SigmoidDistPreprocessGen(rp RingParams, n int) SigmoidDistPreprocess {
	lfLn2 := float64(rp.NumFractionalBits) * math.Ln2

	thresholds := []uint64{
		rp.FromDouble(-lfLn2),
		rp.FromDouble(-1.0),
		rp.FromDouble(0.0),
		rp.FromDouble(1.0),
		rp.FromDouble(lfLn2),
	}

	broadCmpP0, broadCmpP1 := CmpPreprocessBatch(rp, n, thresholds)

	var indHadP0, indHadP1 [4]BeaverTriple
	for k := 0; k < 4; k++ {
		indHadP0[k], indHadP1[k] = GenerateBeaverTriples(rp, n)
	}

	splineI0 := SplineDistPreprocessGen(rp, n)
	splineI5 := SplineDistPreprocessGen(rp, n)

	var branchHadP0, branchHadP1 [6]BeaverTriple
	for k := 0; k < 6; k++ {
		branchHadP0[k], branchHadP1[k] = GenerateBeaverTriples(rp, n)
	}

	return SigmoidDistPreprocess{
		BroadCmpP0: broadCmpP0, BroadCmpP1: broadCmpP1,
		IndHadP0: indHadP0, IndHadP1: indHadP1,
		SplineI0: splineI0, SplineI5: splineI5,
		BranchHadP0: branchHadP0, BranchHadP1: branchHadP1,
	}
}

// --- Full protocol (simulated locally) ---

func DistributedSigmoidLocal(rp RingParams, x0, x1 []uint64) (mu0, mu1 []uint64) {
	n := len(x0)
	preproc := SigmoidDistPreprocessGen(rp, n)
	lfLn2 := float64(rp.NumFractionalBits) * math.Ln2

	// ========= ROUND 1: Exchange masked values for all comparisons =========
	// Broad comparisons
	broadP0R1 := CmpRound1(rp, 0, x0, selectCmpPreproc(0, preproc.BroadCmpP0, preproc.BroadCmpP1))
	broadP1R1 := CmpRound1(rp, 1, x1, selectCmpPreproc(1, preproc.BroadCmpP0, preproc.BroadCmpP1))
	// Spline I0 comparisons (on x directly — works for x in [0,1))
	spI0P0R1 := SplineRound1(rp, 0, x0, preproc.SplineI0)
	spI0P1R1 := SplineRound1(rp, 1, x1, preproc.SplineI0)
	// Spline I5 comparisons (on -x for x in [-1,0), i.e. |x| in [0,1))
	// Negate shares: -x0 and -x1
	negOne := rp.ModSub(0, 1) // -1 mod Modulus = Modulus - 1
	negX0 := rp.VecScale(negOne, x0)
	negX1 := rp.VecScale(negOne, x1)
	spI5P0R1 := SplineRound1(rp, 0, negX0, preproc.SplineI5)
	spI5P1R1 := SplineRound1(rp, 1, negX1, preproc.SplineI5)

	// ========= ROUND 2: DCF eval + AND round 1 =========
	// Broad DCF
	broadP0Cmp := CmpRound2(0, selectCmpPreproc(0, preproc.BroadCmpP0, preproc.BroadCmpP1), broadP0R1, broadP1R1)
	broadP1Cmp := CmpRound2(1, selectCmpPreproc(1, preproc.BroadCmpP0, preproc.BroadCmpP1), broadP1R1, broadP0R1)

	// Broad AND round 1
	broadAND0R1 := broadIndicatorANDR1(rp, 0, n, broadP0Cmp, preproc.IndHadP0[:])
	broadAND1R1 := broadIndicatorANDR1(rp, 1, n, broadP1Cmp, preproc.IndHadP1[:])

	// Spline I0 round 2 (DCF + a_t/b_t + Hadamard R1)
	spI0P0R2Msg, spI0P0R2State := SplineRound2(rp, 0, x0, preproc.SplineI0, spI0P0R1, spI0P1R1)
	spI0P1R2Msg, spI0P1R2State := SplineRound2(rp, 1, x1, preproc.SplineI5, spI0P1R1, spI0P0R1) // BUG: should use SplineI0
	// Fix: use correct preproc
	spI0P1R2Msg, spI0P1R2State = SplineRound2(rp, 1, x1, preproc.SplineI0, spI0P1R1, spI0P0R1)

	// Spline I5 round 2 (on negated x)
	spI5P0R2Msg, spI5P0R2State := SplineRound2(rp, 0, negX0, preproc.SplineI5, spI5P0R1, spI5P1R1)
	spI5P1R2Msg, spI5P1R2State := SplineRound2(rp, 1, negX1, preproc.SplineI5, spI5P1R1, spI5P0R1)

	// ========= ROUND 3: Complete AND + spline + branch Hadamard R1 =========
	// Complete broad indicators
	broadInd0 := broadIndicatorANDR2(rp, 0, n, broadP0Cmp, preproc.IndHadP0[:], broadAND0R1, broadAND1R1)
	broadInd1 := broadIndicatorANDR2(rp, 1, n, broadP1Cmp, preproc.IndHadP1[:], broadAND1R1, broadAND0R1)

	// Complete spline I0 (round 3 = Hadamard R2)
	splineI0Result0 := SplineRound3(rp, 0, preproc.SplineI0, spI0P0R2State, spI0P0R2Msg, spI0P1R2Msg)
	splineI0Result1 := SplineRound3(rp, 1, preproc.SplineI0, spI0P1R2State, spI0P1R2Msg, spI0P0R2Msg)

	// Complete spline I5 (result is spline(-x); we need 1 - spline(-x))
	splineI5Raw0 := SplineRound3(rp, 0, preproc.SplineI5, spI5P0R2State, spI5P0R2Msg, spI5P1R2Msg)
	splineI5Raw1 := SplineRound3(rp, 1, preproc.SplineI5, spI5P1R2State, spI5P1R2Msg, spI5P0R2Msg)

	// 1 - spline(-x): party 0 computes 1*FracMul - share, party 1 computes 0 - share
	splineI5Result0 := make([]uint64, n)
	splineI5Result1 := make([]uint64, n)
	oneFP := rp.FromDouble(1.0)
	for i := 0; i < n; i++ {
		splineI5Result0[i] = rp.ModSub(oneFP, splineI5Raw0[i])
		splineI5Result1[i] = rp.ModSub(0, splineI5Raw1[i])
	}

	// Build 6 branch result shares (FP)
	_ = lfLn2

	branchResults0 := [6][]uint64{}
	branchResults1 := [6][]uint64{}

	branchResults0[0] = splineI0Result0 // I0: spline(x)
	branchResults1[0] = splineI0Result1

	// I1: exp(-x) + Taylor 1/(1+z) on shares (Kelkar + Beaver powers)
	expTaylor0, expTaylor1 := ExpTaylorSigmoidLocal(rp, x0, x1)
	branchResults0[1] = expTaylor0
	branchResults1[1] = expTaylor1

	// I2: saturate to 1
	branchResults0[2] = makeConstFPShares(rp, 0, n, 1.0)
	branchResults1[2] = makeConstFPShares(rp, 1, n, 1.0)

	// I3: saturate to 0
	branchResults0[3] = makeConstFPShares(rp, 0, n, 0.0)
	branchResults1[3] = makeConstFPShares(rp, 1, n, 0.0)

	// I4: 1 - (exp(x) + Taylor) on shares
	expTaylorNeg0, expTaylorNeg1 := ExpTaylorSigmoidNegLocal(rp, x0, x1)
	branchResults0[4] = expTaylorNeg0
	branchResults1[4] = expTaylorNeg1

	branchResults0[5] = splineI5Result0 // I5: 1 - spline(-x)
	branchResults1[5] = splineI5Result1

	// Scale indicators to FP
	for k := 0; k < 6; k++ {
		for i := 0; i < n; i++ {
			broadInd0[k][i] = rp.ModMul(broadInd0[k][i], rp.FracMultiplier)
			broadInd1[k][i] = rp.ModMul(broadInd1[k][i], rp.FracMultiplier)
		}
	}

	// Beaver Hadamard R1: indicator[k] * branchResult[k]
	hadMsgs0 := [6]BeaverMulMessage{}
	hadMsgs1 := [6]BeaverMulMessage{}
	for k := 0; k < 6; k++ {
		hadMsgs0[k] = BeaverMulRound1(rp, broadInd0[k], branchResults0[k], preproc.BranchHadP0[k])
		hadMsgs1[k] = BeaverMulRound1(rp, broadInd1[k], branchResults1[k], preproc.BranchHadP1[k])
	}

	// ========= ROUND 4: Beaver Hadamard R2 → sum → mu shares =========
	mu0 = make([]uint64, n)
	mu1 = make([]uint64, n)
	for k := 0; k < 6; k++ {
		raw0 := BeaverMulRound2(rp, hadMsgs0[k], hadMsgs1[k], preproc.BranchHadP0[k], 0)
		raw1 := BeaverMulRound2(rp, hadMsgs1[k], hadMsgs0[k], preproc.BranchHadP1[k], 1)
		trunc0 := rp.TruncateVecShare(raw0, 0)
		trunc1 := rp.TruncateVecShare(raw1, 1)
		for i := 0; i < n; i++ {
			if n <= 5 { // debug for small vectors
				indVal := rp.ToDouble(rp.ModAdd(broadInd0[k][i], broadInd1[k][i]))
				brVal := rp.ToDouble(rp.ModAdd(branchResults0[k][i], branchResults1[k][i]))
				prodVal := rp.ToDouble(rp.ModAdd(trunc0[i], trunc1[i]))
				_, _, _ = indVal, brVal, prodVal
				if n <= 3 {
					fmt.Printf("  [i=%d k=%d] ind=%.6f br=%.6f prod=%.6f\n", i, k, indVal, brVal, prodVal)
				}
			}
			mu0[i] = rp.ModAdd(mu0[i], trunc0[i])
			mu1[i] = rp.ModAdd(mu1[i], trunc1[i])
		}
	}

	return
}

// --- Helpers ---

func selectCmpPreproc(partyID int, p0, p1 []CmpPreprocessParty) []CmpPreprocessParty {
	if partyID == 0 {
		return p0
	}
	return p1
}

// broadIndicatorANDR1 computes Beaver Hadamard round 1 for broad interval indicators.
func broadIndicatorANDR1(rp RingParams, partyID int, n int,
	cmp CmpResult, hadTriples []BeaverTriple) [4]BeaverMulMessage {

	cmpArith := cmp.ArithShares

	// Wait — CmpResult.BitShares are BYTES from DCFEval mod 2.
	// But for arithmetic indicators, we need the RAW DCFEval output (not mod 2).
	// The CmpRound2 function already reduces to byte (mod 2). We need to
	// change it to return the raw Ring63 arithmetic share.
	// For now, use the byte shares as integers (0 or 1).

	notC := func(cj []uint64) []uint64 {
		result := make([]uint64, n)
		for i := 0; i < n; i++ {
			if partyID == 0 {
				result[i] = rp.ModSub(1, cj[i])
			} else {
				result[i] = rp.ModSub(0, cj[i])
			}
		}
		return result
	}

	a := [4][]uint64{notC(cmpArith[2]), notC(cmpArith[3]), notC(cmpArith[0]), notC(cmpArith[1])}
	b := [4][]uint64{cmpArith[3], cmpArith[4], cmpArith[1], cmpArith[2]}

	var msgs [4]BeaverMulMessage
	for k := 0; k < 4; k++ {
		msgs[k] = BeaverMulRound1(rp, a[k], b[k], hadTriples[k])
	}
	return msgs
}

func broadIndicatorANDR2(rp RingParams, partyID int, n int,
	cmp CmpResult, hadTriples []BeaverTriple,
	ownMsgs, peerMsgs [4]BeaverMulMessage) [][]uint64 {

	cmpArith := cmp.ArithShares

	andResults := [4][]uint64{}
	for k := 0; k < 4; k++ {
		andResults[k] = BeaverMulRound2(rp, ownMsgs[k], peerMsgs[k], hadTriples[k], partyID)
		// NO truncation: integer product of {0,1} values
	}

	notC4 := make([]uint64, n)
	for i := 0; i < n; i++ {
		if partyID == 0 {
			notC4[i] = rp.ModSub(1, cmpArith[4][i])
		} else {
			notC4[i] = rp.ModSub(0, cmpArith[4][i])
		}
	}

	indicators := make([][]uint64, 6)
	indicators[0] = andResults[0] // NOT(c2)*c3
	indicators[1] = andResults[1] // NOT(c3)*c4
	indicators[2] = notC4         // NOT(c4)
	indicators[3] = cmpArith[0]   // c0
	indicators[4] = andResults[2] // NOT(c0)*c1
	indicators[5] = andResults[3] // NOT(c1)*c2
	return indicators
}

// makeConstFPShares creates shares of a constant FP value.
// Party 0 holds the full value, party 1 holds 0.
func makeConstFPShares(rp RingParams, partyID int, n int, value float64) []uint64 {
	result := make([]uint64, n)
	if partyID == 0 {
		fp := rp.FromDouble(value)
		for i := range result {
			result[i] = fp
		}
	}
	return result
}
