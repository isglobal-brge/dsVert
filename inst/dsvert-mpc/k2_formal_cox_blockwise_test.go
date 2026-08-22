package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/markkurossi/mpc/circuit"
)

func formalCoxBlockwiseTestCircuitCacheKey(source string) string {
	digest := sha256.Sum256([]byte(source))
	return hex.EncodeToString(digest[:])
}

func formalCoxBlockwiseTestPolicy(t testing.TB, custodians, capacity int) formalCoxPhase1Policy {
	t.Helper()
	policy := formalCoxTestPolicy(t, custodians)
	policy.Capacity = capacity
	policy.CovariateCount = 2
	policy.GridTickCount = 9
	policy.Iterations = 2
	policy.XLower = []string{"-256", "-256"}
	policy.XUpper = []string{"256", "256"}
	policy.CovariateL2Bound = "256"
	policy.Ridge = "16"
	digest, err := formalCoxExpTableDigest(policy)
	if err != nil {
		t.Fatalf("small: %v", err)
	}
	policy.ExpTableSHA256 = digest
	return policy
}

func TestFormalCoxBlockwisePolicyAcceptsSignedIterationRange(t *testing.T) {
	policy := formalCoxBlockwiseTestPolicy(t, 3, 64)
	policy.Iterations = 12

	if _, err := parseFormalCoxBlockwisePolicy(policy); err != nil {
		t.Fatalf("blockwise policy rejected a signed twelve-iteration schedule: %v", err)
	}
	if _, err := parseFormalCoxPhase1Policy(policy); err == nil {
		t.Fatal("legacy monolithic Phase-1 parser accepted a schedule above its physical limit")
	}

	policy.Iterations = 257
	if _, err := parseFormalCoxBlockwisePolicy(policy); err == nil {
		t.Fatal("blockwise policy accepted an iteration count beyond the signed schema limit")
	}
}

func TestFormalCoxBlockwisePolicyAdmitsThreeCovariatesOnlyWithinItsEnvelope(
	t *testing.T,
) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+fmt.Sprint(custodians), func(t *testing.T) {
			compiled, err := formalCoxCompileSignedRSchema(
				formalCoxRSchemaFixture(t, custodians, 3))
			if err != nil {
				t.Fatalf("compile signed three-covariate schema: %v", err)
			}
			policy := compiled.Policy
			if _, err := parseFormalCoxBlockwisePolicy(policy); err != nil {
				t.Fatalf("blockwise parser rejected three covariates: %v", err)
			}
			if _, err := buildFormalCoxBlockwisePlan(policy, 1,
				strings.Repeat("3", 64)); err != nil {
				t.Fatalf("three-covariate plan did not fit its public envelope: %v", err)
			}
			if _, err := parseFormalCoxPhase1Policy(policy); err == nil {
				t.Fatal("legacy monolithic parser admitted three covariates")
			}
		})
	}
	policy := formalCoxBlockwiseTestPolicy(t, 2, 2)
	policy.CovariateCount = 4
	policy.XLower = []string{"-256", "-256", "-256", "-256"}
	policy.XUpper = []string{"256", "256", "256", "256"}
	if _, err := parseFormalCoxBlockwisePolicy(policy); err == nil {
		t.Fatal("blockwise parser admitted covariates beyond its reviewed envelope")
	}
}

func TestFormalCoxBlockwiseRequiresContractiveIdealStep(t *testing.T) {
	policy := formalCoxBlockwiseTestPolicy(t, 3, 64)
	contract, err := formalCoxBlockwiseDeriveIdealGradientContract(policy)
	if err != nil {
		t.Fatalf("derive ideal grid-Breslow contraction contract: %v", err)
	}
	if contract.SmoothnessUpperNumerator != "69632" ||
		contract.SmoothnessUpperDenominator != "65536" ||
		contract.ContractionFactorNumerator != "64512" ||
		contract.ContractionFactorDenominator != "65536" {
		t.Fatalf("unexpected exact contraction contract: %+v", contract)
	}

	policy.Alpha = "256"
	if _, err := formalCoxBlockwiseDeriveIdealGradientContract(policy); err == nil {
		t.Fatal("blockwise policy accepted a non-contractive ideal-gradient step")
	}
	if _, err := buildFormalCoxBlockwisePlan(policy, 1,
		strings.Repeat("a", 64)); err == nil {
		t.Fatal("blockwise planner accepted a non-contractive ideal-gradient step")
	}
}

func formalCoxBlockwiseTestRows(policy formalCoxPhase1Policy, ringBits int) []*big.Int {
	rows := make([]*big.Int, 0, policy.Capacity*(len(policy.CustodianPeers)+3+policy.CovariateCount))
	for row := 0; row < policy.Capacity; row++ {
		for range policy.CustodianPeers {
			rows = append(rows, big.NewInt(1))
		}
		stop := int64(1 + row%policy.GridTickCount)
		status := int64(0)
		if row%2 == 0 {
			status = 1
		}
		rows = append(rows, big.NewInt(0), big.NewInt(stop), big.NewInt(status))
		for coefficient := 0; coefficient < policy.CovariateCount; coefficient++ {
			x := big.NewInt(int64(96 - 16*coefficient + row%3))
			if (row+coefficient)%2 == 1 {
				x.Neg(x)
			}
			rows = append(rows, formalCoxResidue(x, ringBits))
		}
	}
	return rows
}

func formalCoxBlockwiseTestNoise(plan formalCoxBlockwisePlan) []*big.Int {
	result := make([]*big.Int, plan.Iterations*plan.Policy.CovariateCount)
	for iteration := 0; iteration < plan.Iterations; iteration++ {
		for coefficient := 0; coefficient < plan.Policy.CovariateCount; coefficient++ {
			value := big.NewInt(int64(4 + iteration + coefficient))
			if coefficient%2 == 1 {
				value.Neg(value)
			}
			result[iteration*plan.Policy.CovariateCount+coefficient] =
				formalCoxResidue(value, plan.RingBits)
		}
	}
	return result
}

func formalCoxBlockwiseTestSplit(values []*big.Int, ringBits, salt int) (
	[]*big.Int, []*big.Int) {

	left, right := make([]*big.Int, len(values)), make([]*big.Int, len(values))
	modulus := exactGCModulus(ringBits)
	for index, value := range values {
		left[index] = big.NewInt(int64(17*(index+1) + salt))
		left[index].Mod(left[index], modulus)
		right[index] = new(big.Int).Sub(value, left[index])
		right[index].Mod(right[index], modulus)
	}
	return left, right
}

func formalCoxBlockwiseTestDecode(packed *big.Int, count, stride int) []*big.Int {
	result := make([]*big.Int, count)
	mask := exactGCMask(stride)
	for index := range result {
		result[index] = new(big.Int).Rsh(new(big.Int).Set(packed), uint(index*stride))
		result[index].And(result[index], mask)
	}
	return result
}

func formalCoxBlockwiseTestCompute(t testing.TB, plan formalCoxBlockwisePlan,
	rows, noise []*big.Int) ([]*big.Int, bool) {

	t.Helper()
	blockCircuit, err := compileFormalCoxBlockwiseBlock(plan)
	if err != nil {
		t.Fatal(err)
	}
	gridCircuit, err := compileFormalCoxBlockwiseGridCoefficient(plan)
	if err != nil {
		t.Fatal(err)
	}
	updateCircuit, err := compileFormalCoxBlockwiseUpdate(plan)
	if err != nil {
		t.Fatal(err)
	}
	p := plan.Policy.CovariateCount
	state := make([]*big.Int, plan.StateCoordinates)
	for index := range state {
		state[index] = new(big.Int)
	}
	state[plan.StateArithmetic].SetInt64(1)
	for iteration := 0; iteration < plan.Iterations; iteration++ {
		for block := 0; block < plan.TotalBlocks; block++ {
			blockRows := make([]*big.Int, plan.BlockCapacity*plan.RowWidth)
			for index := range blockRows {
				blockRows[index] = new(big.Int)
			}
			firstRow := block * plan.BlockCapacity
			rowsInBlock := plan.BlockCapacity
			if remaining := plan.TotalCapacity - firstRow; remaining < rowsInBlock {
				rowsInBlock = remaining
			}
			copy(blockRows, rows[firstRow*plan.RowWidth:(firstRow+rowsInBlock)*plan.RowWidth])
			local := append(append([]*big.Int{}, blockRows...), state...)
			left, right := formalCoxBlockwiseTestSplit(
				local, plan.RingBits, 100*iteration+block)
			masks := make([]*big.Int, plan.StateArithmetic)
			for index := range masks {
				masks[index] = big.NewInt(int64(31 + index + block))
			}
			validityMask := (iteration+block)%2 == 1
			garbler := append(append([]*big.Int{}, left...), masks...)
			if validityMask {
				garbler = append(garbler, big.NewInt(1))
			} else {
				garbler = append(garbler, big.NewInt(0))
			}
			computed, err := blockCircuit.Compute([]*big.Int{
				exactGCPackChunks(garbler, plan.ContainerBits),
				exactGCPackChunks(right, plan.ContainerBits)})
			if err != nil || len(computed) != 1 {
				t.Fatalf("block circuit %d/%d: %v", iteration, block, err)
			}
			evaluator := formalCoxBlockwiseTestDecode(
				computed[0], plan.StateCoordinates, plan.ContainerBits)
			for index := 0; index < plan.StateArithmetic; index++ {
				state[index] = exactGCReferenceReconstruct(
					masks[index], evaluator[index], plan.RingBits)
			}
			valid := evaluator[plan.StateArithmetic].Bit(0) == 1
			if validityMask {
				valid = !valid
			}
			state[plan.StateArithmetic].SetInt64(0)
			if valid {
				state[plan.StateArithmetic].SetInt64(1)
			}
		}
		offsets := formalCoxBlockwiseStateOffsets(plan.Policy)
		scores := make([]*big.Int, p)
		for index := range scores {
			scores[index] = new(big.Int)
		}
		valid := state[plan.StateArithmetic].Bit(0) == 1
		for grid := 1; grid <= plan.Policy.GridTickCount; grid++ {
			for coefficient := 0; coefficient < p; coefficient++ {
				local := []*big.Int{
					state[offsets.riskCount+grid-1],
					state[offsets.eventCount+grid-1],
					state[offsets.s0+grid-1],
					state[offsets.s1+(grid-1)*p+coefficient],
					state[offsets.eventX+(grid-1)*p+coefficient],
					scores[coefficient], new(big.Int),
				}
				if valid {
					local[6].SetInt64(1)
				}
				left, right := formalCoxBlockwiseTestSplit(
					local, plan.RingBits, 2000+grid*10+coefficient)
				mask := big.NewInt(int64(91 + grid + coefficient))
				validityMask := (grid+coefficient)%2 == 0
				garbler := append(append([]*big.Int{}, left...), mask)
				if validityMask {
					garbler = append(garbler, big.NewInt(1))
				} else {
					garbler = append(garbler, big.NewInt(0))
				}
				computed, err := gridCircuit.Compute([]*big.Int{
					exactGCPackChunks(garbler, plan.ContainerBits),
					exactGCPackChunks(right, plan.ContainerBits)})
				if err != nil || len(computed) != 1 {
					t.Fatalf("grid circuit %d/%d/%d: %v", iteration, grid, coefficient, err)
				}
				evaluator := formalCoxBlockwiseTestDecode(computed[0], 2,
					plan.ContainerBits)
				scores[coefficient] = exactGCReferenceReconstruct(
					mask, evaluator[0], plan.RingBits)
				valid = evaluator[1].Bit(0) == 1
				if validityMask {
					valid = !valid
				}
			}
		}
		local := append(append([]*big.Int{}, state[:p]...), scores...)
		local = append(local, noise[iteration*p:(iteration+1)*p]...)
		if valid {
			local = append(local, big.NewInt(1))
		} else {
			local = append(local, big.NewInt(0))
		}
		local = append(local, big.NewInt(1))
		left, right := formalCoxBlockwiseTestSplit(
			local, plan.RingBits, 1000+iteration)
		masks := make([]*big.Int, p)
		for index := range masks {
			masks[index] = big.NewInt(int64(71 + index + iteration))
		}
		validityMask := iteration%2 == 0
		garbler := append(append([]*big.Int{}, left...), masks...)
		if validityMask {
			garbler = append(garbler, big.NewInt(1))
		} else {
			garbler = append(garbler, big.NewInt(0))
		}
		computed, err := updateCircuit.Compute([]*big.Int{
			exactGCPackChunks(garbler, plan.ContainerBits),
			exactGCPackChunks(right, plan.ContainerBits)})
		if err != nil || len(computed) != 1 {
			t.Fatalf("update circuit %d: %v", iteration, err)
		}
		evaluator := formalCoxBlockwiseTestDecode(computed[0], p+1,
			plan.ContainerBits)
		candidate := make([]*big.Int, p)
		for index := range candidate {
			candidate[index] = exactGCReferenceReconstruct(
				masks[index], evaluator[index], plan.RingBits)
		}
		valid = evaluator[p].Bit(0) == 1
		if validityMask {
			valid = !valid
		}
		projectionLocal := append(append([]*big.Int{}, candidate...), new(big.Int))
		if valid {
			projectionLocal[p].SetInt64(1)
		}
		left, right = formalCoxBlockwiseTestSplit(
			projectionLocal, plan.RingBits, 3000+iteration)
		beta := make([]*big.Int, p)
		for coefficient := range beta {
			projectionCircuit, compileErr :=
				compileFormalCoxBlockwiseProjectionCoefficient(plan, coefficient)
			if compileErr != nil {
				t.Fatal(compileErr)
			}
			mask := big.NewInt(int64(121 + coefficient + iteration))
			validityMask = (iteration+coefficient)%2 == 1
			garbler = append(append([]*big.Int{}, left...), mask)
			if validityMask {
				garbler = append(garbler, big.NewInt(1))
			} else {
				garbler = append(garbler, big.NewInt(0))
			}
			computed, err = projectionCircuit.Compute([]*big.Int{
				exactGCPackChunks(garbler, plan.ContainerBits),
				exactGCPackChunks(right, plan.ContainerBits)})
			if err != nil || len(computed) != 1 {
				t.Fatalf("projection circuit %d/%d: %v",
					iteration, coefficient, err)
			}
			evaluator = formalCoxBlockwiseTestDecode(computed[0], 2,
				plan.ContainerBits)
			beta[coefficient] = exactGCReferenceReconstruct(
				mask, evaluator[0], plan.RingBits)
			coefficientValid := evaluator[1].Bit(0) == 1
			if validityMask {
				coefficientValid = !coefficientValid
			}
			if coefficient == 0 {
				valid = coefficientValid
			} else if coefficientValid != valid {
				t.Fatalf("projection validity mismatch at %d/%d",
					iteration, coefficient)
			}
		}
		state = make([]*big.Int, plan.StateCoordinates)
		for index := range state {
			state[index] = new(big.Int)
		}
		copy(state, beta)
		if valid {
			state[plan.StateArithmetic].SetInt64(1)
		}
	}
	return state[:p], state[plan.StateArithmetic].Bit(0) == 1
}

func TestFormalCoxBlockwisePlanCoversK2K3K5AndNonToyShape(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		policy := formalCoxBlockwiseTestPolicy(t, custodians, 2)
		plan, err := buildFormalCoxBlockwisePlan(
			policy, 2, strings.Repeat(string(rune('a'+custodians)), 64))
		if err != nil {
			t.Fatalf("K=%d: %v", custodians, err)
		}
		if err := validateFormalCoxBlockwisePlan(plan); err != nil {
			t.Fatalf("K=%d invalid plan: %v", custodians, err)
		}
		t.Logf("K=%d costs block=%d grid=%d update=%d projection=%d", custodians,
			plan.BlockCost.EstimatedWorkingByte,
			plan.GridCost.EstimatedWorkingByte,
			plan.UpdateCost.EstimatedWorkingByte,
			plan.ProjectionCost.EstimatedWorkingByte)
		if plan.Policy.CovariateCount != 2 || plan.Policy.GridTickCount != 9 ||
			plan.Iterations != 2 || plan.TotalCapacity != 2 ||
			plan.StateCoordinates != 2+3*9+2*9*2+1 ||
			plan.BlockCost.EstimatedWorkingByte == 0 ||
			plan.UpdateCost.EstimatedWorkingByte == 0 ||
			plan.ProjectionCost.EstimatedWorkingByte == 0 || plan.ProductionReady {
			t.Fatalf("K=%d unexpected non-toy plan: %+v", custodians, plan)
		}
	}
}

func TestFormalCoxBlockwisePlanCommitsScoreApproximationBounds(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		policy := formalCoxBlockwiseTestPolicy(t, custodians, 2)
		plan, err := buildFormalCoxBlockwisePlan(
			policy, 2, strings.Repeat(fmt.Sprintf("%x", custodians), 64))
		if err != nil {
			t.Fatalf("K=%d plan: %v", custodians, err)
		}
		parsed, err := parseFormalCoxBlockwisePolicy(policy)
		if err != nil {
			t.Fatalf("K=%d policy: %v", custodians, err)
		}
		dyadic, err := formalCoxExpDyadic(parsed.expKnots[0], parsed.scale,
			policy.ExpCertificateBits)
		if err != nil {
			t.Fatalf("K=%d exact lower exp weight: %v", custodians, err)
		}
		minimumExactWeight := new(big.Int).Quo(
			new(big.Int).Mul(dyadic.low, parsed.scale),
			jointDPGaussianDyadicScale(policy.ExpCertificateBits))
		if minimumExactWeight.Sign() <= 0 {
			t.Fatalf("K=%d non-positive exact lower exp weight", custodians)
		}
		weightMin := parsed.expValues[0]
		if minimumExactWeight.Cmp(weightMin) < 0 {
			weightMin = minimumExactWeight
		}
		etaRounding := exactGCCeilDiv(new(big.Int).Mul(
			big.NewInt(int64(policy.CovariateCount)),
			new(big.Int).Add(parsed.expValues[len(parsed.expValues)-1], parsed.expError)),
			parsed.scale)
		effectiveExpError := new(big.Int).Add(parsed.expError, etaRounding)
		wantTable := exactGCCeilDiv(new(big.Int).Mul(
			new(big.Int).Mul(big.NewInt(2), parsed.xNorm),
			effectiveExpError), weightMin)
		wantRounding := exactGCCeilDiv(parsed.scale, parsed.expValues[0])
		wantRounding.Add(wantRounding, big.NewInt(1))
		wantNormalizedRounding := big.NewInt(1)
		wantScore := new(big.Int).Add(
			new(big.Int).Add(new(big.Int).Set(wantTable), wantRounding),
			wantNormalizedRounding)
		certificate := plan.ScoreApproximation
		if certificate.Version != formalCoxBlockwiseScoreApproximationVersion ||
			certificate.LinearPredictorFixedPointRoundingMaximumAbsSteps !=
				big.NewInt(int64(policy.CovariateCount)).String() ||
			certificate.ExpWeightLinearPredictorMaximumAbsErrorSteps !=
				etaRounding.String() ||
			certificate.ExpWeightMaximumAbsErrorSteps != effectiveExpError.String() ||
			certificate.MinimumExactWeightSteps != minimumExactWeight.String() ||
			certificate.MinimumTableWeightSteps != parsed.expValues[0].String() ||
			certificate.RiskMeanTableMaximumAbsErrorSteps != wantTable.String() ||
			certificate.RiskMeanFixedPointRoundingMaximumAbsErrorSteps !=
				wantRounding.String() ||
			certificate.NormalizedScoreFixedPointRoundingMaximumAbsErrorSteps !=
				wantNormalizedRounding.String() ||
			certificate.NormalizedScoreMaximumAbsErrorSteps != wantScore.String() {
			t.Fatalf("K=%d score approximation certificate = %+v", custodians,
				certificate)
		}
		tampered := plan
		tampered.ScoreApproximation.ExpWeightLinearPredictorMaximumAbsErrorSteps = "0"
		if err := validateFormalCoxBlockwisePlan(tampered); err == nil {
			t.Fatalf("K=%d accepted omitted eta-rounding score bound", custodians)
		}
		tampered = plan
		tampered.ScoreApproximation.NormalizedScoreFixedPointRoundingMaximumAbsErrorSteps = "0"
		if err := validateFormalCoxBlockwisePlan(tampered); err == nil {
			t.Fatalf("K=%d accepted omitted normalized-score rounding bound", custodians)
		}
		tampered = plan
		tampered.ScoreApproximation.NormalizedScoreMaximumAbsErrorSteps = "0"
		if err := validateFormalCoxBlockwisePlan(tampered); err == nil {
			t.Fatalf("K=%d accepted tampered score approximation certificate", custodians)
		}
	}
}

func TestFormalCoxBlockwiseNumericCertificateCommitsLatticeTrajectoryBound(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		policy := formalCoxBlockwiseTestPolicy(t, custodians, 2)
		parsed, err := parseFormalCoxBlockwisePolicy(policy)
		if err != nil {
			t.Fatalf("K=%d policy: %v", custodians, err)
		}
		certificate, err := formalCoxBlockwiseNumericCertificateForPolicy(policy)
		if err != nil {
			t.Fatalf("K=%d numeric certificate: %v", custodians, err)
		}
		scoreCertificate, err := formalCoxBlockwiseBuildScoreApproximationCertificate(parsed)
		if err != nil {
			t.Fatalf("K=%d score certificate: %v", custodians, err)
		}
		scoreError, ok := new(big.Int).SetString(
			scoreCertificate.NormalizedScoreMaximumAbsErrorSteps, 10)
		if !ok {
			t.Fatalf("K=%d malformed score certificate", custodians)
		}
		gradientError := new(big.Int).Add(scoreError, big.NewInt(1))
		gradientError.Add(gradientError, parsed.noiseBound)
		updateError := exactGCCeilDiv(new(big.Int).Mul(parsed.alpha, gradientError),
			parsed.scale)
		updateError.Add(updateError, big.NewInt(1))
		projectionError := big.NewInt(2)
		iterationCoordinateError := new(big.Int).Add(updateError, projectionError)
		iterationL2 := formalCoxCeilSqrt(new(big.Int).Mul(
			new(big.Int).Mul(iterationCoordinateError, iterationCoordinateError),
			big.NewInt(int64(policy.CovariateCount))))
		contract, err := formalCoxBlockwiseDeriveIdealGradientContract(policy)
		if err != nil {
			t.Fatalf("K=%d contraction contract: %v", custodians, err)
		}
		contractionNumerator, ok := new(big.Int).SetString(
			contract.ContractionFactorNumerator, 10)
		if !ok {
			t.Fatalf("K=%d malformed contraction numerator", custodians)
		}
		contractionDenominator, ok := new(big.Int).SetString(
			contract.ContractionFactorDenominator, 10)
		if !ok {
			t.Fatalf("K=%d malformed contraction denominator", custodians)
		}
		iterations := big.NewInt(int64(policy.Iterations))
		denominatorPower := new(big.Int).Exp(contractionDenominator, iterations, nil)
		numeratorPower := new(big.Int).Exp(contractionNumerator, iterations, nil)
		trajectory := new(big.Rat).SetFrac(
			new(big.Int).Mul(new(big.Int).Set(iterationL2),
				new(big.Int).Sub(new(big.Int).Set(denominatorPower), numeratorPower)),
			new(big.Int).Mul(
				new(big.Int).Exp(contractionDenominator,
					big.NewInt(int64(policy.Iterations-1)), nil),
				new(big.Int).Sub(new(big.Int).Set(contractionDenominator), contractionNumerator)))
		optimizer := new(big.Rat).SetFrac(
			new(big.Int).Mul(parsed.betaNorm, numeratorPower), denominatorPower)
		optimizer.Add(optimizer, trajectory)
		if !certificate.FixedGridTrajectoryPerturbationCertified ||
			!certificate.FixedGridOptimizerDistanceBoundCertified ||
			len(certificate.Blockers) != 1 ||
			certificate.Blockers[0] !=
				"continuous_cox_trajectory_error_bound_unavailable_v1" ||
			certificate.ImplementedGradientPerturbationMaximumAbsSteps != gradientError.String() ||
			certificate.ImplementedUpdatePerturbationMaximumAbsSteps != updateError.String() ||
			certificate.IntegerProjectionPerturbationMaximumAbsSteps != projectionError.String() ||
			certificate.ImplementedIterationPerturbationL2Steps != iterationL2.String() ||
			certificate.FixedGridTrajectoryErrorUpperNumerator != trajectory.Num().String() ||
			certificate.FixedGridTrajectoryErrorUpperDenominator != trajectory.Denom().String() ||
			certificate.FixedGridOptimizerDistanceUpperNumerator != optimizer.Num().String() ||
			certificate.FixedGridOptimizerDistanceUpperDenominator != optimizer.Denom().String() ||
			certificate.ContinuousCoxTrajectoryCertified ||
			certificate.OptimizerDistanceCertified || certificate.EndToEndNumericCertified ||
			certificate.ProductionReady {
			t.Fatalf("K=%d numeric trajectory certificate = %+v", custodians,
				certificate)
		}
		tampered := certificate
		tampered.ImplementedUpdatePerturbationMaximumAbsSteps = "0"
		if err := formalCoxBlockwiseValidateNumericCertificate(policy, tampered); err == nil {
			t.Fatalf("K=%d accepted a tampered lattice trajectory bound", custodians)
		}
	}
}

func TestFormalCoxBlockwiseCircuitCacheCoalescesConcurrentCompilation(t *testing.T) {
	const workers = 8
	const source = "formal-cox-blockwise-single-flight-test-v1"
	key := formalCoxBlockwiseTestCircuitCacheKey(source)
	formalCoxBlockwiseCircuitCache.Lock()
	delete(formalCoxBlockwiseCircuitCache.entries, key)
	formalCoxBlockwiseCircuitCache.Unlock()
	previousProcs := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(previousProcs)

	start := make(chan struct{})
	ready := make(chan struct{}, workers)
	release := make(chan struct{})
	results := make(chan *circuit.Circuit, workers)
	errorsOut := make(chan error, workers)
	var calls atomic.Int32
	compilerEntered := make(chan struct{}, workers)
	compile := func(string) (*circuit.Circuit, error) {
		calls.Add(1)
		compilerEntered <- struct{}{}
		<-release
		return &circuit.Circuit{}, nil
	}

	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			ready <- struct{}{}
			<-start
			circ, err := compileFormalCoxBlockwiseSourceWith(source,
				"single-flight test", compile)
			results <- circ
			errorsOut <- err
		}()
	}
	var releaseOnce sync.Once
	releaseWorkers := func() { releaseOnce.Do(func() { close(release) }) }
	defer func() {
		releaseWorkers()
		group.Wait()
		formalCoxBlockwiseCircuitCache.Lock()
		delete(formalCoxBlockwiseCircuitCache.entries, key)
		formalCoxBlockwiseCircuitCache.Unlock()
	}()
	for range workers {
		<-ready
	}
	close(start)
	if <-compilerEntered; calls.Load() != 1 {
		t.Fatalf("compiler calls before wait = %d, want 1", calls.Load())
	}
	for range 10000 {
		runtime.Gosched()
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("identical concurrent source compiled %d times", got)
	}
	releaseWorkers()
	group.Wait()
	close(results)
	close(errorsOut)
	var first *circuit.Circuit
	for circ := range results {
		if circ == nil {
			t.Fatal("coalesced compilation returned a nil circuit")
		}
		if first == nil {
			first = circ
		} else if circ != first {
			t.Fatal("waiter received a different compiled circuit")
		}
	}
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestFormalCoxBlockwiseCircuitCacheDoesNotRetainFailedCompilation(t *testing.T) {
	const source = "formal-cox-blockwise-failed-single-flight-test-v1"
	key := formalCoxBlockwiseTestCircuitCacheKey(source)
	formalCoxBlockwiseCircuitCache.Lock()
	delete(formalCoxBlockwiseCircuitCache.entries, key)
	formalCoxBlockwiseCircuitCache.Unlock()
	defer func() {
		formalCoxBlockwiseCircuitCache.Lock()
		delete(formalCoxBlockwiseCircuitCache.entries, key)
		formalCoxBlockwiseCircuitCache.Unlock()
	}()
	want := errors.New("compiler unavailable")
	if _, err := compileFormalCoxBlockwiseSourceWith(source, "failure test",
		func(string) (*circuit.Circuit, error) { return nil, want }); !errors.Is(err, want) {
		t.Fatalf("failed compilation error = %v, want wrapped %v", err, want)
	}
	compiled := &circuit.Circuit{}
	got, err := compileFormalCoxBlockwiseSourceWith(source, "retry test",
		func(string) (*circuit.Circuit, error) { return compiled, nil })
	if err != nil || got != compiled {
		t.Fatalf("retry after failed compilation = (%p, %v), want (%p, nil)",
			got, err, compiled)
	}
}

func TestFormalCoxBlockwiseCircuitCacheEvictsOnlyLeastRecentEntry(t *testing.T) {
	formalCoxBlockwiseCircuitCache.Lock()
	previousEntries := formalCoxBlockwiseCircuitCache.entries
	previousFlights := formalCoxBlockwiseCircuitCache.flights
	previousOrder := formalCoxBlockwiseCircuitCache.order
	formalCoxBlockwiseCircuitCache.entries = make(map[string]*circuit.Circuit)
	formalCoxBlockwiseCircuitCache.flights = make(map[string]*formalCoxBlockwiseCircuitFlight)
	formalCoxBlockwiseCircuitCache.order = nil
	formalCoxBlockwiseCircuitCache.Unlock()
	t.Cleanup(func() {
		formalCoxBlockwiseCircuitCache.Lock()
		formalCoxBlockwiseCircuitCache.entries = previousEntries
		formalCoxBlockwiseCircuitCache.flights = previousFlights
		formalCoxBlockwiseCircuitCache.order = previousOrder
		formalCoxBlockwiseCircuitCache.Unlock()
	})

	var calls atomic.Int32
	compile := func(string) (*circuit.Circuit, error) {
		calls.Add(1)
		return &circuit.Circuit{}, nil
	}
	compileSource := func(index int) *circuit.Circuit {
		t.Helper()
		circ, err := compileFormalCoxBlockwiseSourceWith(
			fmt.Sprintf("formal-cox-blockwise-lru-%d", index), "LRU test", compile)
		if err != nil || circ == nil {
			t.Fatalf("compile %d = (%p, %v)", index, circ, err)
		}
		return circ
	}

	for index := 0; index < 8; index++ {
		compileSource(index)
	}
	first := compileSource(0) // Refresh it before adding the ninth circuit.
	compileSource(8)
	if got := calls.Load(); got != 9 {
		t.Fatalf("initial compiler calls = %d, want 9", got)
	}
	formalCoxBlockwiseCircuitCache.Lock()
	entries := len(formalCoxBlockwiseCircuitCache.entries)
	formalCoxBlockwiseCircuitCache.Unlock()
	if entries != formalCoxBlockwiseCircuitCacheEntries {
		t.Fatalf("cache entries = %d, want %d", entries,
			formalCoxBlockwiseCircuitCacheEntries)
	}
	if got := compileSource(0); got != first || calls.Load() != 9 {
		t.Fatalf("recent entry was evicted: circuit=%p calls=%d", got, calls.Load())
	}
	compileSource(1)
	if got := calls.Load(); got != 10 {
		t.Fatalf("least-recent entry was not evicted: compiler calls=%d", got)
	}
}

func TestFormalCoxBlockwiseCircuitsMatchIndependentOracleK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		policy := formalCoxBlockwiseTestPolicy(t, custodians, 2)
		plan, err := buildFormalCoxBlockwisePlan(
			policy, 2, strings.Repeat(string(rune('0'+custodians)), 64))
		if err != nil {
			t.Fatalf("K=%d plan: %v", custodians, err)
		}
		rows := formalCoxBlockwiseTestRows(policy, plan.RingBits)
		noise := formalCoxBlockwiseTestNoise(plan)
		want, wantValid, err := referenceFormalCoxBlockwiseSchedule(
			plan, rows, noise, []bool{true, true})
		if err != nil {
			t.Fatalf("K=%d oracle: %v", custodians, err)
		}
		got, gotValid := formalCoxBlockwiseTestCompute(t, plan, rows, noise)
		if gotValid != wantValid || len(got) != len(want) {
			t.Fatalf("K=%d validity/shape = (%v,%d), want (%v,%d)",
				custodians, gotValid, len(got), wantValid, len(want))
		}
		for coefficient := range got {
			if got[coefficient].Cmp(want[coefficient]) != 0 {
				t.Fatalf("K=%d beta[%d]=%s want %s", custodians,
					coefficient, got[coefficient], want[coefficient])
			}
		}
	}
}

func TestFormalCoxBlockwiseThreeCovariateCircuitsMatchIndependentOracleK2K3K5(
	t *testing.T,
) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+fmt.Sprint(custodians), func(t *testing.T) {
			compiled, err := formalCoxCompileSignedRSchema(
				formalCoxRSchemaFixture(t, custodians, 3))
			if err != nil {
				t.Fatalf("compile signed three-covariate schema: %v", err)
			}
			plan, err := buildFormalCoxBlockwisePlan(compiled.Policy, 1,
				strings.Repeat(string(rune('0'+custodians)), 64))
			if err != nil {
				t.Fatalf("K=%d plan: %v", custodians, err)
			}
			rows := formalCoxBlockwiseTestRows(plan.Policy, plan.RingBits)
			noise := formalCoxBlockwiseTestNoise(plan)
			noiseValidity := make([]bool, plan.Iterations)
			for index := range noiseValidity {
				noiseValidity[index] = true
			}
			want, wantValid, err := referenceFormalCoxBlockwiseSchedule(
				plan, rows, noise, noiseValidity)
			if err != nil {
				t.Fatalf("K=%d oracle: %v", custodians, err)
			}
			got, gotValid := formalCoxBlockwiseTestCompute(t, plan, rows, noise)
			if gotValid != wantValid || len(got) != len(want) {
				t.Fatalf("K=%d validity/shape = (%v,%d), want (%v,%d)",
					custodians, gotValid, len(got), wantValid, len(want))
			}
			for coefficient := range got {
				if got[coefficient].Cmp(want[coefficient]) != 0 {
					t.Fatalf("K=%d beta[%d]=%s want %s", custodians,
						coefficient, got[coefficient], want[coefficient])
				}
			}
		})
	}
}

func TestFormalCoxBlockwiseResidentShapeIsIndependentOfN(t *testing.T) {
	smallPolicy := formalCoxBlockwiseTestPolicy(t, 3, 64)
	largePolicy := formalCoxBlockwiseTestPolicy(t, 3, 100000)
	small, err := buildFormalCoxBlockwisePlan(
		smallPolicy, 1, strings.Repeat("8", 64))
	if err != nil {
		t.Fatalf("small: %v", err)
	}
	large, err := buildFormalCoxBlockwisePlan(
		largePolicy, 1, strings.Repeat("9", 64))
	if err != nil {
		t.Fatalf("large: %v", err)
	}
	if small.BlockCapacity != large.BlockCapacity ||
		small.StateCoordinates != large.StateCoordinates ||
		small.PeakResidentCoordinates != large.PeakResidentCoordinates ||
		small.ProjectionSearchSteps != large.ProjectionSearchSteps ||
		small.BlockCost.GarblerInputBits != large.BlockCost.GarblerInputBits ||
		small.BlockCost.EvaluatorInputBits != large.BlockCost.EvaluatorInputBits ||
		small.BlockCost.OutputBits != large.BlockCost.OutputBits ||
		small.BlockCost.EstimatedWorkingByte != large.BlockCost.EstimatedWorkingByte ||
		small.GridCost.EstimatedWorkingByte != large.GridCost.EstimatedWorkingByte ||
		small.UpdateCost.EstimatedWorkingByte != large.UpdateCost.EstimatedWorkingByte ||
		small.ProjectionCost.EstimatedWorkingByte != large.ProjectionCost.EstimatedWorkingByte ||
		large.TotalBlocks <= small.TotalBlocks {
		t.Fatalf("resident shape grew with N: small=%+v large=%+v", small, large)
	}
}
