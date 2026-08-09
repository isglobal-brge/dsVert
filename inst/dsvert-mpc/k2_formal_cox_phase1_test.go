package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"math/rand"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func formalCoxTestPolicy(t testing.TB, custodians int) formalCoxPhase1Policy {
	t.Helper()
	peers := make([]string, custodians)
	for index := range peers {
		peers[index] = "peer-" + string(rune('a'+index))
	}
	knots := make([]string, 9)
	values := make([]string, 8)
	for index := range knots {
		knots[index] = big.NewInt(int64(-256 + 64*index)).String()
		if index < len(values) {
			midpoint := float64(-256+64*index+32) / 256
			values[index] = big.NewInt(int64(math.Round(
				math.Exp(midpoint) * 256))).String()
		}
	}
	hash := func(value byte) string { return strings.Repeat(string(value), 64) }
	policy := formalCoxPhase1Policy{
		Version:        formalCoxPhase1PolicyVersion,
		ArtifactSHA256: hash('1'), CapsuleSHA256: hash('2'),
		SnapshotSHA256: hash('3'), PinsetSHA256: hash('4'),
		CompilerSHA256: hash('5'), TheoremSHA256: hash('6'),
		CustodianPeers: peers, ComputePeers: []string{"peer-a", "peer-b"},
		Adjacency: "add_remove_patient", EntryMode: "none",
		Capacity: 1, CovariateCount: 1, GridTickCount: 2,
		Iterations: 1, NoiseChunkCount: 1, FracBits: 8,
		XLower: []string{"-256"}, XUpper: []string{"256"},
		CovariateL2Bound: "256", BetaL2Bound: "256",
		MinimumAtRisk: 1, Alpha: "64", Ridge: "0",
		Epsilon: "2", Delta: "0.000001", NoiseBound: "64",
		ExpKnots: knots, ExpValues: values, ExpErrorUpper: "90",
		ExpCertificateBits: 160,
		Ties:               "breslow",
		PrivacyUnit:        "one_patient_one_fixed_capacity_slot_v1",
		ReductionOrder:     "grid_then_capacity_slot_then_covariate_v1",
		Truncation:         "exact_signed_floor_after_each_fixed_point_product_v1",
		Projection:         "exact_integer_l2_radial_toward_zero_v1",
		InputLayout:        "capacity_major_all_k_validity_entry_stop_status_design_then_zero_beta_blinding_then_iteration_noise_then_sampler_chunk_validity_v2",
		InputSharing:       "additive_mod_2k_two_recipient_v1",
		NoiseInput:         "one_joint_finite_support_discrete_gaussian_vector_tv_charged_to_delta_v1",
		Output:             "sealed_final_beta_additive_shares_and_xor_execution_validity_v1",
	}
	digest, err := formalCoxExpTableDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.ExpTableSHA256 = digest
	return policy
}

func formalCoxTestInput(policy formalCoxPhase1Policy,
	ringBits int) []*big.Int {
	result := make([]*big.Int, 0,
		policy.Capacity*(len(policy.CustodianPeers)+3+policy.CovariateCount)+
			policy.Iterations*policy.CovariateCount)
	for row := 0; row < policy.Capacity; row++ {
		for range policy.CustodianPeers {
			result = append(result, big.NewInt(1))
		}
		result = append(result, big.NewInt(0), big.NewInt(1), big.NewInt(1))
		for coefficient := 0; coefficient < policy.CovariateCount; coefficient++ {
			value := big.NewInt(int64(128 - 32*coefficient))
			if row&1 == 1 {
				value.Neg(value)
			}
			result = append(result, formalCoxResidue(value, ringBits))
		}
	}
	for coefficient := 0; coefficient < policy.CovariateCount; coefficient++ {
		result = append(result, big.NewInt(0))
	}
	for iteration := 0; iteration < policy.Iterations; iteration++ {
		for coefficient := 0; coefficient < policy.CovariateCount; coefficient++ {
			value := big.NewInt(int64(32 - 8*coefficient + iteration))
			result = append(result, formalCoxResidue(value, ringBits))
		}
	}
	for chunk := 0; chunk < policy.NoiseChunkCount; chunk++ {
		result = append(result, big.NewInt(1))
	}
	return result
}

func formalCoxTestSession(t testing.TB,
	policy formalCoxPhase1Policy) exactGCSession {
	t.Helper()
	plan, err := planFormalCoxPhase1(policy)
	if err != nil {
		t.Fatal(err)
	}
	purpose, err := formalCoxPurpose(policy)
	if err != nil {
		t.Fatal(err)
	}
	return exactGCSession{
		SessionID: sha256.Sum256([]byte("formal-cox/session/test")),
		MasterKey: sha256.Sum256([]byte("formal-cox/master/test")),
		GarblerID: policy.ComputePeers[0], EvaluatorID: policy.ComputePeers[1],
		Purpose: purpose,
		Spec: exactGCCircuitSpec{
			Operation: exactGCFormalCoxIterations,
			RingBits:  plan.RingBits, FracBits: policy.FracBits,
			VectorLen: plan.InputCoordinates,
		},
	}
}

func formalCoxTestSplitSourceAndNoise128(rng *rand.Rand,
	input []*big.Int, plan formalCoxPhase1Plan,
) ([]*big.Int, []*big.Int) {
	left := make([]*big.Int, len(input))
	right := make([]*big.Int, len(input))
	noiseStart := plan.RowCoordinates + plan.ZeroBlindCoordinates
	for index := range input {
		bits := plan.RingBits
		if index < plan.RowCoordinates || index >= noiseStart {
			bits = 128
		}
		value := new(big.Int).And(new(big.Int).Set(input[index]), exactGCMask(bits))
		left[index] = exactGCTestRandomResidue(rng, bits)
		right[index] = new(big.Int).Sub(value, left[index])
		right[index].Mod(right[index], exactGCModulus(bits))
	}
	return left, right
}

func TestFormalCoxPhase1PlanCoversK2K3K4K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 4, 5} {
		policy := formalCoxTestPolicy(t, custodians)
		plan, err := planFormalCoxPhase1(policy)
		if err != nil {
			t.Fatalf("K=%d: %v", custodians, err)
		}
		wantRows := custodians + 4
		if plan.RingBits != 128 || plan.ContainerBits != 128 ||
			plan.RowCoordinates != wantRows || plan.ZeroBlindCoordinates != 1 ||
			plan.NoiseCoordinates != 1 || plan.NoiseValidityCoordinates != 1 ||
			plan.InputCoordinates != wantRows+3 ||
			plan.OutputCoordinates != 1 ||
			!plan.DeterministicNoWrap || !plan.FiniteNoiseNoWrap ||
			plan.EndToEndNumericCertificate || plan.ProductionReleaseReady {
			t.Fatalf("K=%d unexpected plan: %+v", custodians, plan)
		}
		if _, _, err := validateFormalCoxSession(
			formalCoxTestSession(t, policy), policy); err != nil {
			t.Fatalf("K=%d invalid internal session: %v", custodians, err)
		}
	}
}

func TestFormalCoxPhase1ExpCertificateIsOutwardAndCommitted(t *testing.T) {
	policy := formalCoxTestPolicy(t, 3)
	if _, err := parseFormalCoxPhase1Policy(policy); err != nil {
		t.Fatal(err)
	}
	tampered := policy
	tampered.ExpValues = append([]string(nil), policy.ExpValues...)
	changed, _ := new(big.Int).SetString(tampered.ExpValues[3], 10)
	tampered.ExpValues[3] = changed.Add(changed, big.NewInt(1)).String()
	if _, err := parseFormalCoxPhase1Policy(tampered); err == nil ||
		!strings.Contains(err.Error(), "commitment") {
		t.Fatalf("tampered table was accepted: %v", err)
	}
	understated := policy
	understated.ExpErrorUpper = "1"
	understated.ExpTableSHA256, _ = formalCoxExpTableDigest(understated)
	if _, err := parseFormalCoxPhase1Policy(understated); err == nil ||
		!strings.Contains(err.Error(), "outward error") {
		t.Fatalf("understated exp error was accepted: %v", err)
	}
}

func TestFormalCoxPhase1PlannerSelectsDynamicRingAndFailsBeyondRing4096(t *testing.T) {
	policy := formalCoxTestPolicy(t, 2)
	policy.NoiseBound = new(big.Int).Lsh(big.NewInt(1), 150).String()
	plan, err := planFormalCoxPhase1(policy)
	if err != nil {
		t.Fatal(err)
	}
	if plan.RingBits != 256 || !plan.DeterministicNoWrap ||
		!plan.FiniteNoiseNoWrap {
		t.Fatalf("dynamic Ring256 not selected: %+v", plan)
	}
	policy.NoiseBound = new(big.Int).Lsh(big.NewInt(1), 4095).String()
	_, err = planFormalCoxPhase1(policy)
	var typed *formalCoxNumericBackendError
	if !errors.As(err, &typed) || typed.Code != "numeric_backend_unrepresentable" ||
		typed.RequiredBits <= exactGCMaxRingBits {
		t.Fatalf("expected typed Ring4096 failure, got %T %v", err, err)
	}
}

func TestFormalCoxPhase1DynamicRingExactlyLiftsRing128SourceAndNoiseShares(t *testing.T) {
	if os.Getenv("DSVERT_RUN_HEAVY_FORMAL_COX_GC") != "1" {
		t.Skip("set DSVERT_RUN_HEAVY_FORMAL_COX_GC=1 for the full Ring256 Cox compiler/execution proof")
	}
	policy := formalCoxTestPolicy(t, 3)
	policy.NoiseBound = new(big.Int).Lsh(big.NewInt(1), 150).String()
	plan, err := planFormalCoxPhase1(policy)
	if err != nil || plan.RingBits != 256 {
		t.Fatalf("dynamic plan: %+v %v", plan, err)
	}
	input := formalCoxTestInput(policy, plan.RingBits)
	xIndex := len(policy.CustodianPeers) + 3
	noiseIndex := plan.RowCoordinates + plan.ZeroBlindCoordinates
	input[xIndex] = exactGCEncodeSigned(big.NewInt(-128), plan.RingBits)
	input[noiseIndex] = exactGCEncodeSigned(big.NewInt(-32), plan.RingBits)
	left, right := formalCoxTestSplitSourceAndNoise128(
		rand.New(rand.NewSource(256)), input, plan)
	mask := new(big.Int).Lsh(big.NewInt(1), 200)
	garblerValues := append(append([]*big.Int(nil), left...), mask, big.NewInt(1))
	circ, err := compileFormalCoxCircuit(policy, plan.RingBits)
	if err != nil {
		t.Fatal(err)
	}
	compute := func(g []*big.Int) (*big.Int, bool, error) {
		outputs, err := circ.Compute([]*big.Int{
			exactGCPackChunks(g, plan.ContainerBits),
			exactGCPackChunks(right, plan.ContainerBits),
		})
		if err != nil || len(outputs) != 1 {
			return nil, false, err
		}
		coefficientShare := new(big.Int).And(
			new(big.Int).Set(outputs[0]), exactGCMask(plan.RingBits))
		validityShare := new(big.Int).Rsh(
			new(big.Int).Set(outputs[0]), uint(plan.ContainerBits))
		return exactGCReferenceReconstruct(mask, coefficientShare, plan.RingBits),
			true != (validityShare.Bit(0) == 1), nil
	}
	got, valid, err := compute(garblerValues)
	want, wantValid, oracleErr := referenceFormalCoxIterations(
		policy, input, plan.RingBits)
	if err != nil || oracleErr != nil || !valid || valid != wantValid ||
		got.Cmp(want[0]) != 0 {
		t.Fatalf("dynamic Ring128 lift mismatch: (%v,%v,%v) want (%v,%v,%v)",
			got, valid, err, want, wantValid, oracleErr)
	}

	// A peer cannot smuggle a wider share into the Ring128 materializer lane:
	// the low residue still reconstructs, but the sealed validity bit fails.
	malformed := append([]*big.Int(nil), garblerValues...)
	malformed[xIndex] = new(big.Int).Add(
		new(big.Int).Set(malformed[xIndex]), new(big.Int).Lsh(big.NewInt(1), 128))
	malformedGot, malformedValid, err := compute(malformed)
	if err != nil || malformedValid || malformedGot.Sign() != 0 {
		t.Fatalf("wide source-share injection was not sealed: %v %v %v",
			malformedGot, malformedValid, err)
	}
}

func TestFormalCoxPhase1DynamicRingLiftContractIsGenerated(t *testing.T) {
	policy := formalCoxTestPolicy(t, 3)
	policy.NoiseBound = new(big.Int).Lsh(big.NewInt(1), 150).String()
	plan, err := planFormalCoxPhase1(policy)
	if err != nil || plan.RingBits != 256 {
		t.Fatalf("dynamic plan: %+v %v", plan, err)
	}
	source, err := formalCoxCircuitSource(policy, plan.RingBits)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"func inputFits128(value uint256) bool",
		"return (value >> 128) == 0",
		"func liftSigned128(value uint128) uint256",
		"result = result | uint256(0xffffffffffffffffffffffffffffffff00000000000000000000000000000000)",
		"executionValid = executionValid && inputFits128(g[",
		"&& inputFits128(e[",
		"noise0_0 := liftSigned128(noise0_0Low128)",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("dynamic Ring128 lift contract omitted %q", required)
		}
	}
}

func TestFormalCoxPhase1CircuitMatchesIndependentLatticeOracle(t *testing.T) {
	for _, custodians := range []int{2, 3, 4, 5} {
		policy := formalCoxTestPolicy(t, custodians)
		plan, err := planFormalCoxPhase1(policy)
		if err != nil {
			t.Fatal(err)
		}
		input := formalCoxTestInput(policy, plan.RingBits)
		left, right := exactGCTestSplit(
			rand.New(rand.NewSource(int64(100+custodians))), input, plan.RingBits)
		mask := big.NewInt(int64(987654 + custodians))
		validityMask := custodians&1 == 0
		garblerValues := append(append([]*big.Int{}, left...), mask)
		garblerValues = append(garblerValues,
			big.NewInt(int64(boolToUint64(validityMask))))
		circ, err := compileFormalCoxCircuit(policy, plan.RingBits)
		if err != nil {
			t.Fatalf("K=%d compile: %v", custodians, err)
		}
		outputs, err := circ.Compute([]*big.Int{
			exactGCPackChunks(garblerValues, plan.ContainerBits),
			exactGCPackChunks(right, plan.ContainerBits),
		})
		if err != nil || len(outputs) != 1 {
			t.Fatalf("K=%d compute: %v / %d", custodians, err, len(outputs))
		}
		coefficientShare := new(big.Int).And(
			new(big.Int).Set(outputs[0]), exactGCMask(plan.RingBits))
		validityShare := new(big.Int).Rsh(
			new(big.Int).Set(outputs[0]), uint(plan.ContainerBits))
		got := exactGCReferenceReconstruct(mask, coefficientShare, plan.RingBits)
		gotValid := validityMask != (validityShare.Bit(0) == 1)
		want, wantValid, err := referenceFormalCoxIterations(
			policy, input, plan.RingBits)
		if err != nil || got.Cmp(want[0]) != 0 || gotValid != wantValid {
			t.Fatalf("K=%d circuit=(%s,%v), oracle=(%v,%v), err=%v",
				custodians, got, gotValid, want, wantValid, err)
		}
	}
}

func TestFormalCoxPinnedCompilerPanicBecomesTypedError(t *testing.T) {
	// The pinned compiler historically panicked when a binary operation
	// assigned an already constant-folded output. Keep the purpose-bound
	// runner fail-closed even if a future circuit generator regresses.
	source := `package main
func main(g [1]uint128, e [1]uint128) [1]uint128 {
	var out [1]uint128
	x := uint128(0)
	if true { x = x + uint128(1) }
	out[0] = x
	return out
}`
	_, err := formalCoxCompileSource(source)
	if err == nil {
		t.Skip("pinned compiler no longer panics on the historical reproducer")
	}
	var classified *exactGCClassifiedError
	if !errors.As(err, &classified) ||
		classified.Code != exactGCFailureNumericBackendUnavailable {
		t.Fatalf("compiler failure was not typed: %T %v", err, err)
	}
}

func TestFormalCoxPhase1RealTwoPeerYaoProtocolK2K3K4K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 4, 5} {
		policy := formalCoxTestPolicy(t, custodians)
		session := formalCoxTestSession(t, policy)
		input := formalCoxTestInput(policy, session.Spec.RingBits)
		leftShares, rightShares := exactGCTestSplit(
			rand.New(rand.NewSource(int64(700+custodians))), input,
			session.Spec.RingBits)
		left, right := net.Pipe()
		_ = left.SetDeadline(time.Now().Add(60 * time.Second))
		_ = right.SetDeadline(time.Now().Add(60 * time.Second))
		type result struct {
			output formalCoxSealedOutput
			err    error
		}
		garbler := make(chan result, 1)
		go func() {
			output, err := runFormalCoxGarbler(left, session, policy, leftShares)
			garbler <- result{output: output, err: err}
		}()
		evaluator, evaluatorErr := runFormalCoxEvaluator(
			right, session, policy, rightShares)
		garblerResult := <-garbler
		left.Close()
		right.Close()
		if evaluatorErr != nil || garblerResult.err != nil {
			t.Fatalf("K=%d Yao: garbler=%v evaluator=%v",
				custodians, garblerResult.err, evaluatorErr)
		}
		opened, valid, err := reconstructFormalCoxOutput(
			garblerResult.output, evaluator, session.Spec.RingBits)
		want, wantValid, oracleErr := referenceFormalCoxIterations(
			policy, input, session.Spec.RingBits)
		if err != nil || oracleErr != nil || valid != wantValid ||
			len(opened) != 1 || opened[0].Cmp(want[0]) != 0 {
			t.Fatalf("K=%d sealed output mismatch: %v %v / %v %v / %v %v",
				custodians, opened, valid, want, wantValid, err, oracleErr)
		}
	}
}

func TestFormalCoxPhase1MalformedNoiseFailsSealedWithoutOpeningIntermediate(t *testing.T) {
	policy := formalCoxTestPolicy(t, 4)
	plan, err := planFormalCoxPhase1(policy)
	if err != nil {
		t.Fatal(err)
	}
	input := formalCoxTestInput(policy, plan.RingBits)
	noiseIndex := plan.RowCoordinates + plan.ZeroBlindCoordinates
	input[noiseIndex] = big.NewInt(65)
	got, valid, err := referenceFormalCoxIterations(policy, input, plan.RingBits)
	if err != nil || valid || len(got) != 1 || got[0].Sign() != 0 {
		t.Fatalf("malformed noise did not fail sealed: %v %v %v", got, valid, err)
	}
}

func TestFormalCoxPhase1RecordLayerRejectsTamperReplayAndWrongRecipient(t *testing.T) {
	policy := formalCoxTestPolicy(t, 4)
	session := formalCoxTestSession(t, policy)
	plaintext := []byte("formal-cox-private-yao-frame")
	raw := exactGCTestRecord(session, plaintext)
	if bytes.Contains(raw, plaintext) {
		t.Fatal("Cox relay record exposed plaintext")
	}

	t.Run("tamper", func(t *testing.T) {
		tampered := append([]byte(nil), raw...)
		tampered[len(tampered)-1] ^= 0x80
		receiver, err := newExactGCSecureRecordRW(
			&readWriter{Reader: bytes.NewReader(tampered)}, session,
			exactGCRoleEvaluator)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(receiver); err == nil ||
			!strings.Contains(err.Error(), "authentication failed") {
			t.Fatalf("tampered Cox record was accepted: %v", err)
		}
	})

	t.Run("replay", func(t *testing.T) {
		replayed := append(append([]byte(nil), raw...), raw...)
		receiver, err := newExactGCSecureRecordRW(
			&readWriter{Reader: bytes.NewReader(replayed)}, session,
			exactGCRoleEvaluator)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(plaintext))
		if _, err := io.ReadFull(receiver, got); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(receiver, got); err == nil ||
			!strings.Contains(err.Error(), "replayed or out-of-order") {
			t.Fatalf("replayed Cox record was accepted: %v", err)
		}
	})

	t.Run("wrong recipient", func(t *testing.T) {
		wrong := session
		wrong.EvaluatorID = "peer-c"
		if _, _, err := validateFormalCoxSession(wrong, policy); err == nil {
			t.Fatal("Cox policy accepted the wrong evaluator")
		}
		receiver, err := newExactGCSecureRecordRW(
			&readWriter{Reader: bytes.NewReader(raw)}, wrong,
			exactGCRoleEvaluator)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(receiver); err == nil ||
			!strings.Contains(err.Error(), "authentication failed") {
			t.Fatalf("wrong Cox recipient decrypted a record: %v", err)
		}
	})
}

func TestFormalCoxDPPlanHasFiniteImplementedSensitivityFixedShapeAndTVDelta(t *testing.T) {
	policy := formalCoxTestPolicy(t, 4)
	// Keep the public fixture inside the productive one-draw resource envelope;
	// resource infeasibility is a typed backend result, not a privacy shortcut.
	policy.XLower = []string{"-16"}
	policy.XUpper = []string{"16"}
	policy.CovariateL2Bound = "16"
	parsed, err := parseFormalCoxPhase1Policy(policy)
	if err != nil {
		t.Fatal(err)
	}
	score, adaptive, riskRounding, normalizedRounding :=
		formalCoxImplementedScoreSensitivity(parsed)
	if score.String() != "74" || adaptive.Cmp(score) != 0 ||
		riskRounding.String() != "4" || normalizedRounding.String() != "5" {
		t.Fatalf("unexpected exact lattice sensitivity: score=%s adaptive=%s risk=%s normalized=%s",
			score, adaptive, riskRounding, normalizedRounding)
	}

	plan, err := planFormalCoxDP(policy)
	if err != nil {
		t.Fatal(err)
	}
	if plan.NoiseCoordinates != policy.Iterations*policy.CovariateCount ||
		plan.SamplerChunkCount != policy.NoiseChunkCount ||
		!plan.PolicyNoiseChunkCountMatches ||
		!plan.NoiseCoordinatesFixedShape || !plan.PrivacyPlanCertified ||
		!plan.FiniteSupportTransferCharged || !plan.FixedWorkSampler ||
		!plan.NoWrapCertified || plan.RuntimeNoiseAdapterConnected ||
		plan.StickyDurableFinalizerConnected || plan.ProductionReady ||
		plan.PolicyNoiseBoundMatches || len(plan.Blockers) == 0 {
		t.Fatalf("dishonest or incomplete Cox DP plan: %+v", plan)
	}
	tail := jointDPGaussianOneDrawRat(plan.VectorTailTVUpperNumerator,
		plan.VectorTailTVUpperDenominator)
	cdf := jointDPGaussianOneDrawRat(plan.VectorCDFTVUpperNumerator,
		plan.VectorCDFTVUpperDenominator)
	total := jointDPGaussianOneDrawRat(plan.VectorTotalTVUpperNumerator,
		plan.VectorTotalTVUpperDenominator)
	implementation := jointDPGaussianOneDrawRat(
		plan.ImplementationDeltaNumerator,
		plan.ImplementationDeltaDenominator)
	core := jointDPGaussianOneDrawRat(plan.CommonPlan.CoreDeltaNumerator,
		plan.CommonPlan.CoreDeltaDenominator)
	delta := jointDPGaussianOneDrawRat("1", "1000000")
	if tail == nil || cdf == nil || total == nil || implementation == nil ||
		core == nil || new(big.Rat).Add(tail, cdf).Cmp(total) != 0 ||
		new(big.Rat).Add(core, implementation).Cmp(delta) > 0 {
		t.Fatal("finite-support TV was not charged inside signed delta")
	}

	policy.NoiseBound = plan.MaximumNoiseMagnitude
	bound, err := planFormalCoxDP(policy)
	if err != nil || !bound.PolicyNoiseBoundMatches ||
		bound.NoiseCoordinates != plan.NoiseCoordinates ||
		bound.AdaptiveStackSensitivitySteps != plan.AdaptiveStackSensitivitySteps {
		t.Fatalf("signed fixed-shape noise bound did not close: %+v %v", bound, err)
	}
	policy.NoiseBound = new(big.Int).Sub(
		new(big.Int).Set(parsed.noiseBound), big.NewInt(1)).String()
	mismatch, err := planFormalCoxDP(policy)
	if err != nil || mismatch.PolicyNoiseBoundMatches {
		t.Fatalf("noise-bound substitution was accepted: %+v %v", mismatch, err)
	}
	invalidPrivacy := policy
	invalidPrivacy.Delta = "1"
	if _, err := planFormalCoxDP(invalidPrivacy); err == nil {
		t.Fatal("unsigned/invalid Cox privacy parameters were accepted")
	}
}

func TestFormalCoxDPPlanFixedShapeAcrossK2K3K4K5(t *testing.T) {
	var reference formalCoxDPPlan
	for _, custodians := range []int{2, 3, 4, 5} {
		policy := formalCoxTestPolicy(t, custodians)
		policy.XLower = []string{"-16"}
		policy.XUpper = []string{"16"}
		policy.CovariateL2Bound = "16"
		plan, err := planFormalCoxDP(policy)
		if err != nil {
			t.Fatalf("K=%d: %v", custodians, err)
		}
		if plan.NoiseCoordinates != 1 || !plan.NoiseCoordinatesFixedShape ||
			!plan.PolicyNoiseChunkCountMatches ||
			!plan.PrivacyPlanCertified || plan.ProductionReady {
			t.Fatalf("K=%d invalid fixed DP shape: %+v", custodians, plan)
		}
		if custodians == 2 {
			reference = plan
			continue
		}
		if plan.ScoreSensitivitySteps != reference.ScoreSensitivitySteps ||
			plan.AdaptiveStackSensitivitySteps !=
				reference.AdaptiveStackSensitivitySteps ||
			plan.MaximumNoiseMagnitude != reference.MaximumNoiseMagnitude ||
			plan.VectorTotalTVUpperNumerator !=
				reference.VectorTotalTVUpperNumerator ||
			plan.VectorTotalTVUpperDenominator !=
				reference.VectorTotalTVUpperDenominator {
			t.Fatalf("K=%d changed the fixed scientific DP plan", custodians)
		}
	}
}

func TestFormalCoxPhase1RemainsAbsentFromGenericCompilerWorkerCLIAndSurface(t *testing.T) {
	policy := formalCoxTestPolicy(t, 4)
	session := formalCoxTestSession(t, policy)
	if err := session.validate(); err != nil {
		t.Fatalf("specialised record-layer admission failed: %v", err)
	}
	if _, err := exactGCCompileCircuit(session.Spec); err == nil ||
		!strings.Contains(err.Error(), "purpose-bound internal runner") {
		t.Fatalf("generic compiler accepted formal Cox: %v", err)
	}
	master := make([]byte, 32)
	master[0] = 1
	_, err := exactGCSessionFromWire(
		strings.Repeat("01", 32), base64.StdEncoding.EncodeToString(master),
		session.GarblerID, session.EvaluatorID, session.Purpose,
		string(exactGCFormalCoxIterations), session.Spec.RingBits,
		session.Spec.FracBits, "", "", "", "", session.Spec.VectorLen)
	if err == nil || !strings.Contains(err.Error(), "internal purpose-bound") {
		t.Fatalf("generic worker accepted formal Cox: %v", err)
	}
	manifest, _ := json.Marshal(runtimeCapabilities())
	if strings.Contains(string(manifest), string(exactGCFormalCoxIterations)) {
		t.Fatal("runtime capability advertises internal formal Cox")
	}
	mainSource, err := os.ReadFile("main.go")
	if err != nil || strings.Contains(string(mainSource), "formal-cox") {
		t.Fatalf("CLI exposes formal Cox: %v", err)
	}
	namespace, err := os.ReadFile("../../NAMESPACE")
	if err != nil || strings.Contains(string(namespace), "formalCox") ||
		strings.Contains(string(namespace), "formal_cox") {
		t.Fatalf("R surface exports formal Cox: %v", err)
	}
}
