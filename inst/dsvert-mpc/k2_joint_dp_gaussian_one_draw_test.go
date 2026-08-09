package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/markkurossi/mpc/circuit"
)

func jointDPGaussianOneDrawTestPlan(t testing.TB, epsilon, delta,
	sensitivity string, total int) jointDPGaussianOneDrawPlanOutput {
	t.Helper()
	plan, err := jointDPPlanGaussianOneDraw(jointDPGaussianOneDrawPlanInput{
		Epsilon: epsilon, Delta: delta, L2SensitivitySteps: sensitivity,
		TotalCoordinateCount: total,
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func jointDPGaussianOneDrawPeerID(fill byte) string {
	return "dsv1_" + strings.Repeat(string(fill), 64)
}

func jointDPGaussianOneDrawTestContract(t testing.TB,
	plan jointDPGaussianOneDrawPlanOutput, chunkStart int, upper []string,
	garblerSeed, evaluatorSeed [32]byte, custodians int,
) jointDPGaussianOneDrawWorkerContractInput {
	t.Helper()
	transcript := sha256.Sum256([]byte("gaussian-one-draw/transcript/" + t.Name()))
	pinset := sha256.Sum256([]byte("gaussian-one-draw/pinset/" + t.Name()))
	garblerID := jointDPGaussianOneDrawPeerID('1')
	evaluatorID := jointDPGaussianOneDrawPeerID('2')
	gctx := jointDPCommitmentContext(transcript,
		jointDPGaussianOneDrawCommitmentPurpose+"/garbler", garblerID)
	ectx := jointDPCommitmentContext(transcript,
		jointDPGaussianOneDrawCommitmentPurpose+"/evaluator", evaluatorID)
	gcommit := jointDPSeedCommitment(gctx, garblerSeed)
	ecommit := jointDPSeedCommitment(ectx, evaluatorSeed)
	epsilon := "1"
	delta := "0.000001"
	fullUpper := make([]string, plan.TotalCoordinateCount)
	for index := range fullUpper {
		fullUpper[index] = "10"
	}
	copy(fullUpper[chunkStart:], upper)
	certificate := formalGLMPhase15DPSensitivityCertificate{
		Version: formalGLMPhase15DPSensitivityCertificateVersion,
		Kind:    jointDPGaussianOneDrawSensitivityCertificateKind,
		Status:  "machine_proven", Norm: "l2",
		SelectedProof:       formalGLMPhase15DPUniversalProof,
		SelectedBoundSteps:  plan.L2SensitivitySteps,
		CoordinateCount:     plan.TotalCoordinateCount,
		OutputLatticeBits:   8,
		ShiftedUpperBounds:  append([]string(nil), fullUpper...),
		UniversalBoundSteps: plan.L2SensitivitySteps,
		Selection:           "test-machine-proven-certificate-v1",
	}
	certificateDigest, err := formalGLMPhase15DPSensitivityCertificateDigest(
		certificate)
	if err != nil {
		t.Fatal(err)
	}
	binding := formalGLMPhase16ReleaseBinding{
		Version:               formalGLMPhase16ReleaseVersion,
		Family:                "binomial",
		Mechanism:             jointDPGaussianOneDrawMechanism,
		Allocation:            jointDPGaussianOneDrawAllocation,
		ReleaseContractSHA256: hex.EncodeToString(transcript[:]),
		Epsilon:               epsilon, AllocatedDelta: delta,
		CommonRingBits: 128, OutputLatticeBits: 8,
		CoordinateCount:              plan.TotalCoordinateCount,
		ShiftedUpperBounds:           fullUpper,
		SensitivitySteps:             plan.L2SensitivitySteps,
		SensitivityNorm:              "l2",
		SensitivityProof:             certificate.SelectedProof,
		SensitivityCertificateKind:   certificate.Kind,
		SensitivityCertificateSHA256: hex.EncodeToString(certificateDigest[:]),
		SensitivityCertificate:       certificate,
		PinsetSHA256:                 hex.EncodeToString(pinset[:]),
		CustodianCount:               custodians,
		GarblerPeerID:                garblerID, EvaluatorPeerID: evaluatorID,
		GarblerCommitmentContext:   hex.EncodeToString(gctx[:]),
		EvaluatorCommitmentContext: hex.EncodeToString(ectx[:]),
		GarblerSeedCommitment:      hex.EncodeToString(gcommit[:]),
		EvaluatorSeedCommitment:    hex.EncodeToString(ecommit[:]),
		OpeningCount:               1,
	}
	preimage, err := formalGLMPhase16ReleaseBindingPreimage(binding)
	if err != nil {
		t.Fatal(err)
	}
	release, err := formalGLMPhase16ReleaseBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	return jointDPGaussianOneDrawWorkerContractInput{
		Version:  jointDPGaussianOneDrawWorkerContractInputVersion,
		RingBits: 128, FracBits: 0, OutputLatticeBits: 8,
		TotalCoordinateCount: plan.TotalCoordinateCount,
		ChunkStart:           chunkStart, CoordinateCount: len(upper),
		Epsilon: epsilon, AllocatedDelta: delta,
		L2SensitivitySteps:             plan.L2SensitivitySteps,
		L2SensitivityCertificateKind:   jointDPGaussianOneDrawSensitivityCertificateKind,
		L2SensitivityCertificateSHA256: hex.EncodeToString(certificateDigest[:]),
		ReleaseBindingDomain:           formalGLMPhase16ReleaseDomain,
		ReleaseBindingCanonicalJSON:    string(preimage),
		ScaleShifts:                    make([]int, len(upper)), RawUpperBounds: upper,
		ReleaseBindingSHA256:       release,
		CrossSignedPolicySHA256:    release,
		TranscriptHash:             hex.EncodeToString(transcript[:]),
		PinsetSHA256:               hex.EncodeToString(pinset[:]),
		CustodianCount:             custodians,
		DesignatedComputePeerCount: 2,
		GarblerPeerID:              garblerID,
		EvaluatorPeerID:            evaluatorID,
		GarblerCommitmentContext:   hex.EncodeToString(gctx[:]),
		EvaluatorCommitmentContext: hex.EncodeToString(ectx[:]),
		GarblerSeedCommitment:      hex.EncodeToString(gcommit[:]),
		EvaluatorSeedCommitment:    hex.EncodeToString(ecommit[:]),
	}
}

func jointDPGaussianOneDrawTestRebindShift(t testing.TB,
	input jointDPGaussianOneDrawWorkerContractInput, local, shift int,
	rawUpper, shiftedUpper string,
) jointDPGaussianOneDrawWorkerContractInput {
	t.Helper()
	if local < 0 || local >= input.CoordinateCount {
		t.Fatal("invalid test coordinate")
	}
	var binding formalGLMPhase16ReleaseBinding
	if err := json.Unmarshal(
		[]byte(input.ReleaseBindingCanonicalJSON), &binding); err != nil {
		t.Fatal(err)
	}
	absolute := input.ChunkStart + local
	binding.ShiftedUpperBounds[absolute] = shiftedUpper
	binding.SensitivityCertificate.ShiftedUpperBounds[absolute] = shiftedUpper
	certificateDigest, err := formalGLMPhase15DPSensitivityCertificateDigest(
		binding.SensitivityCertificate)
	if err != nil {
		t.Fatal(err)
	}
	binding.SensitivityCertificateSHA256 = hex.EncodeToString(certificateDigest[:])
	preimage, err := formalGLMPhase16ReleaseBindingPreimage(binding)
	if err != nil {
		t.Fatal(err)
	}
	release, err := formalGLMPhase16ReleaseBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	input.ScaleShifts[local] = shift
	input.RawUpperBounds[local] = rawUpper
	input.L2SensitivityCertificateSHA256 = hex.EncodeToString(certificateDigest[:])
	input.ReleaseBindingCanonicalJSON = string(preimage)
	input.ReleaseBindingSHA256 = release
	input.CrossSignedPolicySHA256 = release
	return input
}

func jointDPGaussianOneDrawTestSession(
	compiled jointDPGaussianOneDrawWorkerContractOutput, label string,
) exactGCSession {
	sessionID := sha256.Sum256([]byte("gaussian-one-draw/session/" + label))
	master := sha256.Sum256([]byte("gaussian-one-draw/master/" + label))
	return exactGCSession{
		SessionID: sessionID, MasterKey: master,
		GarblerID:   compiled.WorkerPolicy.GarblerPeerID,
		EvaluatorID: compiled.WorkerPolicy.EvaluatorPeerID,
		Purpose:     compiled.Purpose,
		Spec: exactGCCircuitSpec{
			Operation: jointDPGaussianOneDrawOperation,
			RingBits:  128, FracBits: 0,
			VectorLen: compiled.WorkerPolicy.CoordinateCount,
		},
	}
}

func TestJointDPGaussianOneDrawPlanAccountsForOneVectorDraw(t *testing.T) {
	plan := jointDPGaussianOneDrawTestPlan(t, "1", "0.000001", "1", 100)
	if plan.Mechanism != jointDPGaussianOneDrawMechanism ||
		plan.Allocation != jointDPGaussianOneDrawAllocation ||
		plan.NoiseDrawCount != 1 || !plan.CapabilityAvailable ||
		plan.SamplerRandomBitsPerCoordinate != 128 ||
		!plan.FiniteSupportTransferCharged || !plan.FixedWorkSampler ||
		!plan.NoWrapCertified || plan.SecretIndexedPublicRAMAvailable ||
		plan.LogarithmicCircuitSizeClaim || plan.CDFLookupLogicalDepth !=
		plan.SamplerSearchSteps || plan.CDFComparisonsPerCoordinate !=
		plan.SamplerMagnitudeCount-1 {
		t.Fatalf("dishonest one-draw plan: %#v", plan)
	}
	allocated := jointDPTestRat(t, plan.AllocatedDeltaNumerator,
		plan.AllocatedDeltaDenominator)
	core := jointDPTestRat(t, plan.CoreDeltaNumerator,
		plan.CoreDeltaDenominator)
	implementation := jointDPTestRat(t, plan.ImplementationDeltaNumerator,
		plan.ImplementationDeltaDenominator)
	if new(big.Rat).Add(core, implementation).Cmp(allocated) > 0 {
		t.Fatal("core plus tail/CDF transfer exceeds allocated delta")
	}
	tail := jointDPTestRat(t, plan.VectorTailTVUpperNumerator,
		plan.VectorTailTVUpperDenominator)
	cdf := jointDPTestRat(t, plan.VectorCDFTVUpperNumerator,
		plan.VectorCDFTVUpperDenominator)
	total := jointDPTestRat(t, plan.VectorTotalTVUpperNumerator,
		plan.VectorTotalTVUpperDenominator)
	if new(big.Rat).Add(tail, cdf).Cmp(total) != 0 {
		t.Fatal("tail and exact dyadic-CDF TV do not close")
	}
	legacy, err := jointDPPlanVectorGaussian(jointDPGaussianPlanInput{
		Epsilon: "1", Delta: "0.000001", L2SensitivitySteps: "1",
		TotalCoordinateCount: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.FallbackAutomatic || plan.FallbackSelection !=
		"explicit_release_policy_only_never_automatic_v1" ||
		plan.FallbackNominalVarianceMultiplier != 2 ||
		plan.FallbackNominalStandardDeviationFactor !=
			"sqrt(2)_relative_to_one_full_draw" ||
		legacy.NominalVarianceMultiplier != 2 ||
		!legacy.AtLeastOneHonestNoisePeer || legacy.MaximumColludingNoisePeers != 1 ||
		legacy.AdversaryView == "" || legacy.AdversaryViewPrivacyArgument == "" ||
		legacy.SourceShareHidingPrecondition == "" {
		t.Fatal("explicit scalable fallback lacks utility/threat-model certificate")
	}
	oneRadius, _ := new(big.Int).SetString(plan.Simultaneous95Abs, 10)
	twoRadius, _ := new(big.Int).SetString(legacy.Simultaneous95Abs, 10)
	if oneRadius.Cmp(twoRadius) > 0 {
		t.Fatalf("one draw has worse certified accuracy: one=%s two=%s",
			oneRadius, twoRadius)
	}
}

func TestJointDPGaussianOneDrawResourceFallbackIsExplicit(t *testing.T) {
	plan := jointDPGaussianOneDrawTestPlan(t, "0.05", "0.000001", "100", 1000)
	if plan.CapabilityAvailable || plan.UnavailableReason == "" ||
		!plan.FallbackAvailable || plan.FallbackMechanism != jointDPGaussianMechanism ||
		plan.FallbackAutomatic || plan.FallbackSelection !=
		"explicit_release_policy_only_never_automatic_v1" ||
		plan.FallbackNominalVarianceMultiplier != 2 {
		t.Fatalf("resource fallback was silent or ambiguous: %#v", plan)
	}
	if plan.Mechanism != jointDPGaussianOneDrawMechanism || plan.NoiseDrawCount != 1 {
		t.Fatal("unavailable one-draw plan changed its requested mechanism")
	}
	_, err := jointDPPlanGaussianOneDraw(jointDPGaussianOneDrawPlanInput{
		Epsilon: "1e-100", Delta: "1e-100",
		L2SensitivitySteps: "9007199254740991", TotalCoordinateCount: 1000000,
	})
	if err == nil || exactGCFailureCodeOf(err) !=
		exactGCFailureNumericBackendUnavailable {
		t.Fatalf("unavailable Gaussian fallback was not typed: %v", err)
	}
}

func TestJointDPGaussianOneDrawPhase16L2RegressionIsChunkable(t *testing.T) {
	plan := jointDPGaussianOneDrawTestPlan(t, "1", "0.000001", "363", 2)
	wantChunk := jointDPGaussianOneDrawMaxChunk(plan.SamplerMagnitudeCount)
	if wantChunk > plan.TotalCoordinateCount {
		wantChunk = plan.TotalCoordinateCount
	}
	if !plan.CapabilityAvailable || plan.MaximumChunkCoordinates != wantChunk ||
		plan.SamplerSearchSteps != 14 || plan.SamplerMagnitudeCount != 12425 ||
		plan.CDFComparisonsPerCoordinate != plan.SamplerMagnitudeCount-1 ||
		plan.PlannedCDFComparisonsPerCircuit >
			plan.MaximumCDFComparisonsPerCircuit {
		t.Fatalf("Phase1.6 p=2/L2=363 is not honestly chunkable: %#v", plan)
	}
	if plan.CDFComparisonsPerCoordinate == plan.SamplerSearchSteps {
		t.Fatal("planner confused logical binary-search depth with Boolean-circuit work")
	}
}

func TestJointDPGaussianOneDrawWorkerContractK2K3K5AndTamper(t *testing.T) {
	plan := jointDPGaussianOneDrawTestPlan(t, "1", "0.000001", "1", 5)
	gseed := sha256.Sum256([]byte("gaussian-one-draw-contract-g"))
	eseed := sha256.Sum256([]byte("gaussian-one-draw-contract-e"))
	for _, custodians := range []int{2, 3, 5} {
		input := jointDPGaussianOneDrawTestContract(
			t, plan, 0, []string{"10"}, gseed, eseed, custodians)
		compiled, err := jointDPCompileGaussianOneDrawWorkerContract(input)
		if err != nil {
			t.Fatalf("K=%d: %v", custodians, err)
		}
		if compiled.Operation != string(jointDPGaussianOneDrawOperation) ||
			compiled.Mechanism != jointDPGaussianOneDrawMechanism ||
			compiled.Allocation != jointDPGaussianOneDrawAllocation ||
			compiled.DesignatedComputePeerCount != 2 ||
			compiled.CustodianCount != custodians ||
			compiled.ProtectedInputsAccepted || compiled.PrivateSeedAccepted ||
			!compiled.CapabilityAvailable {
			t.Fatalf("K=%d invalid contract: %#v", custodians, compiled)
		}
		encoded := []byte(compiled.Purpose + compiled.CircuitDigest)
		if bytes.Contains(encoded, gseed[:]) || bytes.Contains(encoded, eseed[:]) {
			t.Fatal("data-free contract exposed a seed")
		}
	}
	input := jointDPGaussianOneDrawTestContract(
		t, plan, 0, []string{"10"}, gseed, eseed, 3)
	input.CrossSignedPolicySHA256 = strings.Repeat("f", 64)
	if _, err := jointDPCompileGaussianOneDrawWorkerContract(input); err == nil {
		t.Fatal("cross-signed release binding substitution was accepted")
	}
	input = jointDPGaussianOneDrawTestContract(
		t, plan, 0, []string{"10"}, gseed, eseed, 3)
	input.L2SensitivityCertificateSHA256 = strings.Repeat("e", 64)
	if _, err := jointDPCompileGaussianOneDrawWorkerContract(input); err == nil {
		t.Fatal("unbound L2 sensitivity certificate was accepted")
	}
	input = jointDPGaussianOneDrawTestContract(
		t, plan, 0, []string{"10"}, gseed, eseed, 3)
	input.GarblerPeerID, input.EvaluatorPeerID =
		input.EvaluatorPeerID, input.GarblerPeerID
	if _, err := jointDPCompileGaussianOneDrawWorkerContract(input); err == nil {
		t.Fatal("non-canonical pinned role order was accepted")
	}
}

func TestJointDPGaussianOneDrawShiftedBoundsAreExactAndNoWrap(t *testing.T) {
	plan := jointDPGaussianOneDrawTestPlan(t, "1", "0.000001", "1", 1)
	gseed := sha256.Sum256([]byte("gaussian-one-draw-shift-g"))
	eseed := sha256.Sum256([]byte("gaussian-one-draw-shift-e"))
	base := jointDPGaussianOneDrawTestContract(
		t, plan, 0, []string{"10"}, gseed, eseed, 3)

	shifted := jointDPGaussianOneDrawTestRebindShift(
		t, base, 0, 3, "10", "80")
	if _, err := jointDPCompileGaussianOneDrawWorkerContract(shifted); err != nil {
		t.Fatalf("exact non-zero lattice shift was rejected: %v", err)
	}
	zero := jointDPGaussianOneDrawTestRebindShift(
		t, base, 0, 0, "10", "10")
	if _, err := jointDPCompileGaussianOneDrawWorkerContract(zero); err != nil {
		t.Fatalf("zero-shift formal-GLM compatibility failed: %v", err)
	}

	wrongShift := jointDPGaussianOneDrawTestRebindShift(
		t, base, 0, 2, "10", "80")
	if _, err := jointDPCompileGaussianOneDrawWorkerContract(wrongShift); err == nil {
		t.Fatal("altered lattice shift was accepted")
	}
	wrongRaw := jointDPGaussianOneDrawTestRebindShift(
		t, base, 0, 3, "11", "80")
	if _, err := jointDPCompileGaussianOneDrawWorkerContract(wrongRaw); err == nil {
		t.Fatal("inconsistent raw and shifted bounds were accepted")
	}
	outOfRange := jointDPGaussianOneDrawTestRebindShift(
		t, base, 0, 9, "1", "512")
	if _, err := jointDPCompileGaussianOneDrawWorkerContract(outOfRange); err == nil {
		t.Fatal("out-of-range lattice shift was accepted")
	}

	raw := new(big.Int).Lsh(big.NewInt(1), 126)
	overflow := new(big.Int).Lsh(new(big.Int).Set(raw), 2)
	tooWide := jointDPGaussianOneDrawTestRebindShift(
		t, base, 0, 2, raw.String(), overflow.String())
	if _, err := jointDPCompileGaussianOneDrawWorkerContract(tooWide); err == nil {
		t.Fatal("shifted bound outside signed Ring128 was accepted")
	}
}

func TestJointDPGaussianOneDrawStreamsReplayAndChunkInvariant(t *testing.T) {
	plan := jointDPGaussianOneDrawTestPlan(t, "1", "0.000001", "1", 3)
	gseed := sha256.Sum256([]byte("gaussian-one-draw-stream-g"))
	eseed := sha256.Sum256([]byte("gaussian-one-draw-stream-e"))
	fullInput := jointDPGaussianOneDrawTestContract(
		t, plan, 0, []string{"10", "20"}, gseed, eseed, 3)
	full, err := jointDPCompileGaussianOneDrawWorkerContract(fullInput)
	if err != nil {
		t.Fatal(err)
	}
	fullSession := jointDPGaussianOneDrawTestSession(full, "full")
	fullSpec, err := jointDPGaussianOneDrawSpecFromPolicy(
		full.WorkerPolicy, fullSession)
	if err != nil {
		t.Fatal(err)
	}
	words, signs, err := jointDPGaussianOneDrawPrivateInputs(
		gseed, fullSpec, "garbler")
	if err != nil {
		t.Fatal(err)
	}
	replayWords, replaySigns, _ := jointDPGaussianOneDrawPrivateInputs(
		gseed, fullSpec, "garbler")
	if words[1].Cmp(replayWords[1]) != 0 || signs[1] != replaySigns[1] {
		t.Fatal("same semantic release rerolled Gaussian stream")
	}
	oneInput := jointDPGaussianOneDrawTestContract(
		t, plan, 1, []string{"20"}, gseed, eseed, 3)
	one, err := jointDPCompileGaussianOneDrawWorkerContract(oneInput)
	if err != nil {
		t.Fatal(err)
	}
	oneSpec, err := jointDPGaussianOneDrawSpecFromPolicy(
		one.WorkerPolicy, jointDPGaussianOneDrawTestSession(one, "one"))
	if err != nil {
		t.Fatal(err)
	}
	oneWords, oneSigns, _ := jointDPGaussianOneDrawPrivateInputs(
		gseed, oneSpec, "garbler")
	if words[1].Cmp(oneWords[0]) != 0 || signs[1] != oneSigns[0] {
		t.Fatal("alternate public chunking changed an absolute-coordinate draw")
	}
	peerWords, peerSigns, _ := jointDPGaussianOneDrawPrivateInputs(
		eseed, fullSpec, "evaluator")
	if words[0].Cmp(peerWords[0]) == 0 && signs[0] == peerSigns[0] {
		t.Fatal("pinned peer stream domains collided")
	}
}

func TestJointDPGaussianOneDrawCDFBoundariesAndDistribution(t *testing.T) {
	plan := jointDPGaussianOneDrawTestPlan(t, "1", "0.000001", "1", 1)
	gseed := sha256.Sum256([]byte("gaussian-one-draw-distribution-g"))
	eseed := sha256.Sum256([]byte("gaussian-one-draw-distribution-e"))
	input := jointDPGaussianOneDrawTestContract(
		t, plan, 0, []string{"1000"}, gseed, eseed, 2)
	compiled, err := jointDPCompileGaussianOneDrawWorkerContract(input)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := jointDPGaussianOneDrawSpecFromPolicy(
		compiled.WorkerPolicy, jointDPGaussianOneDrawTestSession(compiled, "distribution"))
	if err != nil {
		t.Fatal(err)
	}
	previous := new(big.Int)
	secondMomentNumerator := new(big.Int)
	for index, threshold := range spec.CDFCumulative {
		count := new(big.Int).Sub(new(big.Int).Set(threshold), previous)
		if count.Sign() > 0 {
			boundary := new(big.Int).Sub(new(big.Int).Set(threshold), big.NewInt(1))
			selected, selectErr := jointDPGaussianOneDrawSelectMagnitude(
				boundary, spec.CDFCumulative)
			if selectErr != nil || selected.Cmp(big.NewInt(int64(index))) != 0 {
				t.Fatalf("CDF boundary %d selected %v: %v", index, selected, selectErr)
			}
			magnitudeSquared := big.NewInt(int64(index * index))
			secondMomentNumerator.Add(secondMomentNumerator,
				new(big.Int).Mul(count, magnitudeSquared))
		}
		previous.Set(threshold)
	}
	expectedVariance, _ := new(big.Rat).SetFrac(secondMomentNumerator,
		new(big.Int).Lsh(big.NewInt(1), 128)).Float64()
	const samples = 6000
	var sum, sumSquares float64
	for index := 0; index < samples; index++ {
		left := sha256.Sum256([]byte("gaussian-one-draw/distribution/g/" +
			strconv.Itoa(index)))
		right := sha256.Sum256([]byte("gaussian-one-draw/distribution/e/" +
			strconv.Itoa(index)))
		candidate := spec
		candidate.GarblerSeedCommitment = jointDPSeedCommitment(
			candidate.GarblerCommitmentContext, left)
		candidate.EvaluatorSeedCommitment = jointDPSeedCommitment(
			candidate.EvaluatorCommitmentContext, right)
		noise, sampleErr := jointDPGaussianOneDrawReferenceNoise(
			candidate, left, right)
		if sampleErr != nil {
			t.Fatal(sampleErr)
		}
		value, _ := new(big.Float).SetInt(noise[0]).Float64()
		sum += value
		sumSquares += value * value
	}
	mean := sum / samples
	variance := sumSquares/float64(samples) - mean*mean
	if math.Abs(mean) > 0.35 ||
		math.Abs(variance-expectedVariance) > 0.12*expectedVariance {
		t.Fatalf("one-draw distribution differs from exact CDF: mean=%g variance=%g want=%g",
			mean, variance, expectedVariance)
	}
}

func TestJointDPGaussianOneDrawScalingProjectionIsExplicit(t *testing.T) {
	cases := []struct {
		p           int
		sensitivity string
	}{
		{p: 1, sensitivity: "256"},
		{p: 2, sensitivity: "363"},
		{p: 10, sensitivity: "810"},
		{p: 100, sensitivity: "2560"},
	}
	for _, tc := range cases {
		plan := jointDPGaussianOneDrawTestPlan(
			t, "1", "0.000001", tc.sensitivity, tc.p)
		t.Logf("p=%d L2=%s available=%t M=%d comparisons/coord=%d chunk=%d projected_gates=%d projected_garbled_bytes=%d projected_wire_bytes=%d",
			tc.p, tc.sensitivity, plan.CapabilityAvailable,
			plan.SamplerMagnitudeCount, plan.CDFComparisonsPerCoordinate,
			plan.MaximumChunkCoordinates, plan.ProjectedGateCountUpper,
			plan.ProjectedGarbledTableBytesUpper,
			plan.ProjectedWireLabelBytesUpper)
		if plan.CapabilityAvailable {
			if plan.MaximumChunkCoordinates < 1 ||
				plan.PlannedCDFComparisonsPerCircuit >
					plan.MaximumCDFComparisonsPerCircuit ||
				plan.ProjectedGateCountUpper > plan.MaximumProjectedGateCount ||
				plan.ProjectedNonXORGateCountUpper >
					plan.MaximumProjectedNonXORGateCount ||
				plan.ProjectedGarbledTableBytesUpper >
					plan.MaximumProjectedGarbledTableBytes ||
				plan.ProjectedWireLabelBytesUpper >
					plan.MaximumProjectedWireLabelBytes ||
				plan.ProjectedCompilerAllocationBytesUpper >
					plan.MaximumProjectedCompilerAllocationBytes ||
				!plan.CostProjectionIsConservative {
				t.Fatalf("p=%d has an invalid resource certificate", tc.p)
			}
		} else if !plan.FallbackAvailable || plan.FallbackAutomatic ||
			plan.FallbackMechanism != jointDPGaussianMechanism {
			t.Fatalf("p=%d has a silent/incorrect fallback", tc.p)
		}
	}
}

func TestJointDPGaussianOneDrawExactGCAgreesWithReferenceAndClamps(t *testing.T) {
	if testing.Short() {
		t.Skip("real KOS/GC protocol")
	}
	plan := jointDPGaussianOneDrawTestPlan(t, "1", "0.000001", "1", 1)
	gseed := sha256.Sum256([]byte("gaussian-one-draw-e2e-g"))
	eseed := sha256.Sum256([]byte("gaussian-one-draw-e2e-e"))
	input := jointDPGaussianOneDrawTestContract(
		t, plan, 0, []string{"17"}, gseed, eseed, 2)
	compiled, err := jointDPCompileGaussianOneDrawWorkerContract(input)
	if err != nil {
		t.Fatal(err)
	}
	session := jointDPGaussianOneDrawTestSession(compiled, "e2e")
	spec, err := jointDPGaussianOneDrawSpecFromPolicy(
		compiled.WorkerPolicy, session)
	if err != nil {
		t.Fatal(err)
	}
	garblerSource := []*big.Int{big.NewInt(123456789)}
	evaluatorSource := []*big.Int{new(big.Int).Sub(
		exactGCModulus(128), big.NewInt(123456772))}
	garbler, evaluator := net.Pipe()
	type outcome struct {
		shares []*big.Int
		err    error
	}
	gdone, edone := make(chan outcome, 1), make(chan outcome, 1)
	go func() {
		shares, runErr := jointDPGaussianOneDrawRunGarbler(
			garbler, session, spec, garblerSource, gseed)
		gdone <- outcome{shares, runErr}
	}()
	go func() {
		shares, runErr := jointDPGaussianOneDrawRunEvaluator(
			evaluator, session, spec, evaluatorSource, eseed)
		edone <- outcome{shares, runErr}
	}()
	gout, eout := <-gdone, <-edone
	if gout.err != nil || eout.err != nil {
		t.Fatalf("one-draw GC: garbler=%v evaluator=%v", gout.err, eout.err)
	}
	if new(big.Int).Xor(gout.shares[1], eout.shares[1]).Cmp(big.NewInt(1)) != 0 {
		t.Fatal("valid source failed hidden validity certificate")
	}
	noise, err := jointDPGaussianOneDrawReferenceNoise(spec, gseed, eseed)
	if err != nil {
		t.Fatal(err)
	}
	want := new(big.Int).Add(big.NewInt(17), noise[0])
	if want.Sign() < 0 {
		want.SetInt64(0)
	} else if want.Cmp(big.NewInt(17)) > 0 {
		want.SetInt64(17)
	}
	got := exactGCReferenceReconstruct(gout.shares[0], eout.shares[0], 128)
	if got.Cmp(want) != 0 {
		t.Fatalf("GC=%s oracle=%s (noise=%s)", got, want, noise[0])
	}

	// The same public contract and sticky roots must yield the same additive
	// output shares across a transport/session retry.
	retrySession := jointDPGaussianOneDrawTestSession(compiled, "retry")
	retrySpec, err := jointDPGaussianOneDrawSpecFromPolicy(
		compiled.WorkerPolicy, retrySession)
	if err != nil {
		t.Fatal(err)
	}
	g2, e2 := net.Pipe()
	gdone, edone = make(chan outcome, 1), make(chan outcome, 1)
	go func() {
		shares, runErr := jointDPGaussianOneDrawRunGarbler(
			g2, retrySession, retrySpec, garblerSource, gseed)
		gdone <- outcome{shares, runErr}
	}()
	go func() {
		shares, runErr := jointDPGaussianOneDrawRunEvaluator(
			e2, retrySession, retrySpec, evaluatorSource, eseed)
		edone <- outcome{shares, runErr}
	}()
	gout2, eout2 := <-gdone, <-edone
	if gout2.err != nil || eout2.err != nil ||
		gout.shares[0].Cmp(gout2.shares[0]) != 0 ||
		eout.shares[0].Cmp(eout2.shares[0]) != 0 ||
		gout.shares[1].Cmp(gout2.shares[1]) != 0 ||
		eout.shares[1].Cmp(eout2.shares[1]) != 0 {
		t.Fatalf("sticky retry changed output shares: %v %v", gout2.err, eout2.err)
	}
}

func TestJointDPGaussianOneDrawInvalidSourceHasNoPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("real KOS/GC protocol")
	}
	plan := jointDPGaussianOneDrawTestPlan(t, "1", "0.000001", "1", 1)
	gseed := sha256.Sum256([]byte("gaussian-one-draw-invalid-g"))
	eseed := sha256.Sum256([]byte("gaussian-one-draw-invalid-e"))
	input := jointDPGaussianOneDrawTestContract(
		t, plan, 0, []string{"17"}, gseed, eseed, 2)
	compiled, err := jointDPCompileGaussianOneDrawWorkerContract(input)
	if err != nil {
		t.Fatal(err)
	}
	session := jointDPGaussianOneDrawTestSession(compiled, "invalid")
	spec, err := jointDPGaussianOneDrawSpecFromPolicy(
		compiled.WorkerPolicy, session)
	if err != nil {
		t.Fatal(err)
	}
	garbler, evaluator := net.Pipe()
	type outcome struct {
		shares []*big.Int
		err    error
	}
	gdone, edone := make(chan outcome, 1), make(chan outcome, 1)
	go func() {
		s, e := jointDPGaussianOneDrawRunGarbler(
			garbler, session, spec, []*big.Int{big.NewInt(123)}, gseed)
		gdone <- outcome{s, e}
	}()
	go func() {
		// 123 + (2^128-105) = 18 mod 2^128, above the public upper 17.
		s, e := jointDPGaussianOneDrawRunEvaluator(evaluator, session, spec,
			[]*big.Int{new(big.Int).Sub(exactGCModulus(128), big.NewInt(105))}, eseed)
		edone <- outcome{s, e}
	}()
	gout, eout := <-gdone, <-edone
	if gout.err != nil || eout.err != nil {
		t.Fatalf("invalid-source GC failed: %v %v", gout.err, eout.err)
	}
	if new(big.Int).Xor(gout.shares[1], eout.shares[1]).Sign() != 0 {
		t.Fatal("out-of-bound source was marked valid")
	}
	if exactGCReferenceReconstruct(gout.shares[0], eout.shares[0], 128).Sign() != 0 {
		t.Fatal("invalid source emitted a payload")
	}
}

func TestJointDPGaussianOneDrawDurableWorkerDispatchIsOpaque(t *testing.T) {
	if testing.Short() {
		t.Skip("real spool/KOS worker")
	}
	plan := jointDPGaussianOneDrawTestPlan(t, "1", "0.000001", "1", 1)
	gseed := sha256.Sum256([]byte("gaussian-one-draw-worker-g"))
	eseed := sha256.Sum256([]byte("gaussian-one-draw-worker-e"))
	input := jointDPGaussianOneDrawTestContract(
		t, plan, 0, []string{"17"}, gseed, eseed, 3)
	compiled, err := jointDPCompileGaussianOneDrawWorkerContract(input)
	if err != nil {
		t.Fatal(err)
	}
	gdir := exactGCTestSpool(t, "gaussian-one-draw-g")
	edir := exactGCTestSpool(t, "gaussian-one-draw-e")
	sid := sha256.Sum256([]byte("gaussian-one-draw-worker-session"))
	master := sha256.Sum256([]byte("gaussian-one-draw-worker-master"))
	encodingSpec := exactGCCircuitSpec{
		Operation: jointDPGaussianOneDrawOperation,
		RingBits:  128, FracBits: 0, VectorLen: 1,
	}
	base := exactGCWorkerConfig{
		Version:     exactGCWorkerConfigVersion,
		SessionID:   hex.EncodeToString(sid[:]),
		MasterKey:   base64.StdEncoding.EncodeToString(master[:]),
		GarblerID:   compiled.WorkerPolicy.GarblerPeerID,
		EvaluatorID: compiled.WorkerPolicy.EvaluatorPeerID,
		Purpose:     compiled.Purpose,
		Operation:   string(jointDPGaussianOneDrawOperation),
		RingBits:    128, FracBits: 0, VectorLen: 1,
		JointDPGaussianOneDraw: &compiled.WorkerPolicy,
		MaxSpoolBytes:          1 << 30, TTLSeconds: 120,
	}
	gconfig := base
	gconfig.Role, gconfig.SpoolDir = "garbler", gdir
	gconfig.PrivateSeed = base64.StdEncoding.EncodeToString(gseed[:])
	gconfig.SourceShare = exactGCTestEncodeSource(
		t, []*big.Int{big.NewInt(123456789)}, encodingSpec)
	econfig := base
	econfig.Role, econfig.SpoolDir = "evaluator", edir
	econfig.PrivateSeed = base64.StdEncoding.EncodeToString(eseed[:])
	econfig.SourceShare = exactGCTestEncodeSource(t, []*big.Int{
		new(big.Int).Sub(exactGCModulus(128), big.NewInt(123456772)),
	}, encodingSpec)
	gpath := exactGCTestWriteConfig(t, gdir, gconfig)
	epath := exactGCTestWriteConfig(t, edir, econfig)
	done := make(chan error, 2)
	go func() { done <- handleExactGCWorker(gpath) }()
	go func() { done <- handleExactGCWorker(epath) }()
	goffset, eoffset := int64(0), int64(0)
	deadline := time.Now().Add(120 * time.Second)
	for !exactGCTestBothDone(gdir, edir) && time.Now().Before(deadline) {
		goffset = exactGCTestRelaySpool(t, gdir, edir, goffset)
		eoffset = exactGCTestRelaySpool(t, edir, gdir, eoffset)
		now := time.Now()
		for _, dir := range []string{gdir, edir} {
			if err := os.Chtimes(filepath.Join(dir, "exchange.hb"), now, now); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(time.Millisecond)
	}
	if !exactGCTestBothDone(gdir, edir) {
		t.Fatal("one-draw Gaussian workers did not complete")
	}
	for index := 0; index < 2; index++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if fileExists(gpath) || fileExists(epath) {
		t.Fatal("seed-bearing worker config survived readiness")
	}
	gres := exactGCTestReadResult(t, gdir)
	eres := exactGCTestReadResult(t, edir)
	if gres.Kind != "joint-dp-vector-gaussian-one-draw-ring128-share-v1" ||
		eres.Kind != gres.Kind || gres.ValidityShare == "" || eres.ValidityShare == "" {
		t.Fatalf("invalid durable one-draw results: %#v %#v", gres, eres)
	}
	spec, err := jointDPGaussianOneDrawSpecFromPolicy(
		compiled.WorkerPolicy, jointDPGaussianOneDrawTestSession(compiled, "scan"))
	if err != nil {
		t.Fatal(err)
	}
	gwords, _, err := jointDPGaussianOneDrawPrivateInputs(gseed, spec, "garbler")
	if err != nil {
		t.Fatal(err)
	}
	ewords, _, err := jointDPGaussianOneDrawPrivateInputs(eseed, spec, "evaluator")
	if err != nil {
		t.Fatal(err)
	}
	defer exactGCZeroBigInts(gwords)
	defer exactGCZeroBigInts(ewords)
	privateWords := make([][]byte, 0, 4)
	for _, word := range []*big.Int{gwords[0], ewords[0]} {
		bigEndian := word.FillBytes(make([]byte, 16))
		littleEndian := append([]byte(nil), bigEndian...)
		for left, right := 0, len(littleEndian)-1; left < right; left, right = left+1, right-1 {
			littleEndian[left], littleEndian[right] = littleEndian[right], littleEndian[left]
		}
		privateWords = append(privateWords, bigEndian, littleEndian)
	}
	for _, dir := range []string{gdir, edir} {
		for _, name := range []string{"inbound.bin", "outbound.bin", "result.json"} {
			data, readErr := os.ReadFile(filepath.Join(dir, name))
			if readErr != nil {
				t.Fatal(readErr)
			}
			for _, forbidden := range [][]byte{
				gseed[:], eseed[:],
				[]byte(base64.StdEncoding.EncodeToString(gseed[:])),
				[]byte(base64.StdEncoding.EncodeToString(eseed[:])),
			} {
				if bytes.Contains(data, forbidden) {
					t.Fatalf("%s/%s exposed a private seed", dir, name)
				}
			}
			for _, forbidden := range privateWords {
				if bytes.Contains(data, forbidden) {
					t.Fatalf("%s/%s exposed a private random word", dir, name)
				}
			}
		}
	}
}

func TestJointDPGaussianOneDrawPolicyTamperAndSessionSubstitutionFail(t *testing.T) {
	plan := jointDPGaussianOneDrawTestPlan(t, "1", "0.000001", "1", 1)
	gseed := sha256.Sum256([]byte("gaussian-one-draw-tamper-g"))
	eseed := sha256.Sum256([]byte("gaussian-one-draw-tamper-e"))
	input := jointDPGaussianOneDrawTestContract(
		t, plan, 0, []string{"17"}, gseed, eseed, 5)
	compiled, err := jointDPCompileGaussianOneDrawWorkerContract(input)
	if err != nil {
		t.Fatal(err)
	}
	session := jointDPGaussianOneDrawTestSession(compiled, "tamper")
	ambiguousConfig := exactGCWorkerConfig{
		Role:                   "garbler",
		GarblerID:              compiled.WorkerPolicy.GarblerPeerID,
		EvaluatorID:            compiled.WorkerPolicy.EvaluatorPeerID,
		PrivateSeed:            base64.StdEncoding.EncodeToString(gseed[:]),
		JointDPGaussianOneDraw: &compiled.WorkerPolicy,
		JointDPVector:          &jointDPVectorWorkerPolicy{},
	}
	if _, _, err := jointDPGaussianOneDrawWorkerInputs(
		ambiguousConfig, session); err == nil {
		t.Fatal("ambiguous worker policy was accepted")
	}
	tampered := compiled.WorkerPolicy
	tampered.CDFCumulative = append([]string(nil), tampered.CDFCumulative...)
	tampered.CDFCumulative[0] = "1"
	if _, err := jointDPGaussianOneDrawSpecFromPolicy(tampered, session); err == nil {
		t.Fatal("tampered exact CDF was accepted")
	}
	tampered = compiled.WorkerPolicy
	tampered.PinsetSHA256 = strings.Repeat("f", 64)
	if _, err := jointDPGaussianOneDrawSpecFromPolicy(tampered, session); err == nil {
		t.Fatal("pinset substitution was accepted")
	}
	wrongSession := session
	wrongSession.GarblerID = jointDPGaussianOneDrawPeerID('0')
	if _, err := jointDPGaussianOneDrawSpecFromPolicy(
		compiled.WorkerPolicy, wrongSession); err == nil {
		t.Fatal("authenticated GC role substitution was accepted")
	}
	tampered = compiled.WorkerPolicy
	tampered.L2SensitivitySteps = "2"
	if _, err := jointDPGaussianOneDrawSpecFromPolicy(tampered, session); err == nil {
		t.Fatal("L2 sensitivity mutation detached from its compiled certificate was accepted")
	}
	tampered = compiled.WorkerPolicy
	tampered.RawUpperBounds = []string{"18"}
	if _, err := jointDPGaussianOneDrawSpecFromPolicy(tampered, session); err == nil {
		t.Fatal("source range mutation detached from the signed binding was accepted")
	}
	tampered = compiled.WorkerPolicy
	var releaseBinding formalGLMPhase16ReleaseBinding
	if err := json.Unmarshal([]byte(tampered.ReleaseBindingCanonicalJSON),
		&releaseBinding); err != nil {
		t.Fatal(err)
	}
	releaseBinding.SensitivityCertificate.SelectedBoundSteps = "2"
	mutatedPreimage, err := formalGLMPhase16ReleaseBindingPreimage(releaseBinding)
	if err != nil {
		t.Fatal(err)
	}
	tampered.ReleaseBindingCanonicalJSON = string(mutatedPreimage)
	if _, err := jointDPGaussianOneDrawSpecFromPolicy(tampered, session); err == nil {
		t.Fatal("mutated certificate body with a stale cross-signed digest was accepted")
	}
}

func TestJointDPGaussianOneDrawCircuitCostIsPublicAndBounded(t *testing.T) {
	plan := jointDPGaussianOneDrawTestPlan(t, "1", "0.000001", "1", 1)
	gseed := sha256.Sum256([]byte("gaussian-one-draw-cost-g"))
	eseed := sha256.Sum256([]byte("gaussian-one-draw-cost-e"))
	input := jointDPGaussianOneDrawTestContract(
		t, plan, 0, []string{"100"}, gseed, eseed, 2)
	compiled, err := jointDPCompileGaussianOneDrawWorkerContract(input)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := jointDPGaussianOneDrawSpecFromPolicy(
		compiled.WorkerPolicy, jointDPGaussianOneDrawTestSession(compiled, "cost"))
	if err != nil {
		t.Fatal(err)
	}
	circ, err := jointDPGaussianOneDrawGCCompile(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Gaussian one-draw d=1 M=%d: gates=%d non-XOR=%d wires=%d input_bits=%d cost=%d",
		plan.SamplerMagnitudeCount, circ.NumGates, circ.Stats.NumNonXOR(),
		circ.NumWires, circ.Inputs.Size(), circ.Cost())
	if circ.NumGates < plan.CDFComparisonsPerCoordinate ||
		circ.Stats.NumNonXOR() == 0 || circ.NumWires <= circ.NumGates ||
		circ.Inputs.Size() != 771 ||
		compiled.CircuitGateCount != circ.NumGates ||
		compiled.CircuitNonXORGateCount != circ.Stats.NumNonXOR() ||
		compiled.CircuitWireCount != circ.NumWires ||
		compiled.CircuitInputBits != circ.Inputs.Size() ||
		compiled.GarbledTableBytes != int64(circ.Stats.NumNonXOR())*32 ||
		compiled.WireLabelResidentBytes != int64(circ.NumWires)*32 ||
		int64(circ.NumGates) > plan.ProjectedGateCountUpper ||
		int64(circ.Stats.NumNonXOR()) > plan.ProjectedNonXORGateCountUpper ||
		int64(circ.NumWires) > plan.ProjectedWireCountUpper {
		t.Fatal("compiled circuit cost/shape certificate is inconsistent")
	}
	source := jointDPGaussianOneDrawCircuitSource(spec)
	changed := spec
	changed.RawUpperBounds = []*big.Int{big.NewInt(999)}
	changed.ReleaseBinding = sha256.Sum256([]byte("changed release binding"))
	changed.CrossSignedPolicy = changed.ReleaseBinding
	changed.L2SensitivityCertificate = changed.ReleaseBinding
	if source != jointDPGaussianOneDrawCircuitSource(changed) ||
		spec.circuitShapeDigest() != changed.circuitShapeDigest() ||
		spec.contractDigest() == changed.contractDigest() {
		t.Fatal("private/bound contract changed circuit shape or escaped purpose binding")
	}
	for _, forbidden := range []string{
		"PrivateSeed", "SeedCommitment", "TranscriptHash", "PreNoise",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("generated circuit exposed forbidden field %q", forbidden)
		}
	}
	for _, required := range []string{
		"g.Random", "e.Random", "g.Sign", "e.Sign", "g.OutputMask",
		"valid != g.ValidityMask",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("generated circuit lacks selective-sharing operation %q", required)
		}
	}
}

func BenchmarkJointDPGaussianOneDrawReference64(b *testing.B) {
	plan := jointDPGaussianOneDrawTestPlan(b, "1", "0.000001", "1", 64)
	gseed := sha256.Sum256([]byte("gaussian-one-draw-benchmark-g"))
	eseed := sha256.Sum256([]byte("gaussian-one-draw-benchmark-e"))
	upper := make([]string, 64)
	for i := range upper {
		upper[i] = "100"
	}
	input := jointDPGaussianOneDrawTestContract(
		b, plan, 0, upper, gseed, eseed, 5)
	compiled, err := jointDPCompileGaussianOneDrawWorkerContract(input)
	if err != nil {
		b.Fatal(err)
	}
	spec, err := jointDPGaussianOneDrawSpecFromPolicy(
		compiled.WorkerPolicy, jointDPGaussianOneDrawTestSession(compiled, "bench"))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := jointDPGaussianOneDrawReferenceNoise(spec, gseed, eseed); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkJointDPGaussianOneDrawCompile(b *testing.B, p int,
	sensitivity string) {
	plan := jointDPGaussianOneDrawTestPlan(
		b, "1", "0.000001", sensitivity, p)
	if !plan.CapabilityAvailable {
		b.Fatalf("p=%d unavailable: %s", p, plan.UnavailableReason)
	}
	gseed := sha256.Sum256([]byte("gaussian-one-draw-compile-bench-g"))
	eseed := sha256.Sum256([]byte("gaussian-one-draw-compile-bench-e"))
	chunkCoordinates := p
	if chunkCoordinates > plan.MaximumChunkCoordinates {
		chunkCoordinates = plan.MaximumChunkCoordinates
	}
	upper := make([]string, chunkCoordinates)
	for index := range upper {
		upper[index] = "1000"
	}
	input := jointDPGaussianOneDrawTestContract(
		b, plan, 0, upper, gseed, eseed, 5)
	var compiled jointDPGaussianOneDrawWorkerContractOutput
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		jointDPGaussianOneDrawGCCache.Lock()
		jointDPGaussianOneDrawGCCache.entries = make(map[string]*circuit.Circuit)
		jointDPGaussianOneDrawGCCache.order = nil
		jointDPGaussianOneDrawGCCache.Unlock()
		var err error
		compiled, err = jointDPCompileGaussianOneDrawWorkerContract(input)
		if err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(plan.CDFComparisonsPerCoordinate), "cdf-comparisons/coord")
	b.ReportMetric(float64(compiled.CircuitGateCount), "gates")
	b.ReportMetric(float64(compiled.CircuitNonXORGateCount), "non-xor-gates")
	b.ReportMetric(float64(compiled.CircuitWireCount), "wires")
	b.ReportMetric(float64(compiled.GarbledTableBytes), "garbled-bytes")
	b.ReportMetric(float64(compiled.WireLabelResidentBytes), "wire-label-bytes")
}

func BenchmarkJointDPGaussianOneDrawCompileP1(b *testing.B) {
	benchmarkJointDPGaussianOneDrawCompile(b, 1, "256")
}

func BenchmarkJointDPGaussianOneDrawCompileP2Phase16(b *testing.B) {
	benchmarkJointDPGaussianOneDrawCompile(b, 2, "363")
}

func benchmarkJointDPGaussianOneDrawProjectedFullVector(b *testing.B, p int) {
	plan := jointDPGaussianOneDrawTestPlan(
		b, "1", "0.000001", "363", p)
	_, _, _, _, gates, nonXOR, wires, garbledBytes, wireBytes :=
		jointDPGaussianOneDrawCostProjection(plan.SamplerMagnitudeCount, p)
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		jointDPGaussianOneDrawCostProjection(plan.SamplerMagnitudeCount, p)
	}
	b.StopTimer()
	b.ReportMetric(float64(plan.CDFComparisonsPerCoordinate),
		"cdf-comparisons/coord")
	b.ReportMetric(float64(plan.SamplerSearchSteps), "logical-depth/coord")
	b.ReportMetric(float64(gates), "projected-gates")
	b.ReportMetric(float64(nonXOR), "projected-non-xor-gates")
	b.ReportMetric(float64(wires), "projected-wires")
	b.ReportMetric(float64(garbledBytes), "projected-garbled-bytes")
	b.ReportMetric(float64(wireBytes*10), "projected-compiler-bytes")
	b.ReportMetric(float64(plan.MaximumChunkCoordinates), "admitted-chunk-coords")
}

func BenchmarkJointDPGaussianOneDrawProjectedFullVectorP1(b *testing.B) {
	benchmarkJointDPGaussianOneDrawProjectedFullVector(b, 1)
}

func BenchmarkJointDPGaussianOneDrawProjectedFullVectorP2(b *testing.B) {
	benchmarkJointDPGaussianOneDrawProjectedFullVector(b, 2)
}

func BenchmarkJointDPGaussianOneDrawProjectedFullVectorP8(b *testing.B) {
	benchmarkJointDPGaussianOneDrawProjectedFullVector(b, 8)
}

func BenchmarkJointDPGaussianOneDrawProjectedFullVectorP64(b *testing.B) {
	benchmarkJointDPGaussianOneDrawProjectedFullVector(b, 64)
}
