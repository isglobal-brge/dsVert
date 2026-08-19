package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func jointDPVectorTestPlan(t testing.TB, epsilon, delta, sensitivity string,
	total int) jointDPVectorPlanOutput {
	t.Helper()
	plan, err := jointDPPlanVectorLaplace(jointDPVectorPlanInput{
		Epsilon: epsilon, Delta: delta, SensitivitySteps: sensitivity,
		TotalCoordinateCount: total,
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func jointDPVectorTestSpec(t testing.TB, plan jointDPVectorPlanOutput,
	chunkStart int, upper []int64, transcriptLabel string,
	garblerSeed, evaluatorSeed [32]byte) jointDPVectorSpec {
	t.Helper()
	stop, ok := new(big.Int).SetString(plan.StopNumerator, 10)
	if !ok {
		t.Fatal("invalid test stop numerator")
	}
	thresholds := make([]*big.Int, len(plan.BernoulliThresholds))
	for index, value := range plan.BernoulliThresholds {
		thresholds[index], ok = new(big.Int).SetString(value, 10)
		if !ok {
			t.Fatal("invalid test Bernoulli threshold")
		}
	}
	bounds := make([]*big.Int, len(upper))
	for index, value := range upper {
		bounds[index] = big.NewInt(value)
	}
	transcript := sha256.Sum256([]byte(transcriptLabel))
	gctx := jointDPCommitmentContext(transcript, "garbler", "peer-a")
	ectx := jointDPCommitmentContext(transcript, "evaluator", "peer-b")
	sensitivity, ok := new(big.Int).SetString(plan.SensitivitySteps, 10)
	if !ok {
		t.Fatal("invalid test sensitivity")
	}
	return jointDPVectorSpec{
		RingBits: 128, FracBits: 0, OutputLatticeBits: 8,
		TotalCoordinateCount: plan.TotalCoordinateCount,
		ChunkStart:           chunkStart, CoordinateCount: len(upper),
		SensitivitySteps: sensitivity, StopNumerator: stop,
		StopBits: plan.StopBits, UniformBits: plan.UniformBits,
		BinaryGeometricBits: plan.BinaryGeometricBits,
		BernoulliThresholds: thresholds,
		ScaleShifts:         make([]int, len(bounds)),
		RawUpperBounds:      bounds,
		TranscriptHash:      transcript, GarblerCommitmentContext: gctx,
		EvaluatorCommitmentContext: ectx,
		GarblerSeedCommitment:      jointDPSeedCommitment(gctx, garblerSeed),
		EvaluatorSeedCommitment:    jointDPSeedCommitment(ectx, evaluatorSeed),
	}
}

func jointDPVectorTestSession(s jointDPVectorSpec, label string) exactGCSession {
	sessionID := sha256.Sum256([]byte("session/" + label))
	master := sha256.Sum256([]byte("master/" + label))
	return exactGCSession{
		SessionID: sessionID, MasterKey: master,
		GarblerID: "peer-a", EvaluatorID: "peer-b", Purpose: s.purpose(),
		Spec: exactGCCircuitSpec{Operation: jointDPVectorOperation,
			RingBits: 128, FracBits: 0, VectorLen: s.CoordinateCount},
	}
}

func TestJointDPVectorBinaryGeometricIdentityExact(t *testing.T) {
	// The infinite product identity implies that the first J independent
	// bits are exactly a Geometric(1-p) conditioned on G < 2^J.
	p := big.NewRat(3, 4)
	const bits = 6
	probability := make([]*big.Rat, bits)
	power := new(big.Rat).Set(p)
	for bit := range probability {
		probability[bit] = new(big.Rat).Quo(
			new(big.Rat).Set(power),
			new(big.Rat).Add(big.NewRat(1, 1), power))
		power.Mul(power, power)
	}
	conditionDenominator := new(big.Rat).Sub(big.NewRat(1, 1), power)
	q := new(big.Rat).Sub(big.NewRat(1, 1), p)
	for value := 0; value < 1<<bits; value++ {
		actual := big.NewRat(1, 1)
		for bit, theta := range probability {
			mass := new(big.Rat).Sub(big.NewRat(1, 1), theta)
			if value&(1<<bit) != 0 {
				mass.Set(theta)
			}
			actual.Mul(actual, mass)
		}
		pPower := new(big.Rat).SetInt64(1)
		for index := 0; index < value; index++ {
			pPower.Mul(pPower, p)
		}
		expected := new(big.Rat).Mul(q, pPower)
		expected.Quo(expected, conditionDenominator)
		if actual.Cmp(expected) != 0 {
			t.Fatalf("binary identity failed at %d: got %s want %s",
				value, actual.RatString(), expected.RatString())
		}
	}
}

func TestJointDPVectorRationalIntervalsContainExactProbabilities(t *testing.T) {
	p := big.NewRat(255, 256)
	const bits = 20
	interval, err := jointDPVectorProbabilityIntervals(p, 128, bits)
	if err != nil {
		t.Fatal(err)
	}

	// Do not materialise p^(2^bits) as a big.Rat here.  Its numerator and
	// denominator each have millions of bits, so the old exact oracle spent
	// minutes multiplying integers although the implementation deliberately
	// keeps a bounded outward interval.  Directed big.Float rounding gives a
	// rigorous, independent enclosure of that same exact rational recurrence:
	// if lower <= x <= upper, then roundDown(lower^2) <= x^2 <=
	// roundUp(upper^2).  Monotonicity of x/(1+x) then encloses every exact
	// Bernoulli probability without constructing the exponentially large Rat.
	const precision = 512
	float := func(mode big.RoundingMode) *big.Float {
		return new(big.Float).SetPrec(precision).SetMode(mode)
	}
	lower := float(big.ToNegativeInf).SetRat(p)
	upper := float(big.ToPositiveInf).SetRat(p)
	denominator := new(big.Int).Lsh(big.NewInt(1), 128)
	actualRoundingUpper := float(big.ToPositiveInf).SetInt64(0)
	for bit := 0; bit < bits; bit++ {
		one := float(big.ToNearestEven).SetInt64(1)
		denominatorLower := float(big.ToNegativeInf).Add(one, lower)
		denominatorUpper := float(big.ToPositiveInf).Add(one, upper)
		thetaLower := float(big.ToNegativeInf).Quo(lower, denominatorUpper)
		thetaUpper := float(big.ToPositiveInf).Quo(upper, denominatorLower)

		draw := float(big.ToNearestEven).SetRat(new(big.Rat).SetFrac(
			new(big.Int).Set(interval.thresholds[bit]), denominator))
		if draw.Acc() != big.Exact {
			t.Fatal("dyadic threshold was not represented exactly by test oracle")
		}
		absDifferenceUpper := func(left, right *big.Float) *big.Float {
			if left.Cmp(right) >= 0 {
				return float(big.ToPositiveInf).Sub(left, right)
			}
			return float(big.ToPositiveInf).Sub(right, left)
		}
		errorUpper := absDifferenceUpper(draw, thetaLower)
		if candidate := absDifferenceUpper(draw, thetaUpper); candidate.Cmp(errorUpper) > 0 {
			errorUpper = candidate
		}
		actualRoundingUpper = float(big.ToPositiveInf).Add(
			actualRoundingUpper, errorUpper)

		lower = float(big.ToNegativeInf).Mul(lower, lower)
		upper = float(big.ToPositiveInf).Mul(upper, upper)
	}
	roundingCertificateLower := float(big.ToNegativeInf).SetRat(interval.rounding)
	tailCertificateLower := float(big.ToNegativeInf).SetRat(interval.tail)
	if actualRoundingUpper.Cmp(roundingCertificateLower) > 0 ||
		upper.Cmp(tailCertificateLower) > 0 {
		t.Fatalf("rational interval is not conservative: rounding_upper=%s certificate_lower=%s tail_upper=%s certificate_lower=%s",
			actualRoundingUpper.Text('g', -1),
			roundingCertificateLower.Text('g', -1), upper.Text('g', -1),
			tailCertificateLower.Text('g', -1))
	}
}

func TestJointDPVectorPlanUsesGlobalSensitivityAndDimension(t *testing.T) {
	delta := "7.888609052210118e-31"
	one := jointDPVectorTestPlan(t, "1", delta, "1", 1)
	million := jointDPVectorTestPlan(t, "1", delta, "1", 1000000)
	doubleSensitivity := jointDPVectorTestPlan(t, "1", delta, "2", 2)
	if million.BinaryGeometricBits < one.BinaryGeometricBits ||
		doubleSensitivity.StopNumerator == one.StopNumerator {
		t.Fatalf("planner ignored global dimension/sensitivity: one=%#v million=%#v double=%#v",
			one, million, doubleSensitivity)
	}
	allocated, _ := jointDPParseDecimalRat(delta, "delta", false)
	implementation := jointDPTestRat(t, million.ImplementationDeltaNumerator,
		million.ImplementationDeltaDenominator)
	if implementation.Cmp(allocated) > 0 || !million.CapabilityAvailable {
		t.Fatalf("invalid global implementation certificate: %#v", million)
	}
	if million.MaximumChunkCoordinates >= million.TotalCoordinateCount {
		t.Fatal("large vectors were not split by the public circuit policy")
	}
}

func TestJointDPVectorPlanRejectsUnsafeOrUnrepresentableInputs(t *testing.T) {
	for _, input := range []jointDPVectorPlanInput{
		{Epsilon: "1", Delta: "0", SensitivitySteps: "1", TotalCoordinateCount: 1},
		{Epsilon: "1", Delta: "1", SensitivitySteps: "1", TotalCoordinateCount: 1},
		{Epsilon: "1", Delta: "1e-30", SensitivitySteps: "1.5", TotalCoordinateCount: 1},
		{Epsilon: "1", Delta: "1e-30", SensitivitySteps: "1", TotalCoordinateCount: 0},
		{Epsilon: "1e-100", Delta: "1e-30", SensitivitySteps: "9007199254740991", TotalCoordinateCount: 1000000},
	} {
		if _, err := jointDPPlanVectorLaplace(input); err == nil {
			t.Fatalf("unsafe vector plan was accepted: %#v", input)
		}
	}
}

func TestJointDPVectorFiniteSamplersRejectPureDPRequest(t *testing.T) {
	input := jointDPVectorPlanInput{
		Epsilon: "1", Delta: "0.000000000000000000e+00",
		SensitivitySteps:     "1",
		TotalCoordinateCount: 2,
	}
	if _, err := jointDPPlanVectorLaplace(input); err == nil ||
		!strings.Contains(err.Error(), "pure-DP") {
		t.Fatalf("exact-GC delta=0 error=%v, want explicit pure-DP unavailability", err)
	}
	if _, err := jointDPPlanVectorConvolutionLaplace(input); err == nil ||
		!strings.Contains(err.Error(), "pure-DP") {
		t.Fatalf("convolution delta=0 error=%v, want explicit pure-DP unavailability", err)
	}
}

func TestJointDPVectorPrivateStreamsAreStickyAndDomainSeparated(t *testing.T) {
	plan := jointDPVectorTestPlan(t, "1", "7.888609052210118e-31", "1", 4)
	gseed := sha256.Sum256([]byte("garbler-vector-seed"))
	eseed := sha256.Sum256([]byte("evaluator-vector-seed"))
	base := jointDPVectorTestSpec(t, plan, 0, []int64{10, 10},
		"capsule/query/transcript-a", gseed, eseed)
	first, err := jointDPVectorPrivateStream(gseed, base, "garbler")
	if err != nil {
		t.Fatal(err)
	}
	retry, _ := jointDPVectorPrivateStream(gseed, base, "garbler")
	if !bytes.Equal(first, retry) {
		t.Fatal("same capsule chunk retry rerolled its private stream")
	}
	role, _ := jointDPVectorPrivateStream(gseed, base, "evaluator")
	if bytes.Equal(first, role) {
		t.Fatal("garbler/evaluator stream domains collided")
	}
	nextChunk := jointDPVectorTestSpec(t, plan, 2, []int64{10, 10},
		"capsule/query/transcript-a", gseed, eseed)
	next, _ := jointDPVectorPrivateStream(gseed, nextChunk, "garbler")
	if bytes.Equal(first, next) {
		t.Fatal("distinct chunk domains collided")
	}
	otherTranscript := jointDPVectorTestSpec(t, plan, 0, []int64{10, 10},
		"capsule/query/transcript-b", gseed, eseed)
	other, _ := jointDPVectorPrivateStream(gseed, otherTranscript, "garbler")
	if bytes.Equal(first, other) {
		t.Fatal("distinct capsule/query transcripts collided")
	}
	changedBounds := jointDPVectorTestSpec(t, plan, 0, []int64{10, 11},
		"capsule/query/transcript-a", gseed, eseed)
	changed, _ := jointDPVectorPrivateStream(gseed, changedBounds, "garbler")
	if bytes.Equal(first, changed) {
		t.Fatal("changed circuit contract reused a private stream")
	}
}

func TestJointDPVectorReferenceDistributionMoments(t *testing.T) {
	plan := jointDPVectorTestPlan(t, "1", "7.888609052210118e-31", "1", 1)
	denominator := new(big.Int).Lsh(big.NewInt(1), uint(plan.UniformBits))
	meanGeom := new(big.Rat)
	varianceGeom := new(big.Rat)
	for bit, thresholdText := range plan.BernoulliThresholds {
		threshold, _ := new(big.Int).SetString(thresholdText, 10)
		probability := new(big.Rat).SetFrac(threshold, denominator)
		weight := new(big.Int).Lsh(big.NewInt(1), uint(bit))
		meanGeom.Add(meanGeom, new(big.Rat).Mul(
			new(big.Rat).SetInt(weight), probability))
		oneMinus := new(big.Rat).Sub(big.NewRat(1, 1), probability)
		weightSquared := new(big.Int).Mul(weight, weight)
		varianceGeom.Add(varianceGeom, new(big.Rat).Mul(
			new(big.Rat).SetInt(weightSquared),
			new(big.Rat).Mul(probability, oneMinus)))
	}
	expectedVariance, _ := new(big.Rat).Mul(varianceGeom, big.NewRat(2, 1)).Float64()
	const samples = 12000
	var sum, sumSquares float64
	for index := 0; index < samples; index++ {
		gseed := sha256.Sum256([]byte("g/" + strconv.Itoa(index)))
		eseed := sha256.Sum256([]byte("e/" + strconv.Itoa(index)))
		spec := jointDPVectorTestSpec(t, plan, 0, []int64{1000},
			"moment-capsule", gseed, eseed)
		noise, err := jointDPVectorReferenceNoise(spec, gseed, eseed)
		if err != nil {
			t.Fatal(err)
		}
		value, _ := new(big.Float).SetInt(noise[0]).Float64()
		sum += value
		sumSquares += value * value
	}
	mean := sum / samples
	variance := sumSquares/float64(samples) - mean*mean
	if math.Abs(mean) > 0.12 ||
		math.Abs(variance-expectedVariance) > 0.12*expectedVariance {
		t.Fatalf("reference sampler moments differ: mean=%g variance=%g want=%g",
			mean, variance, expectedVariance)
	}
}

func TestJointDPVectorExactGCE2EBoundaries(t *testing.T) {
	plan := jointDPVectorTestPlan(t, "1", "7.888609052210118e-31", "1", 2)
	gseed := sha256.Sum256([]byte("vector-e2e-garbler"))
	eseed := sha256.Sum256([]byte("vector-e2e-evaluator"))
	spec := jointDPVectorTestSpec(t, plan, 0, []int64{0, 17},
		"vector-e2e-capsule", gseed, eseed)
	session := jointDPVectorTestSession(spec, "vector-e2e")
	// Exact Ring128 additive shares for source [0,17].
	garblerShares := []*big.Int{
		new(big.Int).Sub(exactGCModulus(128), big.NewInt(9)),
		big.NewInt(123456789),
	}
	evaluatorShares := []*big.Int{
		big.NewInt(9),
		new(big.Int).Sub(exactGCModulus(128), big.NewInt(123456772)),
	}
	garblerConn, evaluatorConn := net.Pipe()
	type outcome struct {
		shares []*big.Int
		err    error
	}
	garblerDone := make(chan outcome, 1)
	evaluatorDone := make(chan outcome, 1)
	go func() {
		shares, err := jointDPVectorRunGarbler(
			garblerConn, session, spec, garblerShares, gseed)
		garblerDone <- outcome{shares, err}
	}()
	go func() {
		shares, err := jointDPVectorRunEvaluator(
			evaluatorConn, session, spec, evaluatorShares, eseed)
		evaluatorDone <- outcome{shares, err}
	}()
	garbler := <-garblerDone
	evaluator := <-evaluatorDone
	if garbler.err != nil || evaluator.err != nil {
		t.Fatalf("vector exact GC failed: garbler=%v evaluator=%v",
			garbler.err, evaluator.err)
	}
	if len(garbler.shares) != 3 || len(evaluator.shares) != 3 {
		t.Fatal("vector exact GC returned a wrong shape")
	}
	validity := new(big.Int).Xor(garbler.shares[2], evaluator.shares[2])
	if validity.Cmp(big.NewInt(1)) != 0 {
		t.Fatal("valid Ring128 source failed the in-circuit bound certificate")
	}
	for index, upper := range []int64{0, 17} {
		value := exactGCReferenceReconstruct(
			garbler.shares[index], evaluator.shares[index], 128)
		if value.Sign() < 0 || value.Cmp(big.NewInt(upper)) > 0 {
			t.Fatalf("coordinate %d escaped clamp [0,%d]: %s",
				index, upper, value.String())
		}
	}
}

func TestJointDPVectorExactGCCommonLatticePreconditioning(t *testing.T) {
	plan := jointDPVectorTestPlan(t, "1", "7.888609052210118e-31", "768", 2)
	gseed := sha256.Sum256([]byte("vector-lattice-garbler"))
	eseed := sha256.Sum256([]byte("vector-lattice-evaluator"))
	spec := jointDPVectorTestSpec(t, plan, 0, []int64{10, 1000},
		"vector-lattice-capsule", gseed, eseed)
	spec.OutputLatticeBits = 8
	spec.ScaleShifts = []int{8, 0}
	session := jointDPVectorTestSession(spec, "vector-lattice")
	raw := []*big.Int{big.NewInt(7), big.NewInt(500)}
	garblerShares := []*big.Int{big.NewInt(123456789), big.NewInt(987654321)}
	evaluatorShares := make([]*big.Int, len(raw))
	for index := range raw {
		evaluatorShares[index] = new(big.Int).Sub(
			exactGCModulus(128), garblerShares[index])
		evaluatorShares[index].Add(evaluatorShares[index], raw[index])
		evaluatorShares[index].Mod(evaluatorShares[index], exactGCModulus(128))
	}
	garblerConn, evaluatorConn := net.Pipe()
	type outcome struct {
		shares []*big.Int
		err    error
	}
	garblerDone := make(chan outcome, 1)
	evaluatorDone := make(chan outcome, 1)
	go func() {
		shares, err := jointDPVectorRunGarbler(
			garblerConn, session, spec, garblerShares, gseed)
		garblerDone <- outcome{shares, err}
	}()
	go func() {
		shares, err := jointDPVectorRunEvaluator(
			evaluatorConn, session, spec, evaluatorShares, eseed)
		evaluatorDone <- outcome{shares, err}
	}()
	garbler := <-garblerDone
	evaluator := <-evaluatorDone
	if garbler.err != nil || evaluator.err != nil {
		t.Fatalf("lattice circuit failed: garbler=%v evaluator=%v",
			garbler.err, evaluator.err)
	}
	if validity := new(big.Int).Xor(garbler.shares[2], evaluator.shares[2]); validity.Cmp(big.NewInt(1)) != 0 {
		t.Fatal("valid preconditioned source failed its bound certificate")
	}
	noise, err := jointDPVectorReferenceNoise(spec, gseed, eseed)
	if err != nil {
		t.Fatal(err)
	}
	for index := range raw {
		upper := new(big.Int).Lsh(
			new(big.Int).Set(spec.RawUpperBounds[index]),
			uint(spec.ScaleShifts[index]))
		want := new(big.Int).Lsh(new(big.Int).Set(raw[index]),
			uint(spec.ScaleShifts[index]))
		want.Add(want, noise[index])
		if want.Sign() < 0 {
			want.SetInt64(0)
		} else if want.Cmp(upper) > 0 {
			want.Set(upper)
		}
		got := exactGCReferenceReconstruct(
			garbler.shares[index], evaluator.shares[index], 128)
		if got.Cmp(want) != 0 {
			t.Fatalf("coordinate %d lattice result=%s want=%s",
				index, got.String(), want.String())
		}
	}
}

func TestJointDPVectorRejectsScaledRing128HeadroomFailure(t *testing.T) {
	plan := jointDPVectorTestPlan(t, "1", "7.888609052210118e-31", "1", 1)
	gseed := sha256.Sum256([]byte("vector-headroom-g"))
	eseed := sha256.Sum256([]byte("vector-headroom-e"))
	spec := jointDPVectorTestSpec(t, plan, 0, []int64{1},
		"vector-headroom", gseed, eseed)
	spec.ScaleShifts = []int{1}
	spec.RawUpperBounds = []*big.Int{exactGCMaxSigned(128)}
	if err := spec.validate(); err == nil {
		t.Fatal("scaled upper bound capable of Ring128 wrap was accepted")
	}
	spec.RawUpperBounds = []*big.Int{big.NewInt(1)}
	spec.ScaleShifts = []int{spec.OutputLatticeBits + 1}
	if err := spec.validate(); err == nil {
		t.Fatal("scale shift outside the declared lattice was accepted")
	}
}

func TestJointDPVectorExactGCRejectsOutOfBoundSourceWithoutPayload(t *testing.T) {
	plan := jointDPVectorTestPlan(t, "1", "7.888609052210118e-31", "1", 1)
	gseed := sha256.Sum256([]byte("vector-invalid-garbler"))
	eseed := sha256.Sum256([]byte("vector-invalid-evaluator"))
	spec := jointDPVectorTestSpec(t, plan, 0, []int64{17},
		"vector-invalid-capsule", gseed, eseed)
	session := jointDPVectorTestSession(spec, "vector-invalid")
	// The reconstructed residue is 18, one above the signed public bound.
	garblerShares := []*big.Int{big.NewInt(123456789)}
	evaluatorShares := []*big.Int{
		new(big.Int).Sub(exactGCModulus(128), big.NewInt(123456771)),
	}
	garblerConn, evaluatorConn := net.Pipe()
	type outcome struct {
		shares []*big.Int
		err    error
	}
	garblerDone := make(chan outcome, 1)
	evaluatorDone := make(chan outcome, 1)
	go func() {
		shares, err := jointDPVectorRunGarbler(
			garblerConn, session, spec, garblerShares, gseed)
		garblerDone <- outcome{shares, err}
	}()
	go func() {
		shares, err := jointDPVectorRunEvaluator(
			evaluatorConn, session, spec, evaluatorShares, eseed)
		evaluatorDone <- outcome{shares, err}
	}()
	garbler := <-garblerDone
	evaluator := <-evaluatorDone
	if garbler.err != nil || evaluator.err != nil {
		t.Fatalf("invalid-source circuit execution failed: garbler=%v evaluator=%v",
			garbler.err, evaluator.err)
	}
	if validity := new(big.Int).Xor(garbler.shares[1], evaluator.shares[1]); validity.Sign() != 0 {
		t.Fatal("out-of-bound Ring128 source was marked valid")
	}
	if payload := exactGCReferenceReconstruct(
		garbler.shares[0], evaluator.shares[0], 128); payload.Sign() != 0 {
		t.Fatalf("invalid source emitted a payload: %s", payload.String())
	}
}

func TestJointDPVectorCircuitShapeIsPublicAndCryptoFree(t *testing.T) {
	plan := jointDPVectorTestPlan(t, "1", "7.888609052210118e-31", "1", 2)
	gseed := sha256.Sum256([]byte("vector-shape-g"))
	eseed := sha256.Sum256([]byte("vector-shape-e"))
	base := jointDPVectorTestSpec(t, plan, 0, []int64{17, 19},
		"vector-shape-a", gseed, eseed)
	changed := jointDPVectorTestSpec(t, plan, 0, []int64{23, 29},
		"vector-shape-b", sha256.Sum256([]byte("other-g")),
		sha256.Sum256([]byte("other-e")))
	baseSource := jointDPVectorCircuitSource(base)
	if baseSource != jointDPVectorCircuitSource(changed) ||
		base.circuitShapeDigest() != changed.circuitShapeDigest() {
		t.Fatal("data, bounds, transcript, or commitments changed public circuit shape")
	}
	if base.contractDigest() == changed.contractDigest() ||
		base.digest() == changed.digest() {
		t.Fatal("purpose digest failed to bind bounds/transcript/commitments")
	}
	shifted := base
	shifted.ScaleShifts = []int{8, 0}
	if baseSource == jointDPVectorCircuitSource(shifted) ||
		base.circuitShapeDigest() == shifted.circuitShapeDigest() ||
		base.contractDigest() == shifted.contractDigest() {
		t.Fatal("public lattice shift was not bound to circuit shape and contract")
	}
	for _, forbidden := range []string{
		"crypto/aes", "crypto/hmac", "crypto/sha256", "HKDF", "ChaCha",
	} {
		if strings.Contains(baseSource, forbidden) {
			t.Fatalf("local stream expansion leaked into the circuit: %q", forbidden)
		}
	}
	baseCircuit, err := jointDPVectorGCCompile(base)
	if err != nil {
		t.Fatal(err)
	}
	changedCircuit, err := jointDPVectorGCCompile(changed)
	if err != nil {
		t.Fatal(err)
	}
	if baseCircuit != changedCircuit {
		t.Fatal("equal public shapes did not reuse the compiled circuit")
	}
}

func jointDPVectorTestContractInput(t testing.TB,
	plan jointDPVectorPlanOutput, upper []string,
	gseed, eseed [32]byte) jointDPVectorWorkerContractInput {
	t.Helper()
	transcript := sha256.Sum256([]byte("vector-worker-contract/" + t.Name()))
	gctx := jointDPCommitmentContext(transcript, "garbler", "peer-a")
	ectx := jointDPCommitmentContext(transcript, "evaluator", "peer-b")
	gcommit := jointDPSeedCommitment(gctx, gseed)
	ecommit := jointDPSeedCommitment(ectx, eseed)
	return jointDPVectorWorkerContractInput{
		Version:  jointDPVectorWorkerContractInputVersion,
		RingBits: 128, FracBits: 0, OutputLatticeBits: 8,
		TotalCoordinateCount: plan.TotalCoordinateCount,
		ChunkStart:           0, CoordinateCount: len(upper),
		Epsilon: "1", AllocatedDelta: "7.888609052210118e-31",
		SensitivitySteps: plan.SensitivitySteps,
		ScaleShifts:      make([]int, len(upper)), RawUpperBounds: upper,
		TranscriptHash:             hex.EncodeToString(transcript[:]),
		GarblerCommitmentContext:   hex.EncodeToString(gctx[:]),
		EvaluatorCommitmentContext: hex.EncodeToString(ectx[:]),
		GarblerSeedCommitment:      hex.EncodeToString(gcommit[:]),
		EvaluatorSeedCommitment:    hex.EncodeToString(ecommit[:]),
	}
}

func TestJointDPVectorWorkerContractIsDataFreeAndTamperEvident(t *testing.T) {
	plan := jointDPVectorTestPlan(t, "1", "7.888609052210118e-31", "2", 2)
	gseed := sha256.Sum256([]byte("vector-contract-g"))
	eseed := sha256.Sum256([]byte("vector-contract-e"))
	input := jointDPVectorTestContractInput(
		t, plan, []string{"10", "20"}, gseed, eseed)
	compiled, err := jointDPCompileVectorWorkerContract(input)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Version != jointDPVectorWorkerContractOutputVersion ||
		compiled.CapabilityID != jointDPVectorExactGCCapabilityID ||
		compiled.Operation != string(jointDPVectorOperation) ||
		compiled.Purpose != string(jointDPVectorOperation)+"/"+compiled.CircuitDigest ||
		compiled.InputContract != "public-data-free-biomedical-vector-chunk-v1" ||
		compiled.ProtectedInputsAccepted || compiled.PrivateSeedAccepted ||
		!compiled.CapabilityAvailable {
		t.Fatalf("invalid vector worker contract: %#v", compiled)
	}
	encoded, err := json.Marshal(compiled)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		[]byte(`"source_share":`), []byte(`"private_seed":`), gseed[:], eseed[:],
	} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf("data-free compiler exposed forbidden material %q", forbidden)
		}
	}

	changed := input
	changed.ChunkStart = 1
	changed.CoordinateCount = 1
	changed.ScaleShifts = []int{0}
	changed.RawUpperBounds = []string{"20"}
	changedCompiled, err := jointDPCompileVectorWorkerContract(changed)
	if err != nil {
		t.Fatal(err)
	}
	if changedCompiled.CircuitDigest == compiled.CircuitDigest ||
		changedCompiled.Purpose == compiled.Purpose {
		t.Fatal("chunk binding did not change the circuit contract")
	}
	tamperedPolicy := compiled.WorkerPolicy
	tamperedPolicy.BernoulliThresholds = append(
		[]string(nil), tamperedPolicy.BernoulliThresholds...)
	tamperedPolicy.BernoulliThresholds[0] = "1"
	dummySession := jointDPVectorTestSession(
		jointDPVectorTestSpec(t, plan, 0, []int64{10, 20},
			"dummy", gseed, eseed), "dummy")
	dummySession.Purpose = compiled.Purpose
	if _, err := jointDPVectorSpecFromPolicy(tamperedPolicy, dummySession); err == nil {
		t.Fatal("tampered probability plan was accepted")
	}
}

func jointDPVectorTestWorkerPolicy(compiled jointDPVectorWorkerContractOutput) *jointDPVectorWorkerPolicy {
	policy := compiled.WorkerPolicy
	return &policy
}

func jointDPVectorTestRunDurableWorkers(t *testing.T,
	compiled jointDPVectorWorkerContractOutput,
	garblerSeed, evaluatorSeed [32]byte,
	garblerShares, evaluatorShares []*big.Int,
	tag string) (exactGCWorkerResult, exactGCWorkerResult, string, string) {
	t.Helper()
	gDir := exactGCTestSpool(t, "vector-worker-g-"+tag)
	eDir := exactGCTestSpool(t, "vector-worker-e-"+tag)
	sid := sha256.Sum256([]byte("vector-worker-session/" + tag))
	master := sha256.Sum256([]byte("vector-worker-master/" + tag))
	base := exactGCWorkerConfig{
		Version:   exactGCWorkerConfigVersion,
		SessionID: hex.EncodeToString(sid[:]),
		MasterKey: base64.StdEncoding.EncodeToString(master[:]),
		GarblerID: "peer-a", EvaluatorID: "peer-b",
		Purpose: compiled.Purpose, Operation: string(jointDPVectorOperation),
		RingBits: 128, FracBits: 0,
		VectorLen:     compiled.WorkerPolicy.CoordinateCount,
		JointDPVector: jointDPVectorTestWorkerPolicy(compiled),
		MaxSpoolBytes: 1 << 30, TTLSeconds: 120,
	}
	encodingSpec := exactGCCircuitSpec{
		Operation: jointDPVectorOperation, RingBits: 128, FracBits: 0,
		VectorLen: base.VectorLen,
	}
	gConfig := base
	gConfig.Role, gConfig.SpoolDir = "garbler", gDir
	gConfig.PrivateSeed = base64.StdEncoding.EncodeToString(garblerSeed[:])
	gConfig.SourceShare = exactGCTestEncodeSource(t, garblerShares, encodingSpec)
	eConfig := base
	eConfig.Role, eConfig.SpoolDir = "evaluator", eDir
	eConfig.PrivateSeed = base64.StdEncoding.EncodeToString(evaluatorSeed[:])
	eConfig.SourceShare = exactGCTestEncodeSource(t, evaluatorShares, encodingSpec)
	gPath := exactGCTestWriteConfig(t, gDir, gConfig)
	ePath := exactGCTestWriteConfig(t, eDir, eConfig)
	errors := make(chan error, 2)
	go func() { errors <- handleExactGCWorker(gPath) }()
	go func() { errors <- handleExactGCWorker(ePath) }()
	gOffset, eOffset := int64(0), int64(0)
	deadline := time.Now().Add(120 * time.Second)
	for !exactGCTestBothDone(gDir, eDir) && time.Now().Before(deadline) {
		gOffset = exactGCTestRelaySpool(t, gDir, eDir, gOffset)
		eOffset = exactGCTestRelaySpool(t, eDir, gDir, eOffset)
		now := time.Now()
		for _, dir := range []string{gDir, eDir} {
			if err := os.Chtimes(filepath.Join(dir, "exchange.hb"), now, now); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(time.Millisecond)
	}
	if !exactGCTestBothDone(gDir, eDir) {
		t.Fatal("joint-DP vector workers did not complete")
	}
	for index := 0; index < 2; index++ {
		if err := <-errors; err != nil {
			t.Fatalf("joint-DP vector worker failed: %v", err)
		}
	}
	if fileExists(gPath) || fileExists(ePath) {
		t.Fatal("a seed-bearing vector worker config survived readiness")
	}
	return exactGCTestReadResult(t, gDir), exactGCTestReadResult(t, eDir),
		gDir, eDir
}

func TestJointDPVectorDurableWorkersNoStreamDisclosureAndStickyRetry(t *testing.T) {
	if testing.Short() {
		t.Skip("real worker/spool KOS protocol")
	}
	plan := jointDPVectorTestPlan(t, "1", "7.888609052210118e-31", "1", 1)
	gseed := sha256.Sum256([]byte("vector-durable-g"))
	eseed := sha256.Sum256([]byte("vector-durable-e"))
	input := jointDPVectorTestContractInput(t, plan, []string{"20"}, gseed, eseed)
	compiled, err := jointDPCompileVectorWorkerContract(input)
	if err != nil {
		t.Fatal(err)
	}
	modulus := exactGCModulus(128)
	garblerSource := []*big.Int{big.NewInt(123456)}
	evaluatorSource := []*big.Int{
		new(big.Int).Sub(new(big.Int).Set(modulus), big.NewInt(123447)),
	}
	firstG, firstE, firstGDir, firstEDir := jointDPVectorTestRunDurableWorkers(
		t, compiled, gseed, eseed, garblerSource, evaluatorSource, "first")
	secondG, secondE, secondGDir, secondEDir := jointDPVectorTestRunDurableWorkers(
		t, compiled, gseed, eseed, garblerSource, evaluatorSource, "retry")
	if firstG.Kind != "joint-dp-vector-ring128-share-v1" ||
		firstE.Kind != firstG.Kind || firstG.Share != secondG.Share ||
		firstE.Share != secondE.Share ||
		firstG.ValidityShare != secondG.ValidityShare ||
		firstE.ValidityShare != secondE.ValidityShare {
		t.Fatalf("sticky durable retry changed output shares: %#v %#v %#v %#v",
			firstG, firstE, secondG, secondE)
	}
	spec, err := jointDPVectorSpecFromPolicy(
		compiled.WorkerPolicy, jointDPVectorTestSession(
			jointDPVectorTestSpec(t, plan, 0, []int64{20},
				"placeholder", gseed, eseed), "placeholder"))
	_ = spec
	// The parser above is deliberately purpose-bound and should reject the
	// placeholder transcript.  Streams for scanning are derived from the
	// compiler policy directly below.
	if err == nil {
		t.Fatal("mismatched worker session unexpectedly parsed")
	}
	workerSession := exactGCSession{
		SessionID: [32]byte{1}, MasterKey: [32]byte{1},
		GarblerID: "peer-a", EvaluatorID: "peer-b",
		Purpose: compiled.Purpose,
		Spec: exactGCCircuitSpec{Operation: jointDPVectorOperation,
			RingBits: 128, VectorLen: 1},
	}
	spec, err = jointDPVectorSpecFromPolicy(compiled.WorkerPolicy, workerSession)
	if err != nil {
		t.Fatal(err)
	}
	gStream, _ := jointDPVectorPrivateStream(gseed, spec, "garbler")
	eStream, _ := jointDPVectorPrivateStream(eseed, spec, "evaluator")
	defer clear(gStream)
	defer clear(eStream)
	for _, dir := range []string{firstGDir, firstEDir, secondGDir, secondEDir} {
		for _, name := range []string{"inbound.bin", "outbound.bin", "result.json"} {
			data, readErr := os.ReadFile(filepath.Join(dir, name))
			if readErr != nil {
				t.Fatal(readErr)
			}
			for _, forbidden := range [][]byte{
				gseed[:], eseed[:], gStream, eStream,
				[]byte(base64.StdEncoding.EncodeToString(gseed[:])),
				[]byte(base64.StdEncoding.EncodeToString(eseed[:])),
			} {
				if len(forbidden) != 0 && bytes.Contains(data, forbidden) {
					t.Fatalf("%s/%s exposed seed or private stream", dir, name)
				}
			}
		}
	}
}

func TestJointDPVectorWorkerTamperFailsBeforeReadyAndPublishesNoResult(t *testing.T) {
	plan := jointDPVectorTestPlan(t, "1", "7.888609052210118e-31", "1", 1)
	gseed := sha256.Sum256([]byte("vector-tamper-g"))
	eseed := sha256.Sum256([]byte("vector-tamper-e"))
	input := jointDPVectorTestContractInput(t, plan, []string{"20"}, gseed, eseed)
	compiled, err := jointDPCompileVectorWorkerContract(input)
	if err != nil {
		t.Fatal(err)
	}
	dir := exactGCTestSpool(t, "vector-worker-tamper")
	sid := sha256.Sum256([]byte("vector-worker-tamper-session"))
	master := sha256.Sum256([]byte("vector-worker-tamper-master"))
	policy := compiled.WorkerPolicy
	policy.BernoulliThresholds = append([]string(nil), policy.BernoulliThresholds...)
	policy.BernoulliThresholds[0] = "1"
	config := exactGCWorkerConfig{
		Version: exactGCWorkerConfigVersion, Role: "garbler",
		SessionID: hex.EncodeToString(sid[:]),
		MasterKey: base64.StdEncoding.EncodeToString(master[:]),
		GarblerID: "peer-a", EvaluatorID: "peer-b",
		Purpose: compiled.Purpose, Operation: string(jointDPVectorOperation),
		RingBits: 128, FracBits: 0, VectorLen: 1,
		SourceShare: exactGCTestEncodeSource(t, []*big.Int{big.NewInt(9)},
			exactGCCircuitSpec{Operation: jointDPVectorOperation,
				RingBits: 128, VectorLen: 1}),
		JointDPVector: &policy,
		PrivateSeed:   base64.StdEncoding.EncodeToString(gseed[:]),
		SpoolDir:      dir, MaxSpoolBytes: 1 << 30, TTLSeconds: 120,
	}
	configPath := exactGCTestWriteConfig(t, dir, config)
	if err := handleExactGCWorker(configPath); err == nil {
		t.Fatal("tampered worker policy was accepted")
	}
	if fileExists(configPath) {
		t.Fatal("seed-bearing config survived a tampered worker failure")
	}
	if !fileExists(filepath.Join(dir, "failure.json")) ||
		fileExists(filepath.Join(dir, "ready")) ||
		fileExists(filepath.Join(dir, "result.json")) ||
		fileExists(filepath.Join(dir, "done")) {
		t.Fatal("tampered worker did not fail before readiness without a result")
	}
}

func TestJointDPVectorV3CostAuditAgainstLinearV2(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles both sampler generations")
	}
	plan := jointDPVectorTestPlan(t, "1", "7.888609052210118e-31", "1", 1)
	gseed := sha256.Sum256([]byte("vector-cost-g"))
	eseed := sha256.Sum256([]byte("vector-cost-e"))
	v3Spec := jointDPVectorTestSpec(t, plan, 0, []int64{1000},
		"vector-cost", gseed, eseed)
	v3, err := jointDPVectorGCCompile(v3Spec)
	if err != nil {
		t.Fatal(err)
	}
	// Use the same one-coordinate Ring127 integer workload and the v2 default
	// certified linear horizon.  This is an implementation-cost audit, not a
	// claim that the two finite approximations have identical distributions.
	v2Spec, _, _ := jointDPTestSpec(t, 127, 0, 1, 71)
	v2, err := jointDPGCCompile(v2Spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("v2 linear sampler: gates=%d cost=%d wires=%d input_bits=%d",
		v2.NumGates, v2.Cost(), v2.NumWires, v2.Inputs.Size())
	t.Logf("v3 binary sampler: gates=%d cost=%d wires=%d input_bits=%d J=%d R=%d",
		v3.NumGates, v3.Cost(), v3.NumWires, v3.Inputs.Size(),
		plan.BinaryGeometricBits, plan.UniformBits)
	if v3.Cost() >= v2.Cost() || v3.NumGates >= v2.NumGates {
		t.Fatal("binary-decomposition sampler did not reduce the v2 circuit cost")
	}
}

func BenchmarkJointDPVectorCircuitCompileAndInput(b *testing.B) {
	plan, err := jointDPPlanVectorLaplace(jointDPVectorPlanInput{
		Epsilon: "1", Delta: "7.888609052210118e-31",
		SensitivitySteps: "131073", TotalCoordinateCount: 1000000,
	})
	if err != nil {
		b.Fatal(err)
	}
	gseed := sha256.Sum256([]byte("benchmark-g"))
	eseed := sha256.Sum256([]byte("benchmark-e"))
	count := plan.MaximumChunkCoordinates
	if requested := os.Getenv("DSVERT_BENCH_VECTOR_COORDS"); requested != "" {
		parsed, parseErr := strconv.Atoi(requested)
		if parseErr != nil || parsed < 1 || parsed > count {
			b.Fatalf("invalid DSVERT_BENCH_VECTOR_COORDS=%q", requested)
		}
		count = parsed
	}
	upper := make([]int64, count)
	for index := range upper {
		upper[index] = 1 << 30
	}
	spec := jointDPVectorTestSpec(b, plan, 0, upper,
		"benchmark", gseed, eseed)
	b.ReportMetric(float64(
		count*(512+4*plan.BinaryGeometricBits*plan.UniformBits)+1),
		"private-input-bits")
	b.ReportMetric(float64(count*plan.PrivateStreamBytesPerCoordinate),
		"stream-bytes/peer-chunk")
	for index := 0; index < b.N; index++ {
		shape := spec.circuitShapeDigest()
		key := fmt.Sprintf("%x", shape[:])
		jointDPVectorGCCache.Lock()
		delete(jointDPVectorGCCache.entries, key)
		jointDPVectorGCCache.Unlock()
		if _, err := jointDPVectorGCCompile(spec); err != nil {
			b.Fatal(err)
		}
	}
}
