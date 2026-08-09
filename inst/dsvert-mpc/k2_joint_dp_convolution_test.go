package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func jointDPConvolutionTestInput(peer string, seedIndex int,
	shares, lower, upper []string) jointDPConvolutionShareInput {

	return jointDPConvolutionShareInput{
		Version:  jointDPConvolutionVersion,
		PeerName: peer, PeerIdentityPK: strings.Repeat(peer[:1], 43),
		QueryID:          strings.Repeat("a", 64),
		CapsuleReleaseID: strings.Repeat("a", 64), AllocationIndex: "0",
		SourceContractHash: strings.Repeat("b", 64),
		MaskContractHash:   strings.Repeat("c", 64),
		RingBits:           128, FracBits: 0, AdditiveShares: shares,
		StatisticLowerBounds: lower, StatisticUpperBounds: upper,
		ReleaseLowerBounds: jointDPConvolutionTestRepeated(
			"-9007199254740991", len(shares)),
		ReleaseUpperBounds: jointDPConvolutionTestRepeated(
			"9007199254740991", len(shares)),
		MaskProtocol:                  jointDPConvolutionMaskProtocol,
		MaskConditionalMinEntropyBits: 128,
		MaskIndependentOfStatistic:    true,
		DesignatedNoisePeerCount:      2,
		Mechanism:                     jointDPConvolutionLaplace,
		CapsuleEpsilon:                1, CapsuleDelta: 1e-20,
		Epsilons:      make([]float64, len(shares)),
		Sensitivities: make([]int64, len(shares)),
		Seed:          testDPSeedFor(seedIndex),
	}
}

func jointDPConvolutionTestRepeated(value string, count int) []string {
	result := make([]string, count)
	for i := range result {
		result[i] = value
	}
	return result
}

func jointDPConvolutionTestSplit(values []*big.Int) ([]string, []string) {
	modulus := exactGCModulus(128)
	left := make([]string, len(values))
	right := make([]string, len(values))
	for i, value := range values {
		mask := new(big.Int).Lsh(big.NewInt(int64(17+i)), uint(96+i))
		mask.Add(mask, big.NewInt(int64(1234567+31*i)))
		mask.Mod(mask, modulus)
		other := new(big.Int).Sub(value, mask)
		other.Mod(other, modulus)
		left[i], right[i] = mask.String(), other.String()
	}
	return left, right
}

func jointDPConvolutionTestClip(value *big.Int) int64 {
	if value.Cmp(big.NewInt(dpNoiseOutputMin)) < 0 {
		return dpNoiseOutputMin
	}
	if value.Cmp(big.NewInt(dpNoiseOutputMax)) > 0 {
		return dpNoiseOutputMax
	}
	return value.Int64()
}

func TestJointDPConvolutionStickyIndependentAndExactFinalOpening(t *testing.T) {
	statistics := []*big.Int{big.NewInt(37), big.NewInt(-91), big.NewInt(0)}
	leftShares, rightShares := jointDPConvolutionTestSplit(statistics)
	lower := []string{"-100", "-100", "-100"}
	upper := []string{"100", "100", "100"}
	leftInput := jointDPConvolutionTestInput(
		"peer_a", 3101, leftShares, lower, upper)
	rightInput := jointDPConvolutionTestInput(
		"peer_b", 7291, rightShares, lower, upper)
	for i := range statistics {
		leftInput.Epsilons[i], rightInput.Epsilons[i] = 0.75, 0.75
		leftInput.Sensitivities[i], rightInput.Sensitivities[i] = 1, 1
	}
	leftInput.CapsuleEpsilon, rightInput.CapsuleEpsilon = 0.75, 0.75

	left, err := jointDPConvolutionShare(leftInput)
	if err != nil {
		t.Fatalf("left complete-capsule share: %v", err)
	}
	leftReplay, err := jointDPConvolutionShare(leftInput)
	if err != nil || !reflect.DeepEqual(left, leftReplay) {
		t.Fatalf("sticky replay changed: err=%v", err)
	}
	right, err := jointDPConvolutionShare(rightInput)
	if err != nil {
		t.Fatalf("right complete-capsule share: %v", err)
	}
	if reflect.DeepEqual(left.NoisedShares, right.NoisedShares) {
		t.Fatal("independently rooted peers produced identical translated shares")
	}
	opened, err := jointDPConvolutionReferenceFinalize(
		128, left.NoisedShares, right.NoisedShares,
		left.ReleaseLowerBounds, left.ReleaseUpperBounds)
	if err != nil {
		t.Fatalf("joint finalizer: %v", err)
	}
	leftSeed, _ := hex.DecodeString(leftInput.Seed)
	rightSeed, _ := hex.DecodeString(rightInput.Seed)
	leftNoise := dpDeterministicAddNoise(leftSeed)
	rightNoise := dpDeterministicAddNoise(rightSeed)
	for i, statistic := range statistics {
		n1, err := leftNoise(i, 0, 1, 1, 0.75, 0)
		if err != nil {
			t.Fatal(err)
		}
		n2, err := rightNoise(i, 0, 1, 1, 0.75, 0)
		if err != nil {
			t.Fatal(err)
		}
		want := new(big.Int).Add(statistic, big.NewInt(n1))
		want.Add(want, big.NewInt(n2))
		if want.Cmp(big.NewInt(dpNoiseOutputMin)) >= 0 &&
			want.Cmp(big.NewInt(dpNoiseOutputMax)) <= 0 &&
			opened[i] != want.Int64() {
			t.Fatalf("coordinate %d did not reconstruct exact S+raw(N1)+raw(N2): got %d want %s",
				i, opened[i], want)
		}
		if opened[i] != jointDPConvolutionTestClip(want) {
			t.Fatalf("coordinate %d opened=%d, want final clip of S+N1+N2=%s",
				i, opened[i], want)
		}
	}
	if !left.FullCapsuleParametersPerPeer || left.EpsilonDividedByPeerCount ||
		left.CapsuleEpsilon != 0.75 || left.DesignatedNoisePeerCount != 2 ||
		left.CapsuleReleaseID != leftInput.CapsuleReleaseID ||
		left.DeltaImplSampler != jointDPConvolutionLaplaceDeltaFloor ||
		left.DeltaMechanism != 0 || left.DeltaTotal != left.DeltaImplSampler ||
		left.DeltaTotal > left.CapsuleDelta ||
		left.NominalVarianceMultiplier != 2 ||
		left.NominalRMSEMultiplier != math.Sqrt2 ||
		left.CapabilityAvailable || left.PayloadDeliveryAvailable ||
		left.ThreatModel !=
			"pinned_semi_honest_noncolluding; malicious_noise_contribution_not_covered" ||
		left.UtilityPreferredBackend != "exact_gc_one_joint_noise_sample" {
		t.Fatalf("invalid fallback contract: %+v", left)
	}
	encoded, err := json.Marshal(left)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"\"seed\"", "noise_values", "statistic_values"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("private field %q escaped command output", forbidden)
		}
	}
}

func TestJointDPConvolutionUsesRawNoiseAndOneFinalSaturation(t *testing.T) {
	input := jointDPConvolutionTestInput(
		"peer_a", 1, []string{"0"}, []string{"-1"}, []string{"1"})
	input.Epsilons[0], input.Sensitivities[0] = 1, 1
	if err := validateJointDPConvolutionShareInput(input); err != nil {
		t.Fatalf("valid Ring128 raw-domain contract: %v", err)
	}
	translated, preLower, preUpper, err := jointDPConvolutionAddShares(
		input, []int64{math.MinInt64})
	if err != nil {
		t.Fatalf("raw MinInt64 draw rejected: %v", err)
	}
	if translated[0] != new(big.Int).Add(
		big.NewInt(math.MinInt64), exactGCModulus(128)).String() {
		t.Fatalf("raw draw was clipped before ring addition: %s", translated[0])
	}
	if preLower[0] != "-18446744073709551617" ||
		preUpper[0] != "18446744073709551615" {
		t.Fatalf("incorrect two-raw-draw headroom: [%s,%s]",
			preLower[0], preUpper[0])
	}
	left := []string{translated[0]}
	rightTranslated, _, _, err := jointDPConvolutionAddShares(
		input, []int64{math.MinInt64})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := jointDPConvolutionReferenceFinalize(
		128, left, rightTranslated,
		input.ReleaseLowerBounds, input.ReleaseUpperBounds)
	if err != nil {
		t.Fatal(err)
	}
	if opened[0] != dpNoiseOutputMin {
		t.Fatalf("single final saturation=%d, want %d", opened[0], dpNoiseOutputMin)
	}

	tooNarrow := input
	tooNarrow.RingBits = 127
	tooNarrow.MaskConditionalMinEntropyBits = 127
	if err := validateJointDPConvolutionShareInput(tooNarrow); err == nil ||
		!strings.Contains(err.Error(), "Ring128") {
		t.Fatalf("Ring127 mask/raw-domain contract error=%v", err)
	}
	nearEdge := input
	nearEdge.StatisticLowerBounds = []string{
		new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 127)).String()}
	if err := validateJointDPConvolutionShareInput(nearEdge); err == nil ||
		!strings.Contains(err.Error(), "no-wrap") {
		t.Fatalf("missing raw-domain no-wrap rejection: %v", err)
	}
	badClip := input
	badClip.ReleaseLowerBounds = []string{"1"}
	badClip.ReleaseUpperBounds = []string{"0"}
	if err := validateJointDPConvolutionShareInput(badClip); err == nil ||
		!strings.Contains(err.Error(), "saturation") {
		t.Fatalf("invalid final saturation error=%v", err)
	}
}

func TestJointDPConvolutionValidationIsStrictBeforeSampling(t *testing.T) {
	valid := jointDPConvolutionTestInput(
		"peer_a", 1, []string{"0", "1"},
		[]string{"-2", "-2"}, []string{"2", "2"})
	valid.Epsilons = []float64{1, 1}
	valid.Sensitivities = []int64{1, 1}
	cases := map[string]func(*jointDPConvolutionShareInput){
		"operation identity differs from capsule": func(x *jointDPConvolutionShareInput) {
			x.QueryID = strings.Repeat("e", 64)
		},
		"missing capsule binding": func(x *jointDPConvolutionShareInput) {
			x.CapsuleReleaseID = ""
		},
		"weak mask entropy": func(x *jointDPConvolutionShareInput) {
			x.MaskConditionalMinEntropyBits = 127
		},
		"mask may depend on statistic": func(x *jointDPConvolutionShareInput) {
			x.MaskIndependentOfStatistic = false
		},
		"three noise peers": func(x *jointDPConvolutionShareInput) {
			x.DesignatedNoisePeerCount = 3
		},
		"noncanonical residue": func(x *jointDPConvolutionShareInput) {
			x.AdditiveShares[0] = "00"
		},
		"outside ring": func(x *jointDPConvolutionShareInput) {
			x.AdditiveShares[0] = exactGCModulus(128).String()
		},
		"coordinate epsilon differs from global": func(x *jointDPConvolutionShareInput) {
			x.Epsilons = []float64{1, 0.5}
		},
		"epsilon divided by K": func(x *jointDPConvolutionShareInput) {
			x.Epsilons = []float64{0.5, 0.5}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.AdditiveShares = append([]string(nil), valid.AdditiveShares...)
			candidate.Epsilons = append([]float64(nil), valid.Epsilons...)
			candidate.Sensitivities = append([]int64(nil), valid.Sensitivities...)
			mutate(&candidate)
			if err := validateJointDPConvolutionShareInput(candidate); err == nil {
				t.Fatal("invalid contract unexpectedly succeeded")
			}
		})
	}

	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	encoded = bytes.Replace(encoded, []byte("}"), []byte(",\"unknown\":1}"), 1)
	if _, err := decodeJointDPConvolutionShareInput(bytes.NewReader(encoded)); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown input field error=%v", err)
	}
}

func TestJointDPConvolutionDeltaAllocationFailsBeforeSeedOrDraw(t *testing.T) {
	input := jointDPConvolutionTestInput(
		"peer_a", 1, []string{"0"}, []string{"0"}, []string{"1"})
	input.Epsilons[0], input.Sensitivities[0] = 1, 1
	input.Seed = "not-a-seed"

	input.CapsuleDelta = 0
	err := validateJointDPConvolutionShareInput(input)
	if err == nil || !strings.Contains(err.Error(), "delta") ||
		strings.Contains(err.Error(), "seed") {
		t.Fatalf("zero-delta proposal was not rejected before seed handling: %v", err)
	}

	input.CapsuleDelta = math.Nextafter(
		jointDPConvolutionLaplaceDeltaFloor, 0)
	err = validateJointDPConvolutionShareInput(input)
	if err == nil || !strings.Contains(err.Error(), "implementation delta") ||
		strings.Contains(err.Error(), "seed") {
		t.Fatalf("underfunded proposal was not rejected before seed handling: %v", err)
	}

	input.CapsuleDelta = jointDPConvolutionLaplaceDeltaFloor
	if err = validateJointDPConvolutionShareInput(input); err == nil ||
		!strings.Contains(err.Error(), "seed") {
		t.Fatalf("funded proposal did not proceed to seed validation: %v", err)
	}

	input.Mechanism = jointDPConvolutionGaussian
	input.Epsilons, input.Sensitivities = nil, nil
	input.L2Sensitivity = 1
	input.CapsuleDelta = dpGaussianScalarTVBound
	err = validateJointDPConvolutionShareInput(input)
	if err == nil || !strings.Contains(err.Error(), "Gaussian") ||
		strings.Contains(err.Error(), "seed") {
		t.Fatalf("underfunded Gaussian proposal was not rejected before seed handling: %v", err)
	}
}

func TestJointDPConvolutionFiniteSamplerDeltaIsConservativeAndNonZero(t *testing.T) {
	for _, coordinates := range []int{1, 2, 1_000_000} {
		bound, err := jointDPConvolutionLaplaceImplementationDeltaBound(
			coordinates, 1, 1)
		if err != nil {
			t.Fatalf("coordinates=%d: %v", coordinates, err)
		}
		if bound != jointDPConvolutionLaplaceDeltaFloor || bound <= 0 {
			t.Fatalf("coordinates=%d bound=%.17g, want conservative non-zero floor %.17g",
				coordinates, bound, jointDPConvolutionLaplaceDeltaFloor)
		}

		granularity := dpCeilPowerOfTwo(
			(1.0 / 1.0) / dpNoiseGranularityParam)
		lambdaLower := math.Nextafter(
			granularity/(1+granularity), 0)
		capLower := math.Nextafter(math.Exp2(63), 0)
		logRawUnionBound := math.Log(float64(
			2*jointDPConvolutionPeerCount*coordinates)) -
			math.Nextafter(lambdaLower*capLower, 0)
		logDPBound := logRawUnionBound + math.Log1p(math.Exp(1))
		if logDPBound >= math.Log(bound) {
			t.Fatalf("coordinates=%d reported delta does not dominate two-peer vector tail: log raw %.17g, log reported %.17g",
				coordinates, logDPBound, math.Log(bound))
		}
	}
}

func TestJointDPConvolutionGaussianIsStickyAndUsesFullAllocation(t *testing.T) {
	statistics := []*big.Int{big.NewInt(4), big.NewInt(-7)}
	leftShares, rightShares := jointDPConvolutionTestSplit(statistics)
	lower, upper := []string{"-10", "-10"}, []string{"10", "10"}
	leftInput := jointDPConvolutionTestInput(
		"peer_a", 711, leftShares, lower, upper)
	rightInput := jointDPConvolutionTestInput(
		"peer_b", 912, rightShares, lower, upper)
	for _, input := range []*jointDPConvolutionShareInput{&leftInput, &rightInput} {
		input.Mechanism = jointDPConvolutionGaussian
		input.CapsuleEpsilon = 1
		input.CapsuleDelta = 1e-6
		input.Epsilons = nil
		input.Sensitivities = nil
		input.L2Sensitivity = math.Sqrt2
	}
	left, err := jointDPConvolutionShare(leftInput)
	if err != nil {
		t.Fatalf("left Gaussian share: %v", err)
	}
	right, err := jointDPConvolutionShare(rightInput)
	if err != nil {
		t.Fatalf("right Gaussian share: %v", err)
	}
	replay, err := jointDPConvolutionShare(leftInput)
	if err != nil || !reflect.DeepEqual(left, replay) {
		t.Fatalf("Gaussian sticky replay changed: %v", err)
	}
	if _, err := jointDPConvolutionReferenceFinalize(
		128, left.NoisedShares, right.NoisedShares,
		left.ReleaseLowerBounds, left.ReleaseUpperBounds); err != nil {
		t.Fatalf("Gaussian final opening: %v", err)
	}
	wantImplementationDelta, err := dpGaussianImplementationDeltaBound(2, 1)
	if err != nil {
		t.Fatalf("Gaussian implementation-delta bound: %v", err)
	}
	if left.DeltaImplSampler != wantImplementationDelta ||
		left.DeltaMechanism <= 0 || left.DeltaTotal != 1e-6 ||
		left.CapsuleEpsilon != 1 || left.EpsilonDividedByPeerCount {
		t.Fatalf("Gaussian full allocation changed: %+v", left)
	}
}

func TestJointDPConvolutionCountUsesOneDirectPublicClamp(t *testing.T) {
	input := jointDPConvolutionTestInput(
		"peer_a", 1, []string{"0"}, []string{"0"}, []string{"100"})
	input.Epsilons[0], input.Sensitivities[0] = 1, 1
	input.ReleaseLowerBounds = []string{"0"}
	input.ReleaseUpperBounds = []string{"100"}
	if err := validateJointDPConvolutionShareInput(input); err != nil {
		t.Fatalf("count release clamp rejected: %v", err)
	}
	modulus := exactGCModulus(128)
	encodeSigned := func(value *big.Int) string {
		return new(big.Int).Mod(value, modulus).String()
	}
	for _, test := range []struct {
		preclip *big.Int
		want    int64
	}{
		{big.NewInt(-7), 0}, {big.NewInt(42), 42}, {big.NewInt(137), 100},
	} {
		opened, err := jointDPConvolutionReferenceFinalize(
			128, []string{encodeSigned(test.preclip)}, []string{"0"},
			input.ReleaseLowerBounds, input.ReleaseUpperBounds)
		if err != nil {
			t.Fatal(err)
		}
		if opened[0] != test.want {
			t.Fatalf("preclip=%s opened=%d, want one direct count clamp=%d",
				test.preclip, opened[0], test.want)
		}
	}
}

func jointDPConvolutionPMF(z int, r float64) float64 {
	if z < 0 {
		z = -z
	}
	normalizer := (1 - r) / (1 + r)
	return normalizer * normalizer * math.Pow(r, float64(z)) *
		(float64(z-1) + 2/(1-r*r))
}

func jointDPConvolutionClippedProbability(
	output, statistic, bound int, r float64,
) float64 {
	if output > -bound && output < bound {
		return jointDPConvolutionPMF(output-statistic, r)
	}
	probability := 0.0
	if output == -bound {
		for z := -10000; z <= -bound-statistic; z++ {
			probability += jointDPConvolutionPMF(z, r)
		}
		return probability
	}
	if output == bound {
		for z := bound - statistic; z <= 10000; z++ {
			probability += jointDPConvolutionPMF(z, r)
		}
		return probability
	}
	return 0
}

func TestJointDPConvolutionPrivacyRatioIncludesFinalClipBoundaries(t *testing.T) {
	// A two-sided geometric component with r=exp(-lambda) is lambda-DP for
	// sensitivity one. Convolution with an independent second component and
	// the one final fixed clipping step must retain that ratio, including both
	// atoms created at the clipping boundaries.
	lambda := 0.7
	r := math.Exp(-lambda)
	bound := 12
	limit := math.Exp(lambda)
	for output := -bound; output <= bound; output++ {
		p0 := jointDPConvolutionClippedProbability(output, 0, bound, r)
		p1 := jointDPConvolutionClippedProbability(output, 1, bound, r)
		if p0 <= 0 || p1 <= 0 || p0/p1 > limit*(1+1e-12) ||
			p1/p0 > limit*(1+1e-12) {
			t.Fatalf("output=%d probabilities=(%.17g,%.17g), ratio limit=%.17g",
				output, p0, p1, limit)
		}
	}
}

func jointDPConvolutionCappedGeometricPMF(value, cap int, r float64) float64 {
	if value < -cap || value > cap {
		return 0
	}
	absolute := value
	if absolute < 0 {
		absolute = -absolute
	}
	if absolute == cap {
		return math.Pow(r, float64(cap)) / (1 + r)
	}
	return ((1 - r) / (1 + r)) * math.Pow(r, float64(absolute))
}

func jointDPConvolutionCappedSumPMF(total, cap int, r float64) float64 {
	probability := 0.0
	for left := -cap; left <= cap; left++ {
		probability += jointDPConvolutionCappedGeometricPMF(left, cap, r) *
			jointDPConvolutionCappedGeometricPMF(total-left, cap, r)
	}
	return probability
}

func TestJointDPConvolutionFiniteSupportNeedsNonZeroDeltaAtBoundary(t *testing.T) {
	// A capped component puts its ideal tail mass on the endpoint. At the
	// lower endpoint of the two-draw support, adjacent statistics have positive
	// versus zero probability. Thus a universal pure-DP claim would be false;
	// the implementation-support coupling loss must be charged to delta before
	// any seed is accepted or any draw is made.
	const cap = 7
	r := math.Exp(-0.7)
	p0 := jointDPConvolutionCappedSumPMF(-2*cap, cap, r)
	p1 := jointDPConvolutionCappedSumPMF(-2*cap-1, cap, r)
	if p0 <= 0 || p1 != 0 {
		t.Fatalf("finite-support edge probabilities=(%.17g,%.17g), want positive/zero",
			p0, p1)
	}
}

func TestJointDPConvolutionIndependentStreamsDoubleVariance(t *testing.T) {
	const count = 40000
	seedA, _ := hex.DecodeString(testDPSeedFor(1801))
	seedB, _ := hex.DecodeString(testDPSeedFor(9723))
	noiseA := dpDeterministicAddNoise(seedA)
	noiseB := dpDeterministicAddNoise(seedB)
	a := make([]float64, count)
	b := make([]float64, count)
	sum := make([]float64, count)
	for i := 0; i < count; i++ {
		drawA, err := noiseA(i, 0, 1, 1, 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		drawB, err := noiseB(i, 0, 1, 1, 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		a[i], b[i] = float64(drawA), float64(drawB)
		sum[i] = a[i] + b[i]
	}
	meanVariance := func(values []float64) (float64, float64) {
		mean := 0.0
		for _, value := range values {
			mean += value
		}
		mean /= float64(len(values))
		variance := 0.0
		for _, value := range values {
			variance += (value - mean) * (value - mean)
		}
		return mean, variance / float64(len(values)-1)
	}
	meanA, varianceA := meanVariance(a)
	meanB, varianceB := meanVariance(b)
	_, varianceSum := meanVariance(sum)
	averageVariance := (varianceA + varianceB) / 2
	varianceRatio := varianceSum / averageVariance
	covariance := 0.0
	for i := range a {
		covariance += (a[i] - meanA) * (b[i] - meanB)
	}
	correlation := covariance / float64(count-1) /
		math.Sqrt(varianceA*varianceB)
	if math.Abs(correlation) > 0.04 {
		t.Fatalf("peer stream correlation=%g, want independent streams", correlation)
	}
	if math.Abs(varianceRatio-2) > 0.12 ||
		math.Abs(math.Sqrt(varianceRatio)-math.Sqrt2) > 0.05 {
		t.Fatalf("variance ratio=%g RMSE ratio=%g, want 2 and sqrt(2)",
			varianceRatio, math.Sqrt(varianceRatio))
	}
}

func TestJointDPConvolutionMaskTranslationPreservesEntropy(t *testing.T) {
	// Exhaust a toy ring to verify the algebraic invariant used by the real
	// Ring128+ contract: translating a uniform mask is a permutation, hence
	// every individual noised share retains exactly k conditional min-entropy
	// bits for every fixed statistic and fixed local noise draw.
	const bits = 8
	const modulus = 1 << bits
	for _, statistic := range []int{0, 17, 255} {
		seen := make([]bool, modulus)
		for mask := 0; mask < modulus; mask++ {
			translated := (mask + statistic + 39) % modulus
			if seen[translated] {
				t.Fatalf("translation is not bijective for statistic %d", statistic)
			}
			seen[translated] = true
		}
		for value, present := range seen {
			if !present {
				t.Fatalf("missing translated residue %d", value)
			}
		}
	}
	if jointDPConvolutionMinimumMaskEntropy != 128 {
		t.Fatalf("production conditional min-entropy=%d, want 128",
			jointDPConvolutionMinimumMaskEntropy)
	}
}

func TestJointDPUniformSplitRing128CoversFullMaskDomainExactly(t *testing.T) {
	count := big.NewInt(73)
	modulus := exactGCModulus(128)
	for name, encoded := range map[string][]byte{
		"zero":     make([]byte, 16),
		"maximum":  bytes.Repeat([]byte{0xff}, 16),
		"interior": {0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7},
	} {
		t.Run(name, func(t *testing.T) {
			left, right, err := jointDPUniformSplitRing128(
				count, bytes.NewReader(encoded))
			if err != nil {
				t.Fatal(err)
			}
			wantLeft := new(big.Int).SetBytes(encoded)
			if left.Cmp(wantLeft) != 0 || left.Sign() < 0 || left.Cmp(modulus) >= 0 ||
				right.Sign() < 0 || right.Cmp(modulus) >= 0 {
				t.Fatalf("noncanonical split left=%s right=%s", left, right)
			}
			reconstructed := new(big.Int).Add(left, right)
			reconstructed.Mod(reconstructed, modulus)
			if reconstructed.Cmp(count) != 0 {
				t.Fatalf("reconstructed=%s, want %s", reconstructed, count)
			}
		})
	}
	if _, _, err := jointDPUniformSplitRing128(
		count, bytes.NewReader(make([]byte, 15))); err == nil ||
		!strings.Contains(err.Error(), "128-bit") {
		t.Fatalf("short CSPRNG read error=%v", err)
	}
}

func TestJointDPUniformSplitCommandContractIsBoundAndNonDisclosive(t *testing.T) {
	input := jointDPUniformSplitInput{
		Version:          jointDPUniformSplitVersion,
		QueryID:          strings.Repeat("a", 64),
		CapsuleReleaseID: strings.Repeat("a", 64), AllocationIndex: "9",
		SourceContractHash: strings.Repeat("b", 64),
		MaskContractHash:   strings.Repeat("c", 64),
		CoordinateIndex:    "0", Count: "9007199254740991",
	}
	result, err := jointDPUniformSplit(
		input, bytes.NewReader(bytes.Repeat([]byte{0x5a}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	left, _ := new(big.Int).SetString(result.LeftShare, 10)
	right, _ := new(big.Int).SetString(result.RightShare, 10)
	reconstructed := new(big.Int).Add(left, right)
	reconstructed.Mod(reconstructed, exactGCModulus(128))
	if reconstructed.String() != input.Count {
		t.Fatalf("reconstructed=%s, want %s", reconstructed, input.Count)
	}
	if result.CapabilityAvailable || !result.RequiresDurableReplay ||
		result.MaskConditionalMinEntropyBits != 128 ||
		result.Generator != "os_csprng_uniform_16_bytes" {
		t.Fatalf("invalid split contract: %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("\"count\"")) {
		t.Fatal("raw count escaped split output")
	}
	if result.QueryID != result.CapsuleReleaseID {
		t.Fatal("split output reintroduced a per-operation identity")
	}

	bad := input
	bad.Count = "9007199254740992"
	if _, err := jointDPUniformSplit(
		bad, bytes.NewReader(make([]byte, 16))); err == nil ||
		!strings.Contains(err.Error(), "2^53") {
		t.Fatalf("out-of-range count error=%v", err)
	}
	mismatched := input
	mismatched.CapsuleReleaseID = strings.Repeat("d", 64)
	if _, err := jointDPUniformSplit(
		mismatched, bytes.NewReader(make([]byte, 16))); err == nil ||
		!strings.Contains(err.Error(), "purpose-bound") {
		t.Fatalf("mismatched split capsule alias error=%v", err)
	}
	wire, _ := json.Marshal(input)
	wire = bytes.Replace(wire, []byte("}"), []byte(",\"unknown\":true}"), 1)
	if _, err := decodeJointDPUniformSplitInput(bytes.NewReader(wire)); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown split input field error=%v", err)
	}
}
