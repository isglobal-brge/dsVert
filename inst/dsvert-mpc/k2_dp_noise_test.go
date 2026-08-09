package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"

	"github.com/google/differential-privacy/go/v4/noise"
)

var testDPSeed = strings.Repeat("0", 64)

func testDPSeedFor(index int) string {
	digest := sha256.Sum256([]byte(strconv.Itoa(index)))
	return hex.EncodeToString(digest[:])
}

func fixedDPConfidence(
	_, _, _ int64, _, _, _ float64,
) (noise.ConfidenceInterval, error) {
	return noise.ConfidenceInterval{LowerBound: -3, UpperBound: 3}, nil
}

func TestDecodeDPNoiseInt64InputIsStrictAndBounded(t *testing.T) {
	got, err := decodeDPNoiseInt64Input(strings.NewReader(
		`{"values":[1,-2],"epsilons":[1,0.5],"sensitivities":[1,2],"seed":"` +
			testDPSeed + `"}`,
	))
	if err != nil {
		t.Fatalf("decode valid input: %v", err)
	}
	if !reflect.DeepEqual(got.Values, []int64{1, -2}) {
		t.Fatalf("values=%v, want [1 -2]", got.Values)
	}

	for name, encoded := range map[string]string{
		"unknown field":  `{"values":[0],"epsilons":[1],"sensitivities":[1],"seed":"` + testDPSeed + `","other":1}`,
		"second value":   `{"values":[0],"epsilons":[1],"sensitivities":[1]} {}`,
		"fractional int": `{"values":[0.5],"epsilons":[1],"sensitivities":[1]}`,
		"string int":     `{"values":["0"],"epsilons":[1],"sensitivities":[1]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeDPNoiseInt64Input(strings.NewReader(encoded)); err == nil {
				t.Fatal("decode unexpectedly succeeded")
			}
		})
	}

	tooLarge := strings.NewReader(strings.Repeat(" ", dpNoiseMaxInputBytes+1))
	if _, err := decodeDPNoiseInt64Input(tooLarge); err == nil ||
		!strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized input error=%v, want size rejection", err)
	}
}

func TestValidateDPNoiseInt64InputBeforeSampling(t *testing.T) {
	valid := dpNoiseInt64Input{
		Values:        []int64{0},
		Epsilons:      []float64{1},
		Sensitivities: []int64{1},
		Seed:          testDPSeed,
	}
	cases := map[string]dpNoiseInt64Input{
		"empty": {},
		"epsilon length": {
			Values: []int64{0}, Sensitivities: []int64{1},
		},
		"sensitivity length": {
			Values: []int64{0}, Epsilons: []float64{1},
		},
		"epsilon zero": {
			Values: []int64{0}, Epsilons: []float64{0}, Sensitivities: []int64{1},
		},
		"epsilon below upstream minimum": {
			Values: []int64{0}, Epsilons: []float64{math.Exp2(-51)}, Sensitivities: []int64{1},
		},
		"epsilon NaN": {
			Values: []int64{0}, Epsilons: []float64{math.NaN()}, Sensitivities: []int64{1},
		},
		"epsilon infinity": {
			Values: []int64{0}, Epsilons: []float64{math.Inf(1)}, Sensitivities: []int64{1},
		},
		"epsilon above supported maximum": {
			Values: []int64{0}, Epsilons: []float64{math.Nextafter(dpNoiseMaximumEpsilon, math.Inf(1))}, Sensitivities: []int64{1},
		},
		"epsilon maximum float": {
			Values: []int64{0}, Epsilons: []float64{math.MaxFloat64}, Sensitivities: []int64{1},
		},
		"sensitivity zero": {
			Values: []int64{0}, Epsilons: []float64{1}, Sensitivities: []int64{0},
		},
		"value outside exact wire range": {
			Values: []int64{dpNoiseOutputMax + 1}, Epsilons: []float64{1}, Sensitivities: []int64{1},
		},
		"granularity above one": {
			Values: []int64{0}, Epsilons: []float64{math.Exp2(-41)}, Sensitivities: []int64{1},
		},
		"missing seed": {
			Values: []int64{0}, Epsilons: []float64{1}, Sensitivities: []int64{1},
		},
		"uppercase seed": {
			Values: []int64{0}, Epsilons: []float64{1}, Sensitivities: []int64{1},
			Seed: strings.Repeat("A", 64),
		},
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if name != "missing seed" && name != "uppercase seed" {
				input.Seed = testDPSeed
			}
			calls := 0
			_, err := addDPNoiseInt64(input, func(_ int, _, _, _ int64, _, _ float64) (int64, error) {
				calls++
				return 0, nil
			}, fixedDPConfidence)
			if err == nil {
				t.Fatal("invalid input unexpectedly succeeded")
			}
			if calls != 0 {
				t.Fatalf("sampler called %d times before complete validation", calls)
			}
		})
	}
	if err := validateDPNoiseInt64Input(valid); err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
	boundary := valid
	boundary.Epsilons = []float64{math.Exp2(-40)}
	if err := validateDPNoiseInt64Input(boundary); err != nil {
		t.Fatalf("granularity-one boundary rejected: %v", err)
	}
	maximum := valid
	maximum.Epsilons = []float64{dpNoiseMaximumEpsilon}
	if err := validateDPNoiseInt64Input(maximum); err != nil {
		t.Fatalf("maximum epsilon boundary rejected: %v", err)
	}

	oversized := dpNoiseInt64Input{
		Values:        make([]int64, dpNoiseMaxCoordinates+1),
		Epsilons:      make([]float64, dpNoiseMaxCoordinates+1),
		Sensitivities: make([]int64, dpNoiseMaxCoordinates+1),
	}
	if err := validateDPNoiseInt64Input(oversized); err == nil ||
		!strings.Contains(err.Error(), "coordinate count") {
		t.Fatalf("oversized vector error=%v, want coordinate rejection", err)
	}
}

func TestDPCeilPowerOfTwoIsExactAcrossNormalAndSubnormalInputs(t *testing.T) {
	tests := []struct {
		input float64
		want  float64
	}{
		{math.SmallestNonzeroFloat64, math.SmallestNonzeroFloat64},
		{3 * math.SmallestNonzeroFloat64, 4 * math.SmallestNonzeroFloat64},
		{math.Nextafter(math.SmallestNonzeroFloat64, 1), 2 * math.SmallestNonzeroFloat64},
		{math.Exp2(-80), math.Exp2(-80)},
		{math.Nextafter(math.Exp2(-80), 1), math.Exp2(-79)},
		{0.75, 1},
		{1, 1},
	}
	for _, test := range tests {
		got := dpCeilPowerOfTwo(test.input)
		if got != test.want {
			t.Errorf("dpCeilPowerOfTwo(%g)=%g, want %g", test.input, got, test.want)
		}
		if !dpIsExactPowerOfTwo(got) {
			t.Errorf("dpCeilPowerOfTwo(%g)=%g is not an exact power of two", test.input, got)
		}
	}
	if !math.IsNaN(dpCeilPowerOfTwo(0)) ||
		!math.IsNaN(dpCeilPowerOfTwo(math.MaxFloat64)) {
		t.Fatal("invalid power-of-two inputs did not return NaN")
	}
	if dpIsExactPowerOfTwo(0) || dpIsExactPowerOfTwo(math.Inf(1)) ||
		dpIsExactPowerOfTwo(3) {
		t.Fatal("invalid exact powers of two were accepted")
	}
}

func TestDPNoiseUsesL0OneDeltaZeroAndClipsWithoutWrap(t *testing.T) {
	input := dpNoiseInt64Input{
		Values:        []int64{dpNoiseOutputMax, dpNoiseOutputMin, 10},
		Epsilons:      []float64{1, 1, 1},
		Sensitivities: []int64{1, 1, 2},
		Seed:          testDPSeed,
	}
	draws := []int64{1, -1, 7}
	call := 0
	result, err := addDPNoiseInt64(input, func(coordinate int, x, l0, lInf int64, epsilon, delta float64) (int64, error) {
		if x != 0 || l0 != 1 || delta != 0 {
			t.Fatalf("AddNoiseInt64(%d,%d,%d,%g,%g), want x=0,l0=1,delta=0", x, l0, lInf, epsilon, delta)
		}
		if coordinate != call || lInf != input.Sensitivities[call] || epsilon != input.Epsilons[call] {
			t.Fatalf("coordinate %d parameters changed", call)
		}
		draw := draws[call]
		call++
		return draw, nil
	}, fixedDPConfidence)
	if err != nil {
		t.Fatalf("addDPNoiseInt64: %v", err)
	}
	if !reflect.DeepEqual(result.Values, []int64{dpNoiseOutputMax, dpNoiseOutputMin, 17}) {
		t.Fatalf("values=%v, want exact-wire boundaries and 17", result.Values)
	}
	if result.ClippedCoordinates != 2 {
		t.Fatalf("clipped=%d, want 2", result.ClippedCoordinates)
	}
	if !reflect.DeepEqual(result.Accuracy95Abs, []int64{3, 3, 3}) {
		t.Fatalf("accuracy=%v, want [3 3 3]", result.Accuracy95Abs)
	}
	if !reflect.DeepEqual(result.AccuracySimultaneous95Abs, []int64{3, 3, 3}) {
		t.Fatalf("simultaneous accuracy=%v, want [3 3 3]", result.AccuracySimultaneous95Abs)
	}
	if result.Mechanism != dpNoiseMechanism || result.Delta != 0 ||
		result.L0Sensitivity != 1 || result.MaxGranularity != 1 ||
		result.MarginalConfidence != 0.95 ||
		result.SimultaneousConfidence != 0.95 ||
		result.SimultaneousMethod != "union_bound" ||
		result.OutputLowerBound != dpNoiseOutputMin ||
		result.OutputUpperBound != dpNoiseOutputMax {
		t.Fatalf("unexpected mechanism metadata: %+v", result)
	}
}

func TestGoogleDPSimultaneousRadiusIsMonotoneAndCoversVectors(t *testing.T) {
	laplace := noise.Laplace()
	previous := int64(0)
	for _, coordinates := range []int{1, 2, 4, 16, 128} {
		input := dpNoiseInt64Input{
			Values:        make([]int64, coordinates),
			Epsilons:      make([]float64, coordinates),
			Sensitivities: make([]int64, coordinates),
			Seed:          testDPSeed,
		}
		for i := range input.Values {
			input.Epsilons[i] = 1
			input.Sensitivities[i] = 1
		}
		result, err := addDPNoiseInt64(
			input, dpDeterministicAddNoise([]byte(strings.Repeat("\x00", 32))),
			laplace.ComputeConfidenceIntervalInt64,
		)
		if err != nil {
			t.Fatalf("coordinates=%d: %v", coordinates, err)
		}
		radius := result.AccuracySimultaneous95Abs[0]
		if radius < result.Accuracy95Abs[0] || radius < previous {
			t.Fatalf("coordinates=%d simultaneous radius=%d marginal=%d previous=%d",
				coordinates, radius, result.Accuracy95Abs[0], previous)
		}
		for _, other := range result.AccuracySimultaneous95Abs {
			if other != radius {
				t.Fatalf("equal-parameter simultaneous radii differ: %v",
					result.AccuracySimultaneous95Abs)
			}
		}
		previous = radius
	}

	const repetitions = 5_000
	covered := 0
	input := dpNoiseInt64Input{
		Values:        make([]int64, 4),
		Epsilons:      []float64{1, 1, 1, 1},
		Sensitivities: []int64{1, 1, 1, 1},
		Seed:          testDPSeed,
	}
	for repetition := 0; repetition < repetitions; repetition++ {
		input.Seed = testDPSeedFor(repetition)
		seed, err := hex.DecodeString(input.Seed)
		if err != nil {
			t.Fatalf("decode test seed: %v", err)
		}
		result, err := addDPNoiseInt64(
			input, dpDeterministicAddNoise(seed),
			laplace.ComputeConfidenceIntervalInt64,
		)
		if err != nil {
			t.Fatalf("joint sample %d: %v", repetition, err)
		}
		jointlyCovered := true
		for i, value := range result.Values {
			if value < -result.AccuracySimultaneous95Abs[i] ||
				value > result.AccuracySimultaneous95Abs[i] {
				jointlyCovered = false
				break
			}
		}
		if jointlyCovered {
			covered++
		}
	}
	if float64(covered)/repetitions < 0.94 {
		t.Fatalf("empirical simultaneous coverage=%g, want at least 0.94",
			float64(covered)/repetitions)
	}
}

func TestDPNoiseDoesNotReturnPartialOutputOnSamplerError(t *testing.T) {
	input := dpNoiseInt64Input{
		Values:        []int64{1, 2},
		Epsilons:      []float64{1, 1},
		Sensitivities: []int64{1, 1},
		Seed:          testDPSeed,
	}
	calls := 0
	result, err := addDPNoiseInt64(input, func(_ int, _, _, _ int64, _, _ float64) (int64, error) {
		calls++
		if calls == 2 {
			return 0, errors.New("entropy failure")
		}
		return 1, nil
	}, fixedDPConfidence)
	if err == nil || !strings.Contains(err.Error(), "coordinate 1 noise") {
		t.Fatalf("error=%v, want coordinate sampler error", err)
	}
	if result.Values != nil {
		t.Fatalf("partial values escaped: %v", result.Values)
	}
}

func TestDeterministicDPSamplerIsSymmetricCalibratedAndSticky(t *testing.T) {
	const draws = 30_000
	input := dpNoiseInt64Input{
		Values:        make([]int64, draws),
		Epsilons:      make([]float64, draws),
		Sensitivities: make([]int64, draws),
		Seed:          testDPSeed,
	}
	for i := range input.Values {
		input.Epsilons[i] = 1
		input.Sensitivities[i] = 1
	}
	laplace := noise.Laplace()
	result, err := addDPNoiseInt64(
		input, dpDeterministicAddNoise(make([]byte, 32)),
		laplace.ComputeConfidenceIntervalInt64,
	)
	if err != nil {
		t.Fatalf("Google DP sampler: %v", err)
	}
	var sum int64
	positive, negative, covered := 0, 0, 0
	for i, value := range result.Values {
		sum += value
		if value > 0 {
			positive++
		} else if value < 0 {
			negative++
		}
		if value >= -result.Accuracy95Abs[i] && value <= result.Accuracy95Abs[i] {
			covered++
		}
	}
	if math.Abs(float64(sum)/draws) > 0.05 {
		t.Fatalf("empirical mean=%g, want symmetric around zero", float64(sum)/draws)
	}
	if math.Abs(float64(positive-negative)/draws) > 0.04 {
		t.Fatalf("positive=%d negative=%d, want symmetric tails", positive, negative)
	}
	if float64(covered)/draws < 0.945 {
		t.Fatalf("95%%-radius coverage=%g, want at least 0.945 empirically", float64(covered)/draws)
	}
	firstInput := dpNoiseInt64Input{
		Values:        make([]int64, 256),
		Epsilons:      input.Epsilons[:256],
		Sensitivities: input.Sensitivities[:256],
		Seed:          testDPSeed,
	}
	first, err := addDPNoiseInt64(
		firstInput, dpDeterministicAddNoise(make([]byte, 32)),
		laplace.ComputeConfidenceIntervalInt64)
	if err != nil {
		t.Fatalf("first sticky sample: %v", err)
	}
	second, err := addDPNoiseInt64(
		firstInput, dpDeterministicAddNoise(make([]byte, 32)),
		laplace.ComputeConfidenceIntervalInt64)
	if err != nil {
		t.Fatalf("second sticky sample: %v", err)
	}
	if !reflect.DeepEqual(first.Values, second.Values) {
		t.Fatal("same deterministic seed did not reproduce the release")
	}
	alternateSeed, _ := hex.DecodeString(testDPSeedFor(999))
	alternateInput := firstInput
	alternateInput.Seed = testDPSeedFor(999)
	alternate, err := addDPNoiseInt64(
		alternateInput, dpDeterministicAddNoise(alternateSeed),
		laplace.ComputeConfidenceIntervalInt64)
	if err != nil {
		t.Fatalf("alternate sticky sample: %v", err)
	}
	if reflect.DeepEqual(first.Values, alternate.Values) {
		t.Fatal("distinct deterministic seeds produced an identical vector")
	}
}

func TestGoogleDPDependencyAndSourceContract(t *testing.T) {
	build, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("Go build information unavailable")
	}
	found := false
	for _, dep := range build.Deps {
		if dep.Path == "github.com/google/differential-privacy/go/v4" {
			found = true
			if dep.Version != "v4.1.0" {
				t.Fatalf("Google DP version=%s, want v4.1.0", dep.Version)
			}
		}
	}
	if !found {
		t.Fatal("Google DP dependency missing from build")
	}

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("test source path unavailable")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(file), "k2_dp_noise.go"))
	if err != nil {
		t.Fatalf("read sampler source: %v", err)
	}
	text := string(source)
	for _, required := range []string{
		`github.com/google/differential-privacy/go/v4/noise`,
		`golang.org/x/crypto/chacha20`,
		`dpTwoSidedGeometric`,
		`laplace.ComputeConfidenceIntervalInt64`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("sampler source lacks required contract %q", required)
		}
	}
	if strings.Contains(text, `"math/rand"`) {
		t.Fatal("sampler source must not use math/rand")
	}
	gaussianSource, err := os.ReadFile(filepath.Join(
		filepath.Dir(file), "k2_dp_gaussian.go"))
	if err != nil {
		t.Fatalf("read Gaussian sampler source: %v", err)
	}
	gaussianText := string(gaussianSource)
	for _, required := range []string{
		`noise.SigmaForGaussian`,
		`dpDeterministicSymmetricBinomial`,
		`dpGaussianBinomialProbability`,
		`dpGaussianStreamDomain`,
	} {
		if !strings.Contains(gaussianText, required) {
			t.Fatalf("Gaussian sampler source lacks required contract %q", required)
		}
	}
	if strings.Contains(gaussianText, `"math/rand"`) {
		t.Fatal("Gaussian sampler source must not use math/rand")
	}
	license, err := os.ReadFile(filepath.Join(
		filepath.Dir(file), "third_party", "google-differential-privacy.LICENSE"))
	if err != nil {
		t.Fatalf("read bundled Google DP license: %v", err)
	}
	if !strings.Contains(string(license), "Apache License") ||
		!strings.Contains(string(license), "Version 2.0") {
		t.Fatal("bundled Google DP Apache-2.0 license is incomplete")
	}
	gonumLicense, err := os.ReadFile(filepath.Join(
		filepath.Dir(file), "third_party", "gonum.LICENSE"))
	if err != nil {
		t.Fatalf("read bundled Gonum license: %v", err)
	}
	if !strings.Contains(string(gonumLicense), "The Gonum Authors") ||
		!strings.Contains(string(gonumLicense), "Redistribution and use") {
		t.Fatal("bundled Gonum BSD-3-Clause license is incomplete")
	}
}
