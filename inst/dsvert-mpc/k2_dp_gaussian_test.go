package main

import (
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

func validDPGaussianInput() dpGaussianInt64Input {
	return dpGaussianInt64Input{
		Values:        []int64{0},
		Epsilon:       1,
		Delta:         1e-5,
		L2Sensitivity: 1,
		Seed:          testDPSeed,
	}
}

func TestDecodeDPGaussianInt64InputIsStrictAndBounded(t *testing.T) {
	encoded := `{"values":[1,-2],"epsilon":1,"delta":0.00001,"l2_sensitivity":1.4142135623730951,"seed":"` +
		testDPSeed + `"}`
	got, err := decodeDPGaussianInt64Input(strings.NewReader(encoded))
	if err != nil {
		t.Fatalf("decode valid Gaussian input: %v", err)
	}
	if !reflect.DeepEqual(got.Values, []int64{1, -2}) ||
		got.L2Sensitivity != math.Sqrt2 {
		t.Fatalf("decoded Gaussian input=%+v", got)
	}

	for name, invalid := range map[string]string{
		"unknown field": strings.TrimSuffix(encoded, "}") + `,"other":1}`,
		"second value":  encoded + ` {}`,
		"fractional int": `{"values":[0.5],"epsilon":1,"delta":0.1,` +
			`"l2_sensitivity":1,"seed":"` + testDPSeed + `"}`,
		"string int": `{"values":["0"],"epsilon":1,"delta":0.1,` +
			`"l2_sensitivity":1,"seed":"` + testDPSeed + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeDPGaussianInt64Input(
				strings.NewReader(invalid)); err == nil {
				t.Fatal("invalid Gaussian JSON unexpectedly decoded")
			}
		})
	}

	tooLarge := strings.NewReader(strings.Repeat(" ", dpNoiseMaxInputBytes+1))
	if _, err := decodeDPGaussianInt64Input(tooLarge); err == nil ||
		!strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized Gaussian input error=%v, want size rejection", err)
	}
}

func TestValidateDPGaussianInt64InputBeforeSampling(t *testing.T) {
	cases := map[string]func(*dpGaussianInt64Input){
		"empty": func(input *dpGaussianInt64Input) {
			input.Values = nil
		},
		"epsilon zero": func(input *dpGaussianInt64Input) {
			input.Epsilon = 0
		},
		"epsilon below minimum": func(input *dpGaussianInt64Input) {
			input.Epsilon = math.Exp2(-51)
		},
		"epsilon infinity": func(input *dpGaussianInt64Input) {
			input.Epsilon = math.Inf(1)
		},
		"delta zero": func(input *dpGaussianInt64Input) {
			input.Delta = 0
		},
		"delta one": func(input *dpGaussianInt64Input) {
			input.Delta = 1
		},
		"delta NaN": func(input *dpGaussianInt64Input) {
			input.Delta = math.NaN()
		},
		"l2 zero": func(input *dpGaussianInt64Input) {
			input.L2Sensitivity = 0
		},
		"l2 infinity": func(input *dpGaussianInt64Input) {
			input.L2Sensitivity = math.Inf(1)
		},
		"l2 outside exact range": func(input *dpGaussianInt64Input) {
			input.L2Sensitivity = float64(dpNoiseOutputMax) + 2
		},
		"value outside exact range": func(input *dpGaussianInt64Input) {
			input.Values[0] = dpNoiseOutputMax + 1
		},
		"bad seed": func(input *dpGaussianInt64Input) {
			input.Seed = strings.Repeat("A", 64)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			input := validDPGaussianInput()
			mutate(&input)
			calls := 0
			_, err := addDPGaussianNoiseInt64(
				input, func(_ int, _ float64) (int64, error) {
					calls++
					return 0, nil
				})
			if err == nil {
				t.Fatal("invalid Gaussian input unexpectedly succeeded")
			}
			if calls != 0 {
				t.Fatalf("Gaussian sampler called %d times before validation", calls)
			}
		})
	}

	if _, _, _, _, err := dpGaussianParameters(validDPGaussianInput()); err != nil {
		t.Fatalf("valid Gaussian parameters rejected: %v", err)
	}
	oversized := validDPGaussianInput()
	oversized.Values = make([]int64, dpNoiseMaxCoordinates+1)
	if _, _, _, _, err := dpGaussianParameters(oversized); err == nil ||
		!strings.Contains(err.Error(), "coordinate count") {
		t.Fatalf("oversized Gaussian vector error=%v", err)
	}
}

func TestDPGaussianMetadataClippingAndNoPartialOutput(t *testing.T) {
	input := validDPGaussianInput()
	input.Values = []int64{dpNoiseOutputMax, dpNoiseOutputMin, 10}
	draws := []int64{1, -1, 7}
	call := 0
	expectedImplementationDelta, err := dpGaussianImplementationDeltaBound(
		len(input.Values), input.Epsilon)
	if err != nil {
		t.Fatal(err)
	}
	result, err := addDPGaussianNoiseInt64(
		input, func(coordinate int, sigma float64) (int64, error) {
			if coordinate != call || sigma <= 0 {
				t.Fatalf("Gaussian coordinate=%d sigma=%g at call=%d",
					coordinate, sigma, call)
			}
			draw := draws[call]
			call++
			return draw, nil
		})
	if err != nil {
		t.Fatalf("addDPGaussianNoiseInt64: %v", err)
	}
	if !reflect.DeepEqual(
		result.Values, []int64{dpNoiseOutputMax, dpNoiseOutputMin, 17}) {
		t.Fatalf("Gaussian values=%v", result.Values)
	}
	if result.ClippedCoordinates != 2 ||
		result.Mechanism != dpGaussianMechanism ||
		result.Implementation != dpGaussianImplementation ||
		result.Sampler != dpGaussianSampler ||
		result.Randomness != dpNoiseRandomness ||
		result.Epsilon != input.Epsilon || result.Delta != input.Delta ||
		result.AnalyticDelta <= 0 ||
		result.ImplementationDeltaBound != expectedImplementationDelta ||
		result.AnalyticDelta+result.ImplementationDeltaBound > result.Delta ||
		result.ImplementationTVPerCoord != dpGaussianScalarTVBound ||
		result.AccountingRule != dpGaussianAccountingRule ||
		result.AccuracyAccounting != dpGaussianAccuracyRule ||
		result.L2Sensitivity != input.L2Sensitivity || result.Sigma <= 0 ||
		!dpIsExactPowerOfTwo(result.Granularity) || result.Granularity > 1 ||
		result.MarginalConfidence != 0.95 ||
		result.SimultaneousConfidence != 0.95 ||
		result.SimultaneousMethod != "union_bound" ||
		result.OutputLowerBound != dpNoiseOutputMin ||
		result.OutputUpperBound != dpNoiseOutputMax {
		t.Fatalf("unexpected Gaussian metadata: %+v", result)
	}
	if len(result.Accuracy95Abs) != 3 ||
		len(result.AccuracySimultaneous95Abs) != 3 ||
		result.Accuracy95Abs[0] <= 0 ||
		result.AccuracySimultaneous95Abs[0] < result.Accuracy95Abs[0] {
		t.Fatalf("invalid Gaussian accuracy certificate: %+v", result)
	}

	failed, err := addDPGaussianNoiseInt64(
		input, func(coordinate int, _ float64) (int64, error) {
			if coordinate == 1 {
				return 0, errors.New("entropy failure")
			}
			return 0, nil
		})
	if err == nil || !strings.Contains(err.Error(), "coordinate 1") {
		t.Fatalf("Gaussian sampler error=%v", err)
	}
	if failed.Values != nil {
		t.Fatalf("partial Gaussian values escaped: %v", failed.Values)
	}
}

func TestDPGaussianAnalyticAccountingAndNeighborTranslation(t *testing.T) {
	input := validDPGaussianInput()
	input.Delta = 1e-6
	input.L2Sensitivity = math.Sqrt2
	sigma, _, analyticDelta, implementationDelta, err :=
		dpGaussianParameters(input)
	if err != nil {
		t.Fatalf("Gaussian parameters: %v", err)
	}
	a := input.L2Sensitivity / (2 * sigma)
	b := input.Epsilon * sigma / input.L2Sensitivity
	phi := func(x float64) float64 {
		return 0.5 * math.Erfc(-x/math.Sqrt2)
	}
	achievedDelta := phi(a-b) - math.Exp(input.Epsilon)*phi(-a-b)
	if achievedDelta > analyticDelta ||
		analyticDelta+implementationDelta > input.Delta {
		t.Fatalf("Gaussian accounting analytic=%g achieved=%g implementation=%g total=%g",
			analyticDelta, achievedDelta, implementationDelta, input.Delta)
	}
	doubled := input
	doubled.L2Sensitivity *= 2
	doubledSigma, _, _, _, err := dpGaussianParameters(doubled)
	if err != nil {
		t.Fatalf("doubled-sensitivity Gaussian parameters: %v", err)
	}
	if math.Abs(doubledSigma/sigma-2) > 1e-12 {
		t.Fatalf("Gaussian sigma did not scale linearly: %g vs %g",
			sigma, doubledSigma)
	}

	seed, _ := hex.DecodeString(input.Seed)
	base := input
	base.Values = []int64{100, 100}
	neighbor := input
	neighbor.Values = []int64{101, 99}
	baseRelease, err := addDPGaussianNoiseInt64(
		base, dpDeterministicGaussianSample(seed))
	if err != nil {
		t.Fatalf("base Gaussian neighbor release: %v", err)
	}
	neighborRelease, err := addDPGaussianNoiseInt64(
		neighbor, dpDeterministicGaussianSample(seed))
	if err != nil {
		t.Fatalf("adjacent Gaussian neighbor release: %v", err)
	}
	for i, want := range []int64{1, -1} {
		if got := neighborRelease.Values[i] - baseRelease.Values[i]; got != want {
			t.Fatalf("coordinate %d translated by %d, want %d", i, got, want)
		}
	}
}

func TestDPGaussianRequiresDeltaForPublishedApproximationBound(t *testing.T) {
	input := validDPGaussianInput()
	input.Values = make([]int64, 64)
	bound, err := dpGaussianImplementationDeltaBound(
		len(input.Values), input.Epsilon)
	if err != nil {
		t.Fatal(err)
	}
	rawTV := 64 * dpGaussianScalarTVBound
	if bound <= rawTV || bound <
		rawTV*(1+math.Exp(input.Epsilon)) {
		t.Fatalf("implementation DP-transfer bound=%g raw TV=%g", bound, rawTV)
	}
	input.Delta = bound
	if _, _, _, _, err := dpGaussianParameters(input); err == nil ||
		!strings.Contains(err.Error(), "must exceed") {
		t.Fatalf("delta at implementation bound error=%v", err)
	}
	input.Delta = math.Nextafter(bound, math.Inf(1))
	sigma, _, analyticDelta, implementationDelta, err :=
		dpGaussianParameters(input)
	if err != nil {
		if !strings.Contains(err.Error(), "granularity") &&
			!strings.Contains(err.Error(), "represent") {
			t.Fatalf("near-boundary Gaussian failed for an unrelated reason: %v", err)
		}
		return
	}
	a := input.L2Sensitivity / (2 * sigma)
	b := input.Epsilon * sigma / input.L2Sensitivity
	phi := func(x float64) float64 {
		return 0.5 * math.Erfc(-x/math.Sqrt2)
	}
	achievedDelta := phi(a-b) - math.Exp(input.Epsilon)*phi(-a-b)
	if analyticDelta <= 0 || implementationDelta != bound ||
		analyticDelta+implementationDelta > input.Delta ||
		achievedDelta > analyticDelta {
		t.Fatalf(
			"near-boundary accounting analytic=%g achieved=%g implementation=%g total=%g",
			analyticDelta, achievedDelta, implementationDelta, input.Delta)
	}
}

func TestDeterministicGaussianIsCalibratedStickyAndDomainSeparated(t *testing.T) {
	const draws = 20_000
	input := validDPGaussianInput()
	input.Delta = 1e-3
	input.Values = make([]int64, draws)
	seed := make([]byte, 32)
	result, err := addDPGaussianNoiseInt64(
		input, dpDeterministicGaussianSample(seed))
	if err != nil {
		t.Fatalf("deterministic Gaussian sample: %v", err)
	}
	var sum, squareSum float64
	positive, negative, covered := 0, 0, 0
	for i, value := range result.Values {
		x := float64(value)
		sum += x
		squareSum += x * x
		if value > 0 {
			positive++
		} else if value < 0 {
			negative++
		}
		if value >= -result.Accuracy95Abs[i] &&
			value <= result.Accuracy95Abs[i] {
			covered++
		}
	}
	mean := sum / draws
	variance := squareSum/draws - mean*mean
	// Integer rounding adds at most a small quantization term to sigma^2.
	if math.Abs(mean) > 0.08 {
		t.Fatalf("Gaussian empirical mean=%g, want symmetry", mean)
	}
	if relative := math.Abs(variance-result.Sigma*result.Sigma) /
		(result.Sigma * result.Sigma); relative > 0.10 {
		t.Fatalf("Gaussian variance=%g sigma^2=%g relative error=%g",
			variance, result.Sigma*result.Sigma, relative)
	}
	if math.Abs(float64(positive-negative)/draws) > 0.04 {
		t.Fatalf("Gaussian positive=%d negative=%d", positive, negative)
	}
	if float64(covered)/draws < 0.94 {
		t.Fatalf("Gaussian 95%%-radius coverage=%g",
			float64(covered)/draws)
	}

	stickyInput := validDPGaussianInput()
	stickyInput.Values = make([]int64, 256)
	first, err := addDPGaussianNoiseInt64(
		stickyInput, dpDeterministicGaussianSample(seed))
	if err != nil {
		t.Fatalf("first sticky Gaussian sample: %v", err)
	}
	second, err := addDPGaussianNoiseInt64(
		stickyInput, dpDeterministicGaussianSample(seed))
	if err != nil {
		t.Fatalf("second sticky Gaussian sample: %v", err)
	}
	if !reflect.DeepEqual(first.Values, second.Values) {
		t.Fatal("same Gaussian seed did not reproduce the release")
	}
	alternateSeed, _ := hex.DecodeString(testDPSeedFor(999))
	alternate, err := addDPGaussianNoiseInt64(
		stickyInput, dpDeterministicGaussianSample(alternateSeed))
	if err != nil {
		t.Fatalf("alternate sticky Gaussian sample: %v", err)
	}
	if reflect.DeepEqual(first.Values, alternate.Values) {
		t.Fatal("distinct Gaussian seeds produced an identical vector")
	}

	laplaceStream, err := newDPDeterministicStream(seed, 0)
	if err != nil {
		t.Fatalf("Laplace stream: %v", err)
	}
	gaussianStream, err := newDPDeterministicStreamForDomain(
		seed, 0, dpGaussianStreamDomain)
	if err != nil {
		t.Fatalf("Gaussian stream: %v", err)
	}
	laplaceBytes, gaussianBytes := make([]byte, 64), make([]byte, 64)
	laplaceStream.read(laplaceBytes)
	gaussianStream.read(gaussianBytes)
	if reflect.DeepEqual(laplaceBytes, gaussianBytes) {
		t.Fatal("Laplace and Gaussian deterministic domains collided")
	}
}

func TestDPDeterministicI63nIsUnbiasedAndRejectsInvalidBounds(t *testing.T) {
	stream, err := newDPDeterministicStreamForDomain(
		make([]byte, 32), 0, "dsvert/test/i63n/v1\x00")
	if err != nil {
		t.Fatalf("uniform stream: %v", err)
	}
	if _, err := stream.i63n(0); err == nil {
		t.Fatal("zero i63n bound unexpectedly accepted")
	}
	const draws = 70_000
	counts := make([]int, 7)
	for i := 0; i < draws; i++ {
		value, err := stream.i63n(int64(len(counts)))
		if err != nil {
			t.Fatalf("i63n draw: %v", err)
		}
		counts[value]++
	}
	want := float64(draws) / float64(len(counts))
	for value, count := range counts {
		if math.Abs(float64(count)-want)/want > 0.04 {
			t.Fatalf("i63n value %d count=%d, counts=%v", value, count, counts)
		}
	}
}
