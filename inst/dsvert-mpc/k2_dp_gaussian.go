package main

// The deterministic Gaussian sampler in this file adapts Google Differential
// Privacy v4.1.0's analytic Gaussian calibration and symmetric-binomial
// sampler (Apache-2.0). The power-of-two granularity and published probability
// law are preserved. The implementation accounts for Google's published
// 2^-40 scalar total-variation approximation bound in both delta and accuracy.
// Only the entropy source is replaced with a release-specific, domain-separated
// HMAC-SHA256/ChaCha20 stream so a ledger replay is sticky.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"

	"github.com/google/differential-privacy/go/v4/noise"
)

const (
	dpGaussianMechanism      = "dsvert_dp_v3_deterministic_approximate_gaussian_int64"
	dpGaussianImplementation = "dsVert adapted Google Differential Privacy v4.1.0 approximate Gaussian integer mechanism with a published 2^-40 scalar total-variation bound"
	dpGaussianSampler        = "deterministic_symmetric_binomial"
	dpGaussianStreamDomain   = "dsvert/dp-gaussian/coordinate/v1\x00"
	dpGaussianBinomialBound  = float64(uint64(1) << 57)
	dpGaussianMaxIterations  = 1 << 20
	dpGaussianScalarTVBound  = 0x1p-40
	dpGaussianAccountingRule = "analytic_gaussian_delta_plus_dp_transfer_from_total_variation_bound"
	dpGaussianAccuracyRule   = "gaussian_tail_alpha_minus_total_variation_union_bound"
)

var dpGaussianGeometricBound = (math.MaxInt64 / int64(math.Round(math.Sqrt2*dpGaussianBinomialBound+1))) - 1

type dpGaussianInt64Input struct {
	Values        []int64 `json:"values"`
	Epsilon       float64 `json:"epsilon"`
	Delta         float64 `json:"delta"`
	L2Sensitivity float64 `json:"l2_sensitivity"`
	Seed          string  `json:"seed"`
}

type dpGaussianInt64Output struct {
	Values                    []int64 `json:"values"`
	Accuracy95Abs             []int64 `json:"accuracy_95_abs"`
	AccuracySimultaneous95Abs []int64 `json:"accuracy_simultaneous_95_abs"`
	ClippedCoordinates        int     `json:"clipped_coordinates"`
	Mechanism                 string  `json:"mechanism"`
	Implementation            string  `json:"implementation"`
	Sampler                   string  `json:"sampler"`
	Randomness                string  `json:"randomness"`
	Epsilon                   float64 `json:"epsilon"`
	Delta                     float64 `json:"delta"`
	AnalyticDelta             float64 `json:"analytic_delta"`
	ImplementationDeltaBound  float64 `json:"implementation_delta_bound"`
	ImplementationTVPerCoord  float64 `json:"implementation_tv_bound_per_coordinate"`
	AccountingRule            string  `json:"accounting_rule"`
	AccuracyAccounting        string  `json:"accuracy_accounting"`
	L2Sensitivity             float64 `json:"l2_sensitivity"`
	Sigma                     float64 `json:"sigma"`
	Granularity               float64 `json:"granularity"`
	MarginalConfidence        float64 `json:"marginal_confidence"`
	SimultaneousConfidence    float64 `json:"simultaneous_confidence"`
	SimultaneousMethod        string  `json:"simultaneous_method"`
	OutputLowerBound          int64   `json:"output_lower_bound"`
	OutputUpperBound          int64   `json:"output_upper_bound"`
}

type dpGaussianSample func(coordinate int, sigma float64) (int64, error)

func decodeDPGaussianInt64Input(r io.Reader) (dpGaussianInt64Input, error) {
	limited := io.LimitReader(r, dpNoiseMaxInputBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return dpGaussianInt64Input{}, fmt.Errorf("read input: %w", err)
	}
	if len(data) > dpNoiseMaxInputBytes {
		return dpGaussianInt64Input{}, fmt.Errorf(
			"input exceeds %d bytes", dpNoiseMaxInputBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var input dpGaussianInt64Input
	if err := dec.Decode(&input); err != nil {
		return dpGaussianInt64Input{}, fmt.Errorf("parse input: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return dpGaussianInt64Input{}, err
	}
	return input, nil
}

func dpGaussianImplementationDeltaBound(
	coordinateCount int, epsilon float64,
) (
	float64, error,
) {
	if coordinateCount < 1 || coordinateCount > dpNoiseMaxCoordinates {
		return 0, fmt.Errorf(
			"coordinate count must be between one and %d", dpNoiseMaxCoordinates)
	}
	if math.IsNaN(epsilon) || math.IsInf(epsilon, 0) ||
		epsilon < dpNoiseMinimumEpsilon || epsilon > dpNoiseMaximumEpsilon {
		return 0, fmt.Errorf("epsilon is outside the Gaussian implementation-bound domain")
	}
	// If the implemented vector law Q is within eta of the ideal Gaussian
	// law P in total variation and P is (epsilon, delta)-DP, then Q is
	// (epsilon, delta+(1+exp(epsilon))*eta)-DP.  Merely charging eta is not a
	// valid DP transfer.  Evaluate in log space so large epsilon fails closed
	// without overflowing, and round every public boundary outwards.
	logTVUpper := math.Nextafter(
		math.Log(float64(coordinateCount))+
			math.Log(dpGaussianScalarTVBound), math.Inf(1))
	logTransferUpper := math.Nextafter(
		epsilon+math.Log1p(math.Exp(-epsilon)), math.Inf(1))
	logBoundUpper := math.Nextafter(
		logTVUpper+logTransferUpper, math.Inf(1))
	if math.IsNaN(logBoundUpper) || math.IsInf(logBoundUpper, 0) ||
		logBoundUpper >= 0 {
		return 0, fmt.Errorf(
			"Gaussian implementation delta bound is not representable")
	}
	bound := math.Nextafter(math.Exp(logBoundUpper), math.Inf(1))
	if math.IsNaN(bound) || math.IsInf(bound, 0) || bound <= 0 || bound >= 1 {
		return 0, fmt.Errorf(
			"Gaussian implementation delta bound is not representable")
	}
	return bound, nil
}

func dpGaussianParameters(input dpGaussianInt64Input) (
	sigma, granularity, analyticDelta, implementationDeltaBound float64,
	err error,
) {
	return dpGaussianParametersForCoordinateCount(input, len(input.Values))
}

func dpGaussianParametersForCoordinateCount(
	input dpGaussianInt64Input, coordinateCount int,
) (
	sigma, granularity, analyticDelta, implementationDeltaBound float64,
	err error,
) {
	if len(input.Values) == 0 {
		return 0, 0, 0, 0, fmt.Errorf("values must be non-empty")
	}
	if len(input.Values) > dpNoiseMaxCoordinates {
		return 0, 0, 0, 0, fmt.Errorf(
			"coordinate count exceeds %d", dpNoiseMaxCoordinates)
	}
	if err := validateDPSeedHex(input.Seed); err != nil {
		return 0, 0, 0, 0, err
	}
	for i, value := range input.Values {
		if value < dpNoiseOutputMin || value > dpNoiseOutputMax {
			return 0, 0, 0, 0, fmt.Errorf(
				"value element %d is outside the exact JSON/R integer range", i)
		}
	}
	if math.IsNaN(input.Epsilon) || math.IsInf(input.Epsilon, 0) ||
		input.Epsilon < dpNoiseMinimumEpsilon ||
		input.Epsilon > dpNoiseMaximumEpsilon {
		return 0, 0, 0, 0, fmt.Errorf(
			"epsilon must be finite and between 2^-50 and 2^40")
	}
	if math.IsNaN(input.Delta) || math.IsInf(input.Delta, 0) ||
		input.Delta <= 0 || input.Delta >= 1 {
		return 0, 0, 0, 0, fmt.Errorf("delta must be finite and strictly between zero and one")
	}
	if math.IsNaN(input.L2Sensitivity) ||
		math.IsInf(input.L2Sensitivity, 0) || input.L2Sensitivity <= 0 ||
		input.L2Sensitivity > float64(dpNoiseOutputMax) {
		return 0, 0, 0, 0, fmt.Errorf(
			"l2_sensitivity must be positive, finite, and exactly representable")
	}
	implementationDeltaBound, err =
		dpGaussianImplementationDeltaBound(coordinateCount, input.Epsilon)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	analyticDelta = input.Delta - implementationDeltaBound
	if math.IsNaN(analyticDelta) || math.IsInf(analyticDelta, 0) ||
		analyticDelta <= 0 {
		return 0, 0, 0, 0, fmt.Errorf(
			"delta must exceed the Gaussian implementation bound %.17g",
			implementationDeltaBound)
	}

	sigma = noise.SigmaForGaussian(
		1, input.L2Sensitivity, input.Epsilon, analyticDelta)
	if math.IsNaN(sigma) || math.IsInf(sigma, 0) || sigma <= 0 {
		return 0, 0, 0, 0, fmt.Errorf("analytic Gaussian sigma is not representable")
	}
	// This is algebraically 2*sigma/2^57, written without the potentially
	// overflowing intermediate multiplication.
	granularity = dpCeilPowerOfTwo(sigma / math.Exp2(56))
	if !dpIsExactPowerOfTwo(granularity) || granularity > 1 {
		return 0, 0, 0, 0, fmt.Errorf(
			"Gaussian mechanism requires granularity above one; increase epsilon or delta, or reduce l2_sensitivity")
	}
	sqrtN := 2 * sigma / granularity
	if math.IsNaN(sqrtN) || math.IsInf(sqrtN, 0) ||
		sqrtN < dpGaussianBinomialBound/2 || sqrtN > dpGaussianBinomialBound {
		return 0, 0, 0, 0, fmt.Errorf("Gaussian symmetric-binomial domain is invalid")
	}
	return sigma, granularity, analyticDelta, implementationDeltaBound, nil
}

func dpGaussianBinomialProbability(sqrtN float64, sample int64) float64 {
	if math.Abs(float64(sample)) > sqrtN*math.Sqrt(math.Log(sqrtN)/2) {
		return 0
	}
	return (math.Sqrt(2/math.Pi) / sqrtN) *
		math.Exp((-2*float64(sample)*float64(sample))/(sqrtN*sqrtN)) *
		(1 - 0.4*math.Pow(2, 1.5)*math.Pow(math.Log(sqrtN), 1.5)/sqrtN)
}

func dpDeterministicSymmetricBinomial(
	stream *dpDeterministicStream, sqrtN float64,
) (int64, error) {
	stepSize := int64(math.Round(math.Sqrt2*sqrtN + 1))
	if stepSize <= 0 {
		return 0, fmt.Errorf("Gaussian symmetric-binomial step is invalid")
	}
	for iteration := 0; iteration < dpGaussianMaxIterations; iteration++ {
		// Google's Gaussian sampler uses the number of failures before the
		// first fair-coin success. halfGeometric implements that exact bit-law
		// (including the leading +1), so subtract one here.
		geometric := int64(stream.halfGeometric()) - 1
		if geometric > dpGaussianGeometricBound {
			geometric = dpGaussianGeometricBound
		}
		twoSided := geometric
		if stream.boolean() {
			twoSided = -twoSided - 1
		}
		uniform, err := stream.i63n(stepSize)
		if err != nil {
			return 0, err
		}
		result := stepSize*twoSided + uniform
		probability := dpGaussianBinomialProbability(sqrtN, result)
		rejectProbability := stream.uniform()
		if probability > 0 && rejectProbability <
			probability*float64(stepSize)*math.Pow(2, float64(geometric))/4 {
			return result, nil
		}
	}
	return 0, fmt.Errorf(
		"Gaussian symmetric-binomial rejection sampler did not terminate")
}

func dpDeterministicGaussianSample(seed []byte) dpGaussianSample {
	return func(coordinate int, sigma float64) (int64, error) {
		stream, err := newDPDeterministicStreamForDomain(
			seed, coordinate, dpGaussianStreamDomain)
		if err != nil {
			return 0, err
		}
		granularity := dpCeilPowerOfTwo(sigma / math.Exp2(56))
		sqrtN := 2 * sigma / granularity
		sample, err := dpDeterministicSymmetricBinomial(stream, sqrtN)
		if err != nil {
			return 0, err
		}
		if granularity == 1 {
			return sample, nil
		}
		scaled := math.Round(float64(sample) * granularity)
		if math.IsNaN(scaled) || math.IsInf(scaled, 0) ||
			scaled >= math.Exp2(63) || scaled < -math.Exp2(63) {
			return 0, fmt.Errorf("Gaussian integer sample is not representable")
		}
		return int64(scaled), nil
	}
}

func dpGaussianAccuracyRadius(sigma, alpha float64) (int64, error) {
	// If P is the continuous Gaussian law and Q is the implemented law with
	// TV(P,Q)<=eta, a P-tail bound alpha-eta gives a Q-tail bound alpha.
	// Applying this per coordinate also gives the simultaneous union bound.
	adjustedAlpha := alpha - dpGaussianScalarTVBound
	if math.IsNaN(adjustedAlpha) || math.IsInf(adjustedAlpha, 0) ||
		adjustedAlpha <= 0 || adjustedAlpha >= 1 {
		return 0, fmt.Errorf(
			"confidence failure probability does not cover the implementation total-variation bound")
	}
	radius := math.Ceil(
		sigma * math.Sqrt2 * math.Abs(math.Erfcinv(adjustedAlpha)))
	if math.IsNaN(radius) || math.IsInf(radius, 0) ||
		radius < 0 || radius > float64(dpNoiseOutputMax) {
		return 0, fmt.Errorf("Gaussian accuracy radius is not exactly representable")
	}
	return int64(radius), nil
}

func addDPGaussianNoiseInt64(
	input dpGaussianInt64Input, sample dpGaussianSample,
) (dpGaussianInt64Output, error) {
	sigma, granularity, analyticDelta, implementationDeltaBound, err :=
		dpGaussianParameters(input)
	if err != nil {
		return dpGaussianInt64Output{}, err
	}
	if sample == nil {
		return dpGaussianInt64Output{}, fmt.Errorf(
			"DP Gaussian noise implementation is unavailable")
	}
	marginalRadius, err := dpGaussianAccuracyRadius(sigma, 0.05)
	if err != nil {
		return dpGaussianInt64Output{}, fmt.Errorf(
			"marginal confidence interval: %w", err)
	}
	simultaneousRadius, err := dpGaussianAccuracyRadius(
		sigma, 0.05/float64(len(input.Values)))
	if err != nil {
		return dpGaussianInt64Output{}, fmt.Errorf(
			"simultaneous confidence interval: %w", err)
	}

	values := make([]int64, len(input.Values))
	clipped := 0
	for coordinate, value := range input.Values {
		draw, err := sample(coordinate, sigma)
		if err != nil {
			return dpGaussianInt64Output{}, fmt.Errorf(
				"coordinate %d Gaussian noise: %w", coordinate, err)
		}
		var wasClipped bool
		values[coordinate], wasClipped = addAndClipDPOutput(value, draw)
		if wasClipped {
			clipped++
		}
	}

	accuracy := make([]int64, len(input.Values))
	simultaneousAccuracy := make([]int64, len(input.Values))
	for i := range accuracy {
		accuracy[i] = marginalRadius
		simultaneousAccuracy[i] = simultaneousRadius
	}
	return dpGaussianInt64Output{
		Values:                    values,
		Accuracy95Abs:             accuracy,
		AccuracySimultaneous95Abs: simultaneousAccuracy,
		ClippedCoordinates:        clipped,
		Mechanism:                 dpGaussianMechanism,
		Implementation:            dpGaussianImplementation,
		Sampler:                   dpGaussianSampler,
		Randomness:                dpNoiseRandomness,
		Epsilon:                   input.Epsilon,
		Delta:                     input.Delta,
		AnalyticDelta:             analyticDelta,
		ImplementationDeltaBound:  implementationDeltaBound,
		ImplementationTVPerCoord:  dpGaussianScalarTVBound,
		AccountingRule:            dpGaussianAccountingRule,
		AccuracyAccounting:        dpGaussianAccuracyRule,
		L2Sensitivity:             input.L2Sensitivity,
		Sigma:                     sigma,
		Granularity:               granularity,
		MarginalConfidence:        0.95,
		SimultaneousConfidence:    0.95,
		SimultaneousMethod:        "union_bound",
		OutputLowerBound:          dpNoiseOutputMin,
		OutputUpperBound:          dpNoiseOutputMax,
	}, nil
}

func handleDPGaussianInt64() {
	input, err := decodeDPGaussianInt64Input(os.Stdin)
	if err != nil {
		mpcFatalError(err.Error())
	}
	seed, err := hex.DecodeString(input.Seed)
	if err != nil {
		mpcFatalError("invalid deterministic DP seed")
	}
	result, err := addDPGaussianNoiseInt64(
		input, dpDeterministicGaussianSample(seed))
	if err != nil {
		mpcFatalError(err.Error())
	}
	mpcWriteOutput(result)
}
