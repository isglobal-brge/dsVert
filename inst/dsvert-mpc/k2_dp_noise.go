package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/bits"
	"os"

	"github.com/google/differential-privacy/go/v4/noise"
	"golang.org/x/crypto/chacha20"
)

const (
	dpNoiseMechanism        = "dsvert_dp_v1_deterministic_granular_laplace_int64"
	dpNoiseImplementation   = "dsVert adapted Google Differential Privacy v4.1.0 granular Laplace integer mechanism"
	dpNoiseSampler          = "deterministic_two_sided_geometric"
	dpNoiseRandomness       = "HMAC-SHA256/ChaCha20"
	dpNoiseMaxCoordinates   = 1_000_000
	dpNoiseMaxInputBytes    = 64 << 20
	dpNoiseGranularityParam = float64(uint64(1) << 40)
	dpNoiseMinimumEpsilon   = 1.0 / float64(uint64(1)<<50)
	dpNoiseMaximumEpsilon   = float64(uint64(1) << 40)
	dpNoiseOutputMax        = int64(1<<53 - 1)
	dpNoiseOutputMin        = -dpNoiseOutputMax
	dpLaplaceStreamDomain   = "dsvert/dp-noise/coordinate/v1\x00"
)

type dpNoiseInt64Input struct {
	Values        []int64   `json:"values"`
	Epsilons      []float64 `json:"epsilons"`
	Sensitivities []int64   `json:"sensitivities"`
	Seed          string    `json:"seed"`
}

type dpNoiseInt64Output struct {
	Values                    []int64 `json:"values"`
	Accuracy95Abs             []int64 `json:"accuracy_95_abs"`
	AccuracySimultaneous95Abs []int64 `json:"accuracy_simultaneous_95_abs"`
	ClippedCoordinates        int     `json:"clipped_coordinates"`
	Mechanism                 string  `json:"mechanism"`
	Implementation            string  `json:"implementation"`
	Sampler                   string  `json:"sampler"`
	Randomness                string  `json:"randomness"`
	L0Sensitivity             int64   `json:"l0_sensitivity"`
	Delta                     float64 `json:"delta"`
	MarginalConfidence        float64 `json:"marginal_confidence"`
	SimultaneousConfidence    float64 `json:"simultaneous_confidence"`
	SimultaneousMethod        string  `json:"simultaneous_method"`
	MaxGranularity            float64 `json:"max_granularity"`
	OutputLowerBound          int64   `json:"output_lower_bound"`
	OutputUpperBound          int64   `json:"output_upper_bound"`
}

type dpAddNoiseInt64 func(
	coordinate int, x, l0Sensitivity, lInfSensitivity int64,
	epsilon, delta float64,
) (int64, error)

type dpConfidenceInt64 func(
	noisedX, l0Sensitivity, lInfSensitivity int64,
	epsilon, delta, alpha float64,
) (noise.ConfidenceInterval, error)

func decodeDPNoiseInt64Input(r io.Reader) (dpNoiseInt64Input, error) {
	limited := io.LimitReader(r, dpNoiseMaxInputBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return dpNoiseInt64Input{}, fmt.Errorf("read input: %w", err)
	}
	if len(data) > dpNoiseMaxInputBytes {
		return dpNoiseInt64Input{}, fmt.Errorf("input exceeds %d bytes", dpNoiseMaxInputBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var input dpNoiseInt64Input
	if err := dec.Decode(&input); err != nil {
		return dpNoiseInt64Input{}, fmt.Errorf("parse input: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return dpNoiseInt64Input{}, err
	}
	return input, nil
}

func requireJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("parse input: multiple JSON values")
		}
		return fmt.Errorf("parse input: %w", err)
	}
	return nil
}

func validateDPNoiseInt64Input(input dpNoiseInt64Input) error {
	n := len(input.Values)
	if n == 0 {
		return fmt.Errorf("values must be non-empty")
	}
	if n > dpNoiseMaxCoordinates {
		return fmt.Errorf("coordinate count exceeds %d", dpNoiseMaxCoordinates)
	}
	if len(input.Epsilons) != n || len(input.Sensitivities) != n {
		return fmt.Errorf("values, epsilons, and sensitivities must have equal length")
	}
	if err := validateDPSeedHex(input.Seed); err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		if input.Values[i] < dpNoiseOutputMin || input.Values[i] > dpNoiseOutputMax {
			return fmt.Errorf("value element %d is outside the exact JSON/R integer range", i)
		}
		epsilon := input.Epsilons[i]
		sensitivity := input.Sensitivities[i]
		if math.IsNaN(epsilon) || math.IsInf(epsilon, 0) ||
			epsilon < dpNoiseMinimumEpsilon || epsilon > dpNoiseMaximumEpsilon {
			return fmt.Errorf(
				"epsilon element %d must be finite and between 2^-50 and 2^40", i)
		}
		if sensitivity <= 0 {
			return fmt.Errorf("sensitivity element %d must be positive", i)
		}
		// Google DP rounds integer inputs to its computed power-of-two
		// granularity when that granularity exceeds one. Restricting it to at
		// most one lets us sample at zero and perform a checked, saturating
		// integer shift below, eliminating the upstream int64 wrap boundary.
		granularityRatio := (float64(sensitivity) / epsilon) /
			dpNoiseGranularityParam
		if granularityRatio <= 0 || math.IsNaN(granularityRatio) ||
			math.IsInf(granularityRatio, 0) {
			return fmt.Errorf("coordinate %d has an unrepresentable granularity", i)
		}
		if granularityRatio > 1 {
			return fmt.Errorf(
				"coordinate %d requires granularity above one; increase epsilon or reduce sensitivity",
				i,
			)
		}
		granularity := dpCeilPowerOfTwo(granularityRatio)
		if !dpIsExactPowerOfTwo(granularity) || granularity > 1 {
			return fmt.Errorf(
				"coordinate %d has an invalid power-of-two granularity", i)
		}
		lambda := granularity * epsilon /
			(float64(sensitivity) + granularity)
		if lambda <= 0 || math.IsNaN(lambda) || math.IsInf(lambda, 0) {
			return fmt.Errorf("coordinate %d has an unrepresentable sampler rate", i)
		}
	}
	return nil
}

// The deterministic sampler below adapts the granular integer Laplace
// mechanism and two-sided geometric inversion sampler from Google
// Differential Privacy v4.1.0 (Apache-2.0). The distribution and power-of-two
// granularity are preserved; only the entropy source is replaced by a
// release-specific, domain-separated ChaCha20 stream. The 32-byte seed is
// produced server-side by HMAC under a custodian-provisioned root and is never
// included in command output or any DSI response.

type dpDeterministicStream struct {
	cipher *chacha20.Cipher
}

func validateDPSeedHex(seed string) error {
	if len(seed) != 64 {
		return fmt.Errorf("seed must contain exactly 32 lowercase-hex bytes")
	}
	if _, err := hex.DecodeString(seed); err != nil {
		return fmt.Errorf("seed must contain exactly 32 lowercase-hex bytes")
	}
	for _, character := range seed {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return fmt.Errorf("seed must contain exactly 32 lowercase-hex bytes")
		}
	}
	return nil
}

func newDPDeterministicStreamForDomain(
	seed []byte, coordinate int, domain string,
) (*dpDeterministicStream, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("deterministic stream seed must contain 32 bytes")
	}
	if coordinate < 0 {
		return nil, fmt.Errorf("deterministic stream coordinate must be non-negative")
	}
	if domain == "" {
		return nil, fmt.Errorf("deterministic stream domain must be non-empty")
	}
	mac := hmac.New(sha256.New, seed)
	_, _ = mac.Write([]byte(domain))
	var encodedCoordinate [8]byte
	binary.LittleEndian.PutUint64(encodedCoordinate[:], uint64(coordinate))
	_, _ = mac.Write(encodedCoordinate[:])
	key := mac.Sum(nil)
	nonce := make([]byte, chacha20.NonceSize)
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, fmt.Errorf("initialize deterministic stream: %w", err)
	}
	return &dpDeterministicStream{cipher: cipher}, nil
}

func newDPDeterministicStream(seed []byte, coordinate int) (*dpDeterministicStream, error) {
	return newDPDeterministicStreamForDomain(
		seed, coordinate, dpLaplaceStreamDomain)
}

func (stream *dpDeterministicStream) read(destination []byte) {
	clear(destination)
	stream.cipher.XORKeyStream(destination, destination)
}

func (stream *dpDeterministicStream) u64() uint64 {
	var encoded [8]byte
	stream.read(encoded[:])
	return binary.LittleEndian.Uint64(encoded[:])
}

func (stream *dpDeterministicStream) u8() uint8 {
	var encoded [1]byte
	stream.read(encoded[:])
	return encoded[0]
}

func (stream *dpDeterministicStream) boolean() bool {
	return stream.u8()&1 == 1
}

func (stream *dpDeterministicStream) sign() int64 {
	if stream.boolean() {
		return 1
	}
	return -1
}

// i63n returns an unbiased value in [0,n), using rejection sampling over a
// 63-bit uniform domain. It mirrors the contract needed by Google's secure
// symmetric-binomial sampler without importing a process-global RNG.
func (stream *dpDeterministicStream) i63n(n int64) (int64, error) {
	if n <= 0 {
		return 0, fmt.Errorf("uniform integer bound must be positive")
	}
	domainSize := uint64(1) << 63
	bound := uint64(n)
	cutoff := domainSize - domainSize%bound
	for {
		candidate := stream.u64() >> 1
		if candidate < cutoff {
			return int64(candidate % bound), nil
		}
	}
}

// uniform mirrors Google's secure Uniform construction on (0,1].
func (stream *dpDeterministicStream) uniform() float64 {
	i := stream.u64() % (uint64(1) << 53)
	r := (1 + float64(i)/(1<<53)) / math.Pow(2, stream.halfGeometric())
	if r == 0 {
		return 1
	}
	return r
}

func (stream *dpDeterministicStream) halfGeometric() float64 {
	b := 1
	var value uint8
	for value == 0 {
		value = stream.u8()
		b += bits.LeadingZeros8(value)
	}
	return float64(b)
}

func dpCeilPowerOfTwo(value float64) float64 {
	if value <= 0 || math.IsInf(value, 0) || math.IsNaN(value) {
		return math.NaN()
	}
	fraction, exponent := math.Frexp(value)
	if fraction == 0.5 {
		return value
	}
	result := math.Ldexp(1, exponent)
	if math.IsInf(result, 0) {
		return math.NaN()
	}
	return result
}

func dpIsExactPowerOfTwo(value float64) bool {
	if value <= 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return false
	}
	const mantissaMask uint64 = 0x000fffffffffffff
	encoded := math.Float64bits(value)
	exponent := encoded >> 52 & 0x7ff
	mantissa := encoded & mantissaMask
	if exponent == 0 {
		return mantissa != 0 && mantissa&(mantissa-1) == 0
	}
	return mantissa == 0
}

func dpGeometric(stream *dpDeterministicStream, lambda float64) int64 {
	if stream.uniform() > -math.Expm1(-lambda*math.MaxInt64) {
		return math.MaxInt64
	}
	left, right := int64(0), int64(math.MaxInt64)
	for left+1 < right {
		mid := left - int64(math.Floor(
			(math.Log(0.5)+math.Log1p(math.Exp(lambda*float64(left-right))))/lambda,
		))
		if mid <= left {
			mid = left + 1
		} else if mid >= right {
			mid = right - 1
		}
		q := math.Expm1(lambda*float64(left-mid)) /
			math.Expm1(lambda*float64(left-right))
		if stream.uniform() <= q {
			right = mid
		} else {
			left = mid
		}
	}
	return right
}

func dpTwoSidedGeometric(stream *dpDeterministicStream, lambda float64) int64 {
	var sample int64
	sign := int64(-1)
	for sample == 0 && sign == -1 {
		sample = dpGeometric(stream, lambda) - 1
		sign = stream.sign()
	}
	return sample * sign
}

func dpDeterministicAddNoise(seed []byte) dpAddNoiseInt64 {
	return func(coordinate int, x, l0Sensitivity, lInfSensitivity int64,
		epsilon, delta float64) (int64, error) {
		if x != 0 || l0Sensitivity != 1 || delta != 0 {
			return 0, fmt.Errorf("unsupported deterministic DP parameters")
		}
		stream, err := newDPDeterministicStream(seed, coordinate)
		if err != nil {
			return 0, err
		}
		granularity := dpCeilPowerOfTwo(
			(float64(lInfSensitivity) / epsilon) / dpNoiseGranularityParam)
		lambda := granularity * epsilon /
			(float64(lInfSensitivity) + granularity)
		sample := dpTwoSidedGeometric(stream, lambda)
		if granularity < 1 {
			return int64(math.Round(float64(sample) * granularity)), nil
		}
		return sample, nil
	}
}

func saturatingAddInt64(x, y int64) (int64, bool) {
	if y > 0 && x > math.MaxInt64-y {
		return math.MaxInt64, true
	}
	if y < 0 && x < math.MinInt64-y {
		return math.MinInt64, true
	}
	return x + y, false
}

func addAndClipDPOutput(x, y int64) (int64, bool) {
	value, clipped := saturatingAddInt64(x, y)
	if value > dpNoiseOutputMax {
		return dpNoiseOutputMax, true
	}
	if value < dpNoiseOutputMin {
		return dpNoiseOutputMin, true
	}
	return value, clipped
}

func addDPNoiseInt64(
	input dpNoiseInt64Input,
	addNoise dpAddNoiseInt64,
	confidenceInterval dpConfidenceInt64,
) (dpNoiseInt64Output, error) {
	if err := validateDPNoiseInt64Input(input); err != nil {
		return dpNoiseInt64Output{}, err
	}
	if addNoise == nil || confidenceInterval == nil {
		return dpNoiseInt64Output{}, fmt.Errorf("DP noise implementation is unavailable")
	}

	accuracy := make([]int64, len(input.Values))
	type accuracyKey struct {
		sensitivity int64
		epsilonBits uint64
		alphaBits   uint64
	}
	accuracyCache := make(map[accuracyKey]int64)
	radiusFor := func(i int, alpha float64) (int64, error) {
		key := accuracyKey{
			sensitivity: input.Sensitivities[i],
			epsilonBits: math.Float64bits(input.Epsilons[i]),
			alphaBits:   math.Float64bits(alpha),
		}
		if cached, ok := accuracyCache[key]; ok {
			return cached, nil
		}
		interval, err := confidenceInterval(
			0, 1, input.Sensitivities[i], input.Epsilons[i], 0, alpha,
		)
		if err != nil {
			return 0, err
		}
		radius := math.Ceil(math.Max(math.Abs(interval.LowerBound), math.Abs(interval.UpperBound)))
		if math.IsNaN(radius) || math.IsInf(radius, 0) || radius > math.MaxInt64 {
			return 0, fmt.Errorf("accuracy radius is not representable")
		}
		result := int64(radius)
		accuracyCache[key] = result
		return result, nil
	}

	simultaneousAccuracy := make([]int64, len(input.Values))
	simultaneousAlpha := 0.05 / float64(len(input.Values))
	for i := range input.Values {
		var err error
		accuracy[i], err = radiusFor(i, 0.05)
		if err != nil {
			return dpNoiseInt64Output{}, fmt.Errorf(
				"coordinate %d marginal confidence interval: %w", i, err)
		}
		simultaneousAccuracy[i], err = radiusFor(i, simultaneousAlpha)
		if err != nil {
			return dpNoiseInt64Output{}, fmt.Errorf(
				"coordinate %d simultaneous confidence interval: %w", i, err)
		}
	}

	result := make([]int64, len(input.Values))
	clipped := 0
	for i := range input.Values {
		// At granularity <= 1, AddNoiseInt64(0, ...) returns the same
		// integer noise that the upstream mechanism would add to x, without
		// risking its unchecked x+noise operation. Clipping to R's exact
		// integer envelope is DP-safe post-processing of the shifted noisy
		// integer and avoids any JSON-to-double precision loss.
		draw, err := addNoise(
			i, 0, 1, input.Sensitivities[i], input.Epsilons[i], 0)
		if err != nil {
			return dpNoiseInt64Output{}, fmt.Errorf("coordinate %d noise: %w", i, err)
		}
		var wasClipped bool
		result[i], wasClipped = addAndClipDPOutput(input.Values[i], draw)
		if wasClipped {
			clipped++
		}
	}

	return dpNoiseInt64Output{
		Values:                    result,
		Accuracy95Abs:             accuracy,
		AccuracySimultaneous95Abs: simultaneousAccuracy,
		ClippedCoordinates:        clipped,
		Mechanism:                 dpNoiseMechanism,
		Implementation:            dpNoiseImplementation,
		Sampler:                   dpNoiseSampler,
		Randomness:                dpNoiseRandomness,
		L0Sensitivity:             1,
		Delta:                     0,
		MarginalConfidence:        0.95,
		SimultaneousConfidence:    0.95,
		SimultaneousMethod:        "union_bound",
		MaxGranularity:            1,
		OutputLowerBound:          dpNoiseOutputMin,
		OutputUpperBound:          dpNoiseOutputMax,
	}, nil
}

func handleDPNoiseInt64() {
	input, err := decodeDPNoiseInt64Input(os.Stdin)
	if err != nil {
		mpcFatalError(err.Error())
	}
	seed, err := hex.DecodeString(input.Seed)
	if err != nil {
		mpcFatalError("invalid deterministic DP seed")
	}
	laplace := noise.Laplace()
	result, err := addDPNoiseInt64(
		input, dpDeterministicAddNoise(seed),
		laplace.ComputeConfidenceIntervalInt64,
	)
	if err != nil {
		mpcFatalError(err.Error())
	}
	mpcWriteOutput(result)
}
