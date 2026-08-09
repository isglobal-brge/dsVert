package main

// This file implements the local arithmetic half of a deliberately
// unpromoted joint-DP capsule fallback. Each of two custodian-designated peers adds
// one complete, independently seeded DP draw to an already uniformly masked
// additive Ring2^k share.  Opening the two translated shares reveals only the
// convolution-noised release.  It never reveals either input share, seed, or
// noise draw at the command boundary.

import (
	"bytes"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"regexp"

	"github.com/google/differential-privacy/go/v4/noise"
)

const (
	jointDPConvolutionVersion            = "dsvert-joint-dp-independent-full-draw-convolution-v1"
	jointDPConvolutionMaskProtocol       = "uniform-additive-mod-2k-v1"
	jointDPConvolutionLaplace            = "granular_laplace_int64"
	jointDPConvolutionGaussian           = "approximate_gaussian_int64"
	jointDPConvolutionMinimumMaskEntropy = 128
	jointDPConvolutionPeerCount          = 2
	jointDPConvolutionUnavailable        = "independent_full_draw_convolution_not_e2e_promoted"
	jointDPConvolutionLaplaceDeltaFloor  = 0x1p-100
	jointDPUniformSplitVersion           = "dsvert-joint-dp-uniform-split-ring128-v1"
)

var jointDPConvolutionUnsignedDecimal = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
var jointDPConvolutionSignedDecimal = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)
var jointDPConvolutionHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var jointDPConvolutionPeer = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type jointDPConvolutionShareInput struct {
	Version                       string    `json:"version"`
	PeerName                      string    `json:"peer_name"`
	PeerIdentityPK                string    `json:"peer_identity_pk"`
	QueryID                       string    `json:"query_id"`
	CapsuleReleaseID              string    `json:"capsule_release_id"`
	AllocationIndex               string    `json:"allocation_index"`
	SourceContractHash            string    `json:"source_contract_hash"`
	MaskContractHash              string    `json:"mask_contract_hash"`
	RingBits                      int       `json:"ring_bits"`
	FracBits                      int       `json:"frac_bits"`
	AdditiveShares                []string  `json:"additive_shares"`
	StatisticLowerBounds          []string  `json:"statistic_lower_bounds"`
	StatisticUpperBounds          []string  `json:"statistic_upper_bounds"`
	ReleaseLowerBounds            []string  `json:"release_lower_bounds"`
	ReleaseUpperBounds            []string  `json:"release_upper_bounds"`
	MaskProtocol                  string    `json:"mask_protocol"`
	MaskConditionalMinEntropyBits int       `json:"mask_conditional_min_entropy_bits"`
	MaskIndependentOfStatistic    bool      `json:"mask_independent_of_statistic"`
	DesignatedNoisePeerCount      int       `json:"designated_noise_peer_count"`
	Mechanism                     string    `json:"mechanism"`
	CapsuleEpsilon                float64   `json:"capsule_epsilon"`
	CapsuleDelta                  float64   `json:"capsule_delta"`
	Epsilons                      []float64 `json:"epsilons"`
	Sensitivities                 []int64   `json:"sensitivities"`
	L2Sensitivity                 float64   `json:"l2_sensitivity"`
	Seed                          string    `json:"seed"`
}

type jointDPConvolutionShareOutput struct {
	Version                       string   `json:"version"`
	Backend                       string   `json:"backend"`
	CapabilityAvailable           bool     `json:"capability_available"`
	PayloadDeliveryAvailable      bool     `json:"payload_delivery_available"`
	UnavailableReason             string   `json:"unavailable_reason"`
	PeerName                      string   `json:"peer_name"`
	PeerIdentityPK                string   `json:"peer_identity_pk"`
	QueryID                       string   `json:"query_id"`
	CapsuleReleaseID              string   `json:"capsule_release_id"`
	AllocationIndex               string   `json:"allocation_index"`
	SourceContractHash            string   `json:"source_contract_hash"`
	MaskContractHash              string   `json:"mask_contract_hash"`
	RingBits                      int      `json:"ring_bits"`
	FracBits                      int      `json:"frac_bits"`
	CoordinateCount               int      `json:"coordinate_count"`
	NoisedShares                  []string `json:"noised_shares"`
	Mechanism                     string   `json:"mechanism"`
	Sampler                       string   `json:"sampler"`
	Randomness                    string   `json:"randomness"`
	CapsuleEpsilon                float64  `json:"capsule_epsilon"`
	CapsuleDelta                  float64  `json:"capsule_delta"`
	DeltaImplSampler              float64  `json:"delta_impl_sampler"`
	DeltaMechanism                float64  `json:"delta_mechanism"`
	DeltaTotal                    float64  `json:"delta_total"`
	FullCapsuleParametersPerPeer  bool     `json:"full_capsule_parameters_per_peer"`
	EpsilonDividedByPeerCount     bool     `json:"epsilon_divided_by_peer_count"`
	DesignatedNoisePeerCount      int      `json:"designated_noise_peer_count"`
	MaskProtocol                  string   `json:"mask_protocol"`
	MaskConditionalMinEntropyBits int      `json:"mask_conditional_min_entropy_bits"`
	MaskContractValidation        string   `json:"mask_contract_validation"`
	NoiseLowerBoundPerPeer        string   `json:"noise_lower_bound_per_peer"`
	NoiseUpperBoundPerPeer        string   `json:"noise_upper_bound_per_peer"`
	PreclipLowerBounds            []string `json:"preclip_lower_bounds"`
	PreclipUpperBounds            []string `json:"preclip_upper_bounds"`
	ReleaseLowerBounds            []string `json:"release_lower_bounds"`
	ReleaseUpperBounds            []string `json:"release_upper_bounds"`
	SingleDrawMarginal95Abs       []string `json:"single_draw_marginal_95_abs"`
	ConvolutionMarginal95Abs      []string `json:"convolution_marginal_95_abs"`
	ConvolutionSimultaneous95Abs  []string `json:"convolution_simultaneous_95_abs"`
	AccuracyAccounting            string   `json:"accuracy_accounting"`
	NominalVarianceMultiplier     float64  `json:"nominal_variance_multiplier"`
	NominalRMSEMultiplier         float64  `json:"nominal_rmse_multiplier"`
	ThreatModel                   string   `json:"threat_model"`
	ConvolutionPrivacyArgument    string   `json:"convolution_privacy_argument"`
	OpeningContract               string   `json:"opening_contract"`
	UtilityPreferredBackend       string   `json:"utility_preferred_backend"`
}

type jointDPUniformSplitInput struct {
	Version            string `json:"version"`
	QueryID            string `json:"query_id"`
	CapsuleReleaseID   string `json:"capsule_release_id"`
	AllocationIndex    string `json:"allocation_index"`
	SourceContractHash string `json:"source_contract_hash"`
	MaskContractHash   string `json:"mask_contract_hash"`
	CoordinateIndex    string `json:"coordinate_index"`
	Count              string `json:"count"`
}

type jointDPUniformSplitOutput struct {
	Version                       string `json:"version"`
	CapabilityAvailable           bool   `json:"capability_available"`
	UnavailableReason             string `json:"unavailable_reason"`
	QueryID                       string `json:"query_id"`
	CapsuleReleaseID              string `json:"capsule_release_id"`
	AllocationIndex               string `json:"allocation_index"`
	SourceContractHash            string `json:"source_contract_hash"`
	MaskContractHash              string `json:"mask_contract_hash"`
	CoordinateIndex               string `json:"coordinate_index"`
	RingBits                      int    `json:"ring_bits"`
	LeftShare                     string `json:"left_share"`
	RightShare                    string `json:"right_share"`
	MaskProtocol                  string `json:"mask_protocol"`
	MaskConditionalMinEntropyBits int    `json:"mask_conditional_min_entropy_bits"`
	Generator                     string `json:"generator"`
	RequiresDurableReplay         bool   `json:"requires_durable_replay"`
}

func decodeJointDPConvolutionShareInput(r io.Reader) (jointDPConvolutionShareInput, error) {
	limited := io.LimitReader(r, dpNoiseMaxInputBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return jointDPConvolutionShareInput{}, fmt.Errorf("read input: %w", err)
	}
	if len(data) > dpNoiseMaxInputBytes {
		return jointDPConvolutionShareInput{}, fmt.Errorf(
			"input exceeds %d bytes", dpNoiseMaxInputBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var input jointDPConvolutionShareInput
	if err := decoder.Decode(&input); err != nil {
		return jointDPConvolutionShareInput{}, fmt.Errorf("parse input: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return jointDPConvolutionShareInput{}, err
	}
	return input, nil
}

func decodeJointDPUniformSplitInput(r io.Reader) (jointDPUniformSplitInput, error) {
	limited := io.LimitReader(r, 4097)
	data, err := io.ReadAll(limited)
	if err != nil {
		return jointDPUniformSplitInput{}, fmt.Errorf("read input: %w", err)
	}
	if len(data) > 4096 {
		return jointDPUniformSplitInput{}, fmt.Errorf("uniform split input exceeds 4096 bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var input jointDPUniformSplitInput
	if err := decoder.Decode(&input); err != nil {
		return jointDPUniformSplitInput{}, fmt.Errorf("parse input: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return jointDPUniformSplitInput{}, err
	}
	return input, nil
}

func jointDPConvolutionParseUnsigned(value, name string) (*big.Int, error) {
	if !jointDPConvolutionUnsignedDecimal.MatchString(value) || len(value) > 156 {
		return nil, fmt.Errorf("%s must be a canonical non-negative decimal", name)
	}
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return nil, fmt.Errorf("%s must be a canonical non-negative decimal", name)
	}
	return parsed, nil
}

func jointDPConvolutionParseSigned(value, name string) (*big.Int, error) {
	if !jointDPConvolutionSignedDecimal.MatchString(value) || len(value) > 157 {
		return nil, fmt.Errorf("%s must be a canonical signed decimal", name)
	}
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return nil, fmt.Errorf("%s must be a canonical signed decimal", name)
	}
	return parsed, nil
}

func validateJointDPUniformSplitInput(input jointDPUniformSplitInput) (*big.Int, error) {
	if input.Version != jointDPUniformSplitVersion ||
		!jointDPConvolutionHash.MatchString(input.QueryID) ||
		!jointDPConvolutionHash.MatchString(input.CapsuleReleaseID) ||
		input.QueryID != input.CapsuleReleaseID ||
		!jointDPConvolutionHash.MatchString(input.SourceContractHash) ||
		!jointDPConvolutionHash.MatchString(input.MaskContractHash) {
		return nil, fmt.Errorf("invalid purpose-bound Ring128 split contract")
	}
	allocation, err := jointDPConvolutionParseUnsigned(
		input.AllocationIndex, "allocation_index")
	if err != nil || allocation.BitLen() > 53 {
		return nil, fmt.Errorf("invalid Ring128 split allocation index")
	}
	coordinate, err := jointDPConvolutionParseUnsigned(
		input.CoordinateIndex, "coordinate_index")
	if err != nil || coordinate.BitLen() > 53 {
		return nil, fmt.Errorf("invalid Ring128 split coordinate index")
	}
	count, err := jointDPConvolutionParseUnsigned(input.Count, "count")
	if err != nil || count.Cmp(big.NewInt(dpNoiseOutputMax)) > 0 {
		return nil, fmt.Errorf("count must lie in [0,2^53-1]")
	}
	return count, nil
}

func jointDPUniformSplitRing128(
	count *big.Int, randomness io.Reader,
) (*big.Int, *big.Int, error) {
	if count == nil || count.Sign() < 0 ||
		count.Cmp(big.NewInt(dpNoiseOutputMax)) > 0 {
		return nil, nil, fmt.Errorf("count must lie in [0,2^53-1]")
	}
	if randomness == nil {
		return nil, nil, fmt.Errorf("Ring128 split randomness is unavailable")
	}
	encoded := make([]byte, 16)
	if _, err := io.ReadFull(randomness, encoded); err != nil {
		return nil, nil, fmt.Errorf("read 128-bit Ring128 mask: %w", err)
	}
	left := new(big.Int).SetBytes(encoded)
	right := new(big.Int).Sub(count, left)
	right.Mod(right, exactGCModulus(128))
	return left, right, nil
}

func jointDPUniformSplit(
	input jointDPUniformSplitInput, randomness io.Reader,
) (jointDPUniformSplitOutput, error) {
	count, err := validateJointDPUniformSplitInput(input)
	if err != nil {
		return jointDPUniformSplitOutput{}, err
	}
	left, right, err := jointDPUniformSplitRing128(count, randomness)
	if err != nil {
		return jointDPUniformSplitOutput{}, err
	}
	return jointDPUniformSplitOutput{
		Version:             jointDPUniformSplitVersion,
		CapabilityAvailable: false,
		UnavailableReason:   jointDPConvolutionUnavailable,
		QueryID:             input.QueryID,
		CapsuleReleaseID:    input.CapsuleReleaseID,
		AllocationIndex:     input.AllocationIndex,
		SourceContractHash:  input.SourceContractHash,
		MaskContractHash:    input.MaskContractHash,
		CoordinateIndex:     input.CoordinateIndex,
		RingBits:            128, LeftShare: left.String(), RightShare: right.String(),
		MaskProtocol:                  jointDPConvolutionMaskProtocol,
		MaskConditionalMinEntropyBits: 128,
		Generator:                     "os_csprng_uniform_16_bytes",
		RequiresDurableReplay:         true,
	}, nil
}

// jointDPConvolutionLaplaceImplementationDeltaBound upper-bounds the
// difference between the ideal unbounded granular-Laplace vector and the two
// finite-int64 sampler vectors used by this fallback.  For one coordinate,
// the capped geometric draw differs only beyond MaxInt64.  The factor two
// covers zero/sign rejection, and the remaining factors union-bound over both
// peers and every coordinate.  The standard TV-to-approximate-DP transfer
// contributes (1+exp(epsilon)).  Every floating-point boundary is rounded in
// the conservative direction; 2^-100 is a deliberately loose non-zero floor
// when the analytic bound is too small to report usefully.
func jointDPConvolutionLaplaceImplementationDeltaBound(
	coordinateCount int, sensitivity int64, epsilon float64,
) (float64, error) {
	if coordinateCount < 1 || coordinateCount > dpNoiseMaxCoordinates ||
		sensitivity <= 0 || math.IsNaN(epsilon) || math.IsInf(epsilon, 0) ||
		epsilon < dpNoiseMinimumEpsilon || epsilon > dpNoiseMaximumEpsilon {
		return 0, fmt.Errorf("invalid Laplace implementation-bound parameters")
	}
	granularity := dpCeilPowerOfTwo(
		(float64(sensitivity) / epsilon) / dpNoiseGranularityParam)
	if !dpIsExactPowerOfTwo(granularity) || granularity > 1 {
		return 0, fmt.Errorf("Laplace implementation bound has invalid granularity")
	}
	lambda := granularity * epsilon / (float64(sensitivity) + granularity)
	if lambda <= 0 || math.IsNaN(lambda) || math.IsInf(lambda, 0) {
		return 0, fmt.Errorf("Laplace implementation bound has invalid rate")
	}

	// float64(MaxInt64) rounds up to 2^63.  Its predecessor is an exact
	// lower bound on MaxInt64, as required for an upper tail bound.
	lambdaLower := math.Nextafter(lambda, 0)
	maxInt64Lower := math.Nextafter(math.Exp2(63), 0)
	tailExponentLower := math.Nextafter(lambdaLower*maxInt64Lower, 0)
	unionFactor := float64(
		2 * jointDPConvolutionPeerCount * coordinateCount)
	logTVUpper := math.Nextafter(
		math.Log(unionFactor)-tailExponentLower, math.Inf(1))
	logDPTransferUpper := math.Nextafter(
		epsilon+math.Log1p(math.Exp(-epsilon)), math.Inf(1))
	logDeltaUpper := math.Nextafter(
		logTVUpper+logDPTransferUpper, math.Inf(1))
	bound := math.Nextafter(math.Exp(logDeltaUpper), math.Inf(1))
	if bound < jointDPConvolutionLaplaceDeltaFloor {
		bound = jointDPConvolutionLaplaceDeltaFloor
	}
	if math.IsNaN(bound) || math.IsInf(bound, 0) || bound <= 0 || bound >= 1 {
		return 0, fmt.Errorf("Laplace implementation delta bound is not representable")
	}
	return bound, nil
}

func validateJointDPConvolutionShareInput(input jointDPConvolutionShareInput) error {
	if input.Version != jointDPConvolutionVersion {
		return fmt.Errorf("unsupported joint-DP convolution version")
	}
	if !jointDPConvolutionPeer.MatchString(input.PeerName) ||
		len(input.PeerIdentityPK) < 32 || len(input.PeerIdentityPK) > 128 {
		return fmt.Errorf("invalid pinned peer identity")
	}
	if !jointDPConvolutionHash.MatchString(input.QueryID) ||
		!jointDPConvolutionHash.MatchString(input.CapsuleReleaseID) ||
		input.QueryID != input.CapsuleReleaseID ||
		!jointDPConvolutionHash.MatchString(input.SourceContractHash) ||
		!jointDPConvolutionHash.MatchString(input.MaskContractHash) {
		return fmt.Errorf("invalid purpose-bound contract hash")
	}
	index, err := jointDPConvolutionParseUnsigned(
		input.AllocationIndex, "allocation_index")
	if err != nil || index.BitLen() > 53 {
		return fmt.Errorf("allocation_index must be an exactly representable canonical integer")
	}
	if input.RingBits < jointDPConvolutionMinimumMaskEntropy ||
		input.RingBits > exactGCMaxRingBits || input.FracBits < 0 ||
		input.FracBits >= input.RingBits {
		return fmt.Errorf("joint-DP convolution requires Ring128 through Ring512")
	}
	count := len(input.AdditiveShares)
	if count < 1 || count > dpNoiseMaxCoordinates ||
		len(input.StatisticLowerBounds) != count ||
		len(input.StatisticUpperBounds) != count ||
		len(input.ReleaseLowerBounds) != count ||
		len(input.ReleaseUpperBounds) != count {
		return fmt.Errorf("share and bound vectors must have one common supported length")
	}
	if input.MaskProtocol != jointDPConvolutionMaskProtocol ||
		input.MaskConditionalMinEntropyBits != input.RingBits ||
		!input.MaskIndependentOfStatistic ||
		input.DesignatedNoisePeerCount != jointDPConvolutionPeerCount {
		return fmt.Errorf("the additive-share mask contract does not prove at least 128 conditional min-entropy bits")
	}
	if math.IsNaN(input.CapsuleEpsilon) || math.IsInf(input.CapsuleEpsilon, 0) ||
		input.CapsuleEpsilon < dpNoiseMinimumEpsilon ||
		input.CapsuleEpsilon > dpNoiseMaximumEpsilon ||
		math.IsNaN(input.CapsuleDelta) || math.IsInf(input.CapsuleDelta, 0) ||
		input.CapsuleDelta < 0 || input.CapsuleDelta >= 1 {
		return fmt.Errorf("invalid fixed capsule privacy parameters")
	}

	modulus := exactGCModulus(input.RingBits)
	// The local samplers return raw int64 draws. Do not clip each component:
	// clip(S+clip(N)) has shifted finite support and is not the mechanism we
	// certify. The ring instead carries the complete raw domain of both draws;
	// a later joint finalizer performs one fixed-envelope post-processing.
	twoNoiseLower := new(big.Int).Mul(big.NewInt(2), big.NewInt(math.MinInt64))
	twoNoiseUpper := new(big.Int).Mul(big.NewInt(2), big.NewInt(math.MaxInt64))
	for coordinate := 0; coordinate < count; coordinate++ {
		share, err := jointDPConvolutionParseUnsigned(
			input.AdditiveShares[coordinate], fmt.Sprintf("share %d", coordinate))
		if err != nil || share.Cmp(modulus) >= 0 {
			return fmt.Errorf("share %d is not a canonical Ring%d residue",
				coordinate, input.RingBits)
		}
		lower, err := jointDPConvolutionParseSigned(
			input.StatisticLowerBounds[coordinate],
			fmt.Sprintf("lower bound %d", coordinate))
		if err != nil {
			return err
		}
		upper, err := jointDPConvolutionParseSigned(
			input.StatisticUpperBounds[coordinate],
			fmt.Sprintf("upper bound %d", coordinate))
		if err != nil {
			return err
		}
		if lower.Cmp(upper) > 0 || !exactGCFitsSigned(lower, input.RingBits) ||
			!exactGCFitsSigned(upper, input.RingBits) {
			return fmt.Errorf("statistic bound %d is outside the signed ring", coordinate)
		}
		preclipLower := new(big.Int).Add(lower, twoNoiseLower)
		preclipUpper := new(big.Int).Add(upper, twoNoiseUpper)
		if !exactGCFitsSigned(preclipLower, input.RingBits) ||
			!exactGCFitsSigned(preclipUpper, input.RingBits) {
			return fmt.Errorf("Ring%d lacks certified two-draw no-wrap headroom at coordinate %d",
				input.RingBits, coordinate)
		}
		releaseLower, err := jointDPConvolutionParseSigned(
			input.ReleaseLowerBounds[coordinate],
			fmt.Sprintf("release lower bound %d", coordinate))
		if err != nil {
			return err
		}
		releaseUpper, err := jointDPConvolutionParseSigned(
			input.ReleaseUpperBounds[coordinate],
			fmt.Sprintf("release upper bound %d", coordinate))
		if err != nil {
			return err
		}
		if releaseLower.Cmp(releaseUpper) > 0 ||
			releaseLower.Cmp(big.NewInt(dpNoiseOutputMin)) < 0 ||
			releaseUpper.Cmp(big.NewInt(dpNoiseOutputMax)) > 0 {
			return fmt.Errorf("release saturation bound %d is outside the exact output envelope", coordinate)
		}
	}

	switch input.Mechanism {
	case jointDPConvolutionLaplace:
		if input.L2Sensitivity != 0 ||
			len(input.Epsilons) != count || len(input.Sensitivities) != count {
			return fmt.Errorf("invalid granular-Laplace convolution parameters")
		}
		if input.CapsuleDelta <= 0 {
			return fmt.Errorf("global delta must be positive for finite-int64 Laplace sampler accounting")
		}
		// This is one vector Laplace mechanism, not d sequential scalar
		// releases. The producer contract proves a global L1 sensitivity; the
		// density-ratio proof therefore uses the complete epsilon and that same
		// global sensitivity on every coordinate.
		for i := range input.Epsilons {
			if input.Epsilons[i] != input.CapsuleEpsilon ||
				input.Sensitivities[i] != input.Sensitivities[0] {
				return fmt.Errorf("every Laplace coordinate must use the complete global epsilon and one global L1 sensitivity")
			}
		}
		implementationDelta, err :=
			jointDPConvolutionLaplaceImplementationDeltaBound(
				count, input.Sensitivities[0], input.CapsuleEpsilon)
		if err != nil {
			return err
		}
		if implementationDelta > input.CapsuleDelta {
			return fmt.Errorf(
				"global delta %.17g does not cover Laplace sampler implementation delta %.17g",
				input.CapsuleDelta, implementationDelta)
		}
		// Seed syntax is deliberately checked only after the complete public
		// delta allocation is proved sufficient. No seed is decoded and no draw
		// occurs for a pure-DP or underfunded proposal.
		probe := dpNoiseInt64Input{
			Values: make([]int64, count), Epsilons: input.Epsilons,
			Sensitivities: input.Sensitivities, Seed: input.Seed,
		}
		if err := validateDPNoiseInt64Input(probe); err != nil {
			return fmt.Errorf("granular-Laplace parameters: %w", err)
		}
	case jointDPConvolutionGaussian:
		if len(input.Epsilons) != 0 || len(input.Sensitivities) != 0 ||
			input.CapsuleDelta <= 0 || input.L2Sensitivity <= 0 {
			return fmt.Errorf("invalid approximate-Gaussian convolution parameters")
		}
		implementationDelta, err := dpGaussianImplementationDeltaBound(
			count, input.CapsuleEpsilon)
		if err != nil {
			return err
		}
		if input.CapsuleDelta <= implementationDelta {
			return fmt.Errorf(
				"global delta %.17g does not leave positive Gaussian mechanism delta after sampler implementation delta %.17g",
				input.CapsuleDelta, implementationDelta)
		}
		probe := dpGaussianInt64Input{
			Values: make([]int64, count), Epsilon: input.CapsuleEpsilon,
			Delta: input.CapsuleDelta, L2Sensitivity: input.L2Sensitivity,
			Seed: input.Seed,
		}
		if _, _, _, _, err := dpGaussianParameters(probe); err != nil {
			return fmt.Errorf("approximate-Gaussian parameters: %w", err)
		}
	default:
		return fmt.Errorf("unsupported joint-DP convolution mechanism")
	}
	return nil
}

func jointDPConvolutionRadiusText(radius int64) string {
	if radius < 0 {
		radius = math.MaxInt64
	}
	return new(big.Int).Mul(big.NewInt(radius), big.NewInt(2)).String()
}

func jointDPConvolutionLaplaceRadius(
	mechanism noise.Noise, sensitivity int64, epsilon, alpha float64,
) (int64, error) {
	interval, err := mechanism.ComputeConfidenceIntervalInt64(
		0, 1, sensitivity, epsilon, 0, alpha)
	if err != nil {
		return 0, err
	}
	radius := math.Ceil(math.Max(
		math.Abs(interval.LowerBound), math.Abs(interval.UpperBound)))
	if math.IsNaN(radius) || math.IsInf(radius, 0) || radius < 0 {
		return 0, fmt.Errorf("Laplace accuracy radius is not representable")
	}
	if radius > float64(dpNoiseOutputMax) {
		return dpNoiseOutputMax, nil
	}
	return int64(radius), nil
}

func jointDPConvolutionAddShares(
	input jointDPConvolutionShareInput, draws []int64,
) ([]string, []string, []string, error) {
	if len(draws) != len(input.AdditiveShares) {
		return nil, nil, nil, fmt.Errorf("noise vector length mismatch")
	}
	modulus := exactGCModulus(input.RingBits)
	twoNoiseLower := new(big.Int).Mul(big.NewInt(2), big.NewInt(math.MinInt64))
	twoNoiseUpper := new(big.Int).Mul(big.NewInt(2), big.NewInt(math.MaxInt64))
	shares := make([]string, len(draws))
	lower := make([]string, len(draws))
	upper := make([]string, len(draws))
	for i, draw := range draws {
		share, _ := jointDPConvolutionParseUnsigned(input.AdditiveShares[i], "share")
		translated := new(big.Int).Add(share, big.NewInt(draw))
		translated.Mod(translated, modulus)
		shares[i] = translated.String()
		statisticLower, _ := jointDPConvolutionParseSigned(
			input.StatisticLowerBounds[i], "lower bound")
		statisticUpper, _ := jointDPConvolutionParseSigned(
			input.StatisticUpperBounds[i], "upper bound")
		lower[i] = new(big.Int).Add(statisticLower, twoNoiseLower).String()
		upper[i] = new(big.Int).Add(statisticUpper, twoNoiseUpper).String()
	}
	return shares, lower, upper, nil
}

func jointDPConvolutionShare(
	input jointDPConvolutionShareInput,
) (jointDPConvolutionShareOutput, error) {
	if err := validateJointDPConvolutionShareInput(input); err != nil {
		return jointDPConvolutionShareOutput{}, err
	}
	seed, err := hex.DecodeString(input.Seed)
	if err != nil {
		return jointDPConvolutionShareOutput{}, fmt.Errorf("invalid deterministic DP seed")
	}
	count := len(input.AdditiveShares)
	var draws []int64
	var sampler string
	var deltaImplSampler float64
	var deltaMechanism float64
	var deltaTotal float64
	single95 := make([]string, count)
	convolution95 := make([]string, count)
	convolutionSimultaneous95 := make([]string, count)

	switch input.Mechanism {
	case jointDPConvolutionLaplace:
		deltaImplSampler, err =
			jointDPConvolutionLaplaceImplementationDeltaBound(
				count, input.Sensitivities[0], input.CapsuleEpsilon)
		if err != nil {
			return jointDPConvolutionShareOutput{}, err
		}
		deltaTotal = deltaImplSampler
		laplace := noise.Laplace()
		draws = make([]int64, count)
		addNoise := dpDeterministicAddNoise(seed)
		for i := range draws {
			draws[i], err = addNoise(
				i, 0, 1, input.Sensitivities[i], input.Epsilons[i], 0)
			if err != nil {
				return jointDPConvolutionShareOutput{}, fmt.Errorf(
					"coordinate %d raw Laplace noise: %w", i, err)
			}
		}
		sampler = dpNoiseSampler
		for i := range draws {
			single, err := jointDPConvolutionLaplaceRadius(
				laplace, input.Sensitivities[i], input.Epsilons[i], 0.05)
			if err != nil {
				return jointDPConvolutionShareOutput{}, err
			}
			single95[i] = big.NewInt(single).String()
			marginal, err := jointDPConvolutionLaplaceRadius(
				laplace, input.Sensitivities[i], input.Epsilons[i], 0.025)
			if err != nil {
				return jointDPConvolutionShareOutput{}, err
			}
			simultaneous, err := jointDPConvolutionLaplaceRadius(
				laplace, input.Sensitivities[i], input.Epsilons[i],
				0.05/float64(2*count))
			if err != nil {
				return jointDPConvolutionShareOutput{}, err
			}
			convolution95[i] = jointDPConvolutionRadiusText(marginal)
			convolutionSimultaneous95[i] =
				jointDPConvolutionRadiusText(simultaneous)
		}
	case jointDPConvolutionGaussian:
		gaussianInput := dpGaussianInt64Input{
			Values: make([]int64, count), Epsilon: input.CapsuleEpsilon,
			Delta: input.CapsuleDelta, L2Sensitivity: input.L2Sensitivity,
			Seed: input.Seed}
		sigma, _, analyticDelta, implementationDelta, err :=
			dpGaussianParameters(gaussianInput)
		if err != nil {
			return jointDPConvolutionShareOutput{}, err
		}
		deltaMechanism = analyticDelta
		deltaImplSampler = implementationDelta
		deltaTotal = deltaMechanism + deltaImplSampler
		if deltaTotal > input.CapsuleDelta {
			return jointDPConvolutionShareOutput{}, fmt.Errorf(
				"Gaussian mechanism and sampler deltas exceed the fixed capsule parameters")
		}
		draws = make([]int64, count)
		sample := dpDeterministicGaussianSample(seed)
		for i := range draws {
			draws[i], err = sample(i, sigma)
			if err != nil {
				return jointDPConvolutionShareOutput{}, fmt.Errorf(
					"coordinate %d raw Gaussian noise: %w", i, err)
			}
		}
		sampler = dpGaussianSampler
		single, err := dpGaussianAccuracyRadius(sigma, 0.05)
		if err != nil {
			return jointDPConvolutionShareOutput{}, err
		}
		marginal, err := dpGaussianAccuracyRadius(sigma, 0.025)
		if err != nil {
			return jointDPConvolutionShareOutput{}, err
		}
		simultaneous, err := dpGaussianAccuracyRadius(
			sigma, 0.05/float64(2*count))
		if err != nil {
			return jointDPConvolutionShareOutput{}, err
		}
		if marginal > dpNoiseOutputMax {
			marginal = dpNoiseOutputMax
		}
		if simultaneous > dpNoiseOutputMax {
			simultaneous = dpNoiseOutputMax
		}
		for i := range draws {
			single95[i] = big.NewInt(single).String()
			convolution95[i] = jointDPConvolutionRadiusText(marginal)
			convolutionSimultaneous95[i] =
				jointDPConvolutionRadiusText(simultaneous)
		}
	}
	noisedShares, releaseLower, releaseUpper, err :=
		jointDPConvolutionAddShares(input, draws)
	if err != nil {
		return jointDPConvolutionShareOutput{}, err
	}
	return jointDPConvolutionShareOutput{
		Version:             jointDPConvolutionVersion,
		Backend:             "independent_full_global_draw_convolution",
		CapabilityAvailable: false, PayloadDeliveryAvailable: false,
		UnavailableReason: jointDPConvolutionUnavailable,
		PeerName:          input.PeerName, PeerIdentityPK: input.PeerIdentityPK,
		QueryID: input.QueryID, CapsuleReleaseID: input.CapsuleReleaseID,
		AllocationIndex:    input.AllocationIndex,
		SourceContractHash: input.SourceContractHash,
		MaskContractHash:   input.MaskContractHash,
		RingBits:           input.RingBits, FracBits: input.FracBits,
		CoordinateCount: count, NoisedShares: noisedShares,
		Mechanism: input.Mechanism, Sampler: sampler,
		Randomness:     dpNoiseRandomness,
		CapsuleEpsilon: input.CapsuleEpsilon, CapsuleDelta: input.CapsuleDelta,
		DeltaImplSampler:             deltaImplSampler,
		DeltaMechanism:               deltaMechanism,
		DeltaTotal:                   deltaTotal,
		FullCapsuleParametersPerPeer: true, EpsilonDividedByPeerCount: false,
		DesignatedNoisePeerCount:      jointDPConvolutionPeerCount,
		MaskProtocol:                  jointDPConvolutionMaskProtocol,
		MaskConditionalMinEntropyBits: input.RingBits,
		MaskContractValidation:        "producer_attested_precondition; translation_preserves_uniformity",
		NoiseLowerBoundPerPeer:        big.NewInt(math.MinInt64).String(),
		NoiseUpperBoundPerPeer:        big.NewInt(math.MaxInt64).String(),
		PreclipLowerBounds:            releaseLower, PreclipUpperBounds: releaseUpper,
		ReleaseLowerBounds:           append([]string(nil), input.ReleaseLowerBounds...),
		ReleaseUpperBounds:           append([]string(nil), input.ReleaseUpperBounds...),
		SingleDrawMarginal95Abs:      single95,
		ConvolutionMarginal95Abs:     convolution95,
		ConvolutionSimultaneous95Abs: convolutionSimultaneous95,
		AccuracyAccounting:           "two_draw_union_bound; each component uses half the failure probability",
		NominalVarianceMultiplier:    2,
		NominalRMSEMultiplier:        math.Sqrt2,
		ThreatModel:                  "pinned_semi_honest_noncolluding; malicious_noise_contribution_not_covered",
		ConvolutionPrivacyArgument:   "under pinned semi-honest non-colluding execution, one hidden complete-capsule mechanism remains (epsilon,delta_total)-DP after independent additive post-processing; delta_total explicitly includes sampler approximation/support loss and never exceeds capsule_delta",
		OpeningContract:              "inside one joint finalizer: sum exactly two purpose-bound raw-noised shares, signed-decode, apply exactly one source-bound fixed saturation, and reveal only that result",
		UtilityPreferredBackend:      "exact_gc_one_joint_noise_sample",
	}, nil
}

// jointDPConvolutionReferenceFinalize is test/reference code for the required
// joint finalizer. A production route must implement the same operation
// inside MPC; it must never deliver the signed pre-clipping value.
func jointDPConvolutionReferenceFinalize(
	ringBits int, left, right, clipLower, clipUpper []string,
) ([]int64, error) {
	if ringBits < jointDPConvolutionMinimumMaskEntropy ||
		ringBits > exactGCMaxRingBits || len(left) == 0 || len(left) != len(right) ||
		len(clipLower) != len(left) || len(clipUpper) != len(left) {
		return nil, fmt.Errorf("invalid joint-DP convolution finalizer shape")
	}
	modulus := exactGCModulus(ringBits)
	sign := new(big.Int).Rsh(new(big.Int).Set(modulus), 1)
	result := make([]int64, len(left))
	for i := range left {
		a, err := jointDPConvolutionParseUnsigned(left[i], "left share")
		if err != nil || a.Cmp(modulus) >= 0 {
			return nil, fmt.Errorf("left share %d is outside Ring%d", i, ringBits)
		}
		b, err := jointDPConvolutionParseUnsigned(right[i], "right share")
		if err != nil || b.Cmp(modulus) >= 0 {
			return nil, fmt.Errorf("right share %d is outside Ring%d", i, ringBits)
		}
		opened := new(big.Int).Add(a, b)
		opened.Mod(opened, modulus)
		if opened.Cmp(sign) >= 0 {
			opened.Sub(opened, modulus)
		}
		lower, err := jointDPConvolutionParseSigned(clipLower[i], "clip lower")
		if err != nil || lower.Cmp(big.NewInt(dpNoiseOutputMin)) < 0 {
			return nil, fmt.Errorf("clip lower %d is invalid", i)
		}
		upper, err := jointDPConvolutionParseSigned(clipUpper[i], "clip upper")
		if err != nil || upper.Cmp(big.NewInt(dpNoiseOutputMax)) > 0 ||
			lower.Cmp(upper) > 0 {
			return nil, fmt.Errorf("clip upper %d is invalid", i)
		}
		if opened.Cmp(lower) < 0 {
			result[i] = lower.Int64()
		} else if opened.Cmp(upper) > 0 {
			result[i] = upper.Int64()
		} else {
			result[i] = opened.Int64()
		}
	}
	return result, nil
}

func handleJointDPConvolutionShare() {
	input, err := decodeJointDPConvolutionShareInput(os.Stdin)
	if err != nil {
		mpcFatalError(err.Error())
	}
	result, err := jointDPConvolutionShare(input)
	if err != nil {
		mpcFatalError(err.Error())
	}
	mpcWriteOutput(result)
}

func handleJointDPUniformSplit() {
	input, err := decodeJointDPUniformSplitInput(os.Stdin)
	if err != nil {
		mpcFatalError(err.Error())
	}
	result, err := jointDPUniformSplit(input, crand.Reader)
	if err != nil {
		mpcFatalError(err.Error())
	}
	mpcWriteOutput(result)
}
