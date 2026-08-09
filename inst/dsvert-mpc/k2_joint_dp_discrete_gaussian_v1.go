package main

// Sticky, local, finite-work discrete-Gaussian noise for the productive
// two-peer biomedical-vector path.
//
// The exact rational sampler is a Go adaptation of Algorithm 3 in Canonne,
// Kamath, and Steinke, "The Discrete Gaussian for Differential Privacy"
// (NeurIPS 2020, arXiv:2004.00010) and the Apache-2.0 reference code at
// https://github.com/IBM/discrete-gaussian-differential-privacy.
//
// The ideal, independent-coordinate discrete Gaussian is calibrated with
// Theorem 14 (multivariate zCDP) and the standard zCDP-to-(epsilon,delta)
// conversion stated as Equation 16 in that paper.  The finite Ring128 route
// cannot represent an infinite-support law, and an exact CKS rejection sampler
// has no finite work bound.  Version 2 therefore truncates the ideal law to a
// public symmetric support and samples a dyadic CDF enclosed by exact rational
// intervals.  Corollary 17 supplies the tail bound; the table approximation
// has a separate exact TV certificate; both transfers are charged explicitly
// to delta.  The mechanism is never labelled an exact or unqualified discrete
// Gaussian.

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

const (
	jointDPGaussianPlanVersion            = "dsvert-joint-dp-vector-dyadic-discrete-gaussian-tv-bounded-plan-v2"
	jointDPGaussianInputVersion           = "dsvert-joint-dp-vector-dyadic-discrete-gaussian-tv-bounded-input-v2"
	jointDPGaussianOutputVersion          = "dsvert-joint-dp-vector-dyadic-discrete-gaussian-tv-bounded-share-v2"
	jointDPGaussianFinalizerInputVersion  = "dsvert-joint-dp-vector-dyadic-discrete-gaussian-tv-bounded-finalizer-input-v2"
	jointDPGaussianFinalizerOutputVersion = "dsvert-joint-dp-vector-dyadic-discrete-gaussian-tv-bounded-finalizer-v2"
	jointDPGaussianMechanism              = "dyadic_discrete_gaussian_truncated_tv_bounded"
	jointDPGaussianSampler                = "cks-target-outward-rational-dyadic-cdf-hkdf-sha256-chacha20-coordinate-domain-v2"
	jointDPGaussianBackend                = "independent_full_global_dyadic_discrete_gaussian_tv_bounded_ring128_v2"
	jointDPGaussianReference              = "Canonne-Kamath-Steinke-2020-Theorem14-Corollary17 ideal target; outward rational dyadic-CDF finite sampler v2"
	jointDPGaussianCommitmentPurpose      = "dyadic-discrete-gaussian-tv-bounded-v2"
	jointDPGaussianRequestBindingDomain   = "dsVert/joint-dp-vector/dyadic-discrete-gaussian-plan-request-binding/v2"
	jointDPGaussianMaxChunk               = 8192
	jointDPGaussianRhoBits                = 128
	jointDPGaussianMaxLogBound            = 10000
	jointDPGaussianMaxInputBytes          = 8 << 20
	// Preserve the complete legacy ChaCha20 coordinate stream: 2^32 blocks of
	// 64 bytes. Only after the old implementation would have exhausted its
	// uint32 block counter do we continue with an unbounded, domain-separated
	// big.Int segment index. This keeps sticky releases byte-identical over the
	// entire previously valid random tape rather than merely over its prefix.
	jointDPGaussianStreamSegmentBytes uint64 = 1 << 38
)

type jointDPGaussianPlanInput struct {
	Epsilon              string `json:"epsilon"`
	Delta                string `json:"delta"`
	L2SensitivitySteps   string `json:"l2_sensitivity_steps"`
	TotalCoordinateCount int    `json:"total_coordinate_count"`
}

type jointDPGaussianPlanOutput struct {
	Version                         string `json:"version"`
	Mechanism                       string `json:"mechanism"`
	Sampler                         string `json:"sampler"`
	Reference                       string `json:"reference"`
	TotalCoordinateCount            int    `json:"total_coordinate_count"`
	MaximumChunkCoordinates         int    `json:"maximum_chunk_coordinates"`
	RequestBindingSHA256            string `json:"request_binding_sha256"`
	EpsilonNumerator                string `json:"epsilon_numerator"`
	EpsilonDenominator              string `json:"epsilon_denominator"`
	AllocatedDeltaNumerator         string `json:"allocated_delta_numerator"`
	AllocatedDeltaDenominator       string `json:"allocated_delta_denominator"`
	CoreDeltaNumerator              string `json:"core_delta_numerator"`
	CoreDeltaDenominator            string `json:"core_delta_denominator"`
	TailDeltaNumerator              string `json:"tail_delta_numerator"`
	TailDeltaDenominator            string `json:"tail_delta_denominator"`
	L2SensitivityNumerator          string `json:"l2_sensitivity_numerator"`
	L2SensitivityDenominator        string `json:"l2_sensitivity_denominator"`
	RhoNumerator                    string `json:"rho_numerator"`
	RhoDenominator                  string `json:"rho_denominator"`
	ZCDPLogUpperInteger             string `json:"zcdp_log_upper_integer"`
	ZCDPConversionExponentNumerator string `json:"zcdp_conversion_exponent_numerator"`
	ZCDPConversionExponentDenom     string `json:"zcdp_conversion_exponent_denominator"`
	SigmaSquaredNumerator           string `json:"sigma_squared_numerator"`
	SigmaSquaredDenominator         string `json:"sigma_squared_denominator"`
	ProposalScale                   string `json:"proposal_scale"`
	MaximumNoiseMagnitudePerPeer    string `json:"maximum_noise_magnitude_per_peer"`
	MaximumNoiseMagnitudeTwoPeers   string `json:"maximum_noise_magnitude_two_peers"`
	TailProofExponentNumerator      string `json:"tail_proof_exponent_numerator"`
	TailProofExponentDenominator    string `json:"tail_proof_exponent_denominator"`
	TailProofTargetNumerator        string `json:"tail_proof_target_numerator"`
	TailProofTargetDenominator      string `json:"tail_proof_target_denominator"`
	VectorTailTVUpperNumerator      string `json:"vector_tail_tv_upper_numerator"`
	VectorTailTVUpperDenominator    string `json:"vector_tail_tv_upper_denominator"`
	PerPeerImplementationDeltaNum   string `json:"per_peer_implementation_delta_numerator"`
	PerPeerImplementationDeltaDenom string `json:"per_peer_implementation_delta_denominator"`
	VectorSamplerTVUpperNumerator   string `json:"vector_sampler_tv_upper_numerator"`
	VectorSamplerTVUpperDenominator string `json:"vector_sampler_tv_upper_denominator"`
	VectorTotalTVUpperNumerator     string `json:"vector_total_tv_upper_numerator"`
	VectorTotalTVUpperDenominator   string `json:"vector_total_tv_upper_denominator"`
	SamplerCandidateCount           int    `json:"sampler_candidate_count"`
	SamplerRandomBitsPerCoordinate  int    `json:"sampler_random_bits_per_coordinate"`
	SamplerRandomBytesPerCoordinate int    `json:"sampler_random_bytes_per_coordinate"`
	SamplerTablePrecisionBits       int    `json:"sampler_table_precision_bits"`
	SamplerMagnitudeCount           int    `json:"sampler_magnitude_count"`
	SamplerSearchSteps              int    `json:"sampler_search_steps"`
	SamplerFullScanSteps            int    `json:"sampler_full_scan_steps"`
	SamplerCDFTableBytes            int    `json:"sampler_cdf_table_bytes"`
	Simultaneous95Abs               string `json:"simultaneous_95_abs"`
	AccuracyAccounting              string `json:"accuracy_accounting"`
	Accounting                      string `json:"accounting"`
	PrivacyTheorem                  string `json:"privacy_theorem"`
	IndependentNoisePeerCount       int    `json:"independent_noise_peer_count"`
	CompleteEpsilonPerPeer          bool   `json:"complete_epsilon_per_peer"`
	EpsilonDividedByPeerCount       bool   `json:"epsilon_divided_by_peer_count"`
	ReleaseDeltaAggregation         string `json:"release_delta_aggregation"`
	NominalVarianceMultiplier       int    `json:"nominal_variance_multiplier"`
	NominalStandardDeviationFactor  string `json:"nominal_standard_deviation_factor"`
	AtLeastOneHonestNoisePeer       bool   `json:"at_least_one_honest_noise_peer"`
	MaximumColludingNoisePeers      int    `json:"maximum_colluding_noise_peers"`
	AdversaryView                   string `json:"adversary_view"`
	AdversaryViewPrivacyArgument    string `json:"adversary_view_privacy_argument"`
	SourceShareHidingPrecondition   string `json:"source_share_hiding_precondition"`
	ExactRationalSampler            bool   `json:"exact_rational_sampler"`
	FiniteSupportTransferCharged    bool   `json:"finite_support_transfer_charged"`
	FixedWorkSampler                bool   `json:"fixed_work_sampler"`
	// This wire field means source-query values only. False is not a
	// constant-time certificate: the productive sampler has fixed loop counts
	// but its comparisons still branch on hidden random draws. State host and
	// transcript-timing guarantees separately.
	SamplerBranchesOnProtectedValues   bool `json:"sampler_branches_on_protected_values"`
	SamplerBranchesOnPrivateRandomness bool `json:"sampler_branches_on_private_randomness"`
	HostConstantTimeClaim              bool `json:"host_constant_time_claim"`
	// TranscriptDPClaim is restricted to the logical worker transcript:
	// public work count, rounds, payload count and payload lengths. It excludes
	// wall-clock completion, scheduling, polling and retransmission cadence.
	TranscriptDPClaim           bool   `json:"transcript_dp_claim"`
	LogicalTranscriptFixedShape bool   `json:"logical_transcript_fixed_shape"`
	PhysicalTimingDPClaim       bool   `json:"physical_timing_dp_claim"`
	ObservableWorkerShape       string `json:"observable_worker_shape"`
	CapabilityAvailable         bool   `json:"capability_available"`
	UnavailableReason           string `json:"unavailable_reason"`
}

func jointDPGaussianRatFields(value *big.Rat) (string, string) {
	return value.Num().String(), value.Denom().String()
}

// jointDPGaussianRequestBinding binds the complete planner request to the
// exact rational values actually used by the calibrator.  Length-prefixed
// fields make the encoding unambiguous without depending on a JSON encoder.
func jointDPGaussianRequestBinding(
	input jointDPGaussianPlanInput,
	epsilonNumerator, epsilonDenominator,
	deltaNumerator, deltaDenominator,
	sensitivityNumerator, sensitivityDenominator string,
) string {
	fields := [][2]string{
		{"epsilon", input.Epsilon},
		{"delta", input.Delta},
		{"l2_sensitivity_steps", input.L2SensitivitySteps},
		{"total_coordinate_count", strconv.Itoa(input.TotalCoordinateCount)},
		{"epsilon_numerator", epsilonNumerator},
		{"epsilon_denominator", epsilonDenominator},
		{"allocated_delta_numerator", deltaNumerator},
		{"allocated_delta_denominator", deltaDenominator},
		{"l2_sensitivity_numerator", sensitivityNumerator},
		{"l2_sensitivity_denominator", sensitivityDenominator},
	}
	var message bytes.Buffer
	message.WriteString(jointDPGaussianRequestBindingDomain)
	message.WriteByte('\n')
	for _, field := range fields {
		message.WriteString(field[0])
		message.WriteByte('=')
		message.WriteString(strconv.Itoa(len([]byte(field[1]))))
		message.WriteByte(':')
		message.WriteString(field[1])
		message.WriteByte('\n')
	}
	digest := sha256.Sum256(message.Bytes())
	return hex.EncodeToString(digest[:])
}

func jointDPGaussianLogUpper(delta *big.Rat) (*big.Int, error) {
	if delta == nil || delta.Sign() <= 0 || delta.Cmp(big.NewRat(1, 1)) >= 0 {
		return nil, fmt.Errorf("invalid core delta")
	}
	// k=ceil(log2(1/delta)) follows from one exact integer comparison.
	// Since ln(2)<7/10, ceil(7*k/10) is a certified upper bound on
	// ln(1/delta).  This avoids Taylor work proportional to a hostile public
	// decimal exponent.
	numerator := delta.Num()
	denominator := delta.Denom()
	k := denominator.BitLen() - numerator.BitLen()
	if k < 0 {
		k = 0
	}
	if new(big.Int).Lsh(new(big.Int).Set(numerator), uint(k)).Cmp(denominator) < 0 {
		k++
	}
	logUpper := (7*k + 9) / 10
	if logUpper < 1 || logUpper > jointDPGaussianMaxLogBound {
		return nil, fmt.Errorf("delta is outside the exact calibration range")
	}
	return big.NewInt(int64(logUpper)), nil
}

// A cheap exact transfer-factor bound.  Since e < 2^(3/2),
// exp(epsilon) <= 2^ceil(3*epsilon/2).  The explicit exponent ceiling keeps
// policy parsing from allocating an attacker-selected enormous big.Int.
func jointDPGaussianExpUpper(epsilon *big.Rat) (*big.Rat, error) {
	if epsilon == nil || epsilon.Sign() < 0 {
		return nil, fmt.Errorf("invalid Gaussian epsilon")
	}
	exponent := jointDPVectorCeilRat(new(big.Rat).Mul(
		new(big.Rat).Set(epsilon), big.NewRat(3, 2)))
	if !exponent.IsInt64() || exponent.Int64() > 16384 {
		return nil, fmt.Errorf("epsilon is outside the Gaussian transfer range")
	}
	return new(big.Rat).SetInt(new(big.Int).Lsh(
		big.NewInt(1), uint(exponent.Int64()))), nil
}

// Choose the largest 128-bit dyadic rho satisfying the standard conversion
// exponent (epsilon-rho)^2/(4*rho) >= L and rho <= epsilon.  Every predicate
// is exact rational arithmetic; the downward dyadic rounding is conservative.
func jointDPGaussianRho(epsilon *big.Rat, logUpper *big.Int) (*big.Rat, error) {
	if epsilon == nil || epsilon.Sign() <= 0 || logUpper == nil ||
		logUpper.Sign() <= 0 {
		return nil, fmt.Errorf("invalid zCDP calibration request")
	}
	denominator := new(big.Int).Lsh(big.NewInt(1), jointDPGaussianRhoBits)
	maximum := jointDPVectorFloorRat(new(big.Rat).Mul(
		new(big.Rat).Set(epsilon), new(big.Rat).SetInt(denominator)))
	if maximum.Sign() <= 0 {
		return nil, fmt.Errorf("epsilon is below the exact rho grid")
	}
	predicate := func(numerator *big.Int) bool {
		if numerator.Sign() <= 0 {
			return true
		}
		rho := new(big.Rat).SetFrac(
			new(big.Int).Set(numerator), new(big.Int).Set(denominator))
		if rho.Cmp(epsilon) > 0 {
			return false
		}
		difference := new(big.Rat).Sub(new(big.Rat).Set(epsilon), rho)
		left := new(big.Rat).Mul(difference, difference)
		right := new(big.Rat).Mul(
			new(big.Rat).Mul(big.NewRat(4, 1), rho),
			new(big.Rat).SetInt(logUpper))
		return left.Cmp(right) >= 0
	}
	low := big.NewInt(0)
	high := new(big.Int).Set(maximum)
	one := big.NewInt(1)
	for low.Cmp(high) < 0 {
		middle := new(big.Int).Add(low, high)
		middle.Add(middle, one)
		middle.Rsh(middle, 1)
		if predicate(middle) {
			low.Set(middle)
		} else {
			high.Sub(middle, one)
		}
	}
	if low.Sign() <= 0 {
		return nil, fmt.Errorf("no positive rho satisfies the exact conversion")
	}
	return new(big.Rat).SetFrac(low, denominator), nil
}

func jointDPGaussianFloorSqrtRat(value *big.Rat) (*big.Int, error) {
	if value == nil || value.Sign() < 0 {
		return nil, fmt.Errorf("invalid rational square root")
	}
	integerPart := new(big.Int).Quo(value.Num(), value.Denom())
	return new(big.Int).Sqrt(integerPart), nil
}

func jointDPGaussianCeilSqrtRat(value *big.Rat) (*big.Int, error) {
	floor, err := jointDPGaussianFloorSqrtRat(value)
	if err != nil {
		return nil, err
	}
	if new(big.Rat).SetInt(new(big.Int).Mul(floor, floor)).Cmp(value) < 0 {
		floor.Add(floor, big.NewInt(1))
	}
	return floor, nil
}

func jointDPGaussianCeilLog2(value *big.Rat) (*big.Int, error) {
	if value == nil || value.Cmp(big.NewRat(1, 1)) <= 0 {
		return nil, fmt.Errorf("invalid exact logarithm target")
	}
	numerator := value.Num()
	denominator := value.Denom()
	k := numerator.BitLen() - denominator.BitLen()
	if k < 0 {
		k = 0
	}
	if new(big.Int).Lsh(new(big.Int).Set(denominator), uint(k)).Cmp(numerator) < 0 {
		k++
	}
	if k < 1 || k > 10*jointDPGaussianMaxLogBound/7 {
		return nil, fmt.Errorf("exact logarithm target is outside the certified range")
	}
	return big.NewInt(int64(k)), nil
}

func jointDPGaussianMinimumRadius(
	sigmaSquared, target *big.Rat, exponentDenominator int64,
	maximum *big.Int,
) (*big.Int, *big.Rat, error) {
	if sigmaSquared == nil || sigmaSquared.Sign() <= 0 || target == nil ||
		target.Cmp(big.NewRat(1, 1)) <= 0 || exponentDenominator <= 0 ||
		maximum == nil || maximum.Sign() <= 0 {
		return nil, nil, fmt.Errorf("invalid exact radius request")
	}
	// If k=ceil(log2(target)), then target<=2^k and
	// exp(7k/10)>2^k because ln(2)<7/10.  Thus it suffices to require
	// radius^2/(c*sigma^2) >= 7k/10.  The exact rational ceiling-square-root
	// is O(log limbs) and replaces a Taylor/binary-search loop.
	k, err := jointDPGaussianCeilLog2(target)
	if err != nil {
		return nil, nil, err
	}
	threshold := new(big.Rat).Mul(
		new(big.Rat).SetInt64(exponentDenominator), sigmaSquared)
	threshold.Mul(threshold, new(big.Rat).SetFrac(
		new(big.Int).Mul(big.NewInt(7), k), big.NewInt(10)))
	radius, err := jointDPGaussianCeilSqrtRat(threshold)
	if err != nil {
		return nil, nil, err
	}
	if radius.Cmp(maximum) > 0 {
		return nil, nil, fmt.Errorf("Ring128 cannot certify the required finite support")
	}
	exponent := new(big.Rat).Quo(
		new(big.Rat).SetInt(new(big.Int).Mul(radius, radius)),
		new(big.Rat).Mul(
			new(big.Rat).SetInt64(exponentDenominator), sigmaSquared))
	return radius, exponent, nil
}

func jointDPPlanVectorGaussian(
	input jointDPGaussianPlanInput,
) (jointDPGaussianPlanOutput, error) {
	var zero jointDPGaussianPlanOutput
	epsilon, err := jointDPParseDecimalRat(input.Epsilon, "epsilon", false)
	if err != nil {
		return zero, err
	}
	expUpper, err := jointDPGaussianExpUpper(epsilon)
	if err != nil {
		return zero, err
	}
	delta, err := jointDPParseDecimalRat(input.Delta, "delta", false)
	if err != nil || (err == nil && delta.Cmp(big.NewRat(1, 1)) >= 0) {
		return zero, fmt.Errorf("delta must be in (0,1)")
	}
	sensitivity, err := jointDPParseDecimalRat(
		input.L2SensitivitySteps, "l2_sensitivity_steps", false)
	if err != nil {
		return zero, err
	}
	if input.TotalCoordinateCount < 1 ||
		input.TotalCoordinateCount > jointDPVectorMaxTotal {
		return zero, fmt.Errorf("total_coordinate_count must be in [1,%d]",
			jointDPVectorMaxTotal)
	}
	coreDelta := new(big.Rat).Quo(new(big.Rat).Set(delta), big.NewRat(2, 1))
	tailDelta := new(big.Rat).Sub(new(big.Rat).Set(delta), coreDelta)
	logUpper, err := jointDPGaussianLogUpper(coreDelta)
	if err != nil {
		return zero, err
	}
	rho, err := jointDPGaussianRho(epsilon, logUpper)
	if err != nil {
		return zero, err
	}
	difference := new(big.Rat).Sub(new(big.Rat).Set(epsilon), rho)
	conversionExponent := new(big.Rat).Quo(
		new(big.Rat).Mul(difference, difference),
		new(big.Rat).Mul(big.NewRat(4, 1), rho))
	if conversionExponent.Cmp(new(big.Rat).SetInt(logUpper)) < 0 ||
		rho.Cmp(epsilon) > 0 {
		return zero, fmt.Errorf("internal zCDP calibration certificate failed")
	}
	sigmaSquared := new(big.Rat).Quo(
		new(big.Rat).Mul(sensitivity, sensitivity),
		new(big.Rat).Mul(big.NewRat(2, 1), rho))
	if sigmaSquared.Sign() <= 0 {
		return zero, fmt.Errorf("invalid exact Gaussian variance")
	}
	floorSigma, err := jointDPGaussianFloorSqrtRat(sigmaSquared)
	if err != nil {
		return zero, err
	}
	proposalScale := new(big.Int).Add(floorSigma, big.NewInt(1))
	transferFactor := new(big.Rat).Add(big.NewRat(1, 1), expUpper)
	// Half of the transfer allocation pays for truncating the ideal CKS law;
	// the other half pays for the finite dyadic CDF.  Both bounds are vector
	// bounds (already unioned across coordinates) and are transferred through
	// (1+exp(epsilon)) exactly once.
	vectorTV := new(big.Rat).Quo(
		new(big.Rat).Set(tailDelta),
		new(big.Rat).Mul(big.NewRat(2, 1), transferFactor))
	vectorSamplerTV := new(big.Rat).Set(vectorTV)
	vectorTotalTV := new(big.Rat).Add(
		new(big.Rat).Set(vectorTV), vectorSamplerTV)
	// Corollary 17 and a union bound require
	// exp(lambda^2/(2*sigma^2)) >= 2*d/vectorTV.
	tailTarget := new(big.Rat).Quo(
		new(big.Rat).SetInt64(int64(2*input.TotalCoordinateCount)), vectorTV)
	maxPerPeer := new(big.Int).Sub(
		new(big.Int).Lsh(big.NewInt(1), 126), big.NewInt(1))
	lambda, tailExponent, err := jointDPGaussianMinimumRadius(
		sigmaSquared, tailTarget, 2, maxPerPeer)
	if err != nil {
		return zero, err
	}
	maximumNoise := new(big.Int).Sub(lambda, big.NewInt(1))
	if maximumNoise.Sign() < 0 {
		maximumNoise.SetInt64(0)
	}
	twoNoise := new(big.Int).Lsh(new(big.Int).Set(maximumNoise), 1)
	// For two independent complete draws, Corollary 17's MGF proof gives
	// P(|X1+X2|>=r)<=2*exp(-r^2/(4*sigma^2)).  Union bound over d and
	// alpha=.05 yields target 40*d. The implemented law is supported on
	// [-M,M], so 2*M is an absolute fallback bound.
	// The implemented two-draw law is within 2*vectorTotalTV of the ideal
	// two-draw law.  Reserve that transfer inside alpha=.05 so the reported
	// simultaneous radius remains a genuine 95% statement.
	accuracyAlpha := new(big.Rat).Sub(
		big.NewRat(1, 20),
		new(big.Rat).Mul(big.NewRat(2, 1), vectorTotalTV))
	if accuracyAlpha.Sign() <= 0 {
		return zero, fmt.Errorf("Gaussian implementation TV exhausts accuracy alpha")
	}
	accuracyTarget := new(big.Rat).Quo(
		new(big.Rat).SetInt64(int64(2*input.TotalCoordinateCount)),
		accuracyAlpha)
	accuracy, _, err := jointDPGaussianMinimumRadius(
		sigmaSquared, accuracyTarget, 4,
		new(big.Int).Add(twoNoise, big.NewInt(1)))
	if err != nil || accuracy.Cmp(twoNoise) > 0 {
		accuracy = new(big.Int).Set(twoNoise)
	}
	implementationDelta := new(big.Rat).Mul(
		new(big.Rat).Set(transferFactor), vectorTotalTV)
	if new(big.Rat).Add(new(big.Rat).Set(coreDelta),
		implementationDelta).Cmp(delta) > 0 {
		return zero, fmt.Errorf("internal delta split certificate failed")
	}
	eNum, eDen := jointDPGaussianRatFields(epsilon)
	dNum, dDen := jointDPGaussianRatFields(delta)
	cNum, cDen := jointDPGaussianRatFields(coreDelta)
	tNum, tDen := jointDPGaussianRatFields(tailDelta)
	sNum, sDen := jointDPGaussianRatFields(sensitivity)
	rNum, rDen := jointDPGaussianRatFields(rho)
	zNum, zDen := jointDPGaussianRatFields(conversionExponent)
	vNum, vDen := jointDPGaussianRatFields(sigmaSquared)
	xNum, xDen := jointDPGaussianRatFields(tailExponent)
	targetNum, targetDen := jointDPGaussianRatFields(tailTarget)
	tvNum, tvDen := jointDPGaussianRatFields(vectorTV)
	samplerTVNum, samplerTVDen := jointDPGaussianRatFields(vectorSamplerTV)
	totalTVNum, totalTVDen := jointDPGaussianRatFields(vectorTotalTV)
	iNum, iDen := jointDPGaussianRatFields(implementationDelta)
	fixedShape, err := jointDPGaussianPlanFixedShape(
		maximumNoise, input.TotalCoordinateCount, vectorSamplerTV)
	if err != nil {
		return zero, err
	}
	requestBinding := jointDPGaussianRequestBinding(
		input, eNum, eDen, dNum, dDen, sNum, sDen)
	maximumChunk := jointDPGaussianMaxChunk
	if maximumChunk > input.TotalCoordinateCount {
		maximumChunk = input.TotalCoordinateCount
	}
	return jointDPGaussianPlanOutput{
		Version: jointDPGaussianPlanVersion, Mechanism: jointDPGaussianMechanism,
		Sampler: jointDPGaussianSampler, Reference: jointDPGaussianReference,
		TotalCoordinateCount:    input.TotalCoordinateCount,
		MaximumChunkCoordinates: maximumChunk,
		RequestBindingSHA256:    requestBinding,
		EpsilonNumerator:        eNum, EpsilonDenominator: eDen,
		AllocatedDeltaNumerator: dNum, AllocatedDeltaDenominator: dDen,
		CoreDeltaNumerator: cNum, CoreDeltaDenominator: cDen,
		TailDeltaNumerator: tNum, TailDeltaDenominator: tDen,
		L2SensitivityNumerator: sNum, L2SensitivityDenominator: sDen,
		RhoNumerator: rNum, RhoDenominator: rDen,
		ZCDPLogUpperInteger:             logUpper.String(),
		ZCDPConversionExponentNumerator: zNum,
		ZCDPConversionExponentDenom:     zDen,
		SigmaSquaredNumerator:           vNum, SigmaSquaredDenominator: vDen,
		ProposalScale:                   proposalScale.String(),
		MaximumNoiseMagnitudePerPeer:    maximumNoise.String(),
		MaximumNoiseMagnitudeTwoPeers:   twoNoise.String(),
		TailProofExponentNumerator:      xNum,
		TailProofExponentDenominator:    xDen,
		TailProofTargetNumerator:        targetNum,
		TailProofTargetDenominator:      targetDen,
		VectorTailTVUpperNumerator:      tvNum,
		VectorTailTVUpperDenominator:    tvDen,
		VectorSamplerTVUpperNumerator:   samplerTVNum,
		VectorSamplerTVUpperDenominator: samplerTVDen,
		VectorTotalTVUpperNumerator:     totalTVNum,
		VectorTotalTVUpperDenominator:   totalTVDen,
		PerPeerImplementationDeltaNum:   iNum,
		PerPeerImplementationDeltaDenom: iDen,
		SamplerCandidateCount:           1,
		SamplerRandomBitsPerCoordinate:  fixedShape.RandomBits,
		SamplerRandomBytesPerCoordinate: fixedShape.RandomBytes,
		SamplerTablePrecisionBits:       fixedShape.PrecisionBits,
		SamplerMagnitudeCount:           fixedShape.MagnitudeCount,
		SamplerSearchSteps:              fixedShape.SearchSteps,
		SamplerFullScanSteps:            fixedShape.FullScanSteps,
		SamplerCDFTableBytes:            fixedShape.MagnitudeCount * fixedShape.RandomBytes,
		Simultaneous95Abs:               accuracy.String(),
		AccuracyAccounting:              "two-independent-draw ideal subgaussian MGF; simultaneous union bound at alpha=0.05-2*implemented_vector_TV; ideal-to-implemented two-draw TV transfer; absolute 2M support fallback",
		Accounting:                      "delta=delta_core+delta_implementation; ideal vector mechanism is rho-zCDP by CKS Theorem 14; Equation 16 is certified by (epsilon-rho)^2/(4rho)>=ceil(7*ceil(log2(1/delta_core))/10); Corollary 17 plus a coordinate union bound bounds ideal tail truncation; outward rational exp intervals and dyadic CDF rounding bound finite-sampler TV; vector_total_TV=tail_truncation_TV+dyadic_sampler_TV; (1+exp(epsilon))*vector_total_TV<=delta_implementation",
		PrivacyTheorem:                  "CKS2020 Theorem 14 + Equation 16 + Corollary 17; integer-valued vector query, independent coordinates, public global L2 sensitivity, rational sigma_squared",
		IndependentNoisePeerCount:       2, CompleteEpsilonPerPeer: true,
		EpsilonDividedByPeerCount:      false,
		ReleaseDeltaAggregation:        "max_per_peer_not_sum",
		NominalVarianceMultiplier:      2,
		NominalStandardDeviationFactor: "sqrt(2)_relative_to_one_full_draw",
		AtLeastOneHonestNoisePeer:      true,
		MaximumColludingNoisePeers:     1,
		AdversaryView:                  "analyst_plus_at_most_one_designated_noise_peer_including_its_seed_draw_source_share_and_protocol_transcript",
		AdversaryViewPrivacyArgument:   "conditioned_on_a_simulatable_own_share_and_fixed_corrupt_peer_view_the_other_independent_complete_epsilon_full_sensitivity_draw_is_an_epsilon_delta_DP_mechanism; own_draw_translation_second_draw_signed_decode_and_public_clamp_are_post_processing; release_delta_is_max_of_the_two_symmetric_conditional_guarantees",
		SourceShareHidingPrecondition:  "each_single_pre_noise_aggregate_share_is_computationally_simulatable_without_the_protected_query_under_authenticated_semi_honest_fanin",
		ExactRationalSampler:           false, FiniteSupportTransferCharged: true,
		FixedWorkSampler:                   true,
		SamplerBranchesOnProtectedValues:   false,
		SamplerBranchesOnPrivateRandomness: false,
		HostConstantTimeClaim:              false,
		TranscriptDPClaim:                  true,
		LogicalTranscriptFixedShape:        true,
		PhysicalTimingDPClaim:              false,
		ObservableWorkerShape:              "one fixed-width dyadic word plus one sign byte and one complete sequential fixed-width CDF scan per coordinate; branchless borrow/mask first-hit selection; no secret-indexed reads; fixed JSON/base64 payload rounds and lengths for public chunk geometry; host completion time and retransmission timing excluded",
		CapabilityAvailable:                true, UnavailableReason: "",
	}, nil
}

func handleJointDPVectorGaussianPlan() {
	var input jointDPGaussianPlanInput
	mpcReadInput(&input)
	plan, err := jointDPPlanVectorGaussian(input)
	if err != nil {
		outputError("joint-DP fixed-work discrete-Gaussian plan unavailable: " + err.Error())
		return
	}
	mpcWriteOutput(plan)
}

// exactDGaussianSampler is retained as an internal CKS/IBM cross-oracle for
// distributional tests.  It is not called by the productive v2 worker because
// its private-randomness rejection loops have no finite work bound.
type exactDGaussianSampler struct {
	random io.Reader
}

func (sampler exactDGaussianSampler) uniform(modulus *big.Int) (*big.Int, error) {
	if sampler.random == nil || modulus == nil || modulus.Sign() <= 0 {
		return nil, fmt.Errorf("invalid exact uniform request")
	}
	byteCount := (modulus.BitLen() + 7) / 8
	buffer := make([]byte, byteCount)
	defer clear(buffer)
	for {
		if _, err := io.ReadFull(sampler.random, buffer); err != nil {
			return nil, fmt.Errorf("exact sampler random stream: %w", err)
		}
		excess := byteCount*8 - modulus.BitLen()
		if excess > 0 {
			buffer[0] &= byte(0xff >> excess)
		}
		candidate := new(big.Int).SetBytes(buffer)
		if candidate.Cmp(modulus) < 0 {
			return candidate, nil
		}
		candidate.SetInt64(0)
	}
}

func (sampler exactDGaussianSampler) bernoulli(probability *big.Rat) (bool, error) {
	if probability == nil || probability.Sign() < 0 ||
		probability.Cmp(big.NewRat(1, 1)) > 0 {
		return false, fmt.Errorf("invalid exact Bernoulli probability")
	}
	draw, err := sampler.uniform(probability.Denom())
	if err != nil {
		return false, err
	}
	return draw.Cmp(probability.Num()) < 0, nil
}

func (sampler exactDGaussianSampler) bernoulliExpUnit(x *big.Rat) (bool, error) {
	if x == nil || x.Sign() < 0 || x.Cmp(big.NewRat(1, 1)) > 0 {
		return false, fmt.Errorf("invalid unit exponential Bernoulli parameter")
	}
	k := big.NewInt(1)
	one := big.NewInt(1)
	defer k.SetInt64(0)
	for {
		probability := new(big.Rat).Quo(
			new(big.Rat).Set(x), new(big.Rat).SetInt(k))
		success, err := sampler.bernoulli(probability)
		if err != nil {
			return false, err
		}
		if !success {
			return k.Bit(0) == 1, nil
		}
		k.Add(k, one)
	}
}

func (sampler exactDGaussianSampler) bernoulliExp(x *big.Rat) (bool, error) {
	if x == nil || x.Sign() < 0 {
		return false, fmt.Errorf("invalid exponential Bernoulli parameter")
	}
	remainder := new(big.Rat).Set(x)
	one := big.NewRat(1, 1)
	for remainder.Cmp(one) > 0 {
		success, err := sampler.bernoulliExpUnit(one)
		if err != nil || !success {
			return false, err
		}
		remainder.Sub(remainder, one)
	}
	return sampler.bernoulliExpUnit(remainder)
}

func (sampler exactDGaussianSampler) geometricExpSlow(x *big.Rat) (*big.Int, error) {
	result := new(big.Int)
	for {
		success, err := sampler.bernoulliExp(x)
		if err != nil {
			return nil, err
		}
		if !success {
			return result, nil
		}
		result.Add(result, big.NewInt(1))
	}
}

func (sampler exactDGaussianSampler) geometricExpFast(x *big.Rat) (*big.Int, error) {
	if x == nil || x.Sign() < 0 {
		return nil, fmt.Errorf("invalid geometric exponential parameter")
	}
	if x.Sign() == 0 {
		return new(big.Int), nil
	}
	t := new(big.Int).Set(x.Denom())
	var u *big.Int
	for {
		var err error
		u, err = sampler.uniform(t)
		if err != nil {
			return nil, err
		}
		accepted, err := sampler.bernoulliExp(
			new(big.Rat).SetFrac(new(big.Int).Set(u), new(big.Int).Set(t)))
		if err != nil {
			return nil, err
		}
		if accepted {
			break
		}
		u.SetInt64(0)
	}
	v, err := sampler.geometricExpSlow(big.NewRat(1, 1))
	if err != nil {
		return nil, err
	}
	value := new(big.Int).Add(new(big.Int).Mul(v, t), u)
	value.Quo(value, x.Num())
	v.SetInt64(0)
	u.SetInt64(0)
	return value, nil
}

func (sampler exactDGaussianSampler) discreteLaplace(scale *big.Int) (*big.Int, error) {
	if scale == nil || scale.Sign() <= 0 {
		return nil, fmt.Errorf("invalid discrete-Laplace proposal scale")
	}
	for {
		sign, err := sampler.bernoulli(big.NewRat(1, 2))
		if err != nil {
			return nil, err
		}
		magnitude, err := sampler.geometricExpFast(
			new(big.Rat).SetFrac(big.NewInt(1), new(big.Int).Set(scale)))
		if err != nil {
			return nil, err
		}
		if sign && magnitude.Sign() == 0 {
			continue
		}
		if sign {
			magnitude.Neg(magnitude)
		}
		return magnitude, nil
	}
}

func (sampler exactDGaussianSampler) discreteGaussian(
	sigmaSquared *big.Rat,
) (*big.Int, error) {
	if sigmaSquared == nil || sigmaSquared.Sign() <= 0 {
		return nil, fmt.Errorf("invalid exact discrete-Gaussian variance")
	}
	floor, err := jointDPGaussianFloorSqrtRat(sigmaSquared)
	if err != nil {
		return nil, err
	}
	scale := new(big.Int).Add(floor, big.NewInt(1))
	for {
		candidate, err := sampler.discreteLaplace(scale)
		if err != nil {
			return nil, err
		}
		absolute := new(big.Int).Abs(new(big.Int).Set(candidate))
		difference := new(big.Rat).Sub(
			new(big.Rat).SetInt(absolute),
			new(big.Rat).Quo(
				new(big.Rat).Set(sigmaSquared), new(big.Rat).SetInt(scale)))
		bias := new(big.Rat).Quo(
			new(big.Rat).Mul(difference, difference),
			new(big.Rat).Mul(big.NewRat(2, 1), sigmaSquared))
		accepted, err := sampler.bernoulliExp(bias)
		absolute.SetInt64(0)
		if err != nil {
			candidate.SetInt64(0)
			return nil, err
		}
		if accepted {
			return candidate, nil
		}
		candidate.SetInt64(0)
	}
}

type jointDPGaussianShareInput struct {
	Version              string   `json:"version"`
	RingBits             int      `json:"ring_bits"`
	FracBits             int      `json:"frac_bits"`
	TotalCoordinateCount int      `json:"total_coordinate_count"`
	ChunkStart           int      `json:"chunk_start"`
	CoordinateCount      int      `json:"coordinate_count"`
	OutputLatticeBits    int      `json:"output_lattice_bits"`
	Epsilon              string   `json:"epsilon"`
	AllocatedDelta       string   `json:"allocated_delta"`
	L2SensitivitySteps   string   `json:"l2_sensitivity_steps"`
	ScaleShifts          []int    `json:"scale_shifts"`
	RawUpperBounds       []string `json:"raw_upper_bounds"`
	ReleaseContractHash  string   `json:"release_contract_hash"`
	TranscriptHash       string   `json:"transcript_hash"`
	PeerName             string   `json:"peer_name"`
	CommitmentContext    string   `json:"commitment_context"`
	SeedCommitment       string   `json:"seed_commitment"`
	PrivateSeed          string   `json:"private_seed"`
	SourceShare          string   `json:"source_share"`
}

type jointDPGaussianShareOutput struct {
	Version                       string                    `json:"version"`
	Backend                       string                    `json:"backend"`
	Mechanism                     string                    `json:"mechanism"`
	Sampler                       string                    `json:"sampler"`
	ReleaseContractHash           string                    `json:"release_contract_hash"`
	SamplerContractHash           string                    `json:"sampler_contract_hash"`
	TranscriptHash                string                    `json:"transcript_hash"`
	PeerName                      string                    `json:"peer_name"`
	SeedCommitment                string                    `json:"seed_commitment"`
	RingBits                      int                       `json:"ring_bits"`
	FracBits                      int                       `json:"frac_bits"`
	TotalCoordinateCount          int                       `json:"total_coordinate_count"`
	ChunkStart                    int                       `json:"chunk_start"`
	CoordinateCount               int                       `json:"coordinate_count"`
	NoisedShare                   string                    `json:"noised_share"`
	MaximumNoiseMagnitudePerPeer  string                    `json:"maximum_noise_magnitude_per_peer"`
	MaximumNoiseMagnitudeTwoPeers string                    `json:"maximum_noise_magnitude_two_peers"`
	FullCapsuleParametersPerPeer  bool                      `json:"full_capsule_parameters_per_peer"`
	EpsilonDividedByPeerCount     bool                      `json:"epsilon_divided_by_peer_count"`
	SourceValuesReturned          bool                      `json:"source_values_returned"`
	NoiseValuesReturned           bool                      `json:"noise_values_returned"`
	PrivateSeedReturned           bool                      `json:"private_seed_returned"`
	PreclampValuesReturned        bool                      `json:"preclamp_values_returned"`
	NoWrapHeadroomCertified       bool                      `json:"no_wrap_headroom_certified"`
	TailProjectionApplied         bool                      `json:"tail_projection_applied"`
	TailTruncationApplied         bool                      `json:"tail_truncation_applied"`
	FixedWorkShapeVerified        bool                      `json:"fixed_work_shape_verified"`
	SourceBoundPrecondition       string                    `json:"source_bound_precondition"`
	NominalVarianceMultiplier     int                       `json:"nominal_variance_multiplier"`
	Plan                          jointDPGaussianPlanOutput `json:"plan"`
}

type jointDPGaussianSpec struct {
	input          jointDPGaussianShareInput
	plan           jointDPGaussianPlanOutput
	rawUpperBounds []*big.Int
	sigmaSquared   *big.Rat
	maxNoise       *big.Int
	transcript     [32]byte
	context        [32]byte
	commitment     [32]byte
	releaseHash    [32]byte
	contractDigest [32]byte
}

func jointDPGaussianDecode[T any](reader io.Reader) (T, error) {
	var result T
	data, err := io.ReadAll(io.LimitReader(reader, jointDPGaussianMaxInputBytes+1))
	if err != nil || len(data) == 0 || len(data) > jointDPGaussianMaxInputBytes {
		return result, fmt.Errorf("invalid joint-DP Gaussian input")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, fmt.Errorf("invalid joint-DP Gaussian input")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return result, fmt.Errorf("invalid joint-DP Gaussian input")
	}
	return result, nil
}

func jointDPGaussianContractDigest(
	input jointDPGaussianShareInput, plan jointDPGaussianPlanOutput,
) [32]byte {
	h := sha256.New()
	h.Write([]byte(jointDPGaussianOutputVersion))
	write := func(value string) {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		h.Write(size[:])
		h.Write([]byte(value))
	}
	// Chunk geometry is deliberately excluded.  The absolute coordinate is
	// appended during stream derivation, so retries and alternate public
	// chunking produce the same sticky draw.
	for _, value := range []string{
		jointDPGaussianMechanism, jointDPGaussianSampler,
		strconv.Itoa(input.RingBits), strconv.Itoa(input.FracBits),
		strconv.Itoa(input.TotalCoordinateCount),
		strconv.Itoa(input.OutputLatticeBits), input.Epsilon,
		input.AllocatedDelta, input.L2SensitivitySteps,
		input.ReleaseContractHash, input.TranscriptHash, input.PeerName,
		input.CommitmentContext, input.SeedCommitment,
		plan.RhoNumerator, plan.RhoDenominator,
		plan.SigmaSquaredNumerator, plan.SigmaSquaredDenominator,
		plan.MaximumNoiseMagnitudePerPeer,
		plan.VectorSamplerTVUpperNumerator,
		plan.VectorSamplerTVUpperDenominator,
		strconv.Itoa(plan.SamplerRandomBitsPerCoordinate),
		strconv.Itoa(plan.SamplerTablePrecisionBits),
		strconv.Itoa(plan.SamplerMagnitudeCount),
		strconv.Itoa(plan.SamplerSearchSteps),
		strconv.Itoa(plan.SamplerFullScanSteps),
		strconv.Itoa(plan.SamplerCDFTableBytes),
	} {
		write(value)
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func jointDPGaussianParseSpec(input jointDPGaussianShareInput) (jointDPGaussianSpec, error) {
	var zero jointDPGaussianSpec
	if input.Version != jointDPGaussianInputVersion || input.RingBits != 128 ||
		input.FracBits != 0 || input.TotalCoordinateCount < 1 ||
		input.TotalCoordinateCount > jointDPVectorMaxTotal ||
		input.CoordinateCount < 1 || input.CoordinateCount > jointDPGaussianMaxChunk ||
		input.ChunkStart < 0 ||
		input.ChunkStart > input.TotalCoordinateCount-input.CoordinateCount ||
		input.OutputLatticeBits < 1 || input.OutputLatticeBits > 62 ||
		len(input.ScaleShifts) != input.CoordinateCount ||
		len(input.RawUpperBounds) != input.CoordinateCount ||
		!jointDPConvolutionPeer.MatchString(input.PeerName) {
		return zero, fmt.Errorf("invalid purpose-bound Gaussian shape")
	}
	plan, err := jointDPPlanVectorGaussian(jointDPGaussianPlanInput{
		Epsilon: input.Epsilon, Delta: input.AllocatedDelta,
		L2SensitivitySteps:   input.L2SensitivitySteps,
		TotalCoordinateCount: input.TotalCoordinateCount,
	})
	if err != nil || !plan.CapabilityAvailable ||
		input.CoordinateCount > plan.MaximumChunkCoordinates {
		return zero, fmt.Errorf("invalid Gaussian privacy certificate")
	}
	transcript, err := jointDPDecodeHex32(input.TranscriptHash, "transcript hash")
	if err != nil || transcript == ([32]byte{}) {
		return zero, fmt.Errorf("invalid Gaussian transcript hash")
	}
	context, err := jointDPDecodeHex32(input.CommitmentContext, "commitment context")
	if err != nil {
		return zero, err
	}
	commitment, err := jointDPDecodeHex32(input.SeedCommitment, "seed commitment")
	if err != nil {
		return zero, err
	}
	releaseHash, err := jointDPDecodeHex32(input.ReleaseContractHash, "release contract hash")
	if err != nil || releaseHash == ([32]byte{}) {
		return zero, fmt.Errorf("invalid Gaussian release contract hash")
	}
	expectedContext := jointDPCommitmentContext(
		transcript, jointDPGaussianCommitmentPurpose, input.PeerName)
	if context != expectedContext {
		return zero, fmt.Errorf("Gaussian seed commitment context mismatch")
	}
	sigmaSquared := new(big.Rat)
	if _, ok := sigmaSquared.SetString(
		plan.SigmaSquaredNumerator + "/" + plan.SigmaSquaredDenominator); !ok {
		return zero, fmt.Errorf("invalid Gaussian variance certificate")
	}
	maxNoise, ok := new(big.Int).SetString(plan.MaximumNoiseMagnitudePerPeer, 10)
	if !ok || maxNoise.Sign() < 0 {
		return zero, fmt.Errorf("invalid Gaussian support certificate")
	}
	twoNoise := new(big.Int).Lsh(new(big.Int).Set(maxNoise), 1)
	maxSigned := exactGCMaxSigned(128)
	minSigned := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 127))
	if new(big.Int).Neg(new(big.Int).Set(twoNoise)).Cmp(minSigned) < 0 {
		return zero, fmt.Errorf("Ring128 lacks negative two-draw Gaussian headroom")
	}
	upperBounds := make([]*big.Int, input.CoordinateCount)
	for index, text := range input.RawUpperBounds {
		upperBounds[index], err = jointDPVectorParseInt(text, "raw upper bound", false)
		shift := input.ScaleShifts[index]
		if err != nil || shift < 0 || shift > input.OutputLatticeBits {
			return zero, fmt.Errorf("invalid Gaussian lattice bound")
		}
		scaledUpper := new(big.Int).Lsh(new(big.Int).Set(upperBounds[index]), uint(shift))
		if scaledUpper.Sign() < 0 ||
			new(big.Int).Add(scaledUpper, twoNoise).Cmp(maxSigned) > 0 {
			return zero, fmt.Errorf(
				"Ring128 lacks certified Gaussian no-wrap headroom at coordinate %d", index)
		}
	}
	return jointDPGaussianSpec{
		input: input, plan: plan, rawUpperBounds: upperBounds,
		sigmaSquared: sigmaSquared, maxNoise: maxNoise,
		transcript: transcript, context: context, commitment: commitment,
		releaseHash:    releaseHash,
		contractDigest: jointDPGaussianContractDigest(input, plan),
	}, nil
}

type jointDPGaussianCoordinateStream struct {
	seed         [32]byte
	transcript   [32]byte
	coordinate   []byte
	nextSegment  big.Int
	stream       cipher.Stream
	remaining    uint64
	segmentBytes uint64
}

func jointDPGaussianNewCoordinateStream(
	seed [32]byte, transcript [32]byte, coordinate []byte, segmentBytes uint64,
) (*jointDPGaussianCoordinateStream, error) {
	if len(coordinate) == 0 || segmentBytes == 0 || segmentBytes > 1<<38 {
		return nil, fmt.Errorf("invalid Gaussian coordinate stream contract")
	}
	reader := &jointDPGaussianCoordinateStream{
		seed: seed, transcript: transcript,
		coordinate:   append([]byte(nil), coordinate...),
		segmentBytes: segmentBytes,
	}
	if err := reader.advance(); err != nil {
		reader.destroy()
		return nil, err
	}
	return reader, nil
}

func (reader *jointDPGaussianCoordinateStream) segmentInfo(index *big.Int) []byte {
	if index.Sign() == 0 {
		return append([]byte(nil), reader.coordinate...)
	}
	info := make([]byte, 0, len(reader.coordinate)+96)
	info = append(info, reader.coordinate...)
	info = append(info, []byte(
		"/dsvert-chacha20-unbounded-stream-segment/v1/")...)
	info = append(info, index.String()...)
	return info
}

func (reader *jointDPGaussianCoordinateStream) advance() error {
	index := new(big.Int).Set(&reader.nextSegment)
	info := reader.segmentInfo(index)
	materialReader := hkdf.New(
		sha256.New, reader.seed[:], reader.transcript[:], info)
	material := make([]byte, chacha20.KeySize+chacha20.NonceSize)
	if _, err := io.ReadFull(materialReader, material); err != nil {
		clear(material)
		clear(info)
		index.SetInt64(0)
		return fmt.Errorf("derive Gaussian coordinate stream segment")
	}
	stream, err := chacha20.NewUnauthenticatedCipher(
		material[:chacha20.KeySize], material[chacha20.KeySize:])
	clear(material)
	clear(info)
	index.SetInt64(0)
	if err != nil {
		return fmt.Errorf("initialize Gaussian coordinate stream segment")
	}
	reader.stream = stream
	reader.remaining = reader.segmentBytes
	reader.nextSegment.Add(&reader.nextSegment, big.NewInt(1))
	return nil
}

func (reader *jointDPGaussianCoordinateStream) Read(output []byte) (int, error) {
	if reader == nil || reader.segmentBytes == 0 || reader.coordinate == nil {
		return 0, fmt.Errorf("invalid Gaussian coordinate stream")
	}
	written := 0
	for written < len(output) {
		if reader.remaining == 0 {
			if err := reader.advance(); err != nil {
				return written, err
			}
		}
		amount := uint64(len(output) - written)
		if amount > reader.remaining {
			amount = reader.remaining
		}
		end := written + int(amount)
		clear(output[written:end])
		reader.stream.XORKeyStream(output[written:end], output[written:end])
		reader.remaining -= amount
		written = end
	}
	return written, nil
}

func (reader *jointDPGaussianCoordinateStream) destroy() {
	if reader == nil {
		return
	}
	clear(reader.seed[:])
	clear(reader.transcript[:])
	clear(reader.coordinate)
	reader.coordinate = nil
	reader.nextSegment.SetInt64(0)
	reader.stream = nil
	reader.remaining = 0
	reader.segmentBytes = 0
}

func jointDPGaussianCoordinateReader(
	seed [32]byte, spec jointDPGaussianSpec, localCoordinate int,
) (io.Reader, error) {
	if localCoordinate < 0 || localCoordinate >= spec.input.CoordinateCount {
		return nil, fmt.Errorf("invalid Gaussian coordinate domain")
	}
	absoluteCoordinate := spec.input.ChunkStart + localCoordinate
	var coordinate [8]byte
	binary.BigEndian.PutUint64(coordinate[:], uint64(absoluteCoordinate))
	info := make([]byte, 0, 96)
	info = append(info, []byte("dsVert/joint-dp/dyadic-discrete-gaussian/coordinate/v2/")...)
	info = append(info, spec.contractDigest[:]...)
	info = append(info, coordinate[:]...)
	var shift [4]byte
	binary.BigEndian.PutUint32(shift[:], uint32(spec.input.ScaleShifts[localCoordinate]))
	info = append(info, shift[:]...)
	bound := []byte(spec.input.RawUpperBounds[localCoordinate])
	var boundLength [4]byte
	binary.BigEndian.PutUint32(boundLength[:], uint32(len(bound)))
	info = append(info, boundLength[:]...)
	info = append(info, bound...)
	reader, err := jointDPGaussianNewCoordinateStream(
		seed, spec.transcript, info, jointDPGaussianStreamSegmentBytes)
	clear(info)
	return reader, err
}

func jointDPGaussianProject(value, maximum *big.Int) *big.Int {
	if value.Cmp(maximum) > 0 {
		value.Set(maximum)
	} else {
		minimum := new(big.Int).Neg(new(big.Int).Set(maximum))
		if value.Cmp(minimum) < 0 {
			value.Set(minimum)
		}
		minimum.SetInt64(0)
	}
	return value
}

func jointDPGaussianNoise(seed [32]byte, spec jointDPGaussianSpec) ([]*big.Int, error) {
	if jointDPSeedCommitment(spec.context, seed) != spec.commitment {
		return nil, fmt.Errorf("local Gaussian seed commitment mismatch")
	}
	vectorSamplerTV := new(big.Rat)
	if _, ok := vectorSamplerTV.SetString(
		spec.plan.VectorSamplerTVUpperNumerator + "/" +
			spec.plan.VectorSamplerTVUpperDenominator); !ok {
		return nil, fmt.Errorf("invalid fixed-work Gaussian TV certificate")
	}
	perCoordinateTV := new(big.Rat).Quo(
		vectorSamplerTV, big.NewRat(int64(spec.input.TotalCoordinateCount), 1))
	table, err := jointDPGaussianBuildDyadicTable(
		spec.sigmaSquared, spec.maxNoise,
		spec.plan.SamplerRandomBitsPerCoordinate,
		spec.plan.SamplerTablePrecisionBits, perCoordinateTV)
	if err != nil {
		return nil, err
	}
	exactGCZeroBigInts(table.Cumulative)
	table.Cumulative = nil
	defer clear(table.CumulativeFixed)
	result := make([]*big.Int, spec.input.CoordinateCount)
	for index := range result {
		reader, err := jointDPGaussianCoordinateReader(seed, spec, index)
		if err != nil {
			exactGCZeroBigInts(result)
			return nil, err
		}
		value, audit, err := jointDPGaussianSampleDyadic(reader, table)
		if disposable, ok := reader.(*jointDPGaussianCoordinateStream); ok {
			disposable.destroy()
		}
		if err != nil {
			exactGCZeroBigInts(result)
			return nil, err
		}
		if audit.RandomBytes != spec.plan.SamplerRandomBytesPerCoordinate ||
			audit.SearchSteps != spec.plan.SamplerFullScanSteps ||
			audit.ThresholdBytesRead != spec.plan.SamplerCDFTableBytes ||
			audit.SecretIndexedReads != 0 || audit.DataDependentBranches {
			value.SetInt64(0)
			exactGCZeroBigInts(result)
			return nil, fmt.Errorf("fixed-work Gaussian sampler shape mismatch")
		}
		result[index] = value
	}
	return result, nil
}

func jointDPGaussianSampleShare(input jointDPGaussianShareInput) (jointDPGaussianShareOutput, error) {
	var zero jointDPGaussianShareOutput
	spec, err := jointDPGaussianParseSpec(input)
	if err != nil {
		return zero, err
	}
	seedBytes, err := hex.DecodeString(input.PrivateSeed)
	if err != nil || len(seedBytes) != 32 || hex.EncodeToString(seedBytes) != input.PrivateSeed {
		return zero, fmt.Errorf("invalid Gaussian private seed")
	}
	var seed [32]byte
	copy(seed[:], seedBytes)
	clear(seedBytes)
	defer clear(seed[:])
	shareBytes, err := jointDPVectorConvolutionCanonicalBase64(
		input.SourceShare, "Ring128 Gaussian source share", 16*input.CoordinateCount)
	if err != nil {
		return zero, err
	}
	defer clear(shareBytes)
	noise, err := jointDPGaussianNoise(seed, spec)
	if err != nil {
		return zero, err
	}
	defer exactGCZeroBigInts(noise)
	modulus := exactGCModulus(128)
	noised := make([]byte, len(shareBytes))
	defer clear(noised)
	for index := 0; index < input.CoordinateCount; index++ {
		share := exactGCLittleEndianBig(shareBytes[index*16 : (index+1)*16])
		share.Lsh(share, uint(input.ScaleShifts[index]))
		share.Add(share, noise[index])
		share.Mod(share, modulus)
		record, encodeErr := exactGCBigLittleEndian(share, 16)
		share.SetInt64(0)
		if encodeErr != nil {
			return zero, encodeErr
		}
		copy(noised[index*16:(index+1)*16], record)
		clear(record)
	}
	twoNoise := new(big.Int).Lsh(new(big.Int).Set(spec.maxNoise), 1)
	return jointDPGaussianShareOutput{
		Version: jointDPGaussianOutputVersion, Backend: jointDPGaussianBackend,
		Mechanism: jointDPGaussianMechanism, Sampler: jointDPGaussianSampler,
		ReleaseContractHash: input.ReleaseContractHash,
		SamplerContractHash: hex.EncodeToString(spec.contractDigest[:]),
		TranscriptHash:      input.TranscriptHash, PeerName: input.PeerName,
		SeedCommitment: input.SeedCommitment, RingBits: 128, FracBits: 0,
		TotalCoordinateCount: input.TotalCoordinateCount,
		ChunkStart:           input.ChunkStart, CoordinateCount: input.CoordinateCount,
		NoisedShare:                   base64.StdEncoding.EncodeToString(noised),
		MaximumNoiseMagnitudePerPeer:  spec.maxNoise.String(),
		MaximumNoiseMagnitudeTwoPeers: twoNoise.String(),
		FullCapsuleParametersPerPeer:  true, EpsilonDividedByPeerCount: false,
		SourceValuesReturned: false, NoiseValuesReturned: false,
		PrivateSeedReturned: false, PreclampValuesReturned: false,
		NoWrapHeadroomCertified: true, TailProjectionApplied: false,
		TailTruncationApplied: true, FixedWorkShapeVerified: true,
		SourceBoundPrecondition:   "authenticated_semi_honest_capsule_materializer_and_source_transport",
		NominalVarianceMultiplier: 2, Plan: spec.plan,
	}, nil
}

type jointDPGaussianFinalizerInput struct {
	Version              string   `json:"version"`
	RingBits             int      `json:"ring_bits"`
	FracBits             int      `json:"frac_bits"`
	TotalCoordinateCount int      `json:"total_coordinate_count"`
	ChunkStart           int      `json:"chunk_start"`
	CoordinateCount      int      `json:"coordinate_count"`
	OutputLatticeBits    int      `json:"output_lattice_bits"`
	Epsilon              string   `json:"epsilon"`
	AllocatedDelta       string   `json:"allocated_delta"`
	L2SensitivitySteps   string   `json:"l2_sensitivity_steps"`
	ScaleShifts          []int    `json:"scale_shifts"`
	RawUpperBounds       []string `json:"raw_upper_bounds"`
	ReleaseContractHash  string   `json:"release_contract_hash"`
	TranscriptHash       string   `json:"transcript_hash"`
	LeftNoisedShare      string   `json:"left_noised_share"`
	RightNoisedShare     string   `json:"right_noised_share"`
}

type jointDPGaussianFinalizerOutput struct {
	Version                 string                    `json:"version"`
	Backend                 string                    `json:"backend"`
	Mechanism               string                    `json:"mechanism"`
	Sampler                 string                    `json:"sampler"`
	ReleaseContractHash     string                    `json:"release_contract_hash"`
	TranscriptHash          string                    `json:"transcript_hash"`
	RingBits                int                       `json:"ring_bits"`
	FracBits                int                       `json:"frac_bits"`
	TotalCoordinateCount    int                       `json:"total_coordinate_count"`
	ChunkStart              int                       `json:"chunk_start"`
	CoordinateCount         int                       `json:"coordinate_count"`
	OutputLatticeBits       int                       `json:"output_lattice_bits"`
	ClampedScaledValues     []string                  `json:"clamped_scaled_values"`
	PreclampValuesReturned  bool                      `json:"preclamp_values_returned"`
	SignedDecode            string                    `json:"signed_decode"`
	Clamping                string                    `json:"clamping"`
	NoWrapHeadroomCertified bool                      `json:"no_wrap_headroom_certified"`
	Plan                    jointDPGaussianPlanOutput `json:"plan"`
}

func jointDPGaussianFinalize(input jointDPGaussianFinalizerInput) (jointDPGaussianFinalizerOutput, error) {
	var zero jointDPGaussianFinalizerOutput
	if input.Version != jointDPGaussianFinalizerInputVersion {
		return zero, fmt.Errorf("invalid Gaussian finalizer version")
	}
	transcript, err := jointDPDecodeHex32(input.TranscriptHash, "transcript hash")
	if err != nil {
		return zero, err
	}
	context := jointDPCommitmentContext(
		transcript, jointDPGaussianCommitmentPurpose, "finalizer")
	seed := sha256.Sum256([]byte("dsVert/vector-gaussian/finalizer-validation-only"))
	commitment := jointDPSeedCommitment(context, seed)
	spec, err := jointDPGaussianParseSpec(jointDPGaussianShareInput{
		Version: jointDPGaussianInputVersion, RingBits: input.RingBits,
		FracBits: input.FracBits, TotalCoordinateCount: input.TotalCoordinateCount,
		ChunkStart: input.ChunkStart, CoordinateCount: input.CoordinateCount,
		OutputLatticeBits: input.OutputLatticeBits, Epsilon: input.Epsilon,
		AllocatedDelta:     input.AllocatedDelta,
		L2SensitivitySteps: input.L2SensitivitySteps,
		ScaleShifts:        input.ScaleShifts, RawUpperBounds: input.RawUpperBounds,
		ReleaseContractHash: input.ReleaseContractHash,
		TranscriptHash:      input.TranscriptHash, PeerName: "finalizer",
		CommitmentContext: hex.EncodeToString(context[:]),
		SeedCommitment:    hex.EncodeToString(commitment[:]),
	})
	clear(seed[:])
	if err != nil {
		return zero, err
	}
	left, err := jointDPVectorConvolutionCanonicalBase64(
		input.LeftNoisedShare, "left Gaussian noised share", 16*input.CoordinateCount)
	if err != nil {
		return zero, err
	}
	defer clear(left)
	right, err := jointDPVectorConvolutionCanonicalBase64(
		input.RightNoisedShare, "right Gaussian noised share", 16*input.CoordinateCount)
	if err != nil {
		return zero, err
	}
	defer clear(right)
	modulus := exactGCModulus(128)
	sign := new(big.Int).Lsh(big.NewInt(1), 127)
	values := make([]string, input.CoordinateCount)
	for index := range values {
		opened := exactGCLittleEndianBig(left[index*16 : (index+1)*16])
		opened.Add(opened, exactGCLittleEndianBig(right[index*16:(index+1)*16]))
		opened.Mod(opened, modulus)
		if opened.Cmp(sign) >= 0 {
			opened.Sub(opened, modulus)
		}
		upper := new(big.Int).Lsh(
			new(big.Int).Set(spec.rawUpperBounds[index]), uint(input.ScaleShifts[index]))
		if opened.Sign() < 0 {
			opened.SetInt64(0)
		} else if opened.Cmp(upper) > 0 {
			opened.Set(upper)
		}
		values[index] = opened.String()
		opened.SetInt64(0)
	}
	return jointDPGaussianFinalizerOutput{
		Version: jointDPGaussianFinalizerOutputVersion,
		Backend: jointDPGaussianBackend, Mechanism: jointDPGaussianMechanism,
		Sampler:             jointDPGaussianSampler,
		ReleaseContractHash: input.ReleaseContractHash,
		TranscriptHash:      input.TranscriptHash, RingBits: 128, FracBits: 0,
		TotalCoordinateCount: input.TotalCoordinateCount,
		ChunkStart:           input.ChunkStart, CoordinateCount: input.CoordinateCount,
		OutputLatticeBits:   input.OutputLatticeBits,
		ClampedScaledValues: values, PreclampValuesReturned: false,
		SignedDecode:            "canonical_Ring128_twos_complement_after_proven_no_wrap",
		Clamping:                "single_fixed_public_per_coordinate_interval_postprocessing",
		NoWrapHeadroomCertified: true, Plan: spec.plan,
	}, nil
}

func handleJointDPVectorGaussianShare() {
	input, err := jointDPGaussianDecode[jointDPGaussianShareInput](os.Stdin)
	if err != nil {
		mpcFatalError(err.Error())
	}
	result, err := jointDPGaussianSampleShare(input)
	input.PrivateSeed = ""
	input.SourceShare = ""
	if err != nil {
		mpcFatalError(err.Error())
	}
	mpcWriteOutput(result)
}

func handleJointDPVectorGaussianFinalize() {
	input, err := jointDPGaussianDecode[jointDPGaussianFinalizerInput](os.Stdin)
	if err != nil {
		mpcFatalError(err.Error())
	}
	result, err := jointDPGaussianFinalize(input)
	input.LeftNoisedShare = ""
	input.RightNoisedShare = ""
	if err != nil {
		mpcFatalError(err.Error())
	}
	mpcWriteOutput(result)
}
