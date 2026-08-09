package main

// One global fixed-work discrete-Gaussian vector draw inside exact GC.
//
// Each of the two pinned compute peers expands its sticky seed locally with
// HKDF-SHA256/ChaCha20. Only fixed-width private random words and sign bits
// enter Yao; the circuit XORs the two streams, reconstructs and validates the
// Ring128 source, performs the public dyadic-CDF lookup, clamps once, and
// returns additive payload shares plus XOR validity shares. The relay never
// receives a seed, stream, source share, pre-noise value, or validity bit.
//
// The ideal discrete Gaussian, finite-support tail transfer, and outward
// rational dyadic-CDF approximation reuse the existing exact planner. This
// file changes the productive composition from two independent full draws to
// one jointly generated draw; it does not weaken or relabel the old fallback.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
	"github.com/markkurossi/mpc/p2p"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

const (
	jointDPGaussianOneDrawPlanVersion                 = "dsvert-joint-dp-vector-discrete-gaussian-one-draw-plan-v1"
	jointDPGaussianOneDrawTemplateVersion             = "dsvert-joint-dp-vector-discrete-gaussian-one-draw-gc-template-v1"
	jointDPGaussianOneDrawWorkerContractInputVersion  = "dsvert-joint-dp-vector-discrete-gaussian-one-draw-worker-contract-input-v1"
	jointDPGaussianOneDrawWorkerContractOutputVersion = "dsvert-joint-dp-vector-discrete-gaussian-one-draw-worker-contract-v1"
	jointDPGaussianOneDrawMechanism                   = "joint_discrete_gaussian_one_global_draw"
	jointDPGaussianOneDrawAllocation                  = "one_stacked_capsule_vector"
	jointDPGaussianOneDrawSampler                     = "fixed-work-outward-rational-dyadic-cdf-hkdf-sha256-chacha20-xor-exact-gc-v1"
	jointDPGaussianOneDrawOperation                   = exactGCOperation("joint-dp-vector-gaussian-one-draw-v1")
	jointDPGaussianOneDrawCommitmentPurpose           = "joint-dp-vector-gaussian-one-draw-v1"
	jointDPGaussianOneDrawSensitivityCertificateKind  = "machine_proven_integer_lattice_l2_v1"

	jointDPGaussianOneDrawMaxCoordinates = 128
	// A secret-path lookup into a public CDF is not a free O(log M) RAM
	// operation in a Boolean circuit: the reviewed decision tree contains
	// M-1 comparisons even though its logical depth is ceil(log2 M). This
	// explicit gate-work envelope covers the Phase-1.6 p=2/L2=363 case in
	// chunks while preventing an unbounded circuit build. It is a per-circuit
	// resource limit, never a request count or privacy-budget gate.
	jointDPGaussianOneDrawMaxCDFComparisons              = 65536
	jointDPGaussianOneDrawMaxProjectedGates        int64 = 85_000_000
	jointDPGaussianOneDrawMaxProjectedNonXOR       int64 = 26_000_000
	jointDPGaussianOneDrawMaxProjectedGarbledBytes int64 = 1 << 30
	jointDPGaussianOneDrawMaxProjectedWireBytes    int64 = 3 << 30
	// Measured compiler allocation for two Phase-1.6 coordinates was 6.58 GB.
	// Keep the admitted projection below 6 GiB, which forces one-coordinate
	// chunks for that shape. This is a per-circuit peak-memory guard, not a
	// request/history limit; all coordinates remain computable sequentially.
	jointDPGaussianOneDrawMaxProjectedCompilerBytes int64 = 6 << 30
	jointDPGaussianOneDrawMaxBindingBytes                 = 4 << 20
)

var jointDPGaussianOneDrawPinnedPeer = regexp.MustCompile(`^dsv1_[0-9a-f]{64}$`)

type jointDPGaussianOneDrawPlanInput struct {
	Epsilon              string `json:"epsilon"`
	Delta                string `json:"delta"`
	L2SensitivitySteps   string `json:"l2_sensitivity_steps"`
	TotalCoordinateCount int    `json:"total_coordinate_count"`
}

type jointDPGaussianOneDrawPlanOutput struct {
	Version                                 string   `json:"version"`
	Mechanism                               string   `json:"mechanism"`
	Allocation                              string   `json:"allocation"`
	Sampler                                 string   `json:"sampler"`
	Reference                               string   `json:"reference"`
	RingBits                                int      `json:"ring_bits"`
	FracBits                                int      `json:"frac_bits"`
	NoiseDrawCount                          int      `json:"noise_draw_count"`
	TotalCoordinateCount                    int      `json:"total_coordinate_count"`
	MaximumChunkCoordinates                 int      `json:"maximum_chunk_coordinates"`
	MaximumCDFComparisonsPerCircuit         int      `json:"maximum_cdf_comparisons_per_circuit"`
	CDFComparisonsPerCoordinate             int      `json:"cdf_comparisons_per_coordinate"`
	PlannedCDFComparisonsPerCircuit         int      `json:"planned_cdf_comparisons_per_circuit"`
	CDFLookupCircuitModel                   string   `json:"cdf_lookup_circuit_model"`
	CDFLookupLogicalDepth                   int      `json:"cdf_lookup_logical_depth"`
	SecretIndexedPublicRAMAvailable         bool     `json:"secret_indexed_public_ram_available"`
	LogarithmicCircuitSizeClaim             bool     `json:"logarithmic_circuit_size_claim"`
	GarblerInputBitsPerCircuit              int      `json:"garbler_input_bits_per_circuit"`
	EvaluatorInputBitsPerCircuit            int      `json:"evaluator_input_bits_per_circuit"`
	TotalInputBitsPerCircuit                int      `json:"total_input_bits_per_circuit"`
	PrivateRandomBytesPerPeerPerCircuit     int      `json:"private_random_bytes_per_peer_per_circuit"`
	ProjectedGateCountUpper                 int64    `json:"projected_gate_count_upper"`
	ProjectedNonXORGateCountUpper           int64    `json:"projected_non_xor_gate_count_upper"`
	ProjectedWireCountUpper                 int64    `json:"projected_wire_count_upper"`
	ProjectedGarbledTableBytesUpper         int64    `json:"projected_garbled_table_bytes_upper"`
	ProjectedWireLabelBytesUpper            int64    `json:"projected_wire_label_bytes_upper"`
	ProjectedCompilerAllocationBytesUpper   int64    `json:"projected_compiler_allocation_bytes_upper"`
	MaximumProjectedGateCount               int64    `json:"maximum_projected_gate_count"`
	MaximumProjectedNonXORGateCount         int64    `json:"maximum_projected_non_xor_gate_count"`
	MaximumProjectedGarbledTableBytes       int64    `json:"maximum_projected_garbled_table_bytes"`
	MaximumProjectedWireLabelBytes          int64    `json:"maximum_projected_wire_label_bytes"`
	MaximumProjectedCompilerAllocationBytes int64    `json:"maximum_projected_compiler_allocation_bytes"`
	WireLabelBytes                          int      `json:"wire_label_bytes"`
	CostProjectionIsConservative            bool     `json:"cost_projection_is_conservative"`
	CircuitTypedInputBitLimit               int      `json:"circuit_typed_input_bit_limit"`
	RequestBindingSHA256                    string   `json:"request_binding_sha256"`
	EpsilonNumerator                        string   `json:"epsilon_numerator"`
	EpsilonDenominator                      string   `json:"epsilon_denominator"`
	AllocatedDeltaNumerator                 string   `json:"allocated_delta_numerator"`
	AllocatedDeltaDenominator               string   `json:"allocated_delta_denominator"`
	CoreDeltaNumerator                      string   `json:"core_delta_numerator"`
	CoreDeltaDenominator                    string   `json:"core_delta_denominator"`
	L2SensitivitySteps                      string   `json:"l2_sensitivity_steps"`
	RhoNumerator                            string   `json:"rho_numerator"`
	RhoDenominator                          string   `json:"rho_denominator"`
	SigmaSquaredNumerator                   string   `json:"sigma_squared_numerator"`
	SigmaSquaredDenominator                 string   `json:"sigma_squared_denominator"`
	MaximumNoiseMagnitude                   string   `json:"maximum_noise_magnitude"`
	VectorTailTVUpperNumerator              string   `json:"vector_tail_tv_upper_numerator"`
	VectorTailTVUpperDenominator            string   `json:"vector_tail_tv_upper_denominator"`
	VectorCDFTVUpperNumerator               string   `json:"vector_cdf_tv_upper_numerator"`
	VectorCDFTVUpperDenominator             string   `json:"vector_cdf_tv_upper_denominator"`
	VectorTotalTVUpperNumerator             string   `json:"vector_total_tv_upper_numerator"`
	VectorTotalTVUpperDenominator           string   `json:"vector_total_tv_upper_denominator"`
	ImplementationDeltaNumerator            string   `json:"implementation_delta_numerator"`
	ImplementationDeltaDenominator          string   `json:"implementation_delta_denominator"`
	SamplerRandomBitsPerCoordinate          int      `json:"sampler_random_bits_per_coordinate"`
	SamplerPrivateBitsPerCoordinate         int      `json:"sampler_private_bits_per_coordinate_per_peer"`
	SamplerTablePrecisionBits               int      `json:"sampler_table_precision_bits"`
	SamplerMagnitudeCount                   int      `json:"sampler_magnitude_count"`
	SamplerSearchSteps                      int      `json:"sampler_search_steps"`
	CDFCumulative                           []string `json:"cdf_cumulative"`
	Simultaneous95Abs                       string   `json:"simultaneous_95_abs"`
	Accounting                              string   `json:"accounting"`
	PrivacyTheorem                          string   `json:"privacy_theorem"`
	FiniteSupportTransferCharged            bool     `json:"finite_support_transfer_charged"`
	FixedWorkSampler                        bool     `json:"fixed_work_sampler"`
	NoWrapCertified                         bool     `json:"no_wrap_certified"`
	DesignatedComputePeerCount              int      `json:"designated_compute_peer_count"`
	CapabilityAvailable                     bool     `json:"capability_available"`
	UnavailableReason                       string   `json:"unavailable_reason"`
	FallbackAvailable                       bool     `json:"fallback_available"`
	FallbackMechanism                       string   `json:"fallback_mechanism"`
	FallbackPlanVersion                     string   `json:"fallback_plan_version"`
	FallbackAutomatic                       bool     `json:"fallback_automatic"`
	FallbackSelection                       string   `json:"fallback_selection"`
	FallbackNominalVarianceMultiplier       int      `json:"fallback_nominal_variance_multiplier"`
	FallbackNominalStandardDeviationFactor  string   `json:"fallback_nominal_standard_deviation_factor"`
	FallbackThreatModel                     string   `json:"fallback_threat_model"`
	FallbackUtilityCertificate              string   `json:"fallback_utility_certificate"`
}

func jointDPGaussianOneDrawCostProjection(magnitudeCount, coordinates int) (
	garblerBits, evaluatorBits, totalBits, randomBytes int,
	gates, nonXOR, wires, garbledBytes, wireBytes int64,
) {
	if magnitudeCount < 1 || coordinates < 1 {
		return
	}
	comparisons := int64((magnitudeCount - 1) * coordinates)
	coordinateCount := int64(coordinates)
	garblerBits = 513*coordinates + 1
	evaluatorBits = 257 * coordinates
	totalBits = garblerBits + evaluatorBits
	randomBytes = 17 * coordinates
	// Conservative envelope for the pinned compiler. Contract compilation
	// checks the actual circuit against it before any private input is read.
	nonXOR = comparisons*384 + coordinateCount*2048 + 4096
	gates = comparisons*1280 + coordinateCount*8192 + 16384
	wires = gates + int64(totalBits) + 4096
	garbledBytes = nonXOR * 2 * 16
	wireBytes = wires * 2 * 16
	return
}

func jointDPGaussianOneDrawBasePlan(
	input jointDPGaussianOneDrawPlanInput,
) (jointDPGaussianPlanOutput, *big.Int, error) {
	epsilon, epsilonErr := jointDPParseDecimalRat(input.Epsilon, "epsilon", false)
	delta, deltaErr := jointDPParseDecimalRat(input.Delta, "delta", false)
	sensitivity, err := jointDPParseDecimalRat(
		input.L2SensitivitySteps, "l2_sensitivity_steps", false)
	if epsilonErr != nil || deltaErr != nil || delta.Cmp(big.NewRat(1, 1)) >= 0 ||
		input.TotalCoordinateCount < 1 ||
		input.TotalCoordinateCount > jointDPVectorMaxTotal ||
		err != nil || !sensitivity.IsInt() {
		return jointDPGaussianPlanOutput{}, nil,
			fmt.Errorf("invalid one-draw Gaussian privacy request")
	}
	_ = epsilon
	base, err := jointDPPlanVectorGaussian(jointDPGaussianPlanInput{
		Epsilon: input.Epsilon, Delta: input.Delta,
		L2SensitivitySteps:   input.L2SensitivitySteps,
		TotalCoordinateCount: input.TotalCoordinateCount,
	})
	if err != nil {
		return jointDPGaussianPlanOutput{}, nil,
			exactGCFailure(exactGCFailureNumericBackendUnavailable,
				fmt.Errorf("one-draw and two-draw Gaussian capability unavailable: %w", err))
	}
	return base, new(big.Int).Set(sensitivity.Num()), nil
}

func jointDPGaussianOneDrawUnavailable(
	base jointDPGaussianPlanOutput, sensitivity *big.Int, reason string,
) jointDPGaussianOneDrawPlanOutput {
	return jointDPGaussianOneDrawPlanOutput{
		Version:    jointDPGaussianOneDrawPlanVersion,
		Mechanism:  jointDPGaussianOneDrawMechanism,
		Allocation: jointDPGaussianOneDrawAllocation,
		Sampler:    jointDPGaussianOneDrawSampler,
		Reference:  base.Reference,
		RingBits:   128, FracBits: 0, NoiseDrawCount: 1,
		TotalCoordinateCount:                    base.TotalCoordinateCount,
		MaximumCDFComparisonsPerCircuit:         jointDPGaussianOneDrawMaxCDFComparisons,
		CDFComparisonsPerCoordinate:             base.SamplerMagnitudeCount - 1,
		CDFLookupCircuitModel:                   "public_constant_threshold_decision_tree_boolean_circuit_m_minus_1_comparators_v1",
		CDFLookupLogicalDepth:                   base.SamplerSearchSteps,
		SecretIndexedPublicRAMAvailable:         false,
		LogarithmicCircuitSizeClaim:             false,
		CircuitTypedInputBitLimit:               exactGCMaxCircuitTypeBits,
		MaximumProjectedGateCount:               jointDPGaussianOneDrawMaxProjectedGates,
		MaximumProjectedNonXORGateCount:         jointDPGaussianOneDrawMaxProjectedNonXOR,
		MaximumProjectedGarbledTableBytes:       jointDPGaussianOneDrawMaxProjectedGarbledBytes,
		MaximumProjectedWireLabelBytes:          jointDPGaussianOneDrawMaxProjectedWireBytes,
		MaximumProjectedCompilerAllocationBytes: jointDPGaussianOneDrawMaxProjectedCompilerBytes,
		RequestBindingSHA256:                    base.RequestBindingSHA256,
		EpsilonNumerator:                        base.EpsilonNumerator,
		EpsilonDenominator:                      base.EpsilonDenominator,
		AllocatedDeltaNumerator:                 base.AllocatedDeltaNumerator,
		AllocatedDeltaDenominator:               base.AllocatedDeltaDenominator,
		CoreDeltaNumerator:                      base.CoreDeltaNumerator,
		CoreDeltaDenominator:                    base.CoreDeltaDenominator,
		L2SensitivitySteps:                      sensitivity.String(),
		RhoNumerator:                            base.RhoNumerator, RhoDenominator: base.RhoDenominator,
		SigmaSquaredNumerator:           base.SigmaSquaredNumerator,
		SigmaSquaredDenominator:         base.SigmaSquaredDenominator,
		MaximumNoiseMagnitude:           base.MaximumNoiseMagnitudePerPeer,
		VectorTailTVUpperNumerator:      base.VectorTailTVUpperNumerator,
		VectorTailTVUpperDenominator:    base.VectorTailTVUpperDenominator,
		VectorCDFTVUpperNumerator:       base.VectorSamplerTVUpperNumerator,
		VectorCDFTVUpperDenominator:     base.VectorSamplerTVUpperDenominator,
		VectorTotalTVUpperNumerator:     base.VectorTotalTVUpperNumerator,
		VectorTotalTVUpperDenominator:   base.VectorTotalTVUpperDenominator,
		ImplementationDeltaNumerator:    base.PerPeerImplementationDeltaNum,
		ImplementationDeltaDenominator:  base.PerPeerImplementationDeltaDenom,
		SamplerRandomBitsPerCoordinate:  base.SamplerRandomBitsPerCoordinate,
		SamplerPrivateBitsPerCoordinate: base.SamplerRandomBitsPerCoordinate + 1,
		SamplerTablePrecisionBits:       base.SamplerTablePrecisionBits,
		SamplerMagnitudeCount:           base.SamplerMagnitudeCount,
		SamplerSearchSteps:              base.SamplerSearchSteps,
		FiniteSupportTransferCharged:    true, FixedWorkSampler: true,
		NoWrapCertified: true, DesignatedComputePeerCount: 2,
		CapabilityAvailable: false, UnavailableReason: reason,
		FallbackAvailable:                      base.CapabilityAvailable,
		FallbackMechanism:                      jointDPGaussianMechanism,
		FallbackPlanVersion:                    jointDPGaussianPlanVersion,
		FallbackAutomatic:                      false,
		FallbackSelection:                      "explicit_release_policy_only_never_automatic_v1",
		FallbackNominalVarianceMultiplier:      2,
		FallbackNominalStandardDeviationFactor: "sqrt(2)_relative_to_one_full_draw",
		FallbackThreatModel:                    "analyst_may_collude_with_at_most_one_of_two_pinned_semi_honest_noise_peers_and_each_single_source_share_is_simulatable",
		FallbackUtilityCertificate:             "two_independent_complete_discrete_gaussian_draws_variances_add_exactly; same_formal_epsilon_delta_conditional_on_either_peer_view; nominal_variance_x2_sd_x_sqrt2_v1",
	}
}

func jointDPGaussianOneDrawMaxChunk(magnitudeCount int) int {
	if magnitudeCount < 1 {
		return 0
	}
	comparisons := magnitudeCount - 1
	if comparisons < 1 {
		comparisons = 1
	}
	byCDF := jointDPGaussianOneDrawMaxCDFComparisons / comparisons
	// Both parties: source share, 128-bit word, and sign. Garbler also
	// supplies the public upper bound, output mask, and validity mask.
	byInput := (exactGCMaxCircuitTypeBits - 1) / (770)
	result := byCDF
	if byInput < result {
		result = byInput
	}
	if result > jointDPGaussianOneDrawMaxCoordinates {
		result = jointDPGaussianOneDrawMaxCoordinates
	}
	for result > 0 {
		_, _, _, _, gates, nonXOR, _, garbledBytes, wireBytes :=
			jointDPGaussianOneDrawCostProjection(magnitudeCount, result)
		if gates <= jointDPGaussianOneDrawMaxProjectedGates &&
			nonXOR <= jointDPGaussianOneDrawMaxProjectedNonXOR &&
			garbledBytes <= jointDPGaussianOneDrawMaxProjectedGarbledBytes &&
			wireBytes <= jointDPGaussianOneDrawMaxProjectedWireBytes &&
			wireBytes*10 <= jointDPGaussianOneDrawMaxProjectedCompilerBytes {
			break
		}
		result--
	}
	return result
}

func jointDPPlanGaussianOneDraw(
	input jointDPGaussianOneDrawPlanInput,
) (jointDPGaussianOneDrawPlanOutput, error) {
	var zero jointDPGaussianOneDrawPlanOutput
	base, sensitivity, err := jointDPGaussianOneDrawBasePlan(input)
	if err != nil {
		return zero, err
	}
	if base.SamplerRandomBitsPerCoordinate != 128 {
		return jointDPGaussianOneDrawUnavailable(base, sensitivity,
			"exact_gc_one_draw_requires_128_bit_dyadic_cdf"), nil
	}
	maxChunk := jointDPGaussianOneDrawMaxChunk(base.SamplerMagnitudeCount)
	if maxChunk < 1 {
		return jointDPGaussianOneDrawUnavailable(base, sensitivity,
			"exact_gc_one_draw_cdf_exceeds_per_circuit_resource_policy"), nil
	}
	sigmaSquared := new(big.Rat)
	if _, ok := sigmaSquared.SetString(base.SigmaSquaredNumerator + "/" +
		base.SigmaSquaredDenominator); !ok {
		return zero, fmt.Errorf("invalid Gaussian variance certificate")
	}
	maximum, ok := new(big.Int).SetString(base.MaximumNoiseMagnitudePerPeer, 10)
	if !ok || maximum.Sign() < 0 {
		return zero, fmt.Errorf("invalid Gaussian support certificate")
	}
	vectorCDFTarget := jointDPGaussianOneDrawRat(
		base.VectorSamplerTVUpperNumerator,
		base.VectorSamplerTVUpperDenominator)
	if vectorCDFTarget == nil {
		return zero, fmt.Errorf("invalid Gaussian CDF TV allocation")
	}
	perCoordinateTarget := new(big.Rat).Quo(vectorCDFTarget,
		big.NewRat(int64(input.TotalCoordinateCount), 1))
	table, err := jointDPGaussianBuildDyadicTable(
		sigmaSquared, maximum, base.SamplerRandomBitsPerCoordinate,
		base.SamplerTablePrecisionBits, perCoordinateTarget)
	if err != nil {
		return zero, err
	}
	defer exactGCZeroBigInts(table.Cumulative)
	vectorCDFTV := new(big.Rat).Mul(new(big.Rat).Set(table.TVUpper),
		big.NewRat(int64(input.TotalCoordinateCount), 1))
	tailTV := jointDPGaussianOneDrawRat(base.VectorTailTVUpperNumerator,
		base.VectorTailTVUpperDenominator)
	if tailTV == nil {
		return zero, fmt.Errorf("invalid Gaussian tail TV certificate")
	}
	totalTV := new(big.Rat).Add(new(big.Rat).Set(tailTV), vectorCDFTV)
	epsilon := jointDPGaussianOneDrawRat(base.EpsilonNumerator, base.EpsilonDenominator)
	allocated := jointDPGaussianOneDrawRat(base.AllocatedDeltaNumerator,
		base.AllocatedDeltaDenominator)
	core := jointDPGaussianOneDrawRat(base.CoreDeltaNumerator, base.CoreDeltaDenominator)
	if epsilon == nil || allocated == nil || core == nil {
		return zero, fmt.Errorf("invalid Gaussian privacy certificate")
	}
	expUpper, err := jointDPGaussianExpUpper(epsilon)
	if err != nil {
		return zero, err
	}
	implementation := new(big.Rat).Mul(
		new(big.Rat).Add(big.NewRat(1, 1), expUpper), totalTV)
	if new(big.Rat).Add(new(big.Rat).Set(core), implementation).Cmp(allocated) > 0 {
		return zero, fmt.Errorf("one-draw tail/CDF transfer exceeds allocated delta")
	}
	accuracyAlpha := new(big.Rat).Sub(big.NewRat(1, 20), totalTV)
	if accuracyAlpha.Sign() <= 0 {
		return zero, fmt.Errorf("Gaussian implementation TV exhausts accuracy alpha")
	}
	accuracyTarget := new(big.Rat).Quo(
		big.NewRat(int64(2*input.TotalCoordinateCount), 1), accuracyAlpha)
	accuracy, _, err := jointDPGaussianMinimumRadius(
		sigmaSquared, accuracyTarget, 2,
		new(big.Int).Add(new(big.Int).Set(maximum), big.NewInt(1)))
	if err != nil || accuracy.Cmp(maximum) > 0 {
		accuracy = new(big.Int).Set(maximum)
	}
	cumulative := make([]string, len(table.Cumulative))
	for index := range table.Cumulative {
		cumulative[index] = table.Cumulative[index].String()
	}
	if maxChunk > input.TotalCoordinateCount {
		maxChunk = input.TotalCoordinateCount
	}
	garblerBits, evaluatorBits, totalBits, randomBytes,
		projectedGates, projectedNonXOR, projectedWires,
		projectedGarbledBytes, projectedWireBytes :=
		jointDPGaussianOneDrawCostProjection(len(cumulative), maxChunk)
	cdfNum, cdfDen := jointDPGaussianRatFields(vectorCDFTV)
	totalNum, totalDen := jointDPGaussianRatFields(totalTV)
	implementationNum, implementationDen := jointDPGaussianRatFields(implementation)
	return jointDPGaussianOneDrawPlanOutput{
		Version:    jointDPGaussianOneDrawPlanVersion,
		Mechanism:  jointDPGaussianOneDrawMechanism,
		Allocation: jointDPGaussianOneDrawAllocation,
		Sampler:    jointDPGaussianOneDrawSampler, Reference: base.Reference,
		RingBits: 128, FracBits: 0, NoiseDrawCount: 1,
		TotalCoordinateCount:                    input.TotalCoordinateCount,
		MaximumChunkCoordinates:                 maxChunk,
		MaximumCDFComparisonsPerCircuit:         jointDPGaussianOneDrawMaxCDFComparisons,
		CDFComparisonsPerCoordinate:             len(cumulative) - 1,
		PlannedCDFComparisonsPerCircuit:         (len(cumulative) - 1) * maxChunk,
		CDFLookupCircuitModel:                   "public_constant_threshold_decision_tree_boolean_circuit_m_minus_1_comparators_v1",
		CDFLookupLogicalDepth:                   table.LookupDepth,
		SecretIndexedPublicRAMAvailable:         false,
		LogarithmicCircuitSizeClaim:             false,
		GarblerInputBitsPerCircuit:              garblerBits,
		EvaluatorInputBitsPerCircuit:            evaluatorBits,
		TotalInputBitsPerCircuit:                totalBits,
		PrivateRandomBytesPerPeerPerCircuit:     randomBytes,
		ProjectedGateCountUpper:                 projectedGates,
		ProjectedNonXORGateCountUpper:           projectedNonXOR,
		ProjectedWireCountUpper:                 projectedWires,
		ProjectedGarbledTableBytesUpper:         projectedGarbledBytes,
		ProjectedWireLabelBytesUpper:            projectedWireBytes,
		ProjectedCompilerAllocationBytesUpper:   projectedWireBytes * 10,
		MaximumProjectedGateCount:               jointDPGaussianOneDrawMaxProjectedGates,
		MaximumProjectedNonXORGateCount:         jointDPGaussianOneDrawMaxProjectedNonXOR,
		MaximumProjectedGarbledTableBytes:       jointDPGaussianOneDrawMaxProjectedGarbledBytes,
		MaximumProjectedWireLabelBytes:          jointDPGaussianOneDrawMaxProjectedWireBytes,
		MaximumProjectedCompilerAllocationBytes: jointDPGaussianOneDrawMaxProjectedCompilerBytes,
		WireLabelBytes:                          16,
		CostProjectionIsConservative:            true,
		CircuitTypedInputBitLimit:               exactGCMaxCircuitTypeBits,
		RequestBindingSHA256:                    base.RequestBindingSHA256,
		EpsilonNumerator:                        base.EpsilonNumerator,
		EpsilonDenominator:                      base.EpsilonDenominator,
		AllocatedDeltaNumerator:                 base.AllocatedDeltaNumerator,
		AllocatedDeltaDenominator:               base.AllocatedDeltaDenominator,
		CoreDeltaNumerator:                      base.CoreDeltaNumerator,
		CoreDeltaDenominator:                    base.CoreDeltaDenominator,
		L2SensitivitySteps:                      sensitivity.String(),
		RhoNumerator:                            base.RhoNumerator, RhoDenominator: base.RhoDenominator,
		SigmaSquaredNumerator:           base.SigmaSquaredNumerator,
		SigmaSquaredDenominator:         base.SigmaSquaredDenominator,
		MaximumNoiseMagnitude:           maximum.String(),
		VectorTailTVUpperNumerator:      base.VectorTailTVUpperNumerator,
		VectorTailTVUpperDenominator:    base.VectorTailTVUpperDenominator,
		VectorCDFTVUpperNumerator:       cdfNum,
		VectorCDFTVUpperDenominator:     cdfDen,
		VectorTotalTVUpperNumerator:     totalNum,
		VectorTotalTVUpperDenominator:   totalDen,
		ImplementationDeltaNumerator:    implementationNum,
		ImplementationDeltaDenominator:  implementationDen,
		SamplerRandomBitsPerCoordinate:  128,
		SamplerPrivateBitsPerCoordinate: 129,
		SamplerTablePrecisionBits:       base.SamplerTablePrecisionBits,
		SamplerMagnitudeCount:           len(cumulative),
		SamplerSearchSteps:              table.LookupDepth,
		CDFCumulative:                   cumulative, Simultaneous95Abs: accuracy.String(),
		Accounting: "delta=delta_core+(1+exp(epsilon))*" +
			"(vector_tail_TV+vector_exact_dyadic_CDF_TV); one ideal " +
			"integer discrete-Gaussian vector draw is rho-zCDP; fixed support " +
			"and CDF approximation are transferred once, never per peer",
		PrivacyTheorem: "CKS2020 Theorem 14 + Equation 16 + Corollary 17; " +
			"one integer-valued vector draw with public global L2 sensitivity",
		FiniteSupportTransferCharged: true, FixedWorkSampler: true,
		NoWrapCertified: true, DesignatedComputePeerCount: 2,
		CapabilityAvailable: true,
		FallbackAvailable:   true, FallbackMechanism: jointDPGaussianMechanism,
		FallbackPlanVersion: jointDPGaussianPlanVersion, FallbackAutomatic: false,
		FallbackSelection:                      "explicit_release_policy_only_never_automatic_v1",
		FallbackNominalVarianceMultiplier:      2,
		FallbackNominalStandardDeviationFactor: "sqrt(2)_relative_to_one_full_draw",
		FallbackThreatModel:                    "analyst_may_collude_with_at_most_one_of_two_pinned_semi_honest_noise_peers_and_each_single_source_share_is_simulatable",
		FallbackUtilityCertificate:             "two_independent_complete_discrete_gaussian_draws_variances_add_exactly; same_formal_epsilon_delta_conditional_on_either_peer_view; nominal_variance_x2_sd_x_sqrt2_v1",
	}, nil
}

// Parse public rational certificate fields without floating-point rounding.
func jointDPGaussianOneDrawRat(numerator, denominator string) *big.Rat {
	value := new(big.Rat)
	if _, ok := value.SetString(numerator + "/" + denominator); !ok ||
		value.Sign() < 0 {
		return nil
	}
	return value
}

type jointDPGaussianOneDrawSpec struct {
	RingBits                     int
	FracBits                     int
	OutputLatticeBits            int
	TotalCoordinateCount         int
	ChunkStart                   int
	CoordinateCount              int
	Epsilon                      *big.Rat
	AllocatedDelta               *big.Rat
	L2SensitivitySteps           *big.Int
	L2SensitivityCertificateKind string
	L2SensitivityCertificate     [32]byte
	ReleaseBindingDomain         string
	ReleaseBindingCanonicalJSON  string
	ScaleShifts                  []int
	RawUpperBounds               []*big.Int
	MaximumNoise                 *big.Int
	CDFCumulative                []*big.Int
	RandomBits                   int
	TablePrecisionBits           int
	SearchSteps                  int
	TranscriptHash               [32]byte
	ReleaseBinding               [32]byte
	CrossSignedPolicy            [32]byte
	PinsetSHA256                 [32]byte
	CustodianCount               int
	GarblerPeerID                string
	EvaluatorPeerID              string
	GarblerCommitmentContext     [32]byte
	EvaluatorCommitmentContext   [32]byte
	GarblerSeedCommitment        [32]byte
	EvaluatorSeedCommitment      [32]byte
	Plan                         jointDPGaussianOneDrawPlanOutput
}

type jointDPGaussianOneDrawWorkerPolicy struct {
	Version                        string                           `json:"version"`
	Mechanism                      string                           `json:"mechanism"`
	Allocation                     string                           `json:"allocation"`
	RingBits                       int                              `json:"ring_bits"`
	FracBits                       int                              `json:"frac_bits"`
	TotalCoordinateCount           int                              `json:"total_coordinate_count"`
	ChunkStart                     int                              `json:"chunk_start"`
	CoordinateCount                int                              `json:"coordinate_count"`
	OutputLatticeBits              int                              `json:"output_lattice_bits"`
	Epsilon                        string                           `json:"epsilon"`
	AllocatedDelta                 string                           `json:"allocated_delta"`
	L2SensitivitySteps             string                           `json:"l2_sensitivity_steps"`
	L2SensitivityCertificateKind   string                           `json:"l2_sensitivity_certificate_kind"`
	L2SensitivityCertificateSHA256 string                           `json:"l2_sensitivity_certificate_sha256"`
	ReleaseBindingDomain           string                           `json:"release_binding_domain"`
	ReleaseBindingCanonicalJSON    string                           `json:"release_binding_canonical_json"`
	ScaleShifts                    []int                            `json:"scale_shifts"`
	RawUpperBounds                 []string                         `json:"raw_upper_bounds"`
	ReleaseBindingSHA256           string                           `json:"release_binding_sha256"`
	CrossSignedPolicySHA256        string                           `json:"cross_signed_policy_sha256"`
	TranscriptHash                 string                           `json:"transcript_hash"`
	PinsetSHA256                   string                           `json:"pinset_sha256"`
	CustodianCount                 int                              `json:"custodian_count"`
	DesignatedComputePeerCount     int                              `json:"designated_compute_peer_count"`
	GarblerPeerID                  string                           `json:"garbler_peer_id"`
	EvaluatorPeerID                string                           `json:"evaluator_peer_id"`
	GarblerCommitmentContext       string                           `json:"garbler_commitment_context"`
	EvaluatorCommitmentContext     string                           `json:"evaluator_commitment_context"`
	GarblerSeedCommitment          string                           `json:"garbler_seed_commitment"`
	EvaluatorSeedCommitment        string                           `json:"evaluator_seed_commitment"`
	CDFCumulative                  []string                         `json:"cdf_cumulative"`
	CircuitDigest                  string                           `json:"circuit_digest"`
	Plan                           jointDPGaussianOneDrawPlanOutput `json:"plan"`
}

type jointDPGaussianOneDrawWorkerContractInput struct {
	Version                        string   `json:"version"`
	RingBits                       int      `json:"ring_bits"`
	FracBits                       int      `json:"frac_bits"`
	TotalCoordinateCount           int      `json:"total_coordinate_count"`
	ChunkStart                     int      `json:"chunk_start"`
	CoordinateCount                int      `json:"coordinate_count"`
	OutputLatticeBits              int      `json:"output_lattice_bits"`
	Epsilon                        string   `json:"epsilon"`
	AllocatedDelta                 string   `json:"allocated_delta"`
	L2SensitivitySteps             string   `json:"l2_sensitivity_steps"`
	L2SensitivityCertificateKind   string   `json:"l2_sensitivity_certificate_kind"`
	L2SensitivityCertificateSHA256 string   `json:"l2_sensitivity_certificate_sha256"`
	ReleaseBindingDomain           string   `json:"release_binding_domain"`
	ReleaseBindingCanonicalJSON    string   `json:"release_binding_canonical_json"`
	ScaleShifts                    []int    `json:"scale_shifts"`
	RawUpperBounds                 []string `json:"raw_upper_bounds"`
	ReleaseBindingSHA256           string   `json:"release_binding_sha256"`
	CrossSignedPolicySHA256        string   `json:"cross_signed_policy_sha256"`
	TranscriptHash                 string   `json:"transcript_hash"`
	PinsetSHA256                   string   `json:"pinset_sha256"`
	CustodianCount                 int      `json:"custodian_count"`
	DesignatedComputePeerCount     int      `json:"designated_compute_peer_count"`
	GarblerPeerID                  string   `json:"garbler_peer_id"`
	EvaluatorPeerID                string   `json:"evaluator_peer_id"`
	GarblerCommitmentContext       string   `json:"garbler_commitment_context"`
	EvaluatorCommitmentContext     string   `json:"evaluator_commitment_context"`
	GarblerSeedCommitment          string   `json:"garbler_seed_commitment"`
	EvaluatorSeedCommitment        string   `json:"evaluator_seed_commitment"`
}

type jointDPGaussianOneDrawWorkerContractOutput struct {
	Version                    string                             `json:"version"`
	CapabilityID               string                             `json:"capability_id"`
	Operation                  string                             `json:"operation"`
	Mechanism                  string                             `json:"mechanism"`
	Allocation                 string                             `json:"allocation"`
	Purpose                    string                             `json:"purpose"`
	CircuitDigest              string                             `json:"circuit_digest"`
	InputContract              string                             `json:"input_contract"`
	ProtectedInputsAccepted    bool                               `json:"protected_inputs_accepted"`
	PrivateSeedAccepted        bool                               `json:"private_seed_accepted"`
	CustodianCount             int                                `json:"custodian_count"`
	DesignatedComputePeerCount int                                `json:"designated_compute_peer_count"`
	CircuitGateCount           int                                `json:"circuit_gate_count"`
	CircuitNonXORGateCount     uint64                             `json:"circuit_non_xor_gate_count"`
	CircuitWireCount           int                                `json:"circuit_wire_count"`
	CircuitInputBits           int                                `json:"circuit_input_bits"`
	GarbledTableBytes          int64                              `json:"garbled_table_bytes"`
	WireLabelResidentBytes     int64                              `json:"wire_label_resident_bytes"`
	WorkerPolicy               jointDPGaussianOneDrawWorkerPolicy `json:"worker_policy"`
	Plan                       jointDPGaussianOneDrawPlanOutput   `json:"plan"`
	CapabilityAvailable        bool                               `json:"capability_available"`
	UnavailableReason          string                             `json:"unavailable_reason"`
}

func jointDPGaussianOneDrawDecodeHex(value, what string) ([32]byte, error) {
	decoded, err := jointDPDecodeHex32(value, what)
	if err != nil || decoded == ([32]byte{}) {
		return [32]byte{}, fmt.Errorf("invalid %s", what)
	}
	return decoded, nil
}

func jointDPGaussianOneDrawValidateReleaseBinding(
	policy jointDPGaussianOneDrawWorkerPolicy) error {
	if policy.ReleaseBindingDomain == formalCoxRuntimeReleaseDomain {
		return formalCoxValidateRuntimeReleaseBinding(policy)
	}
	if policy.ReleaseBindingDomain != formalGLMPhase16ReleaseDomain ||
		len(policy.ReleaseBindingCanonicalJSON) == 0 ||
		len(policy.ReleaseBindingCanonicalJSON) >
			jointDPGaussianOneDrawMaxBindingBytes {
		return fmt.Errorf("joint-dp-gaussian-one-draw: invalid release-binding preimage")
	}
	var binding formalGLMPhase16ReleaseBinding
	if err := json.Unmarshal(
		[]byte(policy.ReleaseBindingCanonicalJSON), &binding); err != nil {
		return fmt.Errorf("joint-dp-gaussian-one-draw: decode release-binding preimage")
	}
	if binding.BindingSHA256 != "" {
		return fmt.Errorf("joint-dp-gaussian-one-draw: release-binding preimage is self-referential")
	}
	canonical, err := json.Marshal(binding)
	if err != nil || !bytes.Equal(canonical,
		[]byte(policy.ReleaseBindingCanonicalJSON)) {
		return fmt.Errorf("joint-dp-gaussian-one-draw: non-canonical release-binding preimage")
	}
	digest := sha256.Sum256(append(
		[]byte(policy.ReleaseBindingDomain+"|"), canonical...))
	digestHex := hex.EncodeToString(digest[:])
	if digestHex != policy.ReleaseBindingSHA256 ||
		digestHex != policy.CrossSignedPolicySHA256 {
		return fmt.Errorf("joint-dp-gaussian-one-draw: cross-signed release-binding digest mismatch")
	}
	certificateDigest, err := formalGLMPhase15DPSensitivityCertificateDigest(
		binding.SensitivityCertificate)
	if err != nil {
		return err
	}
	certificateHex := hex.EncodeToString(certificateDigest[:])
	// The biomedical route must never promote generic machine_proven, while
	// formal GLM must never inherit the biomedical pending-materializer status.
	validSensitivityStatus :=
		jointDPBiomedicalGaussianWorkerSensitivityStatusAllowed(binding)
	if binding.Version != formalGLMPhase16ReleaseVersion ||
		binding.Mechanism != jointDPGaussianOneDrawMechanism ||
		binding.Allocation != jointDPGaussianOneDrawAllocation ||
		binding.Epsilon != policy.Epsilon ||
		binding.AllocatedDelta != policy.AllocatedDelta ||
		binding.CommonRingBits != 128 ||
		binding.OutputLatticeBits != policy.OutputLatticeBits ||
		binding.CoordinateCount != policy.TotalCoordinateCount {
		return fmt.Errorf("joint-dp-gaussian-one-draw: release geometry is not included in the cross-signed binding")
	}
	sensitivityMismatch := make([]string, 0, 10)
	for _, check := range []struct {
		name string
		bad  bool
	}{
		{"norm", binding.SensitivityNorm != "l2"},
		{"steps", binding.SensitivitySteps != policy.L2SensitivitySteps},
		{"kind", binding.SensitivityCertificateKind != jointDPGaussianOneDrawSensitivityCertificateKind},
		{"policy_kind", binding.SensitivityCertificateKind != policy.L2SensitivityCertificateKind},
		{"binding_digest", binding.SensitivityCertificateSHA256 != certificateHex},
		{"policy_digest", certificateHex != policy.L2SensitivityCertificateSHA256},
		{"embedded_kind", binding.SensitivityCertificate.Kind != jointDPGaussianOneDrawSensitivityCertificateKind},
		{"status", !validSensitivityStatus},
		{"embedded_norm", binding.SensitivityCertificate.Norm != "l2"},
		{"selected_proof", binding.SensitivityCertificate.SelectedProof != binding.SensitivityProof},
		{"selected_steps", binding.SensitivityCertificate.SelectedBoundSteps != binding.SensitivitySteps},
	} {
		if check.bad {
			sensitivityMismatch = append(sensitivityMismatch, check.name)
		}
	}
	if len(sensitivityMismatch) != 0 {
		return fmt.Errorf("joint-dp-gaussian-one-draw: sensitivity certificate is not included in the cross-signed release binding (%s)",
			strings.Join(sensitivityMismatch, ","))
	}
	if binding.ReleaseContractSHA256 != policy.TranscriptHash ||
		binding.PinsetSHA256 != policy.PinsetSHA256 ||
		binding.CustodianCount != policy.CustodianCount ||
		binding.GarblerPeerID != policy.GarblerPeerID ||
		binding.EvaluatorPeerID != policy.EvaluatorPeerID ||
		binding.GarblerCommitmentContext !=
			policy.GarblerCommitmentContext ||
		binding.EvaluatorCommitmentContext !=
			policy.EvaluatorCommitmentContext ||
		binding.GarblerSeedCommitment != policy.GarblerSeedCommitment ||
		binding.EvaluatorSeedCommitment != policy.EvaluatorSeedCommitment ||
		binding.OpeningCount != 1 ||
		len(binding.ShiftedUpperBounds) != policy.TotalCoordinateCount {
		return fmt.Errorf("joint-dp-gaussian-one-draw: release authority is not included in the cross-signed binding")
	}
	for local := 0; local < policy.CoordinateCount; local++ {
		absolute := policy.ChunkStart + local
		shift := policy.ScaleShifts[local]
		rawUpper, rawErr := jointDPVectorParseInt(
			policy.RawUpperBounds[local], "raw upper bound", false)
		shiftedUpper, shiftedErr := jointDPVectorParseInt(
			binding.ShiftedUpperBounds[absolute], "shifted upper bound", false)
		if shift < 0 || shift > policy.OutputLatticeBits ||
			rawErr != nil || shiftedErr != nil ||
			new(big.Int).Lsh(rawUpper, uint(shift)).Cmp(shiftedUpper) != 0 {
			return fmt.Errorf("joint-dp-gaussian-one-draw: chunk geometry is not included in the release binding")
		}
	}
	return nil
}

func (s jointDPGaussianOneDrawSpec) validate() error {
	if s.RingBits != 128 || s.FracBits != 0 ||
		s.OutputLatticeBits < 1 || s.OutputLatticeBits > 62 ||
		s.TotalCoordinateCount < 1 ||
		s.TotalCoordinateCount > jointDPVectorMaxTotal ||
		s.CoordinateCount < 1 ||
		s.CoordinateCount > jointDPGaussianOneDrawMaxCoordinates ||
		s.ChunkStart < 0 ||
		s.ChunkStart > s.TotalCoordinateCount-s.CoordinateCount ||
		s.Epsilon == nil || s.Epsilon.Sign() <= 0 ||
		s.AllocatedDelta == nil || s.AllocatedDelta.Sign() <= 0 ||
		s.AllocatedDelta.Cmp(big.NewRat(1, 1)) >= 0 ||
		s.L2SensitivitySteps == nil || s.L2SensitivitySteps.Sign() <= 0 ||
		s.L2SensitivityCertificateKind !=
			jointDPGaussianOneDrawSensitivityCertificateKind ||
		s.RandomBits != 128 || s.TablePrecisionBits < 128 ||
		s.SearchSteps < 1 || s.MaximumNoise == nil || s.MaximumNoise.Sign() < 0 ||
		len(s.CDFCumulative) == 0 ||
		len(s.CDFCumulative) != s.Plan.SamplerMagnitudeCount ||
		len(s.ScaleShifts) != s.CoordinateCount ||
		len(s.RawUpperBounds) != s.CoordinateCount ||
		s.CoordinateCount > jointDPGaussianOneDrawMaxChunk(len(s.CDFCumulative)) {
		return exactGCFailure(exactGCFailureNumericBackendUnavailable,
			fmt.Errorf("joint-dp-gaussian-one-draw: invalid public circuit shape"))
	}
	if s.CustodianCount < 2 ||
		!jointDPGaussianOneDrawPinnedPeer.MatchString(s.GarblerPeerID) ||
		!jointDPGaussianOneDrawPinnedPeer.MatchString(s.EvaluatorPeerID) ||
		s.GarblerPeerID >= s.EvaluatorPeerID ||
		s.ReleaseBinding != s.CrossSignedPolicy ||
		s.L2SensitivityCertificate == ([32]byte{}) ||
		!jointDPGaussianOneDrawReleaseBindingDomainAllowed(
			s.ReleaseBindingDomain) ||
		len(s.ReleaseBindingCanonicalJSON) == 0 ||
		s.TranscriptHash == ([32]byte{}) || s.PinsetSHA256 == ([32]byte{}) {
		return fmt.Errorf("joint-dp-gaussian-one-draw: invalid pinned release binding")
	}
	expectedG := jointDPCommitmentContext(s.TranscriptHash,
		jointDPGaussianOneDrawCommitmentPurpose+"/garbler", s.GarblerPeerID)
	expectedE := jointDPCommitmentContext(s.TranscriptHash,
		jointDPGaussianOneDrawCommitmentPurpose+"/evaluator", s.EvaluatorPeerID)
	if s.GarblerCommitmentContext != expectedG ||
		s.EvaluatorCommitmentContext != expectedE {
		return fmt.Errorf("joint-dp-gaussian-one-draw: seed commitment context mismatch")
	}
	grid := new(big.Int).Lsh(big.NewInt(1), uint(s.RandomBits))
	previous := new(big.Int)
	for index, threshold := range s.CDFCumulative {
		if threshold == nil || threshold.Sign() < 0 ||
			threshold.Cmp(grid) > 0 || threshold.Cmp(previous) < 0 {
			return fmt.Errorf("joint-dp-gaussian-one-draw: invalid exact CDF")
		}
		if index != len(s.CDFCumulative)-1 {
			previous.Set(threshold)
		}
	}
	if s.CDFCumulative[len(s.CDFCumulative)-1].Cmp(grid) != 0 ||
		s.MaximumNoise.Cmp(big.NewInt(int64(len(s.CDFCumulative)-1))) != 0 ||
		s.MaximumNoise.Cmp(exactGCMaxSigned(128)) > 0 {
		return fmt.Errorf("joint-dp-gaussian-one-draw: CDF/support certificate mismatch")
	}
	maxSigned := exactGCMaxSigned(128)
	for index, upper := range s.RawUpperBounds {
		shift := s.ScaleShifts[index]
		if upper == nil || upper.Sign() < 0 || shift < 0 ||
			shift > s.OutputLatticeBits || upper.Cmp(maxSigned) > 0 ||
			new(big.Int).Lsh(new(big.Int).Set(upper), uint(shift)).Cmp(maxSigned) > 0 {
			return exactGCFailure(exactGCFailureBoundExceeded,
				fmt.Errorf("joint-dp-gaussian-one-draw: scaled bound outside Ring128"))
		}
	}
	return nil
}

func jointDPGaussianOneDrawDigestWrite(h io.Writer, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = h.Write(length[:])
	_, _ = h.Write([]byte(value))
}

// globalStreamDigest intentionally excludes public chunk geometry. Absolute
// coordinate, bound and shift are appended per coordinate, so rechunking an
// immutable capsule cannot reroll any draw.
func (s jointDPGaussianOneDrawSpec) globalStreamDigest() [32]byte {
	h := sha256.New()
	h.Write([]byte(jointDPGaussianOneDrawTemplateVersion + "/stream-domain"))
	for _, value := range []string{
		jointDPGaussianOneDrawMechanism, jointDPGaussianOneDrawAllocation,
		strconv.Itoa(s.RingBits), strconv.Itoa(s.FracBits),
		strconv.Itoa(s.OutputLatticeBits), strconv.Itoa(s.TotalCoordinateCount),
		s.Epsilon.RatString(), s.AllocatedDelta.RatString(),
		s.L2SensitivitySteps.String(), s.L2SensitivityCertificateKind,
		hex.EncodeToString(s.L2SensitivityCertificate[:]), s.MaximumNoise.String(),
		s.ReleaseBindingDomain,
		strconv.Itoa(s.RandomBits), strconv.Itoa(s.TablePrecisionBits),
		hex.EncodeToString(s.ReleaseBinding[:]),
		hex.EncodeToString(s.CrossSignedPolicy[:]),
		hex.EncodeToString(s.TranscriptHash[:]),
		hex.EncodeToString(s.PinsetSHA256[:]),
		strconv.Itoa(s.CustodianCount), "2", s.GarblerPeerID, s.EvaluatorPeerID,
		hex.EncodeToString(s.GarblerCommitmentContext[:]),
		hex.EncodeToString(s.EvaluatorCommitmentContext[:]),
		hex.EncodeToString(s.GarblerSeedCommitment[:]),
		hex.EncodeToString(s.EvaluatorSeedCommitment[:]),
	} {
		jointDPGaussianOneDrawDigestWrite(h, value)
	}
	for _, threshold := range s.CDFCumulative {
		jointDPGaussianOneDrawDigestWrite(h, threshold.String())
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func (s jointDPGaussianOneDrawSpec) contractDigest() [32]byte {
	h := sha256.New()
	h.Write([]byte(jointDPGaussianOneDrawTemplateVersion + "/contract"))
	stream := s.globalStreamDigest()
	h.Write(stream[:])
	for _, value := range []string{
		strconv.Itoa(s.ChunkStart), strconv.Itoa(s.CoordinateCount),
	} {
		jointDPGaussianOneDrawDigestWrite(h, value)
	}
	for index := range s.RawUpperBounds {
		jointDPGaussianOneDrawDigestWrite(h, strconv.Itoa(s.ScaleShifts[index]))
		jointDPGaussianOneDrawDigestWrite(h, s.RawUpperBounds[index].String())
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func (s jointDPGaussianOneDrawSpec) circuitShapeDigest() [32]byte {
	h := sha256.New()
	h.Write([]byte(jointDPGaussianOneDrawTemplateVersion + "/shape"))
	for _, value := range []string{
		strconv.Itoa(s.CoordinateCount), strconv.Itoa(s.RandomBits),
		strconv.Itoa(s.SearchSteps),
	} {
		jointDPGaussianOneDrawDigestWrite(h, value)
	}
	for _, threshold := range s.CDFCumulative {
		jointDPGaussianOneDrawDigestWrite(h, threshold.String())
	}
	for _, shift := range s.ScaleShifts {
		jointDPGaussianOneDrawDigestWrite(h, strconv.Itoa(shift))
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func (s jointDPGaussianOneDrawSpec) digest() [32]byte {
	h := sha256.New()
	h.Write([]byte(jointDPGaussianOneDrawTemplateVersion))
	contract := s.contractDigest()
	shape := s.circuitShapeDigest()
	assets := jointDPMPCLManifestDigest()
	h.Write(contract[:])
	h.Write(shape[:])
	h.Write(assets[:])
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func (s jointDPGaussianOneDrawSpec) purpose() string {
	digest := s.digest()
	return string(jointDPGaussianOneDrawOperation) + "/" +
		hex.EncodeToString(digest[:])
}

func jointDPGaussianOneDrawPrivateInputs(seed [32]byte,
	s jointDPGaussianOneDrawSpec, role string,
) ([]*big.Int, []bool, error) {
	return jointDPGaussianOneDrawPrivateInputsBound(seed, s, role, nil)
}

func jointDPGaussianOneDrawPrivateInputsBound(seed [32]byte,
	s jointDPGaussianOneDrawSpec, role string, productiveStream *[32]byte,
) ([]*big.Int, []bool, error) {
	if err := s.validate(); err != nil {
		return nil, nil, err
	}
	if role != "garbler" && role != "evaluator" {
		return nil, nil, fmt.Errorf("joint-dp-gaussian-one-draw: invalid stream role")
	}
	commitment := s.GarblerSeedCommitment
	context := s.GarblerCommitmentContext
	if role == "evaluator" {
		commitment = s.EvaluatorSeedCommitment
		context = s.EvaluatorCommitmentContext
	}
	if jointDPSeedCommitment(context, seed) != commitment {
		return nil, nil,
			fmt.Errorf("joint-dp-gaussian-one-draw: private seed commitment mismatch")
	}
	streamDomain := s.globalStreamDigest()
	words := make([]*big.Int, s.CoordinateCount)
	signs := make([]bool, s.CoordinateCount)
	for local := 0; local < s.CoordinateCount; local++ {
		absolute := s.ChunkStart + local
		info := bytes.NewBuffer(nil)
		info.WriteString("dsVert/joint-dp/gaussian-one-draw/private-stream/v1/")
		info.WriteString(role)
		info.WriteByte(0)
		info.Write(streamDomain[:])
		if productiveStream != nil {
			info.WriteString("/biomedical-productive-stream/v1")
			info.WriteByte(0)
			info.Write(productiveStream[:])
		}
		var coordinate [8]byte
		binary.BigEndian.PutUint64(coordinate[:], uint64(absolute))
		info.Write(coordinate[:])
		var shift [4]byte
		binary.BigEndian.PutUint32(shift[:], uint32(s.ScaleShifts[local]))
		info.Write(shift[:])
		jointDPGaussianOneDrawDigestWrite(info, s.RawUpperBounds[local].String())
		reader := hkdf.New(sha256.New, seed[:], s.TranscriptHash[:], info.Bytes())
		material := make([]byte, chacha20.KeySize+chacha20.NonceSize)
		if _, err := io.ReadFull(reader, material); err != nil {
			exactGCZeroBigInts(words)
			clear(material)
			return nil, nil, fmt.Errorf("joint-dp-gaussian-one-draw: derive stream")
		}
		cipher, err := chacha20.NewUnauthenticatedCipher(
			material[:chacha20.KeySize], material[chacha20.KeySize:])
		clear(material)
		if err != nil {
			exactGCZeroBigInts(words)
			return nil, nil, fmt.Errorf("joint-dp-gaussian-one-draw: initialize stream")
		}
		private := make([]byte, 17)
		cipher.XORKeyStream(private, private)
		word := append([]byte(nil), private[:16]...)
		for left, right := 0, len(word)-1; left < right; left, right = left+1, right-1 {
			word[left], word[right] = word[right], word[left]
		}
		words[local] = new(big.Int).SetBytes(word)
		signs[local] = private[16]&1 == 1
		clear(word)
		clear(private)
	}
	return words, signs, nil
}

func jointDPGaussianOneDrawSelectMagnitude(draw *big.Int,
	cumulative []*big.Int) (*big.Int, error) {
	if draw == nil || draw.Sign() < 0 || draw.BitLen() > 128 ||
		len(cumulative) == 0 {
		return nil, fmt.Errorf("joint-dp-gaussian-one-draw: invalid CDF draw")
	}
	low, high := 0, len(cumulative)
	for low < high {
		middle := low + (high-low)/2
		if draw.Cmp(cumulative[middle]) < 0 {
			high = middle
		} else {
			low = middle + 1
		}
	}
	if low >= len(cumulative) {
		return nil, fmt.Errorf("joint-dp-gaussian-one-draw: CDF did not close")
	}
	return big.NewInt(int64(low)), nil
}

func jointDPGaussianOneDrawReferenceNoise(s jointDPGaussianOneDrawSpec,
	garblerSeed, evaluatorSeed [32]byte,
) ([]*big.Int, error) {
	leftWords, leftSigns, err := jointDPGaussianOneDrawPrivateInputs(
		garblerSeed, s, "garbler")
	if err != nil {
		return nil, err
	}
	defer exactGCZeroBigInts(leftWords)
	rightWords, rightSigns, err := jointDPGaussianOneDrawPrivateInputs(
		evaluatorSeed, s, "evaluator")
	if err != nil {
		return nil, err
	}
	defer exactGCZeroBigInts(rightWords)
	result := make([]*big.Int, s.CoordinateCount)
	for index := range result {
		draw := new(big.Int).Xor(leftWords[index], rightWords[index])
		magnitude, err := jointDPGaussianOneDrawSelectMagnitude(
			draw, s.CDFCumulative)
		draw.SetInt64(0)
		if err != nil {
			exactGCZeroBigInts(result)
			return nil, err
		}
		if magnitude.Sign() != 0 && leftSigns[index] != rightSigns[index] {
			magnitude.Neg(magnitude)
		}
		result[index] = magnitude
	}
	return result, nil
}

func jointDPGaussianOneDrawEmitCDFTree(source *strings.Builder,
	indent, draw, magnitude string, cumulative []*big.Int, low, high int,
	grid *big.Int) {
	if low == high {
		fmt.Fprintf(source, "%s%s = uint128(%d)\n", indent, magnitude, low)
		return
	}
	middle := low + (high-low)/2
	threshold := cumulative[middle]
	if threshold.Sign() == 0 {
		jointDPGaussianOneDrawEmitCDFTree(
			source, indent, draw, magnitude, cumulative, middle+1, high, grid)
		return
	}
	if threshold.Cmp(grid) == 0 {
		jointDPGaussianOneDrawEmitCDFTree(
			source, indent, draw, magnitude, cumulative, low, middle, grid)
		return
	}
	fmt.Fprintf(source, "%sif %s < uint128(%s) {\n", indent, draw,
		threshold.String())
	jointDPGaussianOneDrawEmitCDFTree(
		source, indent+"\t", draw, magnitude, cumulative, low, middle, grid)
	fmt.Fprintf(source, "%s} else {\n", indent)
	jointDPGaussianOneDrawEmitCDFTree(
		source, indent+"\t", draw, magnitude, cumulative, middle+1, high, grid)
	fmt.Fprintf(source, "%s}\n", indent)
}

func jointDPGaussianOneDrawCircuitSource(s jointDPGaussianOneDrawSpec) string {
	var source strings.Builder
	source.WriteString("package main\n")
	fmt.Fprintf(&source,
		"type Garbler struct {\n\tStat [%d]uint128\n\tRandom [%d]uint128\n\tSign [%d]bool\n\tRawUpper [%d]uint128\n\tOutputMask [%d]uint128\n\tValidityMask bool\n}\n",
		s.CoordinateCount, s.CoordinateCount, s.CoordinateCount,
		s.CoordinateCount, s.CoordinateCount)
	fmt.Fprintf(&source,
		"type Evaluator struct {\n\tStat [%d]uint128\n\tRandom [%d]uint128\n\tSign [%d]bool\n}\n",
		s.CoordinateCount, s.CoordinateCount, s.CoordinateCount)
	fmt.Fprintf(&source, "func main(g Garbler, e Evaluator) [%d]uint128 {\n",
		s.CoordinateCount+1)
	source.WriteString("\tvalid := true\n")
	grid := new(big.Int).Lsh(big.NewInt(1), 128)
	for coordinate := 0; coordinate < s.CoordinateCount; coordinate++ {
		fmt.Fprintf(&source,
			"\traw%d := g.Stat[%d] + e.Stat[%d]\n\tvalid = valid && raw%d <= g.RawUpper[%d]\n",
			coordinate, coordinate, coordinate, coordinate, coordinate)
		fmt.Fprintf(&source,
			"\tx%d := raw%d << %d\n\tupper%d := g.RawUpper[%d] << %d\n",
			coordinate, coordinate, s.ScaleShifts[coordinate], coordinate,
			coordinate, s.ScaleShifts[coordinate])
		fmt.Fprintf(&source,
			"\tdraw%d := g.Random[%d] ^ e.Random[%d]\n\tnegative%d := g.Sign[%d] != e.Sign[%d]\n\tvar magnitude%d uint128\n",
			coordinate, coordinate, coordinate, coordinate, coordinate,
			coordinate, coordinate)
		jointDPGaussianOneDrawEmitCDFTree(&source, "\t", fmt.Sprintf("draw%d", coordinate),
			fmt.Sprintf("magnitude%d", coordinate), s.CDFCumulative, 0,
			len(s.CDFCumulative)-1, grid)
	}
	fmt.Fprintf(&source, "\tvar out [%d]uint128\n", s.CoordinateCount+1)
	for coordinate := 0; coordinate < s.CoordinateCount; coordinate++ {
		fmt.Fprintf(&source, "\tresult%d := x%d\n", coordinate, coordinate)
		fmt.Fprintf(&source,
			"\tif magnitude%d != 0 {\n\t\tif negative%d {\n\t\t\tif magnitude%d > x%d { result%d = 0 } else { result%d = x%d - magnitude%d }\n\t\t} else {\n\t\t\troom%d := upper%d - x%d\n\t\t\tif magnitude%d > room%d { result%d = upper%d } else { result%d = x%d + magnitude%d }\n\t\t}\n\t}\n",
			coordinate, coordinate, coordinate, coordinate, coordinate,
			coordinate, coordinate, coordinate, coordinate, coordinate,
			coordinate, coordinate, coordinate, coordinate, coordinate,
			coordinate, coordinate, coordinate)
		fmt.Fprintf(&source,
			"\tif !valid { result%d = 0 }\n\tout[%d] = result%d - g.OutputMask[%d]\n",
			coordinate, coordinate, coordinate, coordinate)
	}
	fmt.Fprintf(&source,
		"\tout[%d] = uint128(0)\n\tif valid != g.ValidityMask { out[%d] = uint128(1) }\n\treturn out\n}\n",
		s.CoordinateCount, s.CoordinateCount)
	return source.String()
}

var jointDPGaussianOneDrawGCCache = struct {
	sync.Mutex
	entries map[string]*circuit.Circuit
	order   []string
}{entries: make(map[string]*circuit.Circuit)}

func jointDPGaussianOneDrawGCCompile(
	s jointDPGaussianOneDrawSpec,
) (*circuit.Circuit, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	shape := s.circuitShapeDigest()
	key := hex.EncodeToString(shape[:])
	jointDPGaussianOneDrawGCCache.Lock()
	if cached := jointDPGaussianOneDrawGCCache.entries[key]; cached != nil {
		jointDPGaussianOneDrawGCCache.Unlock()
		return cached, nil
	}
	jointDPGaussianOneDrawGCCache.Unlock()
	source := jointDPGaussianOneDrawCircuitSource(s)
	var circ *circuit.Circuit
	err := jointDPWithMPCLRuntime(func() error {
		var compileErr error
		circ, _, compileErr = compiler.New(utils.NewParams()).Compile(source, nil)
		return compileErr
	})
	if err != nil {
		return nil, exactGCFailure(exactGCFailureNumericBackendUnavailable,
			fmt.Errorf("joint-dp-gaussian-one-draw: compile fixed CDF circuit: %w", err))
	}
	if len(circ.Inputs) != 2 || len(circ.Outputs) != 1 ||
		circ.Outputs.Size() != (s.CoordinateCount+1)*128 {
		return nil, fmt.Errorf("joint-dp-gaussian-one-draw: invalid compiled circuit shape")
	}
	jointDPGaussianOneDrawGCCache.Lock()
	if len(jointDPGaussianOneDrawGCCache.order) >= exactGCCircuitCacheEntries {
		oldest := jointDPGaussianOneDrawGCCache.order[0]
		delete(jointDPGaussianOneDrawGCCache.entries, oldest)
		jointDPGaussianOneDrawGCCache.order =
			jointDPGaussianOneDrawGCCache.order[1:]
	}
	jointDPGaussianOneDrawGCCache.entries[key] = circ
	jointDPGaussianOneDrawGCCache.order =
		append(jointDPGaussianOneDrawGCCache.order, key)
	jointDPGaussianOneDrawGCCache.Unlock()
	return circ, nil
}

func jointDPGaussianOneDrawDeterministicMasks(seed [32]byte, digest [32]byte,
	count int,
) ([]*big.Int, bool) {
	result := make([]*big.Int, count)
	for index := range result {
		mac := hmac.New(sha256.New, seed[:])
		mac.Write([]byte("dsVert/joint-dp/gaussian-one-draw/output-mask/v1"))
		mac.Write(digest[:])
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], uint32(index))
		mac.Write(encoded[:])
		result[index] = new(big.Int).SetBytes(mac.Sum(nil)[:16])
	}
	mac := hmac.New(sha256.New, seed[:])
	mac.Write([]byte("dsVert/joint-dp/gaussian-one-draw/validity-mask/v1"))
	mac.Write(digest[:])
	return result, mac.Sum(nil)[0]&1 == 1
}

func jointDPGaussianOneDrawDeterministicMasksBound(seed [32]byte,
	s jointDPGaussianOneDrawSpec, productiveStream *[32]byte,
) ([]*big.Int, bool) {
	if productiveStream == nil {
		return jointDPGaussianOneDrawDeterministicMasks(
			seed, s.digest(), s.CoordinateCount)
	}
	result := make([]*big.Int, s.CoordinateCount)
	for local := range result {
		mac := hmac.New(sha256.New, seed[:])
		mac.Write([]byte("dsVert/joint-dp/gaussian-one-draw/biomedical-output-mask/v1"))
		mac.Write(productiveStream[:])
		var coordinate [8]byte
		binary.BigEndian.PutUint64(coordinate[:], uint64(s.ChunkStart+local))
		mac.Write(coordinate[:])
		result[local] = new(big.Int).SetBytes(mac.Sum(nil)[:16])
	}
	validity := jointDPGaussianOneDrawValidityMaskMaterial(
		seed, s, *productiveStream)
	return result, validity[0]&1 == 1
}

// Payload masks are absolute-coordinate stable so the final vector is byte
// identical after rechunking. The control-bit mask is deliberately scoped to
// one chunk: reusing one bit across chunks would let a peer compare its masked
// validity outputs and learn whether two private validity predicates agree.
func jointDPGaussianOneDrawValidityMaskMaterial(seed [32]byte,
	s jointDPGaussianOneDrawSpec, productiveStream [32]byte,
) [32]byte {
	mac := hmac.New(sha256.New, seed[:])
	mac.Write([]byte("dsVert/joint-dp/gaussian-one-draw/biomedical-validity-mask/v2"))
	mac.Write(productiveStream[:])
	var geometry [16]byte
	binary.BigEndian.PutUint64(geometry[:8], uint64(s.ChunkStart))
	binary.BigEndian.PutUint64(geometry[8:], uint64(s.CoordinateCount))
	mac.Write(geometry[:])
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func jointDPGaussianOneDrawPackInput(shares, random, upper, masks []*big.Int,
	signs []bool, validityMask bool, garbler bool) *big.Int {
	fields := make([]struct {
		value *big.Int
		bits  int
	}, 0, len(shares)+len(random)+len(signs)+len(upper)+len(masks)+1)
	add := func(value *big.Int, bits int) {
		fields = append(fields, struct {
			value *big.Int
			bits  int
		}{value: value, bits: bits})
	}
	for _, value := range shares {
		add(value, 128)
	}
	for _, value := range random {
		add(value, 128)
	}
	for _, value := range signs {
		add(new(big.Int).SetUint64(boolToUint64(value)), 1)
	}
	if garbler {
		for _, value := range upper {
			add(value, 128)
		}
		for _, value := range masks {
			add(value, 128)
		}
		add(new(big.Int).SetUint64(boolToUint64(validityMask)), 1)
	}
	return jointDPPackFields(fields)
}

func jointDPGaussianOneDrawUnpackOutputs(value *big.Int,
	s jointDPGaussianOneDrawSpec) []*big.Int {
	result := make([]*big.Int, s.CoordinateCount+1)
	for index := range result {
		result[index] = new(big.Int).Rsh(new(big.Int).Set(value), uint(index*128))
		bits := 128
		if index == s.CoordinateCount {
			bits = 1
		}
		result[index].And(result[index], exactGCMask(bits))
	}
	return result
}

func jointDPGaussianOneDrawValidateSession(session exactGCSession,
	s jointDPGaussianOneDrawSpec) error {
	if err := session.validate(); err != nil {
		return err
	}
	if session.Spec.Operation != jointDPGaussianOneDrawOperation ||
		session.Spec.RingBits != 128 || session.Spec.FracBits != 0 ||
		session.Spec.VectorLen != s.CoordinateCount ||
		session.GarblerID != s.GarblerPeerID ||
		session.EvaluatorID != s.EvaluatorPeerID ||
		session.Purpose != s.purpose() {
		return fmt.Errorf("joint-dp-gaussian-one-draw: session/role binding mismatch")
	}
	return s.validate()
}

func jointDPGaussianOneDrawRunGarbler(rw io.ReadWriter,
	session exactGCSession, s jointDPGaussianOneDrawSpec,
	shares []*big.Int, seed [32]byte,
) ([]*big.Int, error) {
	return jointDPGaussianOneDrawRunGarblerBound(
		rw, session, s, shares, seed, nil)
}

func jointDPGaussianOneDrawRunGarblerBound(rw io.ReadWriter,
	session exactGCSession, s jointDPGaussianOneDrawSpec,
	shares []*big.Int, seed [32]byte, productiveStream *[32]byte,
) ([]*big.Int, error) {
	if rw == nil {
		return nil, fmt.Errorf("joint-dp-gaussian-one-draw: nil peer channel")
	}
	if err := jointDPGaussianOneDrawValidateSession(session, s); err != nil {
		return nil, err
	}
	if err := exactGCValidateShares(shares, session.Spec); err != nil {
		return nil, err
	}
	random, signs, err := jointDPGaussianOneDrawPrivateInputsBound(
		seed, s, "garbler", productiveStream)
	if err != nil {
		return nil, err
	}
	defer exactGCZeroBigInts(random)
	circ, err := jointDPGaussianOneDrawGCCompile(s)
	if err != nil {
		return nil, err
	}
	masks, validityMask := jointDPGaussianOneDrawDeterministicMasksBound(
		seed, s, productiveStream)
	defer exactGCZeroBigInts(masks)
	input := jointDPGaussianOneDrawPackInput(
		shares, random, s.RawUpperBounds, masks, signs, validityMask, true)
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleGarbler)
	if err != nil {
		return nil, err
	}
	conn := p2p.NewConn(secure)
	protocolErr := exactGCGarblerProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return nil, err
	}
	result := make([]*big.Int, 0, len(masks)+1)
	for _, mask := range masks {
		result = append(result, new(big.Int).Set(mask))
	}
	result = append(result,
		new(big.Int).SetUint64(boolToUint64(validityMask)))
	return result, nil
}

func jointDPGaussianOneDrawRunEvaluator(rw io.ReadWriter,
	session exactGCSession, s jointDPGaussianOneDrawSpec,
	shares []*big.Int, seed [32]byte,
) ([]*big.Int, error) {
	return jointDPGaussianOneDrawRunEvaluatorBound(
		rw, session, s, shares, seed, nil)
}

func jointDPGaussianOneDrawRunEvaluatorBound(rw io.ReadWriter,
	session exactGCSession, s jointDPGaussianOneDrawSpec,
	shares []*big.Int, seed [32]byte, productiveStream *[32]byte,
) ([]*big.Int, error) {
	if rw == nil {
		return nil, fmt.Errorf("joint-dp-gaussian-one-draw: nil peer channel")
	}
	if err := jointDPGaussianOneDrawValidateSession(session, s); err != nil {
		return nil, err
	}
	if err := exactGCValidateShares(shares, session.Spec); err != nil {
		return nil, err
	}
	random, signs, err := jointDPGaussianOneDrawPrivateInputsBound(
		seed, s, "evaluator", productiveStream)
	if err != nil {
		return nil, err
	}
	defer exactGCZeroBigInts(random)
	circ, err := jointDPGaussianOneDrawGCCompile(s)
	if err != nil {
		return nil, err
	}
	input := jointDPGaussianOneDrawPackInput(
		shares, random, nil, nil, signs, false, false)
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleEvaluator)
	if err != nil {
		return nil, err
	}
	conn := p2p.NewConn(secure)
	value, protocolErr := exactGCEvaluatorProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return nil, err
	}
	return jointDPGaussianOneDrawUnpackOutputs(value, s), nil
}

func jointDPGaussianOneDrawPolicySpec(
	policy jointDPGaussianOneDrawWorkerPolicy,
) (jointDPGaussianOneDrawSpec, error) {
	var zero jointDPGaussianOneDrawSpec
	if policy.Version != jointDPGaussianOneDrawTemplateVersion ||
		policy.Mechanism != jointDPGaussianOneDrawMechanism ||
		policy.Allocation != jointDPGaussianOneDrawAllocation ||
		policy.RingBits != 128 || policy.FracBits != 0 ||
		policy.DesignatedComputePeerCount != 2 {
		return zero, fmt.Errorf("joint-dp-gaussian-one-draw: missing worker policy")
	}
	plan, err := jointDPPlanGaussianOneDraw(jointDPGaussianOneDrawPlanInput{
		Epsilon: policy.Epsilon, Delta: policy.AllocatedDelta,
		L2SensitivitySteps:   policy.L2SensitivitySteps,
		TotalCoordinateCount: policy.TotalCoordinateCount,
	})
	if err != nil {
		return zero, err
	}
	if !plan.CapabilityAvailable {
		return zero, exactGCFailure(exactGCFailureNumericBackendUnavailable,
			fmt.Errorf("joint-dp-gaussian-one-draw: %s", plan.UnavailableReason))
	}
	if !reflect.DeepEqual(plan, policy.Plan) ||
		!equalStrings(plan.CDFCumulative, policy.CDFCumulative) {
		return zero, fmt.Errorf("joint-dp-gaussian-one-draw: privacy plan substitution")
	}
	if err := jointDPGaussianOneDrawValidateReleaseBinding(policy); err != nil {
		return zero, err
	}
	epsilon, err := jointDPParseDecimalRat(policy.Epsilon, "epsilon", false)
	if err != nil {
		return zero, err
	}
	delta, err := jointDPParseDecimalRat(
		policy.AllocatedDelta, "allocated_delta", false)
	if err != nil || delta.Cmp(big.NewRat(1, 1)) >= 0 {
		return zero, fmt.Errorf("joint-dp-gaussian-one-draw: invalid allocated delta")
	}
	sensitivity, err := jointDPVectorParseInt(
		policy.L2SensitivitySteps, "L2 sensitivity steps", true)
	if err != nil {
		return zero, err
	}
	maximum, err := jointDPVectorParseInt(
		plan.MaximumNoiseMagnitude, "maximum Gaussian magnitude", false)
	if err != nil {
		return zero, err
	}
	cdf := make([]*big.Int, len(policy.CDFCumulative))
	for index, value := range policy.CDFCumulative {
		cdf[index], err = jointDPVectorParseInt(value, "Gaussian CDF threshold", false)
		if err != nil {
			return zero, err
		}
	}
	upper := make([]*big.Int, len(policy.RawUpperBounds))
	for index, value := range policy.RawUpperBounds {
		upper[index], err = jointDPVectorParseInt(value, "raw upper bound", false)
		if err != nil {
			return zero, err
		}
	}
	transcript, err := jointDPGaussianOneDrawDecodeHex(
		policy.TranscriptHash, "Gaussian transcript hash")
	if err != nil {
		return zero, err
	}
	release, err := jointDPGaussianOneDrawDecodeHex(
		policy.ReleaseBindingSHA256, "Gaussian release binding")
	if err != nil {
		return zero, err
	}
	crossSigned, err := jointDPGaussianOneDrawDecodeHex(
		policy.CrossSignedPolicySHA256, "Gaussian cross-signed policy")
	if err != nil {
		return zero, err
	}
	sensitivityCertificate, err := jointDPGaussianOneDrawDecodeHex(
		policy.L2SensitivityCertificateSHA256, "Gaussian L2 sensitivity certificate")
	if err != nil {
		return zero, err
	}
	pinset, err := jointDPGaussianOneDrawDecodeHex(
		policy.PinsetSHA256, "Gaussian pinset hash")
	if err != nil {
		return zero, err
	}
	gctx, err := jointDPGaussianOneDrawDecodeHex(
		policy.GarblerCommitmentContext, "garbler commitment context")
	if err != nil {
		return zero, err
	}
	ectx, err := jointDPGaussianOneDrawDecodeHex(
		policy.EvaluatorCommitmentContext, "evaluator commitment context")
	if err != nil {
		return zero, err
	}
	gcommit, err := jointDPGaussianOneDrawDecodeHex(
		policy.GarblerSeedCommitment, "garbler seed commitment")
	if err != nil {
		return zero, err
	}
	ecommit, err := jointDPGaussianOneDrawDecodeHex(
		policy.EvaluatorSeedCommitment, "evaluator seed commitment")
	if err != nil {
		return zero, err
	}
	spec := jointDPGaussianOneDrawSpec{
		RingBits: 128, FracBits: 0,
		OutputLatticeBits:    policy.OutputLatticeBits,
		TotalCoordinateCount: policy.TotalCoordinateCount,
		ChunkStart:           policy.ChunkStart, CoordinateCount: policy.CoordinateCount,
		Epsilon: epsilon, AllocatedDelta: delta,
		L2SensitivitySteps:           sensitivity,
		L2SensitivityCertificateKind: policy.L2SensitivityCertificateKind,
		L2SensitivityCertificate:     sensitivityCertificate,
		ReleaseBindingDomain:         policy.ReleaseBindingDomain,
		ReleaseBindingCanonicalJSON:  policy.ReleaseBindingCanonicalJSON,
		ScaleShifts:                  append([]int(nil), policy.ScaleShifts...),
		RawUpperBounds:               upper, MaximumNoise: maximum, CDFCumulative: cdf,
		RandomBits:         plan.SamplerRandomBitsPerCoordinate,
		TablePrecisionBits: plan.SamplerTablePrecisionBits,
		SearchSteps:        plan.SamplerSearchSteps,
		TranscriptHash:     transcript, ReleaseBinding: release,
		CrossSignedPolicy: crossSigned, PinsetSHA256: pinset,
		CustodianCount:             policy.CustodianCount,
		GarblerPeerID:              policy.GarblerPeerID,
		EvaluatorPeerID:            policy.EvaluatorPeerID,
		GarblerCommitmentContext:   gctx,
		EvaluatorCommitmentContext: ectx,
		GarblerSeedCommitment:      gcommit,
		EvaluatorSeedCommitment:    ecommit, Plan: plan,
	}
	return spec, spec.validate()
}

func jointDPGaussianOneDrawSpecFromPolicy(
	policy jointDPGaussianOneDrawWorkerPolicy, session exactGCSession,
) (jointDPGaussianOneDrawSpec, error) {
	spec, err := jointDPGaussianOneDrawPolicySpec(policy)
	if err != nil {
		return jointDPGaussianOneDrawSpec{}, err
	}
	digest := spec.digest()
	if policy.CircuitDigest != hex.EncodeToString(digest[:]) ||
		session.Purpose != spec.purpose() ||
		session.Spec.Operation != jointDPGaussianOneDrawOperation ||
		session.GarblerID != spec.GarblerPeerID ||
		session.EvaluatorID != spec.EvaluatorPeerID {
		return jointDPGaussianOneDrawSpec{},
			fmt.Errorf("joint-dp-gaussian-one-draw: worker circuit binding mismatch")
	}
	return spec, nil
}

func jointDPCompileGaussianOneDrawWorkerContract(
	input jointDPGaussianOneDrawWorkerContractInput,
) (jointDPGaussianOneDrawWorkerContractOutput, error) {
	var zero jointDPGaussianOneDrawWorkerContractOutput
	if input.Version != jointDPGaussianOneDrawWorkerContractInputVersion ||
		input.RingBits != 128 || input.FracBits != 0 ||
		input.OutputLatticeBits < 1 || input.OutputLatticeBits > 62 ||
		input.TotalCoordinateCount < 1 ||
		input.TotalCoordinateCount > jointDPVectorMaxTotal ||
		input.CoordinateCount < 1 ||
		input.CoordinateCount != len(input.ScaleShifts) ||
		input.CoordinateCount != len(input.RawUpperBounds) ||
		input.ChunkStart < 0 ||
		input.ChunkStart > input.TotalCoordinateCount-input.CoordinateCount ||
		input.CustodianCount < 2 || input.DesignatedComputePeerCount != 2 ||
		input.ReleaseBindingSHA256 != input.CrossSignedPolicySHA256 ||
		input.L2SensitivityCertificateKind !=
			jointDPGaussianOneDrawSensitivityCertificateKind ||
		!formalGLMIsSHA256(input.L2SensitivityCertificateSHA256) ||
		!jointDPGaussianOneDrawReleaseBindingDomainAllowed(
			input.ReleaseBindingDomain) ||
		len(input.ReleaseBindingCanonicalJSON) == 0 {
		return zero, fmt.Errorf("unsupported one-draw Gaussian worker contract")
	}
	plan, err := jointDPPlanGaussianOneDraw(jointDPGaussianOneDrawPlanInput{
		Epsilon: input.Epsilon, Delta: input.AllocatedDelta,
		L2SensitivitySteps:   input.L2SensitivitySteps,
		TotalCoordinateCount: input.TotalCoordinateCount,
	})
	if err != nil {
		return zero, err
	}
	if !plan.CapabilityAvailable ||
		input.CoordinateCount > plan.MaximumChunkCoordinates {
		return zero, exactGCFailure(exactGCFailureNumericBackendUnavailable,
			fmt.Errorf("joint-dp-gaussian-one-draw: %s",
				plan.UnavailableReason))
	}
	policy := jointDPGaussianOneDrawWorkerPolicy{
		Version:    jointDPGaussianOneDrawTemplateVersion,
		Mechanism:  jointDPGaussianOneDrawMechanism,
		Allocation: jointDPGaussianOneDrawAllocation,
		RingBits:   128, FracBits: 0,
		TotalCoordinateCount: input.TotalCoordinateCount,
		ChunkStart:           input.ChunkStart, CoordinateCount: input.CoordinateCount,
		OutputLatticeBits: input.OutputLatticeBits,
		Epsilon:           input.Epsilon, AllocatedDelta: input.AllocatedDelta,
		L2SensitivitySteps:             input.L2SensitivitySteps,
		L2SensitivityCertificateKind:   input.L2SensitivityCertificateKind,
		L2SensitivityCertificateSHA256: input.L2SensitivityCertificateSHA256,
		ReleaseBindingDomain:           input.ReleaseBindingDomain,
		ReleaseBindingCanonicalJSON:    input.ReleaseBindingCanonicalJSON,
		ScaleShifts:                    append([]int(nil), input.ScaleShifts...),
		RawUpperBounds:                 append([]string(nil), input.RawUpperBounds...),
		ReleaseBindingSHA256:           input.ReleaseBindingSHA256,
		CrossSignedPolicySHA256:        input.CrossSignedPolicySHA256,
		TranscriptHash:                 input.TranscriptHash,
		PinsetSHA256:                   input.PinsetSHA256,
		CustodianCount:                 input.CustodianCount,
		DesignatedComputePeerCount:     2,
		GarblerPeerID:                  input.GarblerPeerID,
		EvaluatorPeerID:                input.EvaluatorPeerID,
		GarblerCommitmentContext:       input.GarblerCommitmentContext,
		EvaluatorCommitmentContext:     input.EvaluatorCommitmentContext,
		GarblerSeedCommitment:          input.GarblerSeedCommitment,
		EvaluatorSeedCommitment:        input.EvaluatorSeedCommitment,
		CDFCumulative:                  append([]string(nil), plan.CDFCumulative...),
		Plan:                           plan,
	}
	spec, err := jointDPGaussianOneDrawPolicySpec(policy)
	if err != nil {
		return zero, err
	}
	digest := spec.digest()
	policy.CircuitDigest = hex.EncodeToString(digest[:])
	circ, err := jointDPGaussianOneDrawGCCompile(spec)
	if err != nil {
		return zero, err
	}
	_, _, projectedInputBits, _, projectedGates, projectedNonXOR,
		projectedWires, _, _ := jointDPGaussianOneDrawCostProjection(
		len(spec.CDFCumulative), spec.CoordinateCount)
	if int64(circ.NumGates) > projectedGates ||
		int64(circ.Stats.NumNonXOR()) > projectedNonXOR ||
		int64(circ.NumWires) > projectedWires ||
		circ.Inputs.Size() != projectedInputBits {
		return zero, exactGCFailure(exactGCFailureNumericBackendUnavailable,
			fmt.Errorf("joint-dp-gaussian-one-draw: compiler cost exceeds signed resource certificate"))
	}
	return jointDPGaussianOneDrawWorkerContractOutput{
		Version:      jointDPGaussianOneDrawWorkerContractOutputVersion,
		CapabilityID: "joint_dp_biomedical_vector_gaussian_one_draw_exact_gc_v1",
		Operation:    string(jointDPGaussianOneDrawOperation),
		Mechanism:    jointDPGaussianOneDrawMechanism,
		Allocation:   jointDPGaussianOneDrawAllocation,
		Purpose:      spec.purpose(), CircuitDigest: policy.CircuitDigest,
		InputContract:           "public-cross-signed-bounded-ring128-vector-chunk-v1",
		ProtectedInputsAccepted: false, PrivateSeedAccepted: false,
		CustodianCount:             input.CustodianCount,
		DesignatedComputePeerCount: 2,
		CircuitGateCount:           circ.NumGates,
		CircuitNonXORGateCount:     circ.Stats.NumNonXOR(),
		CircuitWireCount:           circ.NumWires,
		CircuitInputBits:           circ.Inputs.Size(),
		GarbledTableBytes:          int64(circ.Stats.NumNonXOR()) * 2 * 16,
		WireLabelResidentBytes:     int64(circ.NumWires) * 2 * 16,
		WorkerPolicy:               policy, Plan: plan, CapabilityAvailable: true,
	}, nil
}

func jointDPGaussianOneDrawWorkerInputs(config exactGCWorkerConfig,
	session exactGCSession,
) (jointDPGaussianOneDrawSpec, [32]byte, error) {
	var zeroSpec jointDPGaussianOneDrawSpec
	var zeroSeed [32]byte
	if config.JointDPGaussianOneDraw == nil || config.JointDP != nil ||
		config.JointDPVector != nil {
		return zeroSpec, zeroSeed,
			fmt.Errorf("joint-dp-gaussian-one-draw: missing or ambiguous worker policy")
	}
	spec, err := jointDPGaussianOneDrawSpecFromPolicy(
		*config.JointDPGaussianOneDraw, session)
	if err != nil {
		return zeroSpec, zeroSeed, err
	}
	seedBytes, err := exactGCStrictBase64(config.PrivateSeed, 32)
	if err != nil {
		return zeroSpec, zeroSeed,
			fmt.Errorf("joint-dp-gaussian-one-draw: invalid private seed")
	}
	var seed [32]byte
	copy(seed[:], seedBytes)
	clear(seedBytes)
	commitment := spec.GarblerSeedCommitment
	context := spec.GarblerCommitmentContext
	peerID := spec.GarblerPeerID
	if config.Role == "evaluator" {
		commitment = spec.EvaluatorSeedCommitment
		context = spec.EvaluatorCommitmentContext
		peerID = spec.EvaluatorPeerID
	} else if config.Role != "garbler" {
		clear(seed[:])
		return zeroSpec, zeroSeed,
			fmt.Errorf("joint-dp-gaussian-one-draw: invalid worker role")
	}
	if (config.Role == "garbler" && config.GarblerID != peerID) ||
		(config.Role == "evaluator" && config.EvaluatorID != peerID) ||
		jointDPSeedCommitment(context, seed) != commitment {
		clear(seed[:])
		return zeroSpec, zeroSeed,
			fmt.Errorf("joint-dp-gaussian-one-draw: local pinned seed binding mismatch")
	}
	return spec, seed, nil
}
