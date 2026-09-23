package main

// The v4 mechanism samples unbounded integer noise exactly under ideal bits.
// Ring reduction, signed decoding and the fixed clamp are post-processing.
// Keyed replay retains the computational randomness assumption; sampling time
// and resource exhaustion are outside the output-DP theorem.

import (
	"encoding/base64"
	"fmt"
	"math/big"
)

const (
	jointDPVectorConvolutionPlanVersionV4            = "dsvert-joint-dp-vector-independent-full-draw-convolution-plan-v4"
	jointDPVectorConvolutionInputVersionV4           = "dsvert-joint-dp-vector-independent-full-draw-convolution-input-v4"
	jointDPVectorConvolutionOutputVersionV4          = "dsvert-joint-dp-vector-independent-full-draw-convolution-share-v4"
	jointDPVectorConvolutionFinalizerInputVersionV4  = "dsvert-joint-dp-vector-independent-full-draw-finalizer-input-v4"
	jointDPVectorConvolutionFinalizerOutputVersionV4 = "dsvert-joint-dp-vector-independent-full-draw-finalizer-v4"
	jointDPVectorConvolutionSamplerVersionV4         = "hkdf-sha256-chacha20-independent-full-draw-exact-geometric-v4"
	jointDPVectorConvolutionBackendV4                = "independent_full_global_draw_convolution_ring128_v4"
	jointDPVectorConvolutionSignedDecodeV4           = "canonical_Ring128_twos_complement_after_modular_addition"
)

type jointDPExactAdmittedRanges struct {
	EpsilonMinimumExclusive       string `json:"epsilon_minimum_exclusive"`
	EpsilonMaximum                string `json:"epsilon_maximum"`
	SensitivitySteps              string `json:"sensitivity_steps"`
	EpsilonOverSensitivityMinimum string `json:"epsilon_over_sensitivity_minimum"`
	TotalCoordinateCountMinimum   int    `json:"total_coordinate_count_minimum"`
	TotalCoordinateCountMaximum   int    `json:"total_coordinate_count_maximum"`
	RingBits                      int    `json:"ring_bits"`
}

// WrapBound describes individual-draw representability. SumWrapBound is the
// separate utility bound for the statistic plus both draws, using public source
// headroom. Neither is a mechanism delta or a deterministic no-wrap assertion.
type jointDPExactCertificate struct {
	Guarantee             string                      `json:"guarantee,omitempty"`
	Randomness            string                      `json:"randomness,omitempty"`
	NoiseSupport          string                      `json:"noise_support,omitempty"`
	NoiseCommitment       string                      `json:"noise_commitment,omitempty"`
	RepresentabilityBound string                      `json:"representability_bound,omitempty"`
	WrapBoundCertified    bool                        `json:"wrap_bound_certified,omitempty"`
	WrapBound             string                      `json:"wrap_bound,omitempty"`
	WrapBoundEvent        string                      `json:"wrap_bound_event,omitempty"`
	SumWrapBound          string                      `json:"sum_wrap_bound,omitempty"`
	SumWrapThreshold      string                      `json:"sum_wrap_threshold,omitempty"`
	AdmittedRanges        *jointDPExactAdmittedRanges `json:"admitted_ranges,omitempty"`
}

func jointDPPlanVectorConvolutionLaplaceV4(input jointDPVectorPlanInput) (jointDPVectorConvolutionPlanOutput, error) {
	var zero jointDPVectorConvolutionPlanOutput
	epsilon, err := jointDPParseDecimalRat(input.Epsilon, "epsilon", false)
	if err != nil || epsilon.Cmp(big.NewRat(10000, 1)) > 0 {
		return zero, fmt.Errorf("exact epsilon must be in (0,10000]")
	}
	delta, err := jointDPParseDecimalRat(input.Delta, "delta", true)
	if err != nil || delta.Cmp(big.NewRat(1, 1)) >= 0 {
		return zero, fmt.Errorf("delta must be in [0,1)")
	}
	sensitivity, err := jointDPParseDecimalRat(input.SensitivitySteps, "sensitivity_steps", false)
	if err != nil || !sensitivity.IsInt() {
		return zero, fmt.Errorf("sensitivity_steps must be a positive integer")
	}
	alpha := new(big.Rat).Quo(new(big.Rat).Set(epsilon), sensitivity)
	minimum := new(big.Rat).SetFrac(big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), 100))
	if alpha.Cmp(minimum) < 0 {
		return zero, fmt.Errorf("exact epsilon/sensitivity_steps must be at least 2^-100")
	}
	if input.TotalCoordinateCount < 1 || input.TotalCoordinateCount > jointDPVectorMaxTotal {
		return zero, fmt.Errorf("total_coordinate_count must be in [1,%d]", jointDPVectorMaxTotal)
	}
	exponent := new(big.Rat).Mul(alpha, new(big.Rat).SetInt(new(big.Int).Lsh(big.NewInt(1), 127)))
	bound := jointDPExactExponentialBound(exponent, 2*input.TotalCoordinateCount)
	return jointDPVectorConvolutionPlanOutput{
		jointDPVectorPlanOutput: jointDPVectorPlanOutput{
			Version: jointDPVectorConvolutionPlanVersionV4, Sampler: jointDPVectorConvolutionSamplerVersionV4,
			StopNumerator: "0", BernoulliThresholds: []string{}, SensitivitySteps: sensitivity.Num().String(), TotalCoordinateCount: input.TotalCoordinateCount,
			EpsilonEffectiveUpperNumerator: epsilon.Num().String(), EpsilonEffectiveUpperDenominator: epsilon.Denom().String(),
			OneGeometricTVNumerator: "0", OneGeometricTVDenominator: "1", TailUpperNumerator: "0", TailUpperDenominator: "1",
			RoundingUpperNumerator: "0", RoundingUpperDenominator: "1", ImplementationDeltaNumerator: "0", ImplementationDeltaDenominator: "1", ImplementationDeltaBound: "0",
			MaximumNoiseMagnitude: "unbounded", MaximumChunkCoordinates: min(jointDPVectorConvolutionMaxChunk, input.TotalCoordinateCount),
			Accounting:          "global iid discrete Laplace: each peer samples one unbounded exact full-epsilon global-L1-sensitivity discrete-Laplace vector; ideal-bit mechanism delta is zero; Ring128 modular reduction, fixed signed decoding and clamping are post-processing; representability and sum-wrap bounds are utility events distinct from mechanism delta",
			CapabilityAvailable: true,
		},
		jointDPExactCertificate: jointDPExactCertificate{
			Guarantee: "pure-dp-under-ideal-bits", Randomness: "keyed-stream-computational", NoiseSupport: "unbounded_integer", NoiseCommitment: "modulo_2^128",
			RepresentabilityBound: bound, WrapBoundCertified: true, WrapBound: bound, WrapBoundEvent: "at_least_one_peer_draw_outside_signed_Ring128",
			AdmittedRanges: &jointDPExactAdmittedRanges{EpsilonMinimumExclusive: "0", EpsilonMaximum: "10000", SensitivitySteps: "positive_integer", EpsilonOverSensitivityMinimum: "2^-100", TotalCoordinateCountMinimum: 1, TotalCoordinateCountMaximum: jointDPVectorMaxTotal, RingBits: 128},
		},
		IndependentNoisePeerCount: 2, CompleteEpsilonPerPeer: true,
		GeometricVariablesPerPeerPerCoordinate: 2, GeometricVariablesTotalPerCoordinate: 4,
		PerPeerImplementationDeltaNumerator: "0", PerPeerImplementationDeltaDenominator: "1", PerPeerImplementationDeltaBound: "0",
		ReleaseImplementationDeltaAggregation: "max_per_peer_not_sum",
		TwoPeerIdealTransferDeltaNumerator:    "0", TwoPeerIdealTransferDeltaDenominator: "1", TwoPeerIdealTransferDeltaBound: "0",
		ThreatModel:     "pinned_semi_honest_noncolluding_noise_peers; analyst_may_collude_with_at_most_one_noise_peer",
		PrivacyArgument: "conditioned on either peer's source share, seed, draw, and transcript, the other peer contributes one hidden complete-epsilon global-sensitivity exact discrete-Laplace vector mechanism; translation, the second independent draw, modular reduction, signed decoding, and fixed clamping are post-processing",
	}, nil
}

func handleJointDPVectorConvolutionPlanV4() {
	var input jointDPVectorPlanInput
	mpcReadInput(&input)
	plan, err := jointDPPlanVectorConvolutionLaplaceV4(input)
	if err != nil {
		outputError("joint-DP exact vector convolution plan unavailable: " + err.Error())
		return
	}
	mpcWriteOutput(plan)
}

func jointDPVectorConvolutionExactRate(plan jointDPVectorConvolutionPlanOutput) *big.Rat {
	n, _ := new(big.Int).SetString(plan.EpsilonEffectiveUpperNumerator, 10)
	d, _ := new(big.Int).SetString(plan.EpsilonEffectiveUpperDenominator, 10)
	s, _ := new(big.Int).SetString(plan.SensitivitySteps, 10)
	return new(big.Rat).SetFrac(n, d.Mul(d, s))
}

func jointDPVectorConvolutionSumWrapCertificate(spec jointDPVectorConvolutionSpec) jointDPExactCertificate {
	certificate := spec.plan.jointDPExactCertificate
	maximum := new(big.Int)
	for i, upper := range spec.rawUpperBounds {
		scaled := new(big.Int).Lsh(new(big.Int).Set(upper), uint(spec.input.ScaleShifts[i]))
		if scaled.Cmp(maximum) > 0 {
			maximum.Set(scaled)
		}
	}
	// If each draw lies in [-T,T-1], the unbounded statistic-plus-noise
	// sum lies in [-2^127,2^127-1]. That interval's failure mass is q^T.
	threshold := new(big.Int).Lsh(big.NewInt(1), 127)
	threshold.Sub(threshold, maximum).Rsh(threshold, 1)
	certificate.SumWrapThreshold = threshold.String()
	exponent := new(big.Rat).Mul(jointDPVectorConvolutionExactRate(spec.plan), new(big.Rat).SetInt(threshold))
	certificate.SumWrapBound = jointDPExactExponentialBound(exponent, 2*spec.input.TotalCoordinateCount)
	return certificate
}

func jointDPVectorConvolutionExactNoise(seed [32]byte, spec jointDPVectorConvolutionSpec) ([]*big.Int, error) {
	if !jointDPVectorConvolutionSeedCommitmentMatches(spec.context, seed, spec.commitment) {
		return nil, fmt.Errorf("local convolution seed commitment mismatch")
	}
	stream := &jointDPExactStream{seed: seed, transcript: spec.transcript, contract: spec.contractDigest}
	defer stream.clear()
	bits := &jointDPExactBits{reader: stream}
	defer clear(bits.byte[:])
	alpha := jointDPVectorConvolutionExactRate(spec.plan)
	noise := make([]*big.Int, spec.input.CoordinateCount)
	for i := range noise {
		var err error
		noise[i], err = bits.laplace(alpha)
		if err != nil {
			exactGCZeroBigInts(noise)
			return nil, err
		}
	}
	return noise, nil
}

func jointDPVectorConvolutionAddExactNoise(share []byte, shifts []int, noise []*big.Int) []byte {
	modulus := exactGCModulus(128)
	out := make([]byte, len(share))
	for i, value := range noise {
		residue := exactGCLittleEndianBig(share[16*i : 16*(i+1)])
		residue.Lsh(residue, uint(shifts[i])).Add(residue, value).Mod(residue, modulus)
		encoded, _ := exactGCBigLittleEndian(residue, 16) // reduced residue always fits
		copy(out[16*i:], encoded)
		clear(encoded)
		residue.SetInt64(0)
	}
	return out
}

func jointDPVectorConvolutionSampleExactShare(seed [32]byte, spec jointDPVectorConvolutionSpec, share []byte) (jointDPVectorConvolutionShareOutput, error) {
	var zero jointDPVectorConvolutionShareOutput
	noise, err := jointDPVectorConvolutionExactNoise(seed, spec)
	if err != nil {
		return zero, err
	}
	defer exactGCZeroBigInts(noise)
	noised := jointDPVectorConvolutionAddExactNoise(share, spec.input.ScaleShifts, noise)
	defer clear(noised)
	input := spec.input
	return jointDPVectorConvolutionShareOutput{
		Version: jointDPVectorConvolutionOutputVersionV4, Backend: jointDPVectorConvolutionBackendV4, Sampler: jointDPVectorConvolutionSamplerVersionV4,
		ReleaseContractHash: input.ReleaseContractHash, SamplerContractHash: fmt.Sprintf("%x", spec.contractDigest), TranscriptHash: input.TranscriptHash,
		PeerName: input.PeerName, SeedCommitment: input.SeedCommitment, RingBits: 128, FracBits: 0, TotalCoordinateCount: input.TotalCoordinateCount,
		ChunkStart: input.ChunkStart, CoordinateCount: input.CoordinateCount, NoisedShare: base64.StdEncoding.EncodeToString(noised),
		MaximumNoiseMagnitudePerPeer: "unbounded", MaximumNoiseMagnitudeTwoPeers: "unbounded", FullCapsuleParametersPerPeer: true,
		SourceBoundPrecondition: "authenticated_semi_honest_capsule_materializer_and_source_transport", NominalVarianceMultiplier: 2,
		jointDPExactCertificate: jointDPVectorConvolutionSumWrapCertificate(spec), Plan: spec.plan,
	}, nil
}
