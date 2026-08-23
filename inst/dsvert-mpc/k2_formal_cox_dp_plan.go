package main

// Data-free privacy plan for the internal sealed Cox kernel.
//
// The plan deliberately registers no command or capability. It reuses the
// common fixed-work, finite-support one-draw discrete-Gaussian planner, but it
// does not claim that the sampler, source fan-in, or durable final opening are
// connected to Cox. ProductionReady therefore remains false.

import (
	"encoding/hex"
	"fmt"
	"math/big"
)

const formalCoxDPPlanVersion = "dsvert-formal-cox-dp-plan-v1"

var formalCoxDPPlanBlockers = []string{
	"r_dsi_recipient_encrypted_typed_source_bridge_not_executed_v1",
	"end_to_end_nonlinear_numeric_error_certificate_incomplete_v1",
	"dp_safe_identification_certificate_unavailable_v1",
	"r_dsi_server_to_peer_end_to_end_not_executed_v1",
}

type formalCoxDPPlan struct {
	Version                         string                           `json:"version"`
	PolicySHA256                    string                           `json:"policy_sha256"`
	Epsilon                         string                           `json:"epsilon"`
	Delta                           string                           `json:"delta"`
	Adjacency                       string                           `json:"adjacency"`
	Iterations                      int                              `json:"iterations"`
	CovariateCount                  int                              `json:"covariate_count"`
	NoiseCoordinates                int                              `json:"noise_coordinates"`
	SamplerChunkCount               int                              `json:"sampler_chunk_count"`
	PolicyNoiseChunkCountMatches    bool                             `json:"policy_noise_chunk_count_matches"`
	NoiseCoordinatesFixedShape      bool                             `json:"noise_coordinates_fixed_shape"`
	ScoreSensitivitySteps           string                           `json:"score_l2_sensitivity_steps"`
	AdaptiveStackSensitivitySteps   string                           `json:"adaptive_stack_l2_sensitivity_steps"`
	SensitivityRoute                string                           `json:"sensitivity_route"`
	SensitivityProof                string                           `json:"sensitivity_proof"`
	RiskMeanRoundingPerCoordinate   string                           `json:"risk_mean_rounding_steps_per_coordinate"`
	NormalizedRoundingL2Steps       string                           `json:"normalized_rounding_l2_steps"`
	Mechanism                       string                           `json:"mechanism"`
	Allocation                      string                           `json:"allocation"`
	Sampler                         string                           `json:"sampler"`
	MaximumNoiseMagnitude           string                           `json:"maximum_noise_magnitude"`
	PolicyNoiseBoundMatches         bool                             `json:"policy_noise_bound_matches"`
	VectorTailTVUpperNumerator      string                           `json:"vector_tail_tv_upper_numerator"`
	VectorTailTVUpperDenominator    string                           `json:"vector_tail_tv_upper_denominator"`
	VectorCDFTVUpperNumerator       string                           `json:"vector_cdf_tv_upper_numerator"`
	VectorCDFTVUpperDenominator     string                           `json:"vector_cdf_tv_upper_denominator"`
	VectorTotalTVUpperNumerator     string                           `json:"vector_total_tv_upper_numerator"`
	VectorTotalTVUpperDenominator   string                           `json:"vector_total_tv_upper_denominator"`
	ImplementationDeltaNumerator    string                           `json:"implementation_delta_numerator"`
	ImplementationDeltaDenominator  string                           `json:"implementation_delta_denominator"`
	FiniteSupportTransferCharged    bool                             `json:"finite_support_transfer_charged"`
	FixedWorkSampler                bool                             `json:"fixed_work_sampler"`
	NoWrapCertified                 bool                             `json:"no_wrap_certified"`
	PrivacyPlanCertified            bool                             `json:"privacy_plan_certified"`
	RuntimeNoiseAdapterConnected    bool                             `json:"runtime_noise_adapter_connected"`
	StickyDurableFinalizerConnected bool                             `json:"sticky_durable_finalizer_connected"`
	ProductionReady                 bool                             `json:"production_ready"`
	Blockers                        []string                         `json:"blockers"`
	CommonPlan                      jointDPGaussianOneDrawPlanOutput `json:"common_plan"`
}

// formalCoxImplementedScoreSensitivity bounds the exact integer-lattice score
// evaluated by the circuit, not an ideal floating-point oracle. Positive table
// weights make the unrounded risk mean a convex combination of vectors with
// L2 norm <= Cz. Each floor(w*x/S) loses less than one lattice step; after the
// secret division, the per-coordinate risk-mean discrepancy is bounded by
// ceil(C*S/w_min)+1. The final division by capacity loses less than one more
// step. Thus every implemented normalized score has norm at most
// 2*Cz + ||rounding||_2 and replacement sensitivity is twice that radius.
func formalCoxImplementedScoreSensitivity(parsed formalCoxParsedPolicy) (
	score, adaptive, riskMeanRounding, normalizedRoundingL2 *big.Int,
) {
	c := big.NewInt(int64(parsed.policy.Capacity))
	p := big.NewInt(int64(parsed.policy.CovariateCount))
	iterations := big.NewInt(int64(parsed.policy.Iterations))
	minimumWeight := parsed.expValues[0]
	riskMeanRounding = exactGCCeilDiv(
		new(big.Int).Mul(c, parsed.scale), minimumWeight)
	riskMeanRounding.Add(riskMeanRounding, big.NewInt(1))
	normalizedPerCoordinate := new(big.Int).Add(
		new(big.Int).Set(riskMeanRounding), big.NewInt(1))
	normalizedRoundingSquared := new(big.Int).Mul(
		new(big.Int).Set(normalizedPerCoordinate), normalizedPerCoordinate)
	normalizedRoundingSquared.Mul(normalizedRoundingSquared, p)
	normalizedRoundingL2 = formalCoxCeilSqrt(normalizedRoundingSquared)
	perDatasetRadius := new(big.Int).Mul(big.NewInt(2), parsed.xNorm)
	perDatasetRadius.Add(perDatasetRadius, normalizedRoundingL2)
	score = new(big.Int).Mul(big.NewInt(2), perDatasetRadius)
	adaptiveSquared := new(big.Int).Mul(new(big.Int).Set(score), score)
	adaptiveSquared.Mul(adaptiveSquared, iterations)
	adaptive = formalCoxCeilSqrt(adaptiveSquared)
	return
}

func planFormalCoxDP(policy formalCoxPhase1Policy) (formalCoxDPPlan, error) {
	var zero formalCoxDPPlan
	parsed, err := parseFormalCoxPhase1Policy(policy)
	if err != nil {
		return zero, err
	}
	return planFormalCoxDPFromParsed(policy, parsed)
}

func planFormalCoxBlockwiseDP(policy formalCoxPhase1Policy) (
	formalCoxDPPlan, error,
) {
	var zero formalCoxDPPlan
	parsed, err := parseFormalCoxBlockwisePolicy(policy)
	if err != nil {
		return zero, err
	}
	plan, err := planFormalCoxDPFromParsed(policy, parsed)
	if err != nil {
		return zero, err
	}
	layout, err := formalCoxBlockwiseSamplerLayout(
		plan.NoiseCoordinates, policy.CovariateCount,
		plan.CommonPlan.MaximumChunkCoordinates)
	if err != nil {
		return zero, err
	}
	// The generic one-draw worker accepts any chunk no larger than its
	// resource bound. Cox selects the largest whole-iteration chunk, so a
	// later source adapter never has to reconstruct one iteration's validity
	// from two sampler chunks.
	plan.SamplerChunkCount = layout.chunkCount
	plan.PolicyNoiseChunkCountMatches =
		policy.NoiseChunkCount == layout.chunkCount
	return plan, nil
}

type formalCoxBlockwiseSamplerChunkLayout struct {
	chunkCoordinates int
	chunkCount       int
}

// formalCoxBlockwiseSamplerLayout derives the fixed sampler geometry used by
// the current blockwise source envelope. It carries one secret XOR validity
// share per full Cox update, so no Cox update may straddle sampler chunks.
func formalCoxBlockwiseSamplerLayout(totalCoordinates, covariateCount,
	maximumChunkCoordinates int,
) (formalCoxBlockwiseSamplerChunkLayout, error) {
	var zero formalCoxBlockwiseSamplerChunkLayout
	if totalCoordinates < 1 || covariateCount < 1 ||
		totalCoordinates%covariateCount != 0 ||
		maximumChunkCoordinates < 1 {
		return zero, fmt.Errorf("formal-cox: invalid blockwise sampler geometry")
	}
	chunkCoordinates :=
		(maximumChunkCoordinates / covariateCount) * covariateCount
	if chunkCoordinates < covariateCount {
		return zero, fmt.Errorf(
			"formal-cox: sampler resource bound splits a Cox iteration")
	}
	return formalCoxBlockwiseSamplerChunkLayout{
		chunkCoordinates: chunkCoordinates,
		chunkCount: (totalCoordinates + chunkCoordinates - 1) /
			chunkCoordinates,
	}, nil
}

func planFormalCoxDPFromParsed(policy formalCoxPhase1Policy,
	parsed formalCoxParsedPolicy,
) (formalCoxDPPlan, error) {
	var zero formalCoxDPPlan
	policyDigest, err := formalCoxPolicyDigest(policy)
	if err != nil {
		return zero, err
	}
	score, adaptive, riskRounding, normalizedRounding :=
		formalCoxImplementedScoreSensitivity(parsed)
	coordinates := policy.Iterations * policy.CovariateCount
	common, err := jointDPPlanGaussianOneDraw(jointDPGaussianOneDrawPlanInput{
		Epsilon: policy.Epsilon, Delta: policy.Delta,
		L2SensitivitySteps:   adaptive.String(),
		TotalCoordinateCount: coordinates,
	})
	if err != nil {
		return zero, fmt.Errorf("formal-cox: plan common finite Gaussian: %w", err)
	}
	if !common.CapabilityAvailable {
		return zero, exactGCFailure(exactGCFailureNumericBackendUnavailable,
			fmt.Errorf("formal-cox: common finite Gaussian unavailable: %s",
				common.UnavailableReason))
	}
	privacyCertified := common.FiniteSupportTransferCharged &&
		common.FixedWorkSampler && common.NoWrapCertified &&
		common.NoiseDrawCount == 1 &&
		common.TotalCoordinateCount == coordinates &&
		common.L2SensitivitySteps == adaptive.String()
	chunkCount := (coordinates + common.MaximumChunkCoordinates - 1) /
		common.MaximumChunkCoordinates
	if !privacyCertified {
		return zero, fmt.Errorf("formal-cox: incomplete common Gaussian certificate")
	}
	return formalCoxDPPlan{
		Version:      formalCoxDPPlanVersion,
		PolicySHA256: hex.EncodeToString(policyDigest[:]),
		Epsilon:      policy.Epsilon, Delta: policy.Delta, Adjacency: policy.Adjacency,
		Iterations: policy.Iterations, CovariateCount: policy.CovariateCount,
		NoiseCoordinates: coordinates, SamplerChunkCount: chunkCount,
		PolicyNoiseChunkCountMatches:  policy.NoiseChunkCount == chunkCount,
		NoiseCoordinatesFixedShape:    true,
		ScoreSensitivitySteps:         score.String(),
		AdaptiveStackSensitivitySteps: adaptive.String(),
		SensitivityRoute:              "implemented_positive_weight_bounded_score_plus_exact_floor_error_adaptive_l2_composition_v1",
		SensitivityProof:              "each unrounded event contribution is x_event minus a positive-weight convex risk mean and has L2 norm <=2*Cz; exact lattice floor error is added before taking the two-dataset diameter; T adaptive Gaussian mechanisms compose as one stacked vector with sensitivity ceil(sqrt(T)*Delta_score)",
		RiskMeanRoundingPerCoordinate: riskRounding.String(),
		NormalizedRoundingL2Steps:     normalizedRounding.String(),
		Mechanism:                     common.Mechanism, Allocation: common.Allocation,
		Sampler:               common.Sampler,
		MaximumNoiseMagnitude: common.MaximumNoiseMagnitude,
		PolicyNoiseBoundMatches: parsed.noiseBound.String() ==
			common.MaximumNoiseMagnitude,
		VectorTailTVUpperNumerator:      common.VectorTailTVUpperNumerator,
		VectorTailTVUpperDenominator:    common.VectorTailTVUpperDenominator,
		VectorCDFTVUpperNumerator:       common.VectorCDFTVUpperNumerator,
		VectorCDFTVUpperDenominator:     common.VectorCDFTVUpperDenominator,
		VectorTotalTVUpperNumerator:     common.VectorTotalTVUpperNumerator,
		VectorTotalTVUpperDenominator:   common.VectorTotalTVUpperDenominator,
		ImplementationDeltaNumerator:    common.ImplementationDeltaNumerator,
		ImplementationDeltaDenominator:  common.ImplementationDeltaDenominator,
		FiniteSupportTransferCharged:    common.FiniteSupportTransferCharged,
		FixedWorkSampler:                common.FixedWorkSampler,
		NoWrapCertified:                 common.NoWrapCertified,
		PrivacyPlanCertified:            privacyCertified,
		RuntimeNoiseAdapterConnected:    false,
		StickyDurableFinalizerConnected: false,
		ProductionReady:                 false,
		Blockers:                        append([]string(nil), formalCoxDPPlanBlockers...),
		CommonPlan:                      common,
	}, nil
}
