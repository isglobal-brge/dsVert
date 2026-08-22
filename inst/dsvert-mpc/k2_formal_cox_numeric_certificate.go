package main

// Machine-checkable component certificate for the implemented lattice Cox
// algorithm.  It deliberately separates exact arithmetic/no-wrap claims from
// the still-unproved distance to the continuous Cox optimum.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
)

const formalCoxRuntimeNumericCertificateVersion = "dsvert-formal-cox-runtime-numeric-certificate-v1"

const formalCoxBlockwiseNumericCertificateVersion = "dsvert-formal-cox-blockwise-numeric-certificate-v2"

var formalCoxRuntimeNumericCertificateBlockers = []string{
	"continuous_cox_trajectory_error_bound_unavailable_v1",
	"fixed_iteration_optimizer_distance_bound_unavailable_v1",
}

type formalCoxRuntimeNumericCertificate struct {
	Version                            string   `json:"version"`
	PolicySHA256                       string   `json:"policy_sha256"`
	CircuitSHA256                      string   `json:"circuit_sha256"`
	RingBits                           int      `json:"ring_bits"`
	FracBits                           int      `json:"frac_bits"`
	Scale                              string   `json:"scale"`
	MaximumSignedMagnitude             string   `json:"maximum_signed_magnitude"`
	DynamicRingSelectedFromBounds      bool     `json:"dynamic_ring_selected_from_bounds"`
	DeterministicNoWrapCertified       bool     `json:"deterministic_no_wrap_certified"`
	FiniteNoiseNoWrapCertified         bool     `json:"finite_noise_no_wrap_certified"`
	Ring128InputLiftChecked            bool     `json:"ring128_input_lift_checked"`
	FinalCarrierReductionChecked       bool     `json:"final_carrier_reduction_checked"`
	ExpTableSHA256                     string   `json:"exp_table_sha256"`
	ExpTableOutwardCertified           bool     `json:"exp_table_outward_certified"`
	ExpAbsoluteErrorUpperSteps         string   `json:"exp_absolute_error_upper_steps"`
	ExpAbsoluteErrorUpperNumerator     string   `json:"exp_absolute_error_upper_numerator"`
	ExpAbsoluteErrorUpperDenominator   string   `json:"exp_absolute_error_upper_denominator"`
	ProductFloorErrorStrictlyBelowOne  bool     `json:"product_floor_error_strictly_below_one_step"`
	DivisionFloorErrorStrictlyBelowOne bool     `json:"division_floor_error_strictly_below_one_step"`
	ProjectionIntegerRuleExact         bool     `json:"projection_integer_rule_exact"`
	CircuitMatchesBigIntLatticeOracle  bool     `json:"circuit_matches_bigint_lattice_oracle"`
	CircuitVsLatticeOracleErrorSteps   string   `json:"circuit_vs_lattice_oracle_error_steps"`
	ContinuousCoxTrajectoryCertified   bool     `json:"continuous_cox_trajectory_certified"`
	OptimizerDistanceCertified         bool     `json:"optimizer_distance_certified"`
	IdentificationCertified            bool     `json:"identification_certified"`
	IdentificationRoute                string   `json:"identification_route"`
	DataDependentIdentificationOpened  bool     `json:"data_dependent_identification_opened"`
	FixedIterationCount                int      `json:"fixed_iteration_count"`
	ConvergenceInferred                bool     `json:"convergence_inferred"`
	EndToEndNumericCertified           bool     `json:"end_to_end_numeric_certified"`
	ProductionReady                    bool     `json:"production_ready"`
	Blockers                           []string `json:"blockers"`
}

// formalCoxBlockwiseNumericCertificate covers the public lattice envelope
// before a physical stream block has been selected.  The per-run blockwise
// plan still authenticates the exact circuit costs and shape; this certificate
// must not be confused with the legacy whole-capacity circuit certificate.
type formalCoxBlockwiseNumericCertificate struct {
	Version                           string `json:"version"`
	PolicySHA256                      string `json:"policy_sha256"`
	RingBits                          int    `json:"ring_bits"`
	ContainerBits                     int    `json:"container_bits"`
	FracBits                          int    `json:"frac_bits"`
	Scale                             string `json:"scale"`
	MaximumSignedMagnitude            string `json:"maximum_signed_magnitude"`
	ProjectionRootUpper               string `json:"projection_root_upper"`
	ProjectionSearchSteps             int    `json:"projection_search_steps"`
	DynamicRingSelectedFromBounds     bool   `json:"dynamic_ring_selected_from_bounds"`
	DeterministicNoWrapCertified      bool   `json:"deterministic_no_wrap_certified"`
	FiniteNoiseNoWrapCertified        bool   `json:"finite_noise_no_wrap_certified"`
	Ring128InputLiftChecked           bool   `json:"ring128_input_lift_checked"`
	FinalCarrierReductionChecked      bool   `json:"final_carrier_reduction_checked"`
	ExpTableSHA256                    string `json:"exp_table_sha256"`
	ExpTableOutwardCertified          bool   `json:"exp_table_outward_certified"`
	ExpAbsoluteErrorUpperSteps        string `json:"exp_absolute_error_upper_steps"`
	IdealSmoothnessUpperNumerator     string `json:"ideal_smoothness_upper_numerator"`
	IdealSmoothnessUpperDenominator   string `json:"ideal_smoothness_upper_denominator"`
	IdealStrongConvexityNumerator     string `json:"ideal_strong_convexity_numerator"`
	IdealStrongConvexityDenominator   string `json:"ideal_strong_convexity_denominator"`
	IdealContractionFactorNumerator   string `json:"ideal_contraction_factor_numerator"`
	IdealContractionFactorDenominator string `json:"ideal_contraction_factor_denominator"`
	IdealGradientContractionCertified bool   `json:"ideal_gradient_contraction_certified"`
	// The following finite bounds apply only to a valid execution, and compare
	// the implemented noisy fixed-grid trajectory with the exact noiseless
	// fixed-grid penalized Breslow trajectory under the same public policy.
	ImplementedGradientPerturbationMaximumAbsSteps string   `json:"implemented_gradient_perturbation_maximum_abs_steps"`
	ImplementedUpdatePerturbationMaximumAbsSteps   string   `json:"implemented_update_perturbation_maximum_abs_steps"`
	IntegerProjectionPerturbationMaximumAbsSteps   string   `json:"integer_projection_perturbation_maximum_abs_steps"`
	ImplementedIterationPerturbationL2Steps        string   `json:"implemented_iteration_perturbation_l2_steps"`
	FixedGridTrajectoryErrorUpperNumerator         string   `json:"fixed_grid_trajectory_error_upper_numerator"`
	FixedGridTrajectoryErrorUpperDenominator       string   `json:"fixed_grid_trajectory_error_upper_denominator"`
	FixedGridOptimizerDistanceUpperNumerator       string   `json:"fixed_grid_optimizer_distance_upper_numerator"`
	FixedGridOptimizerDistanceUpperDenominator     string   `json:"fixed_grid_optimizer_distance_upper_denominator"`
	FixedGridTrajectoryPerturbationCertified       bool     `json:"fixed_grid_trajectory_perturbation_certified"`
	FixedGridOptimizerDistanceBoundCertified       bool     `json:"fixed_grid_optimizer_distance_bound_certified"`
	PerRunCircuitPlanValidationNeeded              bool     `json:"per_run_circuit_plan_validation_needed"`
	ContinuousCoxTrajectoryCertified               bool     `json:"continuous_cox_trajectory_certified"`
	OptimizerDistanceCertified                     bool     `json:"optimizer_distance_certified"`
	EndToEndNumericCertified                       bool     `json:"end_to_end_numeric_certified"`
	ProductionReady                                bool     `json:"production_ready"`
	Blockers                                       []string `json:"blockers"`
}

// formalCoxBlockwiseIdealGradientContract is a public, data-free stability
// envelope for the exact grid-Breslow objective before table, lattice and DP
// perturbations are applied.  For ||x|| <= Cz, its smoothness is bounded by
// Cz² + ridge and positive ridge gives strong convexity ridge.  The actual
// fixed-point/DP trajectory remains separately uncertified until its
// accumulated perturbation bound is closed.
type formalCoxBlockwiseIdealGradientContract struct {
	SmoothnessUpperNumerator     string
	SmoothnessUpperDenominator   string
	StrongConvexityNumerator     string
	StrongConvexityDenominator   string
	ContractionFactorNumerator   string
	ContractionFactorDenominator string
}

// formalCoxBlockwiseLatticeTrajectoryBound is a data-free, valid-execution
// perturbation envelope.  It deliberately stops at the committed fixed-grid
// target: it does not infer a data-dependent continuous-model approximation
// or authorize a public release.
type formalCoxBlockwiseLatticeTrajectoryBound struct {
	gradientSteps       string
	updateSteps         string
	projectionSteps     string
	iterationL2Steps    string
	trajectoryNumerator string
	trajectoryDenom     string
	optimizerNumerator  string
	optimizerDenom      string
}

func formalCoxBlockwiseDeriveLatticeTrajectoryBoundFromParsed(
	parsed formalCoxParsedPolicy,
) (formalCoxBlockwiseLatticeTrajectoryBound, error) {
	var zero formalCoxBlockwiseLatticeTrajectoryBound
	scoreCertificate, err := formalCoxBlockwiseBuildScoreApproximationCertificate(parsed)
	if err != nil {
		return zero, err
	}
	scoreError, ok := new(big.Int).SetString(
		scoreCertificate.NormalizedScoreMaximumAbsErrorSteps, 10)
	if !ok || scoreError.Sign() < 0 {
		return zero, fmt.Errorf("formal-cox: malformed normalized score bound")
	}
	// The score certificate already includes its final score/capacity floor.
	// The exact ridge product adds one more floor discrepancy below one step;
	// finite support noise is bounded by the already signed policy value.
	gradientError := new(big.Int).Add(scoreError, big.NewInt(1))
	gradientError.Add(gradientError, parsed.noiseBound)
	updateError := exactGCCeilDiv(new(big.Int).Mul(parsed.alpha, gradientError),
		parsed.scale)
	updateError.Add(updateError, big.NewInt(1))
	// Outside the ball, D=ceil(||candidate||) and the integer radial rule is
	// floor(candidate*B/D).  Its distance to Euclidean radial projection is
	// strictly below two lattice steps per coordinate; inside the ball it is
	// exact.  Two is therefore a closed integer upper bound.
	projectionError := big.NewInt(2)
	iterationCoordinateError := new(big.Int).Add(updateError, projectionError)
	iterationL2 := formalCoxCeilSqrt(new(big.Int).Mul(
		new(big.Int).Mul(iterationCoordinateError, iterationCoordinateError),
		big.NewInt(int64(parsed.policy.CovariateCount))))
	contract, err := formalCoxBlockwiseIdealGradientContractFromParsed(parsed)
	if err != nil {
		return zero, err
	}
	contractionNumerator, ok := new(big.Int).SetString(
		contract.ContractionFactorNumerator, 10)
	if !ok || contractionNumerator.Sign() <= 0 {
		return zero, fmt.Errorf("formal-cox: malformed contraction numerator")
	}
	contractionDenominator, ok := new(big.Int).SetString(
		contract.ContractionFactorDenominator, 10)
	if !ok || contractionNumerator.Cmp(contractionDenominator) >= 0 {
		return zero, fmt.Errorf("formal-cox: malformed contraction denominator")
	}
	iterations := big.NewInt(int64(parsed.policy.Iterations))
	denominatorPower := new(big.Int).Exp(contractionDenominator, iterations, nil)
	numeratorPower := new(big.Int).Exp(contractionNumerator, iterations, nil)
	trajectory := new(big.Rat).SetFrac(
		new(big.Int).Mul(new(big.Int).Set(iterationL2),
			new(big.Int).Sub(new(big.Int).Set(denominatorPower), numeratorPower)),
		new(big.Int).Mul(
			new(big.Int).Exp(contractionDenominator,
				big.NewInt(int64(parsed.policy.Iterations-1)), nil),
			new(big.Int).Sub(new(big.Int).Set(contractionDenominator), contractionNumerator)))
	// The exact constrained optimum lies in the committed beta ball.  Starting
	// from zero, the ideal contraction leaves at most q^T*B; add the finite
	// implementation trajectory envelope by the triangle inequality.
	optimizerDistance := new(big.Rat).SetFrac(
		new(big.Int).Mul(parsed.betaNorm, numeratorPower), denominatorPower)
	optimizerDistance.Add(optimizerDistance, trajectory)
	return formalCoxBlockwiseLatticeTrajectoryBound{
		gradientSteps:       gradientError.String(),
		updateSteps:         updateError.String(),
		projectionSteps:     projectionError.String(),
		iterationL2Steps:    iterationL2.String(),
		trajectoryNumerator: trajectory.Num().String(),
		trajectoryDenom:     trajectory.Denom().String(),
		optimizerNumerator:  optimizerDistance.Num().String(),
		optimizerDenom:      optimizerDistance.Denom().String(),
	}, nil
}

func formalCoxBlockwiseDeriveIdealGradientContract(
	policy formalCoxPhase1Policy,
) (formalCoxBlockwiseIdealGradientContract, error) {
	var zero formalCoxBlockwiseIdealGradientContract
	parsed, err := parseFormalCoxBlockwisePolicy(policy)
	if err != nil {
		return zero, err
	}
	return formalCoxBlockwiseIdealGradientContractFromParsed(parsed)
}

func formalCoxBlockwiseIdealGradientContractFromParsed(
	parsed formalCoxParsedPolicy,
) (formalCoxBlockwiseIdealGradientContract, error) {
	var zero formalCoxBlockwiseIdealGradientContract
	if parsed.ridge.Sign() <= 0 {
		return zero, fmt.Errorf("formal-cox: blockwise ideal-gradient contract requires positive ridge")
	}
	scaleSquared := new(big.Int).Mul(parsed.scale, parsed.scale)
	smoothness := new(big.Int).Mul(parsed.xNorm, parsed.xNorm)
	smoothness.Add(smoothness, new(big.Int).Mul(parsed.ridge, parsed.scale))
	stepProduct := new(big.Int).Mul(parsed.alpha, smoothness)
	stepDenominator := new(big.Int).Mul(scaleSquared, parsed.scale)
	if stepProduct.Cmp(stepDenominator) > 0 {
		return zero, fmt.Errorf("formal-cox: step exceeds the ideal grid-Breslow smoothness limit")
	}
	contraction := new(big.Int).Mul(parsed.alpha, parsed.ridge)
	contraction.Sub(scaleSquared, contraction)
	if contraction.Sign() <= 0 {
		return zero, fmt.Errorf("formal-cox: ideal grid-Breslow step is not contractive")
	}
	return formalCoxBlockwiseIdealGradientContract{
		SmoothnessUpperNumerator:     smoothness.String(),
		SmoothnessUpperDenominator:   scaleSquared.String(),
		StrongConvexityNumerator:     parsed.ridge.String(),
		StrongConvexityDenominator:   parsed.scale.String(),
		ContractionFactorNumerator:   contraction.String(),
		ContractionFactorDenominator: scaleSquared.String(),
	}, nil
}

func formalCoxBlockwiseNumericCertificateForPolicy(
	policy formalCoxPhase1Policy,
) (formalCoxBlockwiseNumericCertificate, error) {
	var zero formalCoxBlockwiseNumericCertificate
	parsed, err := parseFormalCoxBlockwisePolicy(policy)
	if err != nil {
		return zero, err
	}
	gradientContract, err := formalCoxBlockwiseIdealGradientContractFromParsed(parsed)
	if err != nil {
		return zero, err
	}
	trajectoryBound, err := formalCoxBlockwiseDeriveLatticeTrajectoryBoundFromParsed(parsed)
	if err != nil {
		return zero, err
	}
	policyDigest, err := formalCoxPolicyDigest(policy)
	if err != nil {
		return zero, err
	}
	maximum, projectionRoot, ringBits, err := formalCoxBlockwiseNumericEnvelope(policy)
	if err != nil {
		return zero, err
	}
	return formalCoxBlockwiseNumericCertificate{
		Version:                                        formalCoxBlockwiseNumericCertificateVersion,
		PolicySHA256:                                   hex.EncodeToString(policyDigest[:]),
		RingBits:                                       ringBits,
		ContainerBits:                                  exactGCTypeBits(ringBits),
		FracBits:                                       policy.FracBits,
		Scale:                                          parsed.scale.String(),
		MaximumSignedMagnitude:                         maximum.String(),
		ProjectionRootUpper:                            projectionRoot.String(),
		ProjectionSearchSteps:                          projectionRoot.BitLen() + 1,
		DynamicRingSelectedFromBounds:                  true,
		DeterministicNoWrapCertified:                   true,
		FiniteNoiseNoWrapCertified:                     true,
		Ring128InputLiftChecked:                        true,
		FinalCarrierReductionChecked:                   true,
		ExpTableSHA256:                                 policy.ExpTableSHA256,
		ExpTableOutwardCertified:                       true,
		ExpAbsoluteErrorUpperSteps:                     parsed.expError.String(),
		IdealSmoothnessUpperNumerator:                  gradientContract.SmoothnessUpperNumerator,
		IdealSmoothnessUpperDenominator:                gradientContract.SmoothnessUpperDenominator,
		IdealStrongConvexityNumerator:                  gradientContract.StrongConvexityNumerator,
		IdealStrongConvexityDenominator:                gradientContract.StrongConvexityDenominator,
		IdealContractionFactorNumerator:                gradientContract.ContractionFactorNumerator,
		IdealContractionFactorDenominator:              gradientContract.ContractionFactorDenominator,
		IdealGradientContractionCertified:              true,
		ImplementedGradientPerturbationMaximumAbsSteps: trajectoryBound.gradientSteps,
		ImplementedUpdatePerturbationMaximumAbsSteps:   trajectoryBound.updateSteps,
		IntegerProjectionPerturbationMaximumAbsSteps:   trajectoryBound.projectionSteps,
		ImplementedIterationPerturbationL2Steps:        trajectoryBound.iterationL2Steps,
		FixedGridTrajectoryErrorUpperNumerator:         trajectoryBound.trajectoryNumerator,
		FixedGridTrajectoryErrorUpperDenominator:       trajectoryBound.trajectoryDenom,
		FixedGridOptimizerDistanceUpperNumerator:       trajectoryBound.optimizerNumerator,
		FixedGridOptimizerDistanceUpperDenominator:     trajectoryBound.optimizerDenom,
		FixedGridTrajectoryPerturbationCertified:       true,
		FixedGridOptimizerDistanceBoundCertified:       true,
		PerRunCircuitPlanValidationNeeded:              true,
		ContinuousCoxTrajectoryCertified:               false,
		OptimizerDistanceCertified:                     false,
		EndToEndNumericCertified:                       false,
		ProductionReady:                                false,
		Blockers:                                       append([]string(nil), formalCoxRuntimeNumericCertificateBlockers...),
	}, nil
}

func formalCoxBlockwiseNumericCertificateSHA256(
	certificate formalCoxBlockwiseNumericCertificate,
) (string, error) {
	encoded, err := json.Marshal(certificate)
	if err != nil {
		return "", err
	}
	digest := formalCoxSHA256Domain(
		"dsVert/formal-cox/blockwise-numeric-certificate/v2|", encoded)
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxBlockwiseValidateNumericCertificate(policy formalCoxPhase1Policy,
	certificate formalCoxBlockwiseNumericCertificate,
) error {
	want, err := formalCoxBlockwiseNumericCertificateForPolicy(policy)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(certificate, want) || certificate.ProductionReady ||
		certificate.EndToEndNumericCertified ||
		certificate.ContinuousCoxTrajectoryCertified ||
		certificate.OptimizerDistanceCertified ||
		!certificate.IdealGradientContractionCertified ||
		!certificate.FixedGridTrajectoryPerturbationCertified ||
		!certificate.FixedGridOptimizerDistanceBoundCertified ||
		!certificate.PerRunCircuitPlanValidationNeeded {
		return fmt.Errorf("formal-cox: invalid or overstated blockwise numeric certificate")
	}
	return nil
}

func formalCoxRuntimeNumericCertificateForPolicy(
	policy formalCoxPhase1Policy, plan formalCoxPhase1Plan,
) (formalCoxRuntimeNumericCertificate, error) {
	var zero formalCoxRuntimeNumericCertificate
	parsed, err := parseFormalCoxPhase1Policy(policy)
	if err != nil {
		return zero, err
	}
	wantPlan, err := planFormalCoxPhase1(policy)
	if err != nil || !reflect.DeepEqual(plan, wantPlan) {
		return zero, fmt.Errorf("formal-cox: numeric certificate plan mismatch")
	}
	policyDigest, err := formalCoxPolicyDigest(policy)
	if err != nil {
		return zero, err
	}
	circuitSHA256, err := formalCoxRuntimeCircuitSHA256(policy, plan.RingBits)
	if err != nil {
		return zero, err
	}
	identification := parsed.ridge.Sign() > 0
	identificationRoute := "unpenalized_identification_is_data_dependent_and_not_opened_v1"
	blockers := append([]string(nil), formalCoxRuntimeNumericCertificateBlockers...)
	if identification {
		identificationRoute = "public_positive_ridge_strongly_identifies_bounded_penalized_target_v1"
	} else {
		blockers = append(blockers,
			"dp_safe_unpenalized_identification_certificate_unavailable_v1")
	}
	return formalCoxRuntimeNumericCertificate{
		Version:       formalCoxRuntimeNumericCertificateVersion,
		PolicySHA256:  hex.EncodeToString(policyDigest[:]),
		CircuitSHA256: circuitSHA256, RingBits: plan.RingBits,
		FracBits: policy.FracBits, Scale: parsed.scale.String(),
		MaximumSignedMagnitude:        plan.MaximumSignedMagnitude,
		DynamicRingSelectedFromBounds: true,
		DeterministicNoWrapCertified:  plan.DeterministicNoWrap,
		FiniteNoiseNoWrapCertified:    plan.FiniteNoiseNoWrap,
		Ring128InputLiftChecked:       true, FinalCarrierReductionChecked: true,
		ExpTableSHA256:                     policy.ExpTableSHA256,
		ExpTableOutwardCertified:           true,
		ExpAbsoluteErrorUpperSteps:         parsed.expError.String(),
		ExpAbsoluteErrorUpperNumerator:     parsed.expError.String(),
		ExpAbsoluteErrorUpperDenominator:   parsed.scale.String(),
		ProductFloorErrorStrictlyBelowOne:  true,
		DivisionFloorErrorStrictlyBelowOne: true,
		ProjectionIntegerRuleExact:         true,
		CircuitMatchesBigIntLatticeOracle:  true,
		CircuitVsLatticeOracleErrorSteps:   "0",
		ContinuousCoxTrajectoryCertified:   false,
		OptimizerDistanceCertified:         false,
		IdentificationCertified:            identification,
		IdentificationRoute:                identificationRoute,
		DataDependentIdentificationOpened:  false,
		FixedIterationCount:                policy.Iterations, ConvergenceInferred: false,
		EndToEndNumericCertified: false, ProductionReady: false,
		Blockers: blockers,
	}, nil
}

func formalCoxRuntimeNumericCertificateSHA256(
	certificate formalCoxRuntimeNumericCertificate,
) (string, error) {
	encoded, err := json.Marshal(certificate)
	if err != nil {
		return "", err
	}
	digest := formalCoxSHA256Domain(
		"dsVert/formal-cox/runtime-numeric-certificate/v1|", encoded)
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxRuntimeValidateNumericCertificate(policy formalCoxPhase1Policy,
	plan formalCoxPhase1Plan, certificate formalCoxRuntimeNumericCertificate,
) error {
	want, err := formalCoxRuntimeNumericCertificateForPolicy(policy, plan)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(certificate, want) || certificate.ProductionReady ||
		certificate.EndToEndNumericCertified ||
		certificate.ContinuousCoxTrajectoryCertified ||
		certificate.OptimizerDistanceCertified ||
		certificate.DataDependentIdentificationOpened ||
		certificate.ConvergenceInferred {
		return fmt.Errorf("formal-cox: invalid or overstated numeric certificate")
	}
	scale, ok := new(big.Int).SetString(certificate.Scale, 10)
	wantScale := new(big.Int).Lsh(big.NewInt(1), uint(policy.FracBits))
	errorSteps, errorOK := new(big.Int).SetString(
		certificate.ExpAbsoluteErrorUpperSteps, 10)
	if !ok || scale.Cmp(wantScale) != 0 ||
		!errorOK || errorSteps.Sign() < 0 ||
		certificate.ExpAbsoluteErrorUpperNumerator != errorSteps.String() ||
		certificate.ExpAbsoluteErrorUpperDenominator != scale.String() {
		return fmt.Errorf("formal-cox: malformed numeric error rational")
	}
	return nil
}
