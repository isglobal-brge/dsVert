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

const formalCoxBlockwiseNumericCertificateVersion = "dsvert-formal-cox-blockwise-numeric-certificate-v1"

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
	Version                           string   `json:"version"`
	PolicySHA256                      string   `json:"policy_sha256"`
	RingBits                          int      `json:"ring_bits"`
	ContainerBits                     int      `json:"container_bits"`
	FracBits                          int      `json:"frac_bits"`
	Scale                             string   `json:"scale"`
	MaximumSignedMagnitude            string   `json:"maximum_signed_magnitude"`
	ProjectionRootUpper               string   `json:"projection_root_upper"`
	ProjectionSearchSteps             int      `json:"projection_search_steps"`
	DynamicRingSelectedFromBounds     bool     `json:"dynamic_ring_selected_from_bounds"`
	DeterministicNoWrapCertified      bool     `json:"deterministic_no_wrap_certified"`
	FiniteNoiseNoWrapCertified        bool     `json:"finite_noise_no_wrap_certified"`
	Ring128InputLiftChecked           bool     `json:"ring128_input_lift_checked"`
	FinalCarrierReductionChecked      bool     `json:"final_carrier_reduction_checked"`
	ExpTableSHA256                    string   `json:"exp_table_sha256"`
	ExpTableOutwardCertified          bool     `json:"exp_table_outward_certified"`
	ExpAbsoluteErrorUpperSteps        string   `json:"exp_absolute_error_upper_steps"`
	PerRunCircuitPlanValidationNeeded bool     `json:"per_run_circuit_plan_validation_needed"`
	ContinuousCoxTrajectoryCertified  bool     `json:"continuous_cox_trajectory_certified"`
	OptimizerDistanceCertified        bool     `json:"optimizer_distance_certified"`
	EndToEndNumericCertified          bool     `json:"end_to_end_numeric_certified"`
	ProductionReady                   bool     `json:"production_ready"`
	Blockers                          []string `json:"blockers"`
}

func formalCoxBlockwiseNumericCertificateForPolicy(
	policy formalCoxPhase1Policy,
) (formalCoxBlockwiseNumericCertificate, error) {
	var zero formalCoxBlockwiseNumericCertificate
	parsed, err := parseFormalCoxBlockwisePolicy(policy)
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
		Version:                           formalCoxBlockwiseNumericCertificateVersion,
		PolicySHA256:                      hex.EncodeToString(policyDigest[:]),
		RingBits:                          ringBits,
		ContainerBits:                     exactGCTypeBits(ringBits),
		FracBits:                          policy.FracBits,
		Scale:                             parsed.scale.String(),
		MaximumSignedMagnitude:            maximum.String(),
		ProjectionRootUpper:               projectionRoot.String(),
		ProjectionSearchSteps:             projectionRoot.BitLen() + 1,
		DynamicRingSelectedFromBounds:     true,
		DeterministicNoWrapCertified:      true,
		FiniteNoiseNoWrapCertified:        true,
		Ring128InputLiftChecked:           true,
		FinalCarrierReductionChecked:      true,
		ExpTableSHA256:                    policy.ExpTableSHA256,
		ExpTableOutwardCertified:          true,
		ExpAbsoluteErrorUpperSteps:        parsed.expError.String(),
		PerRunCircuitPlanValidationNeeded: true,
		ContinuousCoxTrajectoryCertified:  false,
		OptimizerDistanceCertified:        false,
		EndToEndNumericCertified:          false,
		ProductionReady:                   false,
		Blockers:                          append([]string(nil), formalCoxRuntimeNumericCertificateBlockers...),
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
		"dsVert/formal-cox/blockwise-numeric-certificate/v1|", encoded)
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
