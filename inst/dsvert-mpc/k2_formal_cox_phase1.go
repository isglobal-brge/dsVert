package main

// Internal sealed Cox PH vertical slice.
//
// This file deliberately registers no command, handler, capability or DSI/R
// route. It is the only compiler allowed to consume the specialised session
// operation below. All patient rows, risk sets, scores, iteration noise and
// coefficients remain secret-shared; the circuit returns only fresh final
// coefficient shares plus one XOR-shared execution-validity bit.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
	"sync"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
	"github.com/markkurossi/mpc/p2p"
)

const (
	exactGCFormalCoxIterations exactGCOperation = "formal-cox-iterations-v1"

	formalCoxPhase1PolicyVersion = "dsvert-formal-cox-phase1-policy-v1"
	formalCoxPhase1PlanVersion   = "dsvert-formal-cox-phase1-plan-v1"

	// These are per-circuit resource bounds for the current reviewed vertical
	// slice, never request-count or history-dependent quotas.
	formalCoxPhase1MaxCustodians    = 8
	formalCoxPhase1MaxCapacity      = 4
	formalCoxPhase1MaxCovariates    = 2
	formalCoxPhase1MaxGridTicks     = 8
	formalCoxPhase1MaxIterations    = 3
	formalCoxPhase1MaxExpSegments   = 8
	formalCoxPhase1MaxDecimalDigits = 1300
)

type formalCoxPhase1Policy struct {
	Version            string   `json:"version"`
	ArtifactSHA256     string   `json:"artifact_sha256"`
	CapsuleSHA256      string   `json:"capsule_sha256"`
	SnapshotSHA256     string   `json:"snapshot_sha256"`
	PinsetSHA256       string   `json:"pinset_sha256"`
	CompilerSHA256     string   `json:"compiler_sha256"`
	TheoremSHA256      string   `json:"theorem_sha256"`
	ExpTableSHA256     string   `json:"exp_table_sha256"`
	CustodianPeers     []string `json:"custodian_peers"`
	ComputePeers       []string `json:"compute_peers"`
	Adjacency          string   `json:"adjacency"`
	EntryMode          string   `json:"entry_mode"`
	Capacity           int      `json:"capacity"`
	CovariateCount     int      `json:"covariate_count"`
	GridTickCount      int      `json:"grid_tick_count"`
	Iterations         int      `json:"iterations"`
	NoiseChunkCount    int      `json:"noise_chunk_count"`
	FracBits           int      `json:"frac_bits"`
	XLower             []string `json:"x_lower"`
	XUpper             []string `json:"x_upper"`
	CovariateL2Bound   string   `json:"covariate_l2_bound"`
	BetaL2Bound        string   `json:"beta_l2_bound"`
	MinimumAtRisk      int      `json:"minimum_at_risk"`
	Alpha              string   `json:"alpha"`
	Ridge              string   `json:"ridge"`
	Epsilon            string   `json:"epsilon"`
	Delta              string   `json:"delta"`
	NoiseBound         string   `json:"noise_bound"`
	ExpKnots           []string `json:"exp_knots"`
	ExpValues          []string `json:"exp_values"`
	ExpErrorUpper      string   `json:"exp_error_upper"`
	ExpCertificateBits int      `json:"exp_certificate_bits"`
	Ties               string   `json:"ties"`
	PrivacyUnit        string   `json:"privacy_unit"`
	ReductionOrder     string   `json:"reduction_order"`
	Truncation         string   `json:"truncation"`
	Projection         string   `json:"projection"`
	InputLayout        string   `json:"input_layout"`
	InputSharing       string   `json:"input_sharing"`
	NoiseInput         string   `json:"noise_input"`
	Output             string   `json:"output"`
}

type formalCoxParsedPolicy struct {
	policy     formalCoxPhase1Policy
	scale      *big.Int
	xLower     []*big.Int
	xUpper     []*big.Int
	xNorm      *big.Int
	betaNorm   *big.Int
	alpha      *big.Int
	ridge      *big.Int
	noiseBound *big.Int
	expKnots   []*big.Int
	expValues  []*big.Int
	expError   *big.Int
	epsilon    *big.Rat
	delta      *big.Rat
}

type formalCoxPhase1Plan struct {
	Version                    string `json:"version"`
	PolicySHA256               string `json:"policy_sha256"`
	RingBits                   int    `json:"ring_bits"`
	ContainerBits              int    `json:"container_bits"`
	FracBits                   int    `json:"frac_bits"`
	RowCoordinates             int    `json:"row_coordinates"`
	ZeroBlindCoordinates       int    `json:"zero_blind_coordinates"`
	NoiseCoordinates           int    `json:"noise_coordinates"`
	NoiseValidityCoordinates   int    `json:"noise_validity_coordinates"`
	InputCoordinates           int    `json:"input_coordinates"`
	OutputCoordinates          int    `json:"output_coordinates"`
	MaximumSignedMagnitude     string `json:"maximum_signed_magnitude"`
	ProjectionRootUpper        string `json:"projection_root_upper"`
	ProjectionSearchSteps      int    `json:"projection_search_steps"`
	ExpMaximumAbsError         string `json:"exp_maximum_abs_error"`
	Reciprocal                 string `json:"reciprocal"`
	Comparison                 string `json:"comparison"`
	Truncation                 string `json:"truncation"`
	Projection                 string `json:"projection"`
	DeterministicNoWrap        bool   `json:"deterministic_no_wrap"`
	FiniteNoiseNoWrap          bool   `json:"finite_noise_no_wrap"`
	EndToEndNumericCertificate bool   `json:"end_to_end_numeric_certificate"`
	ProductionReleaseReady     bool   `json:"production_release_ready"`
	ProducerAdapterStatus      string `json:"producer_adapter_status"`
	NoiseAdapterStatus         string `json:"noise_adapter_status"`
	OpeningStatus              string `json:"opening_status"`
}

type formalCoxNumericBackendError struct {
	Code         string
	RequiredBits int
}

func (e *formalCoxNumericBackendError) Error() string {
	return fmt.Sprintf("formal-cox: %s (required ring bits %d)",
		e.Code, e.RequiredBits)
}

type formalCoxResourcePlanError struct {
	Code             string
	TypedInputBits   int
	MaximumInputBits int
}

func (e *formalCoxResourcePlanError) Error() string {
	return fmt.Sprintf("formal-cox: %s (typed input bits %d exceed %d)",
		e.Code, e.TypedInputBits, e.MaximumInputBits)
}

func formalCoxCanonicalSigned(value, name string) (*big.Int, error) {
	if value == "" || len(value) > formalCoxPhase1MaxDecimalDigits ||
		strings.HasPrefix(value, "+") || value == "-0" ||
		(len(value) > 1 && value[0] == '0') ||
		(len(value) > 2 && value[0] == '-' && value[1] == '0') {
		return nil, fmt.Errorf("formal-cox: invalid %s", name)
	}
	result := new(big.Int)
	if _, ok := result.SetString(value, 10); !ok || result.String() != value {
		return nil, fmt.Errorf("formal-cox: invalid %s", name)
	}
	return result, nil
}

func formalCoxParseVector(values []string, count int,
	name string) ([]*big.Int, error) {
	if len(values) != count {
		return nil, fmt.Errorf("formal-cox: invalid %s shape", name)
	}
	result := make([]*big.Int, count)
	for index, value := range values {
		parsed, err := formalCoxCanonicalSigned(
			value, fmt.Sprintf("%s[%d]", name, index))
		if err != nil {
			return nil, err
		}
		result[index] = parsed
	}
	return result, nil
}

func formalCoxIsSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func formalCoxAbs(value *big.Int) *big.Int {
	return new(big.Int).Abs(new(big.Int).Set(value))
}

func formalCoxMax(values ...*big.Int) *big.Int {
	result := new(big.Int)
	for _, value := range values {
		if value != nil && value.Cmp(result) > 0 {
			result.Set(value)
		}
	}
	return result
}

func formalCoxFloorMul(left, right, scale *big.Int) *big.Int {
	product := new(big.Int).Mul(left, right)
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(product, scale, remainder)
	if product.Sign() < 0 && remainder.Sign() != 0 {
		quotient.Sub(quotient, big.NewInt(1))
	}
	return quotient
}

func formalCoxCeilMulMagnitude(left, right, scale *big.Int) *big.Int {
	return exactGCCeilDiv(new(big.Int).Mul(
		formalCoxAbs(left), formalCoxAbs(right)), scale)
}

func formalCoxCeilSqrt(value *big.Int) *big.Int {
	if value == nil || value.Sign() <= 0 {
		return new(big.Int)
	}
	root := new(big.Int).Sqrt(value)
	if new(big.Int).Mul(new(big.Int).Set(root), root).Cmp(value) < 0 {
		root.Add(root, big.NewInt(1))
	}
	return root
}

func formalCoxPolicyDigest(policy formalCoxPhase1Policy) ([32]byte, error) {
	encoded, err := json.Marshal(policy)
	if err != nil {
		return [32]byte{}, fmt.Errorf("formal-cox: encode policy: %w", err)
	}
	return sha256.Sum256(append(
		[]byte("dsVert/formal-cox/phase1-policy/v1|"), encoded...)), nil
}

func formalCoxPurpose(policy formalCoxPhase1Policy) (string, error) {
	digest, err := formalCoxPolicyDigest(policy)
	if err != nil {
		return "", err
	}
	return "formal-cox/phase1-v1/" + hex.EncodeToString(digest[:]), nil
}

func formalCoxExpTableDigest(policy formalCoxPhase1Policy) (string, error) {
	encoded, err := json.Marshal(struct {
		FracBits        int      `json:"frac_bits"`
		Knots           []string `json:"knots"`
		Values          []string `json:"values"`
		ErrorUpper      string   `json:"error_upper"`
		CertificateBits int      `json:"certificate_bits"`
	}{policy.FracBits, policy.ExpKnots, policy.ExpValues,
		policy.ExpErrorUpper, policy.ExpCertificateBits})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte("dsVert/formal-cox/exp-table/v1|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

// formalCoxExpDyadic encloses exp(x/scale) with outward dyadic endpoints.
// It reuses the sampler's independently tested alternating-series enclosure
// for exp(-x); positive x is enclosed by exact interval reciprocation.
func formalCoxExpDyadic(value, scale *big.Int,
	bits int) (jointDPGaussianDyadicInterval, error) {
	var zero jointDPGaussianDyadicInterval
	if value == nil || scale == nil || scale.Sign() <= 0 || bits < 64 {
		return zero, fmt.Errorf("formal-cox: invalid exp certificate input")
	}
	x := new(big.Rat).SetFrac(formalCoxAbs(value), scale)
	negative, err := jointDPGaussianExpNegDyadic(x, bits)
	if err != nil {
		return zero, fmt.Errorf("formal-cox: exp enclosure: %w", err)
	}
	if value.Sign() <= 0 {
		return negative, nil
	}
	if negative.low.Sign() <= 0 {
		return zero, fmt.Errorf("formal-cox: positive exp reciprocal underflow")
	}
	dyadicScale := jointDPGaussianDyadicScale(bits)
	numerator := new(big.Int).Mul(dyadicScale, dyadicScale)
	low := new(big.Int).Quo(new(big.Int).Set(numerator), negative.high)
	high := exactGCCeilDiv(numerator, negative.low)
	return jointDPGaussianDyadicInterval{low: low, high: high, bits: bits}, nil
}

func formalCoxValidateExpCertificate(parsed formalCoxParsedPolicy) error {
	policy := parsed.policy
	if digest, err := formalCoxExpTableDigest(policy); err != nil ||
		digest != policy.ExpTableSHA256 {
		return fmt.Errorf("formal-cox: exp table commitment mismatch")
	}
	dyadicScale := jointDPGaussianDyadicScale(policy.ExpCertificateBits)
	for segment := range parsed.expValues {
		left, err := formalCoxExpDyadic(parsed.expKnots[segment],
			parsed.scale, policy.ExpCertificateBits)
		if err != nil {
			return err
		}
		right, err := formalCoxExpDyadic(parsed.expKnots[segment+1],
			parsed.scale, policy.ExpCertificateBits)
		if err != nil {
			return err
		}
		value := new(big.Int).Mul(parsed.expValues[segment], dyadicScale)
		errorGrid := new(big.Int).Mul(parsed.expError, dyadicScale)
		leftLow := new(big.Int).Mul(left.low, parsed.scale)
		rightHigh := new(big.Int).Mul(right.high, parsed.scale)
		lowerError := new(big.Int).Sub(value, leftLow)
		upperError := new(big.Int).Sub(rightHigh, value)
		if lowerError.Sign() < 0 {
			lowerError.Neg(lowerError)
		}
		if upperError.Sign() < 0 {
			upperError.Neg(upperError)
		}
		if formalCoxMax(lowerError, upperError).Cmp(errorGrid) > 0 {
			return fmt.Errorf("formal-cox: exp segment %d exceeds its outward error certificate", segment)
		}
	}
	return nil
}

func parseFormalCoxPhase1Policy(
	policy formalCoxPhase1Policy) (formalCoxParsedPolicy, error) {
	return parseFormalCoxPolicyWithLimits(policy,
		formalCoxPhase1MaxCapacity, formalCoxPhase1MaxCovariates,
		formalCoxPhase1MaxGridTicks,
		formalCoxPhase1MaxIterations)
}

func parseFormalCoxPolicyWithLimits(policy formalCoxPhase1Policy,
	maxCapacity, maxCovariates, maxGridTicks,
	maxIterations int) (formalCoxParsedPolicy, error) {
	var result formalCoxParsedPolicy
	if policy.Version != formalCoxPhase1PolicyVersion ||
		policy.Adjacency != "add_remove_patient" &&
			policy.Adjacency != "replace_one_patient" ||
		policy.EntryMode != "none" && policy.EntryMode != "single_interval" ||
		len(policy.CustodianPeers) < 2 ||
		len(policy.CustodianPeers) > formalCoxPhase1MaxCustodians ||
		len(policy.ComputePeers) != 2 ||
		policy.Capacity < 1 || policy.Capacity > maxCapacity ||
		policy.CovariateCount < 1 ||
		policy.CovariateCount > maxCovariates ||
		policy.GridTickCount < 2 ||
		policy.GridTickCount > maxGridTicks ||
		policy.Iterations < 1 ||
		policy.Iterations > maxIterations ||
		policy.NoiseChunkCount < 1 ||
		policy.NoiseChunkCount > policy.Iterations*policy.CovariateCount ||
		policy.FracBits < 8 || policy.FracBits > 60 ||
		policy.MinimumAtRisk != 1 ||
		len(policy.ExpValues) < 1 ||
		len(policy.ExpValues) > formalCoxPhase1MaxExpSegments ||
		len(policy.ExpKnots) != len(policy.ExpValues)+1 ||
		policy.ExpCertificateBits < 96 || policy.ExpCertificateBits > 4096 {
		return result, fmt.Errorf("formal-cox: unsupported Phase-1 policy shape")
	}
	for _, value := range []string{
		policy.ArtifactSHA256, policy.CapsuleSHA256, policy.SnapshotSHA256,
		policy.PinsetSHA256, policy.CompilerSHA256, policy.TheoremSHA256,
		policy.ExpTableSHA256,
	} {
		if !formalCoxIsSHA256(value) {
			return result, fmt.Errorf("formal-cox: invalid public commitment")
		}
	}
	if !sort.StringsAreSorted(policy.CustodianPeers) {
		return result, fmt.Errorf("formal-cox: custodian peer set is not canonical")
	}
	seen := make(map[string]bool, len(policy.CustodianPeers))
	for _, peer := range policy.CustodianPeers {
		if exactGCValidateLabel("formal Cox custodian", peer, 256) != nil ||
			seen[peer] {
			return result, fmt.Errorf("formal-cox: invalid custodian peer set")
		}
		seen[peer] = true
	}
	if policy.ComputePeers[0] == policy.ComputePeers[1] ||
		!seen[policy.ComputePeers[0]] || !seen[policy.ComputePeers[1]] {
		return result, fmt.Errorf("formal-cox: invalid designated compute peers")
	}
	if policy.Ties != "breslow" ||
		policy.PrivacyUnit != "one_patient_one_fixed_capacity_slot_v1" ||
		policy.ReductionOrder != "grid_then_capacity_slot_then_covariate_v1" ||
		policy.Truncation != "exact_signed_floor_after_each_fixed_point_product_v1" ||
		policy.Projection != "exact_integer_l2_radial_toward_zero_v1" ||
		policy.InputLayout != "capacity_major_all_k_validity_entry_stop_status_design_then_zero_beta_blinding_then_iteration_noise_then_sampler_chunk_validity_v2" ||
		policy.InputSharing != "additive_mod_2k_two_recipient_v1" ||
		policy.NoiseInput != "one_joint_finite_support_discrete_gaussian_vector_tv_charged_to_delta_v1" ||
		policy.Output != "sealed_final_beta_additive_shares_and_xor_execution_validity_v1" {
		return result, fmt.Errorf("formal-cox: unsupported scientific or cryptographic contract")
	}
	var err error
	result.xLower, err = formalCoxParseVector(
		policy.XLower, policy.CovariateCount, "x lower")
	if err != nil {
		return result, err
	}
	result.xUpper, err = formalCoxParseVector(
		policy.XUpper, policy.CovariateCount, "x upper")
	if err != nil {
		return result, err
	}
	result.expKnots, err = formalCoxParseVector(
		policy.ExpKnots, len(policy.ExpKnots), "exp knot")
	if err != nil {
		return result, err
	}
	result.expValues, err = formalCoxParseVector(
		policy.ExpValues, len(policy.ExpValues), "exp value")
	if err != nil {
		return result, err
	}
	parseScalar := func(value, name string) (*big.Int, error) {
		return formalCoxCanonicalSigned(value, name)
	}
	if result.xNorm, err = parseScalar(
		policy.CovariateL2Bound, "covariate L2 bound"); err != nil {
		return result, err
	}
	if result.betaNorm, err = parseScalar(
		policy.BetaL2Bound, "beta L2 bound"); err != nil {
		return result, err
	}
	if result.alpha, err = parseScalar(policy.Alpha, "alpha"); err != nil {
		return result, err
	}
	if result.ridge, err = parseScalar(policy.Ridge, "ridge"); err != nil {
		return result, err
	}
	if result.noiseBound, err = parseScalar(
		policy.NoiseBound, "finite noise bound"); err != nil {
		return result, err
	}
	if result.expError, err = parseScalar(
		policy.ExpErrorUpper, "exp error upper"); err != nil {
		return result, err
	}
	if result.epsilon, err = jointDPParseDecimalRat(
		policy.Epsilon, "formal Cox epsilon", false); err != nil {
		return result, err
	}
	if result.delta, err = jointDPParseDecimalRat(
		policy.Delta, "formal Cox delta", false); err != nil ||
		result.delta.Cmp(big.NewRat(1, 1)) >= 0 {
		return result, fmt.Errorf("formal-cox: delta must be in (0,1)")
	}
	result.scale = new(big.Int).Lsh(big.NewInt(1), uint(policy.FracBits))
	if result.xNorm.Sign() <= 0 || result.betaNorm.Sign() <= 0 ||
		result.alpha.Sign() <= 0 || result.alpha.Cmp(result.scale) > 0 ||
		result.ridge.Sign() < 0 || result.noiseBound.Sign() <= 0 ||
		result.expError.Sign() < 0 {
		return result, fmt.Errorf("formal-cox: invalid scalar numeric contract")
	}
	boxSquared := new(big.Int)
	for index := 0; index < policy.CovariateCount; index++ {
		if result.xLower[index].Cmp(result.xUpper[index]) >= 0 {
			return result, fmt.Errorf("formal-cox: invalid covariate box")
		}
		magnitude := formalCoxMax(formalCoxAbs(result.xLower[index]),
			formalCoxAbs(result.xUpper[index]))
		boxSquared.Add(boxSquared,
			new(big.Int).Mul(new(big.Int).Set(magnitude), magnitude))
	}
	if new(big.Int).Mul(new(big.Int).Set(result.xNorm), result.xNorm).Cmp(
		boxSquared) > 0 {
		return result, fmt.Errorf("formal-cox: L2 bound is looser than the signed coordinate box")
	}
	for index := range result.expValues {
		if result.expKnots[index].Cmp(result.expKnots[index+1]) >= 0 ||
			result.expValues[index].Sign() <= 0 || index > 0 &&
			result.expValues[index].Cmp(result.expValues[index-1]) < 0 {
			return result, fmt.Errorf("formal-cox: invalid monotone exp table")
		}
	}
	etaBound := formalCoxCeilMulMagnitude(
		result.xNorm, result.betaNorm, result.scale)
	// Every signed fixed-point product floors toward negative infinity before
	// the terms are accumulated.  With p covariates that can move eta down by
	// fewer than p lattice steps from its real L2 envelope.  Require that
	// margin in the committed table rather than turning a valid bounded row
	// into an invalid execution at the lower endpoint.
	etaFloorLower := new(big.Int).Add(
		new(big.Int).Set(etaBound),
		big.NewInt(int64(policy.CovariateCount)))
	etaFloorLower.Neg(etaFloorLower)
	if result.expKnots[0].Cmp(etaFloorLower) > 0 ||
		result.expKnots[len(result.expKnots)-1].Cmp(etaBound) < 0 {
		return result, fmt.Errorf(
			"formal-cox: exp domain does not cover the quantized eta floor margin")
	}
	result.policy = policy
	if err := formalCoxValidateExpCertificate(result); err != nil {
		return formalCoxParsedPolicy{}, err
	}
	return result, nil
}

func planFormalCoxPhase1(
	policy formalCoxPhase1Policy) (formalCoxPhase1Plan, error) {
	parsed, err := parseFormalCoxPhase1Policy(policy)
	if err != nil {
		return formalCoxPhase1Plan{}, err
	}
	digest, _ := formalCoxPolicyDigest(policy)
	c, p, k := policy.Capacity, policy.CovariateCount,
		len(policy.CustodianPeers)
	xMax := new(big.Int)
	for index := 0; index < p; index++ {
		xMax = formalCoxMax(xMax, formalCoxAbs(parsed.xLower[index]),
			formalCoxAbs(parsed.xUpper[index]))
	}
	weightMin := new(big.Int).Set(parsed.expValues[0])
	weightMax := new(big.Int).Set(parsed.expValues[len(parsed.expValues)-1])
	etaBound := formalCoxCeilMulMagnitude(
		parsed.xNorm, parsed.betaNorm, parsed.scale)
	weightedX := new(big.Int).Add(
		formalCoxCeilMulMagnitude(weightMax, xMax, parsed.scale), big.NewInt(1))
	s0Bound := new(big.Int).Mul(big.NewInt(int64(c)), weightMax)
	s1Bound := new(big.Int).Mul(big.NewInt(int64(c)), weightedX)
	meanNumerator := new(big.Int).Mul(new(big.Int).Set(s1Bound), parsed.scale)
	meanBound := exactGCCeilDiv(meanNumerator, weightMin)
	eventXBound := new(big.Int).Mul(big.NewInt(int64(c)), xMax)
	riskTermBound := new(big.Int).Mul(big.NewInt(int64(c)), meanBound)
	scoreBound := new(big.Int).Add(eventXBound, riskTermBound)
	averageScoreBound := exactGCCeilDiv(scoreBound, big.NewInt(int64(c)))
	ridgeBound := formalCoxCeilMulMagnitude(
		parsed.ridge, parsed.betaNorm, parsed.scale)
	gradientBound := new(big.Int).Add(averageScoreBound, ridgeBound)
	gradientBound.Add(gradientBound, parsed.noiseBound)
	updateBound := formalCoxCeilMulMagnitude(
		parsed.alpha, gradientBound, parsed.scale)
	candidateBound := new(big.Int).Add(parsed.betaNorm, updateBound)
	projectionNormSquared := new(big.Int).Mul(candidateBound, candidateBound)
	projectionNormSquared.Mul(projectionNormSquared, big.NewInt(int64(p)))
	projectionRoot := formalCoxCeilSqrt(projectionNormSquared)
	maximum := formalCoxMax(
		parsed.scale, big.NewInt(int64(c)), big.NewInt(int64(policy.GridTickCount)),
		xMax, parsed.xNorm, parsed.betaNorm, parsed.alpha, parsed.ridge,
		parsed.noiseBound, etaBound, weightMin, weightMax, weightedX,
		s0Bound, s1Bound, meanBound, eventXBound, riskTermBound,
		scoreBound, averageScoreBound, ridgeBound, gradientBound,
		updateBound, candidateBound, projectionRoot)
	for _, value := range parsed.expKnots {
		maximum = formalCoxMax(maximum, formalCoxAbs(value))
	}
	for _, value := range parsed.expValues {
		maximum = formalCoxMax(maximum, value)
	}
	requiredBits := maximum.BitLen() + 2
	ringBits := 128
	if requiredBits > ringBits {
		ringBits = exactGCTypeBits(requiredBits)
	}
	if ringBits > exactGCMaxRingBits {
		return formalCoxPhase1Plan{}, &formalCoxNumericBackendError{
			Code: "numeric_backend_unrepresentable", RequiredBits: requiredBits}
	}
	rowCoordinates := c * (k + 3 + p)
	zeroBlindCoordinates := p
	noiseCoordinates := policy.Iterations * p
	noiseValidityCoordinates := policy.NoiseChunkCount
	inputCoordinates := rowCoordinates + zeroBlindCoordinates +
		noiseCoordinates + noiseValidityCoordinates
	containerBits := exactGCTypeBits(ringBits)
	// session.validate deliberately uses the conservative generic 3*n bound;
	// the specialised circuit's actual input is 2*n+p+1 containers.
	typedInputBits := 3 * containerBits * inputCoordinates
	if typedInputBits > exactGCMaxCircuitTypeBits {
		return formalCoxPhase1Plan{}, &formalCoxResourcePlanError{
			Code:           "public_circuit_shape_unrepresentable",
			TypedInputBits: typedInputBits, MaximumInputBits: exactGCMaxCircuitTypeBits}
	}
	return formalCoxPhase1Plan{
		Version:      formalCoxPhase1PlanVersion,
		PolicySHA256: hex.EncodeToString(digest[:]),
		RingBits:     ringBits, ContainerBits: containerBits,
		FracBits: policy.FracBits, RowCoordinates: rowCoordinates,
		ZeroBlindCoordinates:     zeroBlindCoordinates,
		NoiseCoordinates:         noiseCoordinates,
		NoiseValidityCoordinates: noiseValidityCoordinates,
		InputCoordinates:         inputCoordinates,
		OutputCoordinates:        p, MaximumSignedMagnitude: maximum.String(),
		ProjectionRootUpper:   projectionRoot.String(),
		ProjectionSearchSteps: projectionRoot.BitLen() + 1,
		ExpMaximumAbsError:    parsed.expError.String(),
		Reciprocal:            "exact_secret_integer_division_floor_on_fixed_lattice_v1",
		Comparison:            "exact_signed_boolean_comparison_inside_composite_gc_v1",
		Truncation:            policy.Truncation, Projection: policy.Projection,
		DeterministicNoWrap: true, FiniteNoiseNoWrap: true,
		EndToEndNumericCertificate: false,
		ProductionReleaseReady:     false,
		ProducerAdapterStatus:      "authenticated_recipient_local_typed_source_fanin_available_in_internal_runtime_v1",
		NoiseAdapterStatus:         "finite_support_tv_accounted_joint_vector_available_in_internal_runtime_v1",
		OpeningStatus:              "common_sticky_one_opening_available_in_internal_runtime_v1",
	}, nil
}

func formalCoxResidue(value *big.Int, bits int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Set(value), exactGCModulus(bits))
}

func formalCoxHex(value *big.Int, bits int) string {
	return formalCoxResidue(value, bits).Text(16)
}

func formalCoxCircuitSource(policy formalCoxPhase1Policy,
	ringBits int) (string, error) {
	parsed, err := parseFormalCoxPhase1Policy(policy)
	if err != nil {
		return "", err
	}
	plan, err := planFormalCoxPhase1(policy)
	if err != nil || plan.RingBits != ringBits {
		if err == nil {
			err = fmt.Errorf("formal-cox: circuit ring does not match numeric plan")
		}
		return "", err
	}
	typeBits := exactGCTypeBits(ringBits)
	uintType := fmt.Sprintf("uint%d", typeBits)
	wideType := fmt.Sprintf("uint%d", 2*typeBits)
	mask := exactGCMask(ringBits).Text(16)
	sign := new(big.Int).Lsh(big.NewInt(1), uint(ringBits-1)).Text(16)
	fracMask := new(big.Int).Sub(new(big.Int).Set(parsed.scale), big.NewInt(1)).Text(16)
	c, p, k := policy.Capacity, policy.CovariateCount,
		len(policy.CustodianPeers)
	n := plan.InputCoordinates
	projectionRootUpper, ok := new(big.Int).SetString(
		plan.ProjectionRootUpper, 10)
	if !ok || projectionRootUpper.Sign() <= 0 {
		return "", fmt.Errorf("formal-cox: invalid planned projection root")
	}
	constant := func(value *big.Int) string {
		return fmt.Sprintf("%s(0x%s)", uintType, formalCoxHex(value, ringBits))
	}
	var source strings.Builder
	fmt.Fprintf(&source, `package main
func signedLess(a %s, b %s) bool {
	aNeg := (a & %s(0x%s)) != 0
	bNeg := (b & %s(0x%s)) != 0
	if aNeg != bNeg { return aNeg }
	return a < b
}
`, uintType, uintType, uintType, sign, uintType, sign)
	fmt.Fprintf(&source, `func mulFloor(a %s, b %s) %s {
	aNeg := (a & %s(0x%s)) != 0
	bNeg := (b & %s(0x%s)) != 0
	aMag := a
	bMag := b
	if aNeg { aMag = (%s(0) - a) & %s(0x%s) }
	if bNeg { bMag = (%s(0) - b) & %s(0x%s) }
	product := wideMul(aMag, bMag)
	quotient := product >> %d
	remainder := product & %s(0x%s)
	negative := aNeg != bNeg
	if negative && remainder != 0 { quotient = quotient + 1 }
	result := %s(quotient)
	if negative { result = (%s(0) - result) & %s(0x%s) }
	return result
}
`, uintType, uintType, uintType, uintType, sign, uintType, sign,
		uintType, uintType, mask, uintType, uintType, mask,
		policy.FracBits, wideType, fracMask, uintType,
		uintType, uintType, mask)
	if c > 1 {
		fmt.Fprintf(&source, `func divFloorInteger(a %s, denominator %s) %s {
	negative := (a & %s(0x%s)) != 0
	magnitude := a
	if negative { magnitude = (%s(0) - a) & %s(0x%s) }
	quotient := magnitude / denominator
	remainder := magnitude %% denominator
	if negative && remainder != 0 { quotient = quotient + 1 }
	if negative { quotient = (%s(0) - quotient) & %s(0x%s) }
	return quotient
}
`, uintType, uintType, uintType, uintType, sign, uintType, uintType, mask,
			uintType, uintType, mask)
	}
	fmt.Fprintf(&source, `func divScaledFloor(a %s, denominator %s) %s {
	negative := (a & %s(0x%s)) != 0
	magnitude := a
	if negative { magnitude = (%s(0) - a) & %s(0x%s) }
	numerator := wideMul(magnitude, %s(0x%s))
	wideDenominator := %s(denominator)
	quotient := numerator / wideDenominator
	remainder := numerator %% wideDenominator
	if negative && remainder != 0 { quotient = quotient + 1 }
	result := %s(quotient)
	if negative { result = (%s(0) - result) & %s(0x%s) }
	return result
}
`, uintType, uintType, uintType, uintType, sign, uintType, uintType, mask,
		uintType, parsed.scale.Text(16), wideType, uintType,
		uintType, uintType, mask)
	fmt.Fprintf(&source, `func mulInteger(a %s, integer %s) %s {
	negative := (a & %s(0x%s)) != 0
	magnitude := a
	if negative { magnitude = (%s(0) - a) & %s(0x%s) }
	product := wideMul(magnitude, integer)
	result := %s(product)
	if negative { result = (%s(0) - result) & %s(0x%s) }
	return result
}
`, uintType, uintType, uintType, uintType, sign, uintType, uintType, mask,
		uintType, uintType, uintType, mask)
	fmt.Fprintf(&source, `func projectTowardZero(a %s, bound %s, denominator %s) %s {
	negative := (a & %s(0x%s)) != 0
	magnitude := a
	if negative { magnitude = (%s(0) - a) & %s(0x%s) }
	product := wideMul(magnitude, bound)
	quotient := product / %s(denominator)
	result := %s(quotient)
	if negative { result = (%s(0) - result) & %s(0x%s) }
	return result
}
`, uintType, uintType, uintType, uintType, uintType, sign, uintType,
		uintType, mask, wideType, uintType, uintType, uintType, mask)
	if ringBits > 128 {
		highMask := new(big.Int).Xor(exactGCMask(ringBits), exactGCMask(128))
		fmt.Fprintf(&source, `func inputFits128(value %s) bool {
	return (value >> 128) == 0
}
func liftSigned128(value uint128) %s {
	result := %s(value)
	if (value & uint128(0x80000000000000000000000000000000)) != 0 {
		result = result | %s(0x%s)
	}
	return result
}
`, uintType, uintType, uintType, uintType, highMask.Text(16))
	}
	fmt.Fprintf(&source, "func main(g [%d]%s, e [%d]%s) [%d]%s {\n",
		n+p+1, uintType, n, uintType, p+1, uintType)
	source.WriteString("\texecutionValid := true\n")
	emitRing128Input := func(name string, index int, signed bool) {
		if ringBits == 128 {
			fmt.Fprintf(&source, "\t%s := (g[%d] + e[%d]) & %s(0x%s)\n",
				name, index, index, uintType, mask)
			return
		}
		fmt.Fprintf(&source,
			"\t%sLow128 := uint128(g[%d]) + uint128(e[%d])\n",
			name, index, index)
		fmt.Fprintf(&source,
			"\texecutionValid = executionValid && inputFits128(g[%d]) && inputFits128(e[%d])\n",
			index, index)
		if signed {
			fmt.Fprintf(&source, "\t%s := liftSigned128(%sLow128)\n", name, name)
		} else {
			fmt.Fprintf(&source, "\t%s := %s(%sLow128)\n", name, uintType, name)
		}
	}
	rowWidth := k + 3 + p
	for row := 0; row < c; row++ {
		base := row * rowWidth
		fmt.Fprintf(&source, "\trowValid%d := true\n", row)
		for peer := 0; peer < k; peer++ {
			index := base + peer
			emitRing128Input(fmt.Sprintf("validity%d_%d", row, peer), index, false)
			fmt.Fprintf(&source,
				"\trowValid%d = rowValid%d && validity%d_%d == %s(1)\n",
				row, row, row, peer, uintType)
		}
		entryIndex, stopIndex, statusIndex := base+k, base+k+1, base+k+2
		emitRing128Input(fmt.Sprintf("entry%d", row), entryIndex, false)
		emitRing128Input(fmt.Sprintf("stop%d", row), stopIndex, false)
		emitRing128Input(fmt.Sprintf("status%d", row), statusIndex, false)
		fmt.Fprintf(&source,
			"\tresponseValid%d := entry%d < %s(%d) && stop%d >= %s(1) && stop%d <= %s(%d) && entry%d < stop%d && (status%d == %s(0) || status%d == %s(1))\n",
			row, row, uintType, policy.GridTickCount, row, uintType, row,
			uintType, policy.GridTickCount, row, row, row, uintType, row, uintType)
		if policy.EntryMode == "none" {
			fmt.Fprintf(&source,
				"\tresponseValid%d = responseValid%d && entry%d == %s(0)\n",
				row, row, row, uintType)
		}
		fmt.Fprintf(&source, "\trowValid%d = rowValid%d && responseValid%d\n",
			row, row, row)
		fmt.Fprintf(&source, "\txNormSquared%d := %s(0)\n", row, wideType)
		for coefficient := 0; coefficient < p; coefficient++ {
			index := base + k + 3 + coefficient
			emitRing128Input(fmt.Sprintf("x%d_%d", row, coefficient), index, true)
			fmt.Fprintf(&source,
				"\txValid%d_%d := !signedLess(x%d_%d, %s) && !signedLess(%s, x%d_%d)\n",
				row, coefficient, row, coefficient,
				constant(parsed.xLower[coefficient]),
				constant(parsed.xUpper[coefficient]), row, coefficient)
			fmt.Fprintf(&source,
				"\trowValid%d = rowValid%d && xValid%d_%d\n",
				row, row, row, coefficient)
			fmt.Fprintf(&source, "\txMagnitude%d_%d := x%d_%d\n",
				row, coefficient, row, coefficient)
			fmt.Fprintf(&source,
				"\tif (x%d_%d & %s(0x%s)) != 0 { xMagnitude%d_%d = (%s(0) - x%d_%d) & %s(0x%s) }\n",
				row, coefficient, uintType, sign, row, coefficient, uintType,
				row, coefficient, uintType, mask)
			fmt.Fprintf(&source,
				"\txNormSquared%d = xNormSquared%d + wideMul(xMagnitude%d_%d, xMagnitude%d_%d)\n",
				row, row, row, coefficient, row, coefficient)
		}
		xNormSquaredBound := new(big.Int).Mul(
			new(big.Int).Set(parsed.xNorm), parsed.xNorm)
		fmt.Fprintf(&source,
			"\trowValid%d = rowValid%d && xNormSquared%d <= %s(0x%s)\n",
			row, row, row, wideType, xNormSquaredBound.Text(16))
		fmt.Fprintf(&source, "\tif !rowValid%d {\n", row)
		fmt.Fprintf(&source, "\t\tentry%d = %s(0)\n\t\tstop%d = %s(1)\n\t\tstatus%d = %s(0)\n",
			row, uintType, row, uintType, row, uintType)
		for coefficient := 0; coefficient < p; coefficient++ {
			fmt.Fprintf(&source, "\t\tx%d_%d = %s(0)\n",
				row, coefficient, uintType)
		}
		source.WriteString("\t}\n")
	}
	for coefficient := 0; coefficient < p; coefficient++ {
		index := plan.RowCoordinates + coefficient
		fmt.Fprintf(&source,
			"\tbeta%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			coefficient, index, index, uintType, mask)
		fmt.Fprintf(&source, "\tbetaStartValid%d := beta%d == %s(0)\n",
			coefficient, coefficient, uintType)
		fmt.Fprintf(&source, "\texecutionValid = executionValid && betaStartValid%d\n",
			coefficient)
		fmt.Fprintf(&source, "\tif !betaStartValid%d { beta%d = %s(0) }\n",
			coefficient, coefficient, uintType)
	}
	noiseStart := plan.RowCoordinates + plan.ZeroBlindCoordinates
	noiseValidityStart := noiseStart + plan.NoiseCoordinates
	for chunk := 0; chunk < policy.NoiseChunkCount; chunk++ {
		index := noiseValidityStart + chunk
		fmt.Fprintf(&source,
			"\tsamplerValid%d := (((g[%d] + e[%d]) & %s(1)) == %s(1))\n",
			chunk, index, index, uintType, uintType)
		fmt.Fprintf(&source,
			"\texecutionValid = executionValid && samplerValid%d\n", chunk)
	}
	for iteration := 0; iteration < policy.Iterations; iteration++ {
		for coefficient := 0; coefficient < p; coefficient++ {
			index := noiseStart + iteration*p + coefficient
			emitRing128Input(fmt.Sprintf("noise%d_%d", iteration, coefficient),
				index, true)
			negativeNoiseBound := new(big.Int).Neg(new(big.Int).Set(parsed.noiseBound))
			fmt.Fprintf(&source,
				"\tnoiseValid%d_%d := !signedLess(noise%d_%d, %s) && !signedLess(%s, noise%d_%d)\n",
				iteration, coefficient, iteration, coefficient,
				constant(negativeNoiseBound), constant(parsed.noiseBound),
				iteration, coefficient)
			fmt.Fprintf(&source,
				"\texecutionValid = executionValid && noiseValid%d_%d\n",
				iteration, coefficient)
			fmt.Fprintf(&source, "\tif !noiseValid%d_%d { noise%d_%d = %s(0) }\n",
				iteration, coefficient, iteration, coefficient, uintType)
		}
		for row := 0; row < c; row++ {
			fmt.Fprintf(&source, "\teta%d_%d := %s(0)\n", iteration, row, uintType)
			// The public start is exactly zero. Omitting those algebraic zero
			// products also avoids asking the pinned compiler to synthesize a
			// dead constant wide-multiply branch.
			if iteration > 0 {
				for coefficient := 0; coefficient < p; coefficient++ {
					fmt.Fprintf(&source,
						"\teta%d_%d = (eta%d_%d + mulFloor(x%d_%d, beta%d)) & %s(0x%s)\n",
						iteration, row, iteration, row, row, coefficient, coefficient,
						uintType, mask)
				}
			}
			fmt.Fprintf(&source,
				"\tetaValid%d_%d := !signedLess(eta%d_%d, %s) && !signedLess(%s, eta%d_%d)\n",
				iteration, row, iteration, row, constant(parsed.expKnots[0]),
				constant(parsed.expKnots[len(parsed.expKnots)-1]), iteration, row)
			fmt.Fprintf(&source,
				"\texecutionValid = executionValid && etaValid%d_%d\n",
				iteration, row)
			fmt.Fprintf(&source, "\tif signedLess(eta%d_%d, %s) { eta%d_%d = %s }\n",
				iteration, row, constant(parsed.expKnots[0]), iteration, row,
				constant(parsed.expKnots[0]))
			fmt.Fprintf(&source, "\tif signedLess(%s, eta%d_%d) { eta%d_%d = %s }\n",
				constant(parsed.expKnots[len(parsed.expKnots)-1]), iteration, row,
				iteration, row, constant(parsed.expKnots[len(parsed.expKnots)-1]))
			fmt.Fprintf(&source, "\tweight%d_%d := %s\n",
				iteration, row, constant(parsed.expValues[0]))
			for segment := 1; segment < len(parsed.expValues); segment++ {
				fmt.Fprintf(&source,
					"\tif !signedLess(eta%d_%d, %s) { weight%d_%d = %s }\n",
					iteration, row, constant(parsed.expKnots[segment]), iteration,
					row, constant(parsed.expValues[segment]))
			}
		}
		for coefficient := 0; coefficient < p; coefficient++ {
			fmt.Fprintf(&source, "\tscore%d_%d := %s(0)\n",
				iteration, coefficient, uintType)
		}
		for grid := 1; grid <= policy.GridTickCount; grid++ {
			fmt.Fprintf(&source, "\triskCount%d_%d := %s(0)\n",
				iteration, grid, uintType)
			fmt.Fprintf(&source, "\teventCount%d_%d := %s(0)\n",
				iteration, grid, uintType)
			fmt.Fprintf(&source, "\ts0_%d_%d := %s(0)\n",
				iteration, grid, uintType)
			for coefficient := 0; coefficient < p; coefficient++ {
				fmt.Fprintf(&source, "\ts1_%d_%d_%d := %s(0)\n",
					iteration, grid, coefficient, uintType)
				fmt.Fprintf(&source, "\teventX%d_%d_%d := %s(0)\n",
					iteration, grid, coefficient, uintType)
			}
			for row := 0; row < c; row++ {
				fmt.Fprintf(&source,
					"\tatRisk%d_%d_%d := rowValid%d && entry%d < %s(%d) && stop%d >= %s(%d)\n",
					iteration, grid, row, row, row, uintType, grid, row, uintType, grid)
				fmt.Fprintf(&source,
					"\tevent%d_%d_%d := rowValid%d && status%d == %s(1) && stop%d == %s(%d)\n",
					iteration, grid, row, row, row, uintType, row, uintType, grid)
				fmt.Fprintf(&source, "\triskIncrement%d_%d_%d := %s(0)\n",
					iteration, grid, row, uintType)
				fmt.Fprintf(&source, "\triskWeight%d_%d_%d := %s(0)\n",
					iteration, grid, row, uintType)
				for coefficient := 0; coefficient < p; coefficient++ {
					fmt.Fprintf(&source, "\triskX%d_%d_%d_%d := %s(0)\n",
						iteration, grid, row, coefficient, uintType)
				}
				fmt.Fprintf(&source, "\tif atRisk%d_%d_%d {\n", iteration, grid, row)
				fmt.Fprintf(&source, "\t\triskIncrement%d_%d_%d = %s(1)\n",
					iteration, grid, row, uintType)
				fmt.Fprintf(&source, "\t\triskWeight%d_%d_%d = weight%d_%d\n",
					iteration, grid, row, iteration, row)
				for coefficient := 0; coefficient < p; coefficient++ {
					fmt.Fprintf(&source,
						"\t\triskX%d_%d_%d_%d = mulFloor(weight%d_%d, x%d_%d)\n",
						iteration, grid, row, coefficient, iteration, row, row, coefficient)
				}
				source.WriteString("\t}\n")
				fmt.Fprintf(&source, "\triskCount%d_%d = riskCount%d_%d + riskIncrement%d_%d_%d\n",
					iteration, grid, iteration, grid, iteration, grid, row)
				fmt.Fprintf(&source, "\ts0_%d_%d = (s0_%d_%d + riskWeight%d_%d_%d) & %s(0x%s)\n",
					iteration, grid, iteration, grid, iteration, grid, row, uintType, mask)
				for coefficient := 0; coefficient < p; coefficient++ {
					fmt.Fprintf(&source,
						"\ts1_%d_%d_%d = (s1_%d_%d_%d + riskX%d_%d_%d_%d) & %s(0x%s)\n",
						iteration, grid, coefficient, iteration, grid, coefficient,
						iteration, grid, row, coefficient, uintType, mask)
				}
				fmt.Fprintf(&source, "\teventIncrement%d_%d_%d := %s(0)\n",
					iteration, grid, row, uintType)
				for coefficient := 0; coefficient < p; coefficient++ {
					fmt.Fprintf(&source, "\teventContribution%d_%d_%d_%d := %s(0)\n",
						iteration, grid, row, coefficient, uintType)
				}
				fmt.Fprintf(&source, "\tif event%d_%d_%d {\n", iteration, grid, row)
				fmt.Fprintf(&source, "\t\teventIncrement%d_%d_%d = %s(1)\n",
					iteration, grid, row, uintType)
				for coefficient := 0; coefficient < p; coefficient++ {
					fmt.Fprintf(&source,
						"\t\teventContribution%d_%d_%d_%d = x%d_%d\n",
						iteration, grid, row, coefficient, row, coefficient)
				}
				source.WriteString("\t}\n")
				fmt.Fprintf(&source, "\teventCount%d_%d = eventCount%d_%d + eventIncrement%d_%d_%d\n",
					iteration, grid, iteration, grid, iteration, grid, row)
				for coefficient := 0; coefficient < p; coefficient++ {
					fmt.Fprintf(&source,
						"\teventX%d_%d_%d = (eventX%d_%d_%d + eventContribution%d_%d_%d_%d) & %s(0x%s)\n",
						iteration, grid, coefficient, iteration, grid, coefficient,
						iteration, grid, row, coefficient, uintType, mask)
				}
			}
			fmt.Fprintf(&source,
				"\triskFloorValid%d_%d := eventCount%d_%d == %s(0) || riskCount%d_%d >= %s(%d)\n",
				iteration, grid, iteration, grid, uintType, iteration, grid,
				uintType, policy.MinimumAtRisk)
			fmt.Fprintf(&source,
				"\texecutionValid = executionValid && riskFloorValid%d_%d\n",
				iteration, grid)
			fmt.Fprintf(&source, "\tdenominator%d_%d := s0_%d_%d\n",
				iteration, grid, iteration, grid)
			fmt.Fprintf(&source, "\tif denominator%d_%d == %s(0) { denominator%d_%d = %s(1) }\n",
				iteration, grid, uintType, iteration, grid, uintType)
			for coefficient := 0; coefficient < p; coefficient++ {
				fmt.Fprintf(&source,
					"\tmean%d_%d_%d := divScaledFloor(s1_%d_%d_%d, denominator%d_%d)\n",
					iteration, grid, coefficient, iteration, grid, coefficient,
					iteration, grid)
				fmt.Fprintf(&source,
					"\triskTerm%d_%d_%d := mulInteger(mean%d_%d_%d, eventCount%d_%d)\n",
					iteration, grid, coefficient, iteration, grid, coefficient,
					iteration, grid)
				fmt.Fprintf(&source,
					"\tscore%d_%d = (score%d_%d + eventX%d_%d_%d - riskTerm%d_%d_%d) & %s(0x%s)\n",
					iteration, coefficient, iteration, coefficient, iteration, grid,
					coefficient, iteration, grid, coefficient, uintType, mask)
			}
		}
		for coefficient := 0; coefficient < p; coefficient++ {
			if c == 1 {
				fmt.Fprintf(&source, "\taverage%d_%d := score%d_%d\n",
					iteration, coefficient, iteration, coefficient)
			} else {
				fmt.Fprintf(&source,
					"\taverage%d_%d := divFloorInteger(score%d_%d, %s(%d))\n",
					iteration, coefficient, iteration, coefficient, uintType, c)
			}
			if parsed.ridge.Sign() == 0 {
				fmt.Fprintf(&source, "\tridge%d_%d := %s(0)\n",
					iteration, coefficient, uintType)
			} else {
				fmt.Fprintf(&source, "\tridge%d_%d := mulFloor(%s, beta%d)\n",
					iteration, coefficient, constant(parsed.ridge), coefficient)
			}
			fmt.Fprintf(&source,
				"\tgradient%d_%d := (average%d_%d - ridge%d_%d + noise%d_%d) & %s(0x%s)\n",
				iteration, coefficient, iteration, coefficient, iteration,
				coefficient, iteration, coefficient, uintType, mask)
			fmt.Fprintf(&source, "\tstep%d_%d := mulFloor(%s, gradient%d_%d)\n",
				iteration, coefficient, constant(parsed.alpha), iteration, coefficient)
			fmt.Fprintf(&source,
				"\tcandidate%d_%d := (beta%d + step%d_%d) & %s(0x%s)\n",
				iteration, coefficient, coefficient, iteration, coefficient,
				uintType, mask)
		}
		fmt.Fprintf(&source, "\tbetaNormSquared%d := %s(0)\n", iteration, wideType)
		for coefficient := 0; coefficient < p; coefficient++ {
			fmt.Fprintf(&source, "\tcandidateMagnitude%d_%d := candidate%d_%d\n",
				iteration, coefficient, iteration, coefficient)
			fmt.Fprintf(&source,
				"\tif (candidate%d_%d & %s(0x%s)) != 0 { candidateMagnitude%d_%d = (%s(0) - candidate%d_%d) & %s(0x%s) }\n",
				iteration, coefficient, uintType, sign, iteration, coefficient,
				uintType, iteration, coefficient, uintType, mask)
			fmt.Fprintf(&source,
				"\tbetaNormSquared%d = betaNormSquared%d + wideMul(candidateMagnitude%d_%d, candidateMagnitude%d_%d)\n",
				iteration, iteration, iteration, coefficient, iteration, coefficient)
		}
		betaNormSquared := new(big.Int).Mul(
			new(big.Int).Set(parsed.betaNorm), parsed.betaNorm)
		fmt.Fprintf(&source, "\toutsideBall%d := betaNormSquared%d > %s(0x%s)\n",
			iteration, iteration, wideType, betaNormSquared.Text(16))
		fmt.Fprintf(&source, "\trootLow%d := %s(0)\n", iteration, uintType)
		fmt.Fprintf(&source, "\trootHigh%d := %s(0x%s)\n",
			iteration, uintType, projectionRootUpper.Text(16))
		firstRootMid := new(big.Int).Rsh(
			new(big.Int).Set(projectionRootUpper), 1)
		firstRootSquare := new(big.Int).Mul(
			new(big.Int).Set(firstRootMid), firstRootMid)
		fmt.Fprintf(&source,
			"\trootLess%d_0 := %s(0x%s) < betaNormSquared%d\n",
			iteration, wideType, firstRootSquare.Text(16), iteration)
		fmt.Fprintf(&source, "\tif rootLess%d_0 { rootLow%d = %s(0x%s) }\n",
			iteration, iteration, uintType,
			new(big.Int).Add(new(big.Int).Set(firstRootMid), big.NewInt(1)).Text(16))
		fmt.Fprintf(&source, "\tif !rootLess%d_0 { rootHigh%d = %s(0x%s) }\n",
			iteration, iteration, uintType, firstRootMid.Text(16))
		for search := 1; search < plan.ProjectionSearchSteps; search++ {
			fmt.Fprintf(&source,
				"\trootMid%d_%d := rootLow%d + ((rootHigh%d - rootLow%d) >> 1)\n",
				iteration, search, iteration, iteration, iteration)
			fmt.Fprintf(&source,
				"\trootSquare%d_%d := wideMul(rootMid%d_%d, rootMid%d_%d)\n",
				iteration, search, iteration, search, iteration, search)
			fmt.Fprintf(&source, "\trootLess%d_%d := rootSquare%d_%d < betaNormSquared%d\n",
				iteration, search, iteration, search, iteration)
			fmt.Fprintf(&source, "\tnextRootLow%d_%d := rootLow%d\n",
				iteration, search, iteration)
			fmt.Fprintf(&source, "\tnextRootHigh%d_%d := rootHigh%d\n",
				iteration, search, iteration)
			fmt.Fprintf(&source, "\tif rootLess%d_%d { nextRootLow%d_%d = rootMid%d_%d + %s(1) }\n",
				iteration, search, iteration, search, iteration, search, uintType)
			fmt.Fprintf(&source, "\tif !rootLess%d_%d { nextRootHigh%d_%d = rootMid%d_%d }\n",
				iteration, search, iteration, search, iteration, search)
			fmt.Fprintf(&source, "\trootLow%d = nextRootLow%d_%d\n",
				iteration, iteration, search)
			fmt.Fprintf(&source, "\trootHigh%d = nextRootHigh%d_%d\n",
				iteration, iteration, search)
		}
		fmt.Fprintf(&source, "\tprojectionDenominator%d := rootLow%d\n",
			iteration, iteration)
		fmt.Fprintf(&source, "\tif projectionDenominator%d == %s(0) { projectionDenominator%d = %s(1) }\n",
			iteration, uintType, iteration, uintType)
		for coefficient := 0; coefficient < p; coefficient++ {
			fmt.Fprintf(&source, "\tbeta%d = candidate%d_%d\n",
				coefficient, iteration, coefficient)
			fmt.Fprintf(&source,
				"\tif outsideBall%d { beta%d = projectTowardZero(candidate%d_%d, %s, projectionDenominator%d) }\n",
				iteration, coefficient, iteration, coefficient,
				constant(parsed.betaNorm), iteration)
		}
	}
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tif !executionValid { beta%d = %s(0) }\n",
			coefficient, uintType)
		fmt.Fprintf(&source,
			"\tout%d := (beta%d - g[%d]) & %s(0x%s)\n",
			coefficient, coefficient, n+coefficient, uintType, mask)
	}
	fmt.Fprintf(&source, "\tvar out [%d]%s\n", p+1, uintType)
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tout[%d] = out%d\n", coefficient, coefficient)
	}
	fmt.Fprintf(&source, "\tout[%d] = %s(0)\n", p, uintType)
	fmt.Fprintf(&source,
		"\tif executionValid != ((g[%d] & %s(1)) != 0) { out[%d] = %s(1) }\n",
		n+p, uintType, p, uintType)
	source.WriteString("\treturn out\n}\n")
	return source.String(), nil
}

var formalCoxCircuitCache = struct {
	sync.Mutex
	digest string
	ring   int
	circ   *circuit.Circuit
}{}

func formalCoxCompileSource(source string) (circ *circuit.Circuit, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			circ = nil
			err = exactGCFailure(exactGCFailureNumericBackendUnavailable,
				fmt.Errorf("formal-cox: pinned compiler panic: %v", recovered))
		}
	}()
	circ, _, err = compiler.New(utils.NewParams()).Compile(source, nil)
	return circ, err
}

func compileFormalCoxCircuit(policy formalCoxPhase1Policy,
	ringBits int) (*circuit.Circuit, error) {
	digest, err := formalCoxPolicyDigest(policy)
	if err != nil {
		return nil, err
	}
	key := hex.EncodeToString(digest[:])
	formalCoxCircuitCache.Lock()
	if formalCoxCircuitCache.circ != nil &&
		formalCoxCircuitCache.digest == key && formalCoxCircuitCache.ring == ringBits {
		result := formalCoxCircuitCache.circ
		formalCoxCircuitCache.Unlock()
		return result, nil
	}
	formalCoxCircuitCache.Unlock()
	source, err := formalCoxCircuitSource(policy, ringBits)
	if err != nil {
		return nil, err
	}
	circ, err := formalCoxCompileSource(source)
	if err != nil {
		return nil, exactGCFailure(exactGCFailureNumericBackendUnavailable,
			fmt.Errorf("formal-cox: compile sealed iterations: %w", err))
	}
	plan, _ := planFormalCoxPhase1(policy)
	if len(circ.Inputs) != 2 || len(circ.Outputs) != 1 ||
		circ.Outputs.Size() != (policy.CovariateCount+1)*plan.ContainerBits {
		return nil, fmt.Errorf("formal-cox: compiler produced invalid circuit arity")
	}
	formalCoxCircuitCache.Lock()
	formalCoxCircuitCache.digest = key
	formalCoxCircuitCache.ring = ringBits
	formalCoxCircuitCache.circ = circ
	formalCoxCircuitCache.Unlock()
	return circ, nil
}

func validateFormalCoxSession(session exactGCSession,
	policy formalCoxPhase1Policy) (formalCoxParsedPolicy,
	formalCoxPhase1Plan, error) {
	parsed, err := parseFormalCoxPhase1Policy(policy)
	if err != nil {
		return parsed, formalCoxPhase1Plan{}, err
	}
	plan, err := planFormalCoxPhase1(policy)
	if err != nil {
		return parsed, plan, err
	}
	purpose, _ := formalCoxPurpose(policy)
	if session.Spec.Operation != exactGCFormalCoxIterations ||
		session.Spec.RingBits != plan.RingBits ||
		session.Spec.FracBits != policy.FracBits ||
		session.Spec.VectorLen != plan.InputCoordinates ||
		session.Spec.Threshold != nil || session.Spec.BoundX != nil ||
		session.Spec.BoundY != nil || session.Spec.MulBackend != "" ||
		session.Purpose != purpose ||
		session.GarblerID != policy.ComputePeers[0] ||
		session.EvaluatorID != policy.ComputePeers[1] {
		return parsed, plan, fmt.Errorf("formal-cox: session/policy binding mismatch")
	}
	if err := session.validate(); err != nil {
		return parsed, plan, err
	}
	return parsed, plan, nil
}

type formalCoxSealedOutput struct {
	CoefficientShares []*big.Int
	ValidityShare     bool
}

func formalCoxRandomOutputMasks(count, ringBits int) ([]*big.Int, bool, error) {
	result := make([]*big.Int, count)
	for index := range result {
		value, err := rand.Int(rand.Reader, exactGCModulus(ringBits))
		if err != nil {
			return nil, false, fmt.Errorf("formal-cox: generate output mask: %w", err)
		}
		result[index] = value
	}
	bit, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		exactGCZeroBigInts(result)
		return nil, false, fmt.Errorf("formal-cox: generate validity mask: %w", err)
	}
	return result, bit.Sign() != 0, nil
}

func runFormalCoxGarbler(rw io.ReadWriter, session exactGCSession,
	policy formalCoxPhase1Policy, shares []*big.Int) (formalCoxSealedOutput, error) {
	var zero formalCoxSealedOutput
	_, _, err := validateFormalCoxSession(session, policy)
	if err != nil {
		return zero, err
	}
	if rw == nil {
		return zero, fmt.Errorf("formal-cox: nil peer channel")
	}
	if err := exactGCValidateShares(shares, session.Spec); err != nil {
		return zero, err
	}
	masks, validity, err := formalCoxRandomOutputMasks(
		policy.CovariateCount, session.Spec.RingBits)
	if err != nil {
		return zero, err
	}
	circ, err := compileFormalCoxCircuit(policy, session.Spec.RingBits)
	if err != nil {
		exactGCZeroBigInts(masks)
		return zero, err
	}
	packed := append(append([]*big.Int{}, shares...), masks...)
	if validity {
		packed = append(packed, big.NewInt(1))
	} else {
		packed = append(packed, big.NewInt(0))
	}
	input := exactGCPackChunks(packed, exactGCTypeBits(session.Spec.RingBits))
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleGarbler)
	if err != nil {
		exactGCZeroBigInts(masks)
		return zero, err
	}
	conn := p2p.NewConn(secure)
	protocolErr := exactGCGarblerProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		exactGCZeroBigInts(masks)
		return zero, err
	}
	return formalCoxSealedOutput{
		CoefficientShares: masks, ValidityShare: validity,
	}, nil
}

func runFormalCoxEvaluator(rw io.ReadWriter, session exactGCSession,
	policy formalCoxPhase1Policy, shares []*big.Int) (formalCoxSealedOutput, error) {
	var zero formalCoxSealedOutput
	_, _, err := validateFormalCoxSession(session, policy)
	if err != nil {
		return zero, err
	}
	if rw == nil {
		return zero, fmt.Errorf("formal-cox: nil peer channel")
	}
	if err := exactGCValidateShares(shares, session.Spec); err != nil {
		return zero, err
	}
	circ, err := compileFormalCoxCircuit(policy, session.Spec.RingBits)
	if err != nil {
		return zero, err
	}
	input := exactGCPackChunks(shares, exactGCTypeBits(session.Spec.RingBits))
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleEvaluator)
	if err != nil {
		return zero, err
	}
	conn := p2p.NewConn(secure)
	result, protocolErr := exactGCEvaluatorProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return zero, err
	}
	stride := exactGCTypeBits(session.Spec.RingBits)
	outputs := make([]*big.Int, policy.CovariateCount+1)
	for index := range outputs {
		outputs[index] = new(big.Int).Rsh(new(big.Int).Set(result), uint(index*stride))
		outputs[index].And(outputs[index], exactGCMask(session.Spec.RingBits))
	}
	validity := outputs[len(outputs)-1].Bit(0) == 1
	return formalCoxSealedOutput{
		CoefficientShares: outputs[:len(outputs)-1], ValidityShare: validity,
	}, nil
}

func reconstructFormalCoxOutput(left, right formalCoxSealedOutput,
	ringBits int) ([]*big.Int, bool, error) {
	if len(left.CoefficientShares) != len(right.CoefficientShares) {
		return nil, false, errors.New("formal-cox: output share shape mismatch")
	}
	result := make([]*big.Int, len(left.CoefficientShares))
	for index := range result {
		result[index] = exactGCReferenceReconstruct(
			left.CoefficientShares[index], right.CoefficientShares[index], ringBits)
	}
	return result, left.ValidityShare != right.ValidityShare, nil
}

func formalCoxFloorDiv(value, denominator *big.Int) *big.Int {
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(value, denominator, remainder)
	if value.Sign() < 0 && remainder.Sign() != 0 {
		quotient.Sub(quotient, big.NewInt(1))
	}
	return quotient
}

func formalCoxProjectTowardZero(value, bound,
	denominator *big.Int) *big.Int {
	magnitude := formalCoxAbs(value)
	magnitude.Mul(magnitude, bound)
	magnitude.Quo(magnitude, denominator)
	if value.Sign() < 0 {
		magnitude.Neg(magnitude)
	}
	return magnitude
}

type formalCoxReferenceRow struct {
	valid       bool
	entry, stop int
	status      int
	x           []*big.Int
}

// referenceFormalCoxIterations is an independent unbounded-big.Int lattice
// oracle. It mirrors the signed-floor contract, but does not use the circuit
// compiler, Boolean types, modular intermediates or Yao protocol.
func referenceFormalCoxIterations(policy formalCoxPhase1Policy,
	input []*big.Int, ringBits int) ([]*big.Int, bool, error) {
	parsed, err := parseFormalCoxPhase1Policy(policy)
	if err != nil {
		return nil, false, err
	}
	plan, err := planFormalCoxPhase1(policy)
	if err != nil {
		return nil, false, err
	}
	if ringBits != plan.RingBits || len(input) != plan.InputCoordinates {
		return nil, false, fmt.Errorf("formal-cox: invalid reference input shape")
	}
	values := make([]*big.Int, len(input))
	for index := range input {
		if input[index] == nil || input[index].Sign() < 0 ||
			input[index].Cmp(exactGCModulus(ringBits)) >= 0 {
			return nil, false, fmt.Errorf("formal-cox: invalid reference residue")
		}
		values[index] = exactGCReferenceSigned(input[index], ringBits)
	}
	c, p, k := policy.Capacity, policy.CovariateCount,
		len(policy.CustodianPeers)
	rowWidth := k + 3 + p
	rows := make([]formalCoxReferenceRow, c)
	for row := 0; row < c; row++ {
		base := row * rowWidth
		valid := true
		for peer := 0; peer < k; peer++ {
			valid = valid && values[base+peer].Cmp(big.NewInt(1)) == 0
		}
		entryValue, stopValue, statusValue := values[base+k],
			values[base+k+1], values[base+k+2]
		entryOK := entryValue.Sign() >= 0 && entryValue.IsInt64() &&
			entryValue.Int64() < int64(policy.GridTickCount)
		stopOK := stopValue.IsInt64() && stopValue.Int64() >= 1 &&
			stopValue.Int64() <= int64(policy.GridTickCount)
		statusOK := statusValue.Sign() == 0 || statusValue.Cmp(big.NewInt(1)) == 0
		if policy.EntryMode == "none" {
			entryOK = entryOK && entryValue.Sign() == 0
		}
		valid = valid && entryOK && stopOK && statusOK &&
			entryValue.Cmp(stopValue) < 0
		x := make([]*big.Int, p)
		normSquared := new(big.Int)
		for coefficient := 0; coefficient < p; coefficient++ {
			x[coefficient] = new(big.Int).Set(values[base+k+3+coefficient])
			valid = valid && x[coefficient].Cmp(parsed.xLower[coefficient]) >= 0 &&
				x[coefficient].Cmp(parsed.xUpper[coefficient]) <= 0
			normSquared.Add(normSquared,
				new(big.Int).Mul(new(big.Int).Set(x[coefficient]), x[coefficient]))
		}
		valid = valid && normSquared.Cmp(new(big.Int).Mul(
			new(big.Int).Set(parsed.xNorm), parsed.xNorm)) <= 0
		rows[row] = formalCoxReferenceRow{valid: valid, x: x}
		if valid {
			rows[row].entry, rows[row].stop = int(entryValue.Int64()), int(stopValue.Int64())
			rows[row].status = int(statusValue.Int64())
		} else {
			rows[row].entry, rows[row].stop, rows[row].status = 0, 1, 0
			for coefficient := range rows[row].x {
				rows[row].x[coefficient] = new(big.Int)
			}
		}
	}
	beta := make([]*big.Int, p)
	executionValid := true
	for coefficient := range beta {
		beta[coefficient] = new(big.Int).Set(
			values[plan.RowCoordinates+coefficient])
		if beta[coefficient].Sign() != 0 {
			executionValid = false
			beta[coefficient].SetInt64(0)
		}
	}
	noiseStart := plan.RowCoordinates + plan.ZeroBlindCoordinates
	noiseValidityStart := noiseStart + plan.NoiseCoordinates
	for chunk := 0; chunk < policy.NoiseChunkCount; chunk++ {
		if values[noiseValidityStart+chunk].Bit(0) != 1 {
			executionValid = false
		}
	}
	for iteration := 0; iteration < policy.Iterations; iteration++ {
		noise := make([]*big.Int, p)
		for coefficient := 0; coefficient < p; coefficient++ {
			noise[coefficient] = new(big.Int).Set(
				values[noiseStart+iteration*p+coefficient])
			if formalCoxAbs(noise[coefficient]).Cmp(parsed.noiseBound) > 0 {
				executionValid = false
				noise[coefficient].SetInt64(0)
			}
		}
		weights := make([]*big.Int, c)
		for row := 0; row < c; row++ {
			eta := new(big.Int)
			for coefficient := 0; coefficient < p; coefficient++ {
				eta.Add(eta, formalCoxFloorMul(
					rows[row].x[coefficient], beta[coefficient], parsed.scale))
			}
			if eta.Cmp(parsed.expKnots[0]) < 0 ||
				eta.Cmp(parsed.expKnots[len(parsed.expKnots)-1]) > 0 {
				executionValid = false
				if eta.Cmp(parsed.expKnots[0]) < 0 {
					eta.Set(parsed.expKnots[0])
				} else {
					eta.Set(parsed.expKnots[len(parsed.expKnots)-1])
				}
			}
			segment := 0
			for segment+1 < len(parsed.expValues) &&
				eta.Cmp(parsed.expKnots[segment+1]) >= 0 {
				segment++
			}
			weights[row] = new(big.Int).Set(parsed.expValues[segment])
		}
		score := make([]*big.Int, p)
		for coefficient := range score {
			score[coefficient] = new(big.Int)
		}
		for grid := 1; grid <= policy.GridTickCount; grid++ {
			riskCount, eventCount := 0, 0
			s0 := new(big.Int)
			s1 := make([]*big.Int, p)
			eventX := make([]*big.Int, p)
			for coefficient := 0; coefficient < p; coefficient++ {
				s1[coefficient], eventX[coefficient] = new(big.Int), new(big.Int)
			}
			for row := 0; row < c; row++ {
				atRisk := rows[row].valid && rows[row].entry < grid &&
					rows[row].stop >= grid
				event := rows[row].valid && rows[row].status == 1 &&
					rows[row].stop == grid
				if atRisk {
					riskCount++
					s0.Add(s0, weights[row])
					for coefficient := 0; coefficient < p; coefficient++ {
						s1[coefficient].Add(s1[coefficient], formalCoxFloorMul(
							weights[row], rows[row].x[coefficient], parsed.scale))
					}
				}
				if event {
					eventCount++
					for coefficient := 0; coefficient < p; coefficient++ {
						eventX[coefficient].Add(
							eventX[coefficient], rows[row].x[coefficient])
					}
				}
			}
			if eventCount > 0 && riskCount < policy.MinimumAtRisk {
				executionValid = false
			}
			denominator := new(big.Int).Set(s0)
			if denominator.Sign() == 0 {
				denominator.SetInt64(1)
			}
			for coefficient := 0; coefficient < p; coefficient++ {
				mean := formalCoxFloorDiv(new(big.Int).Mul(
					new(big.Int).Set(s1[coefficient]), parsed.scale), denominator)
				riskTerm := new(big.Int).Mul(mean, big.NewInt(int64(eventCount)))
				score[coefficient].Add(score[coefficient], eventX[coefficient])
				score[coefficient].Sub(score[coefficient], riskTerm)
			}
		}
		candidate := make([]*big.Int, p)
		normSquared := new(big.Int)
		for coefficient := 0; coefficient < p; coefficient++ {
			average := formalCoxFloorDiv(
				score[coefficient], big.NewInt(int64(c)))
			ridge := formalCoxFloorMul(
				parsed.ridge, beta[coefficient], parsed.scale)
			gradient := new(big.Int).Sub(average, ridge)
			gradient.Add(gradient, noise[coefficient])
			step := formalCoxFloorMul(parsed.alpha, gradient, parsed.scale)
			candidate[coefficient] = new(big.Int).Add(beta[coefficient], step)
			normSquared.Add(normSquared, new(big.Int).Mul(
				new(big.Int).Set(candidate[coefficient]), candidate[coefficient]))
		}
		boundSquared := new(big.Int).Mul(
			new(big.Int).Set(parsed.betaNorm), parsed.betaNorm)
		if normSquared.Cmp(boundSquared) > 0 {
			denominator := formalCoxCeilSqrt(normSquared)
			for coefficient := 0; coefficient < p; coefficient++ {
				beta[coefficient] = formalCoxProjectTowardZero(
					candidate[coefficient], parsed.betaNorm, denominator)
			}
		} else {
			beta = candidate
		}
	}
	result := make([]*big.Int, p)
	for coefficient := range result {
		if !executionValid {
			result[coefficient] = new(big.Int)
		} else {
			result[coefficient] = formalCoxResidue(beta[coefficient], ringBits)
		}
	}
	return result, executionValid, nil
}
