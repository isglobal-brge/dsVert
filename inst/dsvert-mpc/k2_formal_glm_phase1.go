package main

// Phase-1 vertical slice for a sealed formal GLM iteration.
//
// This is deliberately a specialised exact-GC runner, not a command handler.
// It opens no value and is absent from the advertised runtime capability.  A
// producer-bound worker/DSI adapter and the Phase-2 noisy opening are required
// before this can become a package method.

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
	exactGCFormalGLMOneIteration   exactGCOperation = "formal-glm-one-iteration-v1"
	formalGLMPhase1PolicyVersion                    = "dsvert-formal-glm-phase1-policy-v1"
	formalGLMPhase1PlanVersion                      = "dsvert-formal-glm-phase1-plan-v1"
	formalGLMPhase1MaxCapacity                      = 8
	formalGLMPhase1MaxCoefficients                  = 4
	formalGLMPhase1MaxSegments                      = 8
)

// formalGLMPhase1Policy is public, custodian-cross-signed policy. Every fixed-
// point number is a canonical signed decimal integer in units of 2^-FracBits.
// SourceShare itself is never part of this object or its digest.
type formalGLMPhase1Policy struct {
	Version          string   `json:"version"`
	ArtifactSHA256   string   `json:"artifact_sha256"`
	CapsuleSHA256    string   `json:"capsule_sha256"`
	SnapshotSHA256   string   `json:"snapshot_sha256"`
	PinsetSHA256     string   `json:"pinset_sha256"`
	CompilerSHA256   string   `json:"compiler_sha256"`
	TheoremSHA256    string   `json:"theorem_sha256"`
	CustodianPeers   []string `json:"custodian_peers"`
	ComputePeers     []string `json:"compute_peers"`
	Family           string   `json:"family"`
	Adjacency        string   `json:"adjacency"`
	Capacity         int      `json:"capacity"`
	CoefficientCount int      `json:"coefficient_count"`
	Iterations       int      `json:"iterations"`
	FracBits         int      `json:"frac_bits"`
	XKind            []string `json:"x_kind"`
	XLower           []string `json:"x_lower"`
	XUpper           []string `json:"x_upper"`
	WeightUpper      string   `json:"weight_upper"`
	OutcomeUpper     string   `json:"outcome_upper"`
	OffsetLower      string   `json:"offset_lower"`
	OffsetUpper      string   `json:"offset_upper"`
	BetaStart        []string `json:"beta_start"`
	Ridge            []string `json:"ridge"`
	CoefficientBox   []string `json:"coefficient_box"`
	Alpha            string   `json:"alpha"`
	LinkKnots        []string `json:"link_knots"`
	LinkValues       []string `json:"link_values"`
	LinkSlopes       []string `json:"link_slopes"`
	LinkErrorUpper   string   `json:"link_error_upper"`
	LinkTableSHA256  string   `json:"link_table_sha256"`
	Missingness      string   `json:"missingness"`
	PatientCollapse  string   `json:"patient_collapse"`
	ReductionOrder   string   `json:"reduction_order"`
	Truncation       string   `json:"truncation"`
	InputLayout      string   `json:"input_layout"`
	InputSharing     string   `json:"input_sharing"`
	Output           string   `json:"output"`
}

type formalGLMPhase1Plan struct {
	Version                string `json:"version"`
	PolicySHA256           string `json:"policy_sha256"`
	RingBits               int    `json:"ring_bits"`
	ContainerBits          int    `json:"container_bits"`
	FracBits               int    `json:"frac_bits"`
	InputCoordinates       int    `json:"input_coordinates"`
	OutputCoordinates      int    `json:"output_coordinates"`
	MaximumMagnitude       string `json:"maximum_magnitude"`
	RhoStepsUpper          string `json:"rho_steps_upper"`
	LogicalFixedShapeMul   int    `json:"logical_fixed_shape_multiplications"`
	LogicalFixedShapeCmp   int    `json:"logical_fixed_shape_comparisons"`
	ProductionReleaseReady bool   `json:"production_release_ready"`
	ProducerAdapterStatus  string `json:"producer_adapter_status"`
	Phase2OpeningStatus    string `json:"phase2_opening_status"`
}

type formalGLMNumericBackendError struct {
	Code         string
	RequiredBits int
}

type formalGLMResourcePlanError struct {
	Code             string
	TypedInputBits   int
	MaximumInputBits int
}

func (e *formalGLMResourcePlanError) Error() string {
	return fmt.Sprintf("formal-glm: %s (typed input bits %d exceed %d)",
		e.Code, e.TypedInputBits, e.MaximumInputBits)
}

// formalGLMPhase1Cost is derived solely from cross-signed public policy. It
// lets an adapter admit or decline the exact circuit before any source share
// is materialised. Network bytes remain transport-dependent and are not
// disguised as an exact estimate.
type formalGLMPhase1Cost struct {
	Version                   string `json:"version"`
	PolicySHA256              string `json:"policy_sha256"`
	CircuitSourceSHA256       string `json:"circuit_source_sha256"`
	RingBits                  int    `json:"ring_bits"`
	ContainerBits             int    `json:"container_bits"`
	GarblerInputBits          int    `json:"garbler_input_bits"`
	EvaluatorInputBits        int    `json:"evaluator_input_bits"`
	OutputBits                int    `json:"output_bits"`
	Gates                     int    `json:"gates"`
	Wires                     int    `json:"wires"`
	XORGates                  uint64 `json:"xor_gates"`
	NonXORGates               uint64 `json:"non_xor_gates"`
	CompilerRelativeCost      uint64 `json:"compiler_relative_cost"`
	BackendSelection          string `json:"backend_selection"`
	NetworkByteEstimateStatus string `json:"network_byte_estimate_status"`
	TranscriptShapeStatus     string `json:"transcript_shape_status"`
	ProductionReleaseReady    bool   `json:"production_release_ready"`
}

func (e *formalGLMNumericBackendError) Error() string {
	return fmt.Sprintf("formal-glm: %s (required ring bits %d)",
		e.Code, e.RequiredBits)
}

type formalGLMParsedPolicy struct {
	policy       formalGLMPhase1Policy
	scale        *big.Int
	xLower       []*big.Int
	xUpper       []*big.Int
	weightUpper  *big.Int
	outcomeUpper *big.Int
	offsetLower  *big.Int
	offsetUpper  *big.Int
	betaStart    []*big.Int
	ridge        []*big.Int
	box          []*big.Int
	alpha        *big.Int
	knots        []*big.Int
	values       []*big.Int
	slopes       []*big.Int
	linkError    *big.Int
}

func formalGLMCanonicalSigned(value, name string) (*big.Int, error) {
	if value == "" || len(value) > exactGCMaxDecimalBoundDigits ||
		strings.HasPrefix(value, "+") || value == "-0" ||
		(len(value) > 1 && value[0] == '0') ||
		(len(value) > 2 && value[0] == '-' && value[1] == '0') {
		return nil, fmt.Errorf("formal-glm: invalid %s", name)
	}
	result := new(big.Int)
	if _, ok := result.SetString(value, 10); !ok || result.String() != value {
		return nil, fmt.Errorf("formal-glm: invalid %s", name)
	}
	return result, nil
}

func formalGLMParseVector(values []string, n int, name string) ([]*big.Int, error) {
	if len(values) != n {
		return nil, fmt.Errorf("formal-glm: invalid %s shape", name)
	}
	result := make([]*big.Int, n)
	for i, value := range values {
		parsed, err := formalGLMCanonicalSigned(value, fmt.Sprintf("%s[%d]", name, i))
		if err != nil {
			return nil, err
		}
		result[i] = parsed
	}
	return result, nil
}

func formalGLMIsSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func formalGLMPolicyDigest(policy formalGLMPhase1Policy) ([32]byte, error) {
	encoded, err := json.Marshal(policy)
	if err != nil {
		return [32]byte{}, fmt.Errorf("formal-glm: encode policy: %w", err)
	}
	return sha256.Sum256(append(
		[]byte("dsVert/formal-glm/phase1-policy/v1|"), encoded...)), nil
}

func formalGLMPurpose(policy formalGLMPhase1Policy) (string, error) {
	digest, err := formalGLMPolicyDigest(policy)
	if err != nil {
		return "", err
	}
	return "formal-glm/phase1-v1/" + hex.EncodeToString(digest[:]), nil
}

func parseFormalGLMPhase1Policy(policy formalGLMPhase1Policy) (formalGLMParsedPolicy, error) {
	var result formalGLMParsedPolicy
	if policy.Version != formalGLMPhase1PolicyVersion ||
		policy.Family != "binomial" && policy.Family != "poisson" ||
		policy.Adjacency != "add_remove" && policy.Adjacency != "replace_one" ||
		policy.Capacity < 1 || policy.Capacity > formalGLMPhase1MaxCapacity ||
		policy.CoefficientCount < 1 ||
		policy.CoefficientCount > formalGLMPhase1MaxCoefficients ||
		policy.Iterations != 1 || policy.FracBits < 8 || policy.FracBits > 256 ||
		len(policy.LinkSlopes) < 2 ||
		len(policy.LinkSlopes) > formalGLMPhase1MaxSegments ||
		len(policy.LinkKnots) != len(policy.LinkSlopes)+1 ||
		len(policy.LinkValues) != len(policy.LinkKnots) {
		return result, fmt.Errorf("formal-glm: unsupported Phase-1 policy shape")
	}
	for _, value := range []string{
		policy.ArtifactSHA256, policy.CapsuleSHA256, policy.SnapshotSHA256,
		policy.PinsetSHA256, policy.CompilerSHA256, policy.TheoremSHA256,
		policy.LinkTableSHA256,
	} {
		if !formalGLMIsSHA256(value) {
			return result, fmt.Errorf("formal-glm: invalid public commitment")
		}
	}
	if len(policy.CustodianPeers) < 2 || len(policy.ComputePeers) != 2 ||
		!sort.StringsAreSorted(policy.CustodianPeers) ||
		!sort.StringsAreSorted(policy.ComputePeers) {
		return result, fmt.Errorf("formal-glm: invalid custodian/compute peer set")
	}
	seen := make(map[string]bool)
	for _, peer := range policy.CustodianPeers {
		if err := exactGCValidateLabel("custodian identity", peer, 256); err != nil || seen[peer] {
			return result, fmt.Errorf("formal-glm: invalid custodian peer set")
		}
		seen[peer] = true
	}
	if policy.ComputePeers[0] == policy.ComputePeers[1] ||
		!seen[policy.ComputePeers[0]] || !seen[policy.ComputePeers[1]] {
		return result, fmt.Errorf("formal-glm: invalid designated compute peers")
	}
	if policy.Missingness != "complete_tuple_zero_weight" ||
		policy.PatientCollapse != "one_aligned_record_duplicates_zero_weight_v1" ||
		policy.ReductionOrder != "capacity_slot_then_coefficient_v1" ||
		policy.Truncation != "signed_floor_after_each_multiply_v1" ||
		policy.InputLayout != "capacity_major_weight_design_outcome_offset_v1" ||
		policy.InputSharing != "additive_mod_2k_two_recipient_v1" ||
		policy.Output != "sealed_coefficient_additive_shares_only_v1" {
		return result, fmt.Errorf("formal-glm: unsupported scientific contract")
	}
	p := policy.CoefficientCount
	if len(policy.XKind) != p {
		return result, fmt.Errorf("formal-glm: invalid design-kind shape")
	}
	for _, kind := range policy.XKind {
		if kind != "numeric" && kind != "intercept" &&
			kind != "categorical_indicator" && kind != "binary_indicator" {
			return result, fmt.Errorf("formal-glm: invalid design kind")
		}
	}
	var err error
	result.xLower, err = formalGLMParseVector(policy.XLower, p, "x lower")
	if err != nil {
		return result, err
	}
	result.xUpper, err = formalGLMParseVector(policy.XUpper, p, "x upper")
	if err != nil {
		return result, err
	}
	result.betaStart, err = formalGLMParseVector(policy.BetaStart, p, "beta start")
	if err != nil {
		return result, err
	}
	result.ridge, err = formalGLMParseVector(policy.Ridge, p, "ridge")
	if err != nil {
		return result, err
	}
	result.box, err = formalGLMParseVector(policy.CoefficientBox, p, "coefficient box")
	if err != nil {
		return result, err
	}
	result.knots, err = formalGLMParseVector(policy.LinkKnots,
		len(policy.LinkKnots), "link knot")
	if err != nil {
		return result, err
	}
	result.values, err = formalGLMParseVector(policy.LinkValues,
		len(policy.LinkValues), "link value")
	if err != nil {
		return result, err
	}
	result.slopes, err = formalGLMParseVector(policy.LinkSlopes,
		len(policy.LinkSlopes), "link slope")
	if err != nil {
		return result, err
	}
	parseScalar := func(value, name string) (*big.Int, error) {
		return formalGLMCanonicalSigned(value, name)
	}
	if result.weightUpper, err = parseScalar(policy.WeightUpper, "weight upper"); err != nil {
		return result, err
	}
	if result.outcomeUpper, err = parseScalar(policy.OutcomeUpper, "outcome upper"); err != nil {
		return result, err
	}
	if result.offsetLower, err = parseScalar(policy.OffsetLower, "offset lower"); err != nil {
		return result, err
	}
	if result.offsetUpper, err = parseScalar(policy.OffsetUpper, "offset upper"); err != nil {
		return result, err
	}
	if result.alpha, err = parseScalar(policy.Alpha, "alpha"); err != nil {
		return result, err
	}
	if result.linkError, err = parseScalar(policy.LinkErrorUpper, "link error upper"); err != nil {
		return result, err
	}
	result.scale = new(big.Int).Lsh(big.NewInt(1), uint(policy.FracBits))
	if result.weightUpper.Sign() <= 0 || result.outcomeUpper.Sign() < 0 ||
		result.linkError.Sign() < 0 ||
		result.offsetLower.Cmp(result.offsetUpper) > 0 || result.alpha.Sign() <= 0 {
		return result, fmt.Errorf("formal-glm: invalid scalar bounds")
	}
	if policy.Family == "binomial" && result.outcomeUpper.Cmp(result.scale) != 0 {
		return result, fmt.Errorf("formal-glm: binomial outcome domain must be {0,1}")
	}
	if policy.Family == "poisson" && (result.outcomeUpper.Sign() <= 0 ||
		new(big.Int).Mod(new(big.Int).Set(result.outcomeUpper), result.scale).Sign() != 0) {
		return result, fmt.Errorf("formal-glm: Poisson outcome cap must be a positive integer")
	}
	for i := 0; i < p; i++ {
		if result.xLower[i].Cmp(result.xUpper[i]) > 0 ||
			result.betaStart[i].Sign() != 0 || result.ridge[i].Sign() <= 0 ||
			result.box[i].Sign() <= 0 {
			return result, fmt.Errorf("formal-glm: invalid coefficient policy")
		}
		if formalGLMIndicatorKind(policy.XKind[i]) &&
			(result.xLower[i].Sign() != 0 || result.xUpper[i].Cmp(result.scale) != 0) {
			return result, fmt.Errorf("formal-glm: invalid indicator domain")
		}
		if policy.XKind[i] == "intercept" &&
			(result.xLower[i].Cmp(result.scale) != 0 ||
				result.xUpper[i].Cmp(result.scale) != 0) {
			return result, fmt.Errorf("formal-glm: invalid intercept domain")
		}
	}
	if result.knots[0].Cmp(result.knots[len(result.knots)-1]) >= 0 {
		return result, fmt.Errorf("formal-glm: invalid link domain")
	}
	for i := range result.slopes {
		if result.knots[i].Cmp(result.knots[i+1]) >= 0 ||
			result.values[i].Cmp(result.values[i+1]) > 0 ||
			result.slopes[i].Sign() < 0 {
			return result, fmt.Errorf("formal-glm: non-monotone link table")
		}
		width := new(big.Int).Sub(result.knots[i+1], result.knots[i])
		predicted := formalGLMFloorMul(result.slopes[i], width, result.scale)
		predicted.Add(predicted, result.values[i])
		if predicted.Cmp(result.values[i+1]) != 0 {
			return result, fmt.Errorf("formal-glm: discontinuous fixed-point link table")
		}
	}
	if policy.Family == "binomial" {
		for _, value := range result.values {
			if value.Sign() < 0 || value.Cmp(result.scale) > 0 {
				return result, fmt.Errorf("formal-glm: binomial link is outside [0,1]")
			}
		}
	} else {
		for _, value := range result.values {
			if value.Sign() <= 0 {
				return result, fmt.Errorf("formal-glm: Poisson link must be positive")
			}
		}
	}
	if err := formalGLMValidateContraction(result); err != nil {
		return result, err
	}
	result.policy = policy
	return result, nil
}

func formalGLMIndicatorKind(kind string) bool {
	return kind == "categorical_indicator" || kind == "binary_indicator"
}

func formalGLMValidateContraction(policy formalGLMParsedPolicy) error {
	toRat := func(value *big.Int) *big.Rat {
		return new(big.Rat).SetFrac(new(big.Int).Set(value),
			new(big.Int).Set(policy.scale))
	}
	lambdaMin := new(big.Int).Set(policy.ridge[0])
	lambdaMax := new(big.Int).Set(policy.ridge[0])
	rSquared := new(big.Rat)
	for i := range policy.ridge {
		if policy.ridge[i].Cmp(lambdaMin) < 0 {
			lambdaMin.Set(policy.ridge[i])
		}
		if policy.ridge[i].Cmp(lambdaMax) > 0 {
			lambdaMax.Set(policy.ridge[i])
		}
		x := formalGLMMax(formalGLMAbs(policy.xLower[i]),
			formalGLMAbs(policy.xUpper[i]))
		xRat := toRat(x)
		rSquared.Add(rSquared, new(big.Rat).Mul(xRat, xRat))
	}
	slopeMax := big.NewInt(0)
	for _, slope := range policy.slopes {
		slopeMax = formalGLMMax(slopeMax, slope)
	}
	smoothness := new(big.Rat).Add(toRat(lambdaMax),
		new(big.Rat).Mul(toRat(policy.weightUpper),
			new(big.Rat).Mul(rSquared, toRat(slopeMax))))
	strongConvexity := toRat(lambdaMin)
	denominator := new(big.Rat).Add(strongConvexity, smoothness)
	stepLimit := new(big.Rat).Quo(big.NewRat(2, 1), denominator)
	alpha := toRat(policy.alpha)
	if alpha.Cmp(stepLimit) > 0 {
		return fmt.Errorf("formal-glm: public step is not contractive")
	}
	one := big.NewRat(1, 1)
	left := new(big.Rat).Sub(one,
		new(big.Rat).Mul(alpha, strongConvexity))
	right := new(big.Rat).Sub(big.NewRat(1, 1),
		new(big.Rat).Mul(alpha, smoothness))
	left.Abs(left)
	right.Abs(right)
	if left.Cmp(one) >= 0 || right.Cmp(one) >= 0 {
		return fmt.Errorf("formal-glm: public optimizer is not strictly contractive")
	}
	return nil
}

func formalGLMAbs(value *big.Int) *big.Int {
	return new(big.Int).Abs(new(big.Int).Set(value))
}

func formalGLMMax(values ...*big.Int) *big.Int {
	result := big.NewInt(0)
	for _, value := range values {
		if value.Cmp(result) > 0 {
			result.Set(value)
		}
	}
	return result
}

func formalGLMCeilMul(left, right, scale *big.Int) *big.Int {
	product := new(big.Int).Mul(formalGLMAbs(left), formalGLMAbs(right))
	return exactGCCeilDiv(product, scale)
}

func formalGLMFloorMul(left, right, scale *big.Int) *big.Int {
	product := new(big.Int).Mul(left, right)
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(product, scale, remainder)
	if product.Sign() < 0 && remainder.Sign() != 0 {
		quotient.Sub(quotient, big.NewInt(1))
	}
	return quotient
}

func planFormalGLMPhase1(policy formalGLMPhase1Policy) (formalGLMPhase1Plan, error) {
	parsed, err := parseFormalGLMPhase1Policy(policy)
	if err != nil {
		return formalGLMPhase1Plan{}, err
	}
	digest, _ := formalGLMPolicyDigest(policy)
	p, c := policy.CoefficientCount, policy.Capacity
	maximum := formalGLMMax(parsed.scale, parsed.weightUpper,
		parsed.outcomeUpper, formalGLMAbs(parsed.offsetLower),
		formalGLMAbs(parsed.offsetUpper), parsed.alpha)
	etaLower := new(big.Int).Set(parsed.offsetLower)
	etaUpper := new(big.Int).Set(parsed.offsetUpper)
	for i := 0; i < p; i++ {
		x := formalGLMMax(formalGLMAbs(parsed.xLower[i]),
			formalGLMAbs(parsed.xUpper[i]))
		maximum = formalGLMMax(maximum, x, parsed.box[i], parsed.ridge[i],
			formalGLMAbs(parsed.betaStart[i]))
		contribution := formalGLMCeilMul(x, parsed.box[i], parsed.scale)
		etaLower.Sub(etaLower, contribution)
		etaUpper.Add(etaUpper, contribution)
	}
	if etaLower.Cmp(parsed.knots[0]) < 0 ||
		etaUpper.Cmp(parsed.knots[len(parsed.knots)-1]) > 0 {
		return formalGLMPhase1Plan{}, fmt.Errorf("formal-glm: link domain does not cover eta bound")
	}
	etaMagnitude := formalGLMMax(formalGLMAbs(etaLower), formalGLMAbs(etaUpper))
	linkMagnitude := big.NewInt(0)
	segmentWidth := big.NewInt(0)
	for i, knot := range parsed.knots {
		maximum = formalGLMMax(maximum, formalGLMAbs(knot),
			formalGLMAbs(parsed.values[i]))
		linkMagnitude = formalGLMMax(linkMagnitude,
			formalGLMAbs(parsed.values[i]))
		if i < len(parsed.slopes) {
			width := new(big.Int).Sub(parsed.knots[i+1], parsed.knots[i])
			segmentWidth = formalGLMMax(segmentWidth, width)
			maximum = formalGLMMax(maximum, parsed.slopes[i])
		}
	}
	maximum = formalGLMMax(maximum, etaMagnitude, segmentWidth, linkMagnitude)
	residual := new(big.Int).Add(linkMagnitude, parsed.outcomeUpper)
	weightedResidual := formalGLMCeilMul(parsed.weightUpper, residual, parsed.scale)
	gradient := make([]*big.Int, p)
	candidate := make([]*big.Int, p)
	for i := 0; i < p; i++ {
		x := formalGLMMax(formalGLMAbs(parsed.xLower[i]),
			formalGLMAbs(parsed.xUpper[i]))
		rowScore := formalGLMCeilMul(x, weightedResidual, parsed.scale)
		accumulator := new(big.Int).Mul(rowScore, big.NewInt(int64(c)))
		average := exactGCCeilDiv(accumulator, big.NewInt(int64(c)))
		ridge := formalGLMCeilMul(parsed.ridge[i],
			formalGLMAbs(parsed.betaStart[i]), parsed.scale)
		gradient[i] = new(big.Int).Add(average, ridge)
		step := formalGLMCeilMul(parsed.alpha, gradient[i], parsed.scale)
		candidate[i] = new(big.Int).Add(
			formalGLMAbs(parsed.betaStart[i]), step)
		maximum = formalGLMMax(maximum, etaMagnitude, linkMagnitude, residual,
			weightedResidual, accumulator, gradient[i], candidate[i])
	}
	// One fixed-point step of uncertainty for each floor, propagated with a
	// deliberately conservative public L1 envelope. This is a Phase-1 numeric
	// differential bound, not a DP sensitivity or mechanism radius.
	slopeMax := big.NewInt(0)
	for _, slope := range parsed.slopes {
		slopeMax = formalGLMMax(slopeMax, slope)
	}
	etaError := big.NewInt(int64(p))
	muError := new(big.Int).Add(
		formalGLMCeilMul(slopeMax, etaError, parsed.scale), big.NewInt(1))
	wrError := new(big.Int).Add(
		formalGLMCeilMul(parsed.weightUpper, muError, parsed.scale), big.NewInt(1))
	rho := big.NewInt(0)
	for i := 0; i < p; i++ {
		x := formalGLMMax(formalGLMAbs(parsed.xLower[i]),
			formalGLMAbs(parsed.xUpper[i]))
		scoreError := new(big.Int).Add(
			formalGLMCeilMul(x, wrError, parsed.scale), big.NewInt(1))
		averageError := new(big.Int).Add(scoreError, big.NewInt(1))
		gradientError := new(big.Int).Add(averageError, big.NewInt(1))
		stepError := new(big.Int).Add(
			formalGLMCeilMul(parsed.alpha, gradientError, parsed.scale), big.NewInt(1))
		rho.Add(rho, stepError)
	}
	required := maximum.BitLen() + 2
	ringBits := 128
	if required > ringBits {
		ringBits = required
	}
	if ringBits > exactGCMaxRingBits {
		return formalGLMPhase1Plan{}, &formalGLMNumericBackendError{
			Code: "numeric_backend_unrepresentable", RequiredBits: ringBits}
	}
	spec := exactGCCircuitSpec{
		Operation: exactGCFormalGLMOneIteration,
		RingBits:  ringBits, FracBits: policy.FracBits,
		VectorLen: c * (p + 3),
	}
	if inputBits := exactGCCircuitInputBits(spec); inputBits > exactGCMaxCircuitTypeBits {
		return formalGLMPhase1Plan{}, &formalGLMResourcePlanError{
			Code: "public_circuit_shape_unrepresentable", TypedInputBits: inputBits,
			MaximumInputBits: exactGCMaxCircuitTypeBits,
		}
	}
	segments := len(parsed.slopes)
	return formalGLMPhase1Plan{
		Version:      formalGLMPhase1PlanVersion,
		PolicySHA256: hex.EncodeToString(digest[:]), RingBits: ringBits,
		ContainerBits: exactGCTypeBits(ringBits), FracBits: policy.FracBits,
		InputCoordinates: c * (p + 3), OutputCoordinates: p,
		MaximumMagnitude: maximum.String(), RhoStepsUpper: rho.String(),
		LogicalFixedShapeMul:   c*(2*p+2) + 2*p,
		LogicalFixedShapeCmp:   c*(2*p+segments+8) + 2*p,
		ProductionReleaseReady: false,
		ProducerAdapterStatus:  "phase1_worker_dsi_adapter_pending",
		Phase2OpeningStatus:    "sealed_shares_only_no_opening",
	}, nil
}

func formalGLMPhase1PublicCost(policy formalGLMPhase1Policy) (formalGLMPhase1Cost, error) {
	plan, err := planFormalGLMPhase1(policy)
	if err != nil {
		return formalGLMPhase1Cost{}, err
	}
	source, err := formalGLMCircuitSource(policy, plan.RingBits)
	if err != nil {
		return formalGLMPhase1Cost{}, err
	}
	circ, err := compileFormalGLMCircuit(policy, plan.RingBits)
	if err != nil {
		return formalGLMPhase1Cost{}, err
	}
	policyDigest, _ := formalGLMPolicyDigest(policy)
	sourceDigest := sha256.Sum256([]byte(source))
	n := plan.InputCoordinates
	p := plan.OutputCoordinates
	return formalGLMPhase1Cost{
		Version:             "dsvert-formal-glm-phase1-cost-v1",
		PolicySHA256:        hex.EncodeToString(policyDigest[:]),
		CircuitSourceSHA256: hex.EncodeToString(sourceDigest[:]),
		RingBits:            plan.RingBits, ContainerBits: plan.ContainerBits,
		GarblerInputBits:   (n + p) * plan.ContainerBits,
		EvaluatorInputBits: n * plan.ContainerBits,
		OutputBits:         p * plan.ContainerBits,
		Gates:              circ.NumGates, Wires: circ.NumWires,
		XORGates: circ.Stats.NumXOR(), NonXORGates: circ.Stats.NumNonXOR(),
		CompilerRelativeCost:      circ.Cost(),
		BackendSelection:          "single_composite_exact_gc_ot_no_runtime_fallback_v1",
		NetworkByteEstimateStatus: "transport_and_garbling_dependent_not_estimated",
		TranscriptShapeStatus:     "fixed_logical_schedule_randomized_encoded_byte_count_padding_audit_pending",
		ProductionReleaseReady:    false,
	}, nil
}

func validateFormalGLMSession(session exactGCSession,
	policy formalGLMPhase1Policy) (formalGLMParsedPolicy, formalGLMPhase1Plan, error) {
	parsed, err := parseFormalGLMPhase1Policy(policy)
	if err != nil {
		return parsed, formalGLMPhase1Plan{}, err
	}
	plan, err := planFormalGLMPhase1(policy)
	if err != nil {
		return parsed, plan, err
	}
	purpose, _ := formalGLMPurpose(policy)
	wantInputs := policy.Capacity * (policy.CoefficientCount + 3)
	if session.Spec.Operation != exactGCFormalGLMOneIteration ||
		session.Spec.RingBits != plan.RingBits ||
		session.Spec.FracBits != policy.FracBits ||
		session.Spec.VectorLen != wantInputs || session.Purpose != purpose ||
		session.GarblerID != policy.ComputePeers[0] ||
		session.EvaluatorID != policy.ComputePeers[1] {
		return parsed, plan, fmt.Errorf("formal-glm: session/policy binding mismatch")
	}
	if err := session.validate(); err != nil {
		return parsed, plan, err
	}
	return parsed, plan, nil
}

func formalGLMResidue(value *big.Int, bits int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Set(value), exactGCModulus(bits))
}

func formalGLMHex(value *big.Int, bits int) string {
	return formalGLMResidue(value, bits).Text(16)
}

func formalGLMCircuitSource(policy formalGLMPhase1Policy, ringBits int) (string, error) {
	parsed, err := parseFormalGLMPhase1Policy(policy)
	if err != nil {
		return "", err
	}
	typeBits := exactGCTypeBits(ringBits)
	uintType := fmt.Sprintf("uint%d", typeBits)
	wideType := fmt.Sprintf("uint%d", 2*typeBits)
	mask := exactGCMask(ringBits).Text(16)
	sign := new(big.Int).Lsh(big.NewInt(1), uint(ringBits-1)).Text(16)
	fracMask := new(big.Int).Sub(new(big.Int).Set(parsed.scale), big.NewInt(1)).Text(16)
	p, c := policy.CoefficientCount, policy.Capacity
	n := c * (p + 3)
	constValue := func(value *big.Int) string {
		return fmt.Sprintf("%s(0x%s)", uintType, formalGLMHex(value, ringBits))
	}
	var source strings.Builder
	fmt.Fprintf(&source, `package main
func signedLess(a %s, b %s) bool {
	aNeg := (a & %s(0x%s)) != 0
	bNeg := (b & %s(0x%s)) != 0
	if aNeg != bNeg { return aNeg }
	return a < b
}
func mulFloor(a %s, b %s) %s {
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
func divFloor(a %s, denominator %s) %s {
	negative := (a & %s(0x%s)) != 0
	magnitude := a
	if negative { magnitude = (%s(0) - a) & %s(0x%s) }
	quotient := magnitude / denominator
	remainder := magnitude %% denominator
	if negative && remainder != 0 { quotient = quotient + 1 }
	if negative { quotient = (%s(0) - quotient) & %s(0x%s) }
	return quotient
}
`, uintType, uintType, uintType, sign, uintType, sign,
		uintType, uintType, uintType,
		uintType, sign, uintType, sign,
		uintType, uintType, mask, uintType, uintType, mask,
		policy.FracBits, wideType, fracMask, uintType,
		uintType, uintType, mask,
		uintType, uintType, uintType, uintType, sign,
		uintType, uintType, mask, uintType, uintType, mask)
	fmt.Fprintf(&source, "func main(g [%d]%s, e [%d]%s) [%d]%s {\n",
		n+p, uintType, n, uintType, p, uintType)
	for j := 0; j < p; j++ {
		fmt.Fprintf(&source, "\tgradient%d := %s(0)\n", j, uintType)
	}
	for row := 0; row < c; row++ {
		base := row * (p + 3)
		fmt.Fprintf(&source, "\tw%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			row, base, base, uintType, mask)
		fmt.Fprintf(&source, "\tif signedLess(w%d, %s(0)) { w%d = %s(0) }\n",
			row, uintType, row, uintType)
		fmt.Fprintf(&source, "\tif signedLess(%s, w%d) { w%d = %s }\n",
			constValue(parsed.weightUpper), row, row, constValue(parsed.weightUpper))
		fmt.Fprintf(&source, "\trowValid%d := true\n", row)
		for j := 0; j < p; j++ {
			index := base + 1 + j
			fmt.Fprintf(&source, "\tx%d_%d := (g[%d] + e[%d]) & %s(0x%s)\n",
				row, j, index, index, uintType, mask)
			if formalGLMIndicatorKind(policy.XKind[j]) {
				fmt.Fprintf(&source,
					"\txValid%d_%d := x%d_%d == %s(0) || x%d_%d == %s\n",
					row, j, row, j, uintType, row, j, constValue(parsed.scale))
				fmt.Fprintf(&source,
					"\trowValid%d = rowValid%d && xValid%d_%d\n", row, row, row, j)
				fmt.Fprintf(&source,
					"\tif !xValid%d_%d { x%d_%d = %s(0) }\n",
					row, j, row, j, uintType)
			} else {
				fmt.Fprintf(&source,
					"\tif signedLess(x%d_%d, %s) { x%d_%d = %s }\n",
					row, j, constValue(parsed.xLower[j]), row, j,
					constValue(parsed.xLower[j]))
				fmt.Fprintf(&source,
					"\tif signedLess(%s, x%d_%d) { x%d_%d = %s }\n",
					constValue(parsed.xUpper[j]), row, j, row, j,
					constValue(parsed.xUpper[j]))
			}
		}
		yIndex, oIndex := base+p+1, base+p+2
		fmt.Fprintf(&source, "\ty%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			row, yIndex, yIndex, uintType, mask)
		if policy.Family == "binomial" {
			fmt.Fprintf(&source, "\tyValid%d := y%d == %s(0) || y%d == %s\n",
				row, row, uintType, row, constValue(parsed.scale))
		} else {
			fmt.Fprintf(&source, "\tyValid%d := (y%d & %s(0x%s)) == 0\n",
				row, row, uintType, fracMask)
		}
		fmt.Fprintf(&source, "\trowValid%d = rowValid%d && yValid%d\n",
			row, row, row)
		fmt.Fprintf(&source, "\tif !yValid%d { y%d = %s(0) }\n", row, row, uintType)
		fmt.Fprintf(&source, "\tif signedLess(y%d, %s(0)) { y%d = %s(0) }\n",
			row, uintType, row, uintType)
		fmt.Fprintf(&source, "\tif signedLess(%s, y%d) { y%d = %s }\n",
			constValue(parsed.outcomeUpper), row, row,
			constValue(parsed.outcomeUpper))
		fmt.Fprintf(&source, "\to%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			row, oIndex, oIndex, uintType, mask)
		fmt.Fprintf(&source, "\tif signedLess(o%d, %s) { o%d = %s }\n",
			row, constValue(parsed.offsetLower), row, constValue(parsed.offsetLower))
		fmt.Fprintf(&source, "\tif signedLess(%s, o%d) { o%d = %s }\n",
			constValue(parsed.offsetUpper), row, row, constValue(parsed.offsetUpper))
		fmt.Fprintf(&source, "\tif !rowValid%d { w%d = %s(0) }\n", row, row, uintType)
		fmt.Fprintf(&source, "\teta%d := o%d\n", row, row)
		fmt.Fprintf(&source, "\tif signedLess(eta%d, %s) { eta%d = %s }\n",
			row, constValue(parsed.knots[0]), row, constValue(parsed.knots[0]))
		fmt.Fprintf(&source, "\tif signedLess(%s, eta%d) { eta%d = %s }\n",
			constValue(parsed.knots[len(parsed.knots)-1]), row, row,
			constValue(parsed.knots[len(parsed.knots)-1]))
		fmt.Fprintf(&source, "\tknot%d := %s\n\tmuBase%d := %s\n\tslope%d := %s\n",
			row, constValue(parsed.knots[0]), row, constValue(parsed.values[0]),
			row, constValue(parsed.slopes[0]))
		for segment := 1; segment < len(parsed.slopes); segment++ {
			fmt.Fprintf(&source, "\tif !signedLess(eta%d, %s) {\n", row,
				constValue(parsed.knots[segment]))
			fmt.Fprintf(&source, "\t\tknot%d = %s\n\t\tmuBase%d = %s\n\t\tslope%d = %s\n\t}\n",
				row, constValue(parsed.knots[segment]), row,
				constValue(parsed.values[segment]), row,
				constValue(parsed.slopes[segment]))
		}
		fmt.Fprintf(&source,
			"\tmu%d := (muBase%d + mulFloor(slope%d, (eta%d - knot%d) & %s(0x%s))) & %s(0x%s)\n",
			row, row, row, row, row, uintType, mask, uintType, mask)
		fmt.Fprintf(&source, "\tresidual%d := (mu%d - y%d) & %s(0x%s)\n",
			row, row, row, uintType, mask)
		fmt.Fprintf(&source, "\tweighted%d := mulFloor(w%d, residual%d)\n",
			row, row, row)
		for j := 0; j < p; j++ {
			fmt.Fprintf(&source,
				"\tgradient%d = (gradient%d + mulFloor(x%d_%d, weighted%d)) & %s(0x%s)\n",
				j, j, row, j, row, uintType, mask)
		}
	}
	for j := 0; j < p; j++ {
		fmt.Fprintf(&source, "\taverage%d := divFloor(gradient%d, %s(%d))\n",
			j, j, uintType, c)
		fmt.Fprintf(&source, "\tfullGradient%d := average%d\n", j, j)
		fmt.Fprintf(&source, "\tstep%d := mulFloor(%s, fullGradient%d)\n",
			j, constValue(parsed.alpha), j)
		fmt.Fprintf(&source, "\tbeta%d := (%s - step%d) & %s(0x%s)\n",
			j, constValue(parsed.betaStart[j]), j, uintType, mask)
		negativeBox := new(big.Int).Neg(new(big.Int).Set(parsed.box[j]))
		fmt.Fprintf(&source, "\tif signedLess(beta%d, %s) { beta%d = %s }\n",
			j, constValue(negativeBox), j, constValue(negativeBox))
		fmt.Fprintf(&source, "\tif signedLess(%s, beta%d) { beta%d = %s }\n",
			constValue(parsed.box[j]), j, j, constValue(parsed.box[j]))
		fmt.Fprintf(&source, "\tout%d := (beta%d - g[%d]) & %s(0x%s)\n",
			j, j, n+j, uintType, mask)
	}
	fmt.Fprintf(&source, "\tvar out [%d]%s\n", p, uintType)
	for j := 0; j < p; j++ {
		fmt.Fprintf(&source, "\tout[%d] = out%d\n", j, j)
	}
	source.WriteString("\treturn out\n}\n")
	return source.String(), nil
}

var formalGLMCircuitCache = struct {
	sync.Mutex
	digest string
	ring   int
	circ   *circuit.Circuit
}{}

func compileFormalGLMCircuit(policy formalGLMPhase1Policy,
	ringBits int) (*circuit.Circuit, error) {
	digest, err := formalGLMPolicyDigest(policy)
	if err != nil {
		return nil, err
	}
	key := hex.EncodeToString(digest[:])
	formalGLMCircuitCache.Lock()
	if formalGLMCircuitCache.circ != nil && formalGLMCircuitCache.digest == key &&
		formalGLMCircuitCache.ring == ringBits {
		circ := formalGLMCircuitCache.circ
		formalGLMCircuitCache.Unlock()
		return circ, nil
	}
	formalGLMCircuitCache.Unlock()
	source, err := formalGLMCircuitSource(policy, ringBits)
	if err != nil {
		return nil, err
	}
	circ, _, err := compiler.New(utils.NewParams()).Compile(source, nil)
	if err != nil {
		return nil, exactGCFailure(exactGCFailureNumericBackendUnavailable,
			fmt.Errorf("formal-glm: compile sealed iteration: %w", err))
	}
	if len(circ.Inputs) != 2 || len(circ.Outputs) != 1 ||
		circ.Outputs.Size() != policy.CoefficientCount*exactGCTypeBits(ringBits) {
		return nil, fmt.Errorf("formal-glm: compiler produced invalid circuit arity")
	}
	formalGLMCircuitCache.Lock()
	formalGLMCircuitCache.digest = key
	formalGLMCircuitCache.ring = ringBits
	formalGLMCircuitCache.circ = circ
	formalGLMCircuitCache.Unlock()
	return circ, nil
}

func formalGLMRandomMasks(count, ringBits int) ([]*big.Int, error) {
	result := make([]*big.Int, count)
	for i := range result {
		value, err := rand.Int(rand.Reader, exactGCModulus(ringBits))
		if err != nil {
			return nil, fmt.Errorf("formal-glm: generate sealed output mask: %w", err)
		}
		result[i] = value
	}
	return result, nil
}

func runFormalGLMGarbler(rw io.ReadWriter, session exactGCSession,
	policy formalGLMPhase1Policy, shares []*big.Int) ([]*big.Int, error) {
	parsed, _, err := validateFormalGLMSession(session, policy)
	if err != nil {
		return nil, err
	}
	_ = parsed
	if rw == nil {
		return nil, fmt.Errorf("formal-glm: nil peer channel")
	}
	if err := exactGCValidateShares(shares, session.Spec); err != nil {
		return nil, err
	}
	masks, err := formalGLMRandomMasks(policy.CoefficientCount, session.Spec.RingBits)
	if err != nil {
		return nil, err
	}
	circ, err := compileFormalGLMCircuit(policy, session.Spec.RingBits)
	if err != nil {
		return nil, err
	}
	input := exactGCPackChunks(append(append([]*big.Int{}, shares...), masks...),
		exactGCTypeBits(session.Spec.RingBits))
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleGarbler)
	if err != nil {
		return nil, err
	}
	conn := p2p.NewConn(secure)
	protocolErr := exactGCGarblerProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return nil, err
	}
	return masks, nil
}

func runFormalGLMEvaluator(rw io.ReadWriter, session exactGCSession,
	policy formalGLMPhase1Policy, shares []*big.Int) ([]*big.Int, error) {
	_, _, err := validateFormalGLMSession(session, policy)
	if err != nil {
		return nil, err
	}
	if rw == nil {
		return nil, fmt.Errorf("formal-glm: nil peer channel")
	}
	if err := exactGCValidateShares(shares, session.Spec); err != nil {
		return nil, err
	}
	circ, err := compileFormalGLMCircuit(policy, session.Spec.RingBits)
	if err != nil {
		return nil, err
	}
	input := exactGCPackChunks(shares, exactGCTypeBits(session.Spec.RingBits))
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleEvaluator)
	if err != nil {
		return nil, err
	}
	conn := p2p.NewConn(secure)
	result, protocolErr := exactGCEvaluatorProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return nil, err
	}
	outputs := make([]*big.Int, policy.CoefficientCount)
	stride := exactGCTypeBits(session.Spec.RingBits)
	for i := range outputs {
		outputs[i] = new(big.Int).Rsh(new(big.Int).Set(result), uint(i*stride))
		outputs[i].And(outputs[i], exactGCMask(session.Spec.RingBits))
	}
	return outputs, nil
}

func formalGLMClamp(value, lower, upper *big.Int) *big.Int {
	if value.Cmp(lower) < 0 {
		return new(big.Int).Set(lower)
	}
	if value.Cmp(upper) > 0 {
		return new(big.Int).Set(upper)
	}
	return new(big.Int).Set(value)
}

// referenceFormalGLMOneIteration is independent of the circuit compiler and
// specifies the exact signed-floor lattice result used by differential tests.
func referenceFormalGLMOneIteration(policy formalGLMPhase1Policy,
	input []*big.Int, ringBits int) ([]*big.Int, error) {
	parsed, err := parseFormalGLMPhase1Policy(policy)
	if err != nil {
		return nil, err
	}
	p, c := policy.CoefficientCount, policy.Capacity
	if len(input) != c*(p+3) {
		return nil, fmt.Errorf("formal-glm: invalid reference input shape")
	}
	values := make([]*big.Int, len(input))
	for i := range input {
		if input[i] == nil || input[i].Sign() < 0 || input[i].Cmp(exactGCModulus(ringBits)) >= 0 {
			return nil, fmt.Errorf("formal-glm: invalid reference residue")
		}
		values[i] = exactGCReferenceSigned(input[i], ringBits)
	}
	gradient := make([]*big.Int, p)
	for i := range gradient {
		gradient[i] = big.NewInt(0)
	}
	for row := 0; row < c; row++ {
		base := row * (p + 3)
		weight := formalGLMClamp(values[base], big.NewInt(0), parsed.weightUpper)
		valid := true
		x := make([]*big.Int, p)
		for j := 0; j < p; j++ {
			x[j] = new(big.Int).Set(values[base+1+j])
			if formalGLMIndicatorKind(policy.XKind[j]) {
				if x[j].Sign() != 0 && x[j].Cmp(parsed.scale) != 0 {
					valid = false
					x[j].SetInt64(0)
				}
			} else {
				x[j] = formalGLMClamp(x[j], parsed.xLower[j], parsed.xUpper[j])
			}
		}
		y := new(big.Int).Set(values[base+p+1])
		if policy.Family == "binomial" {
			if y.Sign() != 0 && y.Cmp(parsed.scale) != 0 {
				valid = false
				y.SetInt64(0)
			}
		} else if new(big.Int).And(new(big.Int).Set(y),
			new(big.Int).Sub(new(big.Int).Set(parsed.scale), big.NewInt(1))).Sign() != 0 {
			valid = false
			y.SetInt64(0)
		}
		y = formalGLMClamp(y, big.NewInt(0), parsed.outcomeUpper)
		offset := formalGLMClamp(values[base+p+2], parsed.offsetLower, parsed.offsetUpper)
		if !valid {
			weight.SetInt64(0)
		}
		eta := new(big.Int).Set(offset)
		for j := 0; j < p; j++ {
			eta.Add(eta, formalGLMFloorMul(x[j], parsed.betaStart[j], parsed.scale))
		}
		eta = formalGLMClamp(eta, parsed.knots[0], parsed.knots[len(parsed.knots)-1])
		segment := 0
		for segment+1 < len(parsed.slopes) && eta.Cmp(parsed.knots[segment+1]) >= 0 {
			segment++
		}
		mu := new(big.Int).Add(parsed.values[segment], formalGLMFloorMul(
			parsed.slopes[segment], new(big.Int).Sub(eta, parsed.knots[segment]), parsed.scale))
		residual := new(big.Int).Sub(mu, y)
		weighted := formalGLMFloorMul(weight, residual, parsed.scale)
		for j := 0; j < p; j++ {
			gradient[j].Add(gradient[j], formalGLMFloorMul(x[j], weighted, parsed.scale))
		}
	}
	result := make([]*big.Int, p)
	for j := 0; j < p; j++ {
		average, remainder := new(big.Int), new(big.Int)
		average.QuoRem(gradient[j], big.NewInt(int64(c)), remainder)
		if gradient[j].Sign() < 0 && remainder.Sign() != 0 {
			average.Sub(average, big.NewInt(1))
		}
		fullGradient := average.Add(average,
			formalGLMFloorMul(parsed.ridge[j], parsed.betaStart[j], parsed.scale))
		candidate := new(big.Int).Sub(parsed.betaStart[j],
			formalGLMFloorMul(parsed.alpha, fullGradient, parsed.scale))
		candidate = formalGLMClamp(candidate,
			new(big.Int).Neg(new(big.Int).Set(parsed.box[j])), parsed.box[j])
		result[j] = formalGLMResidue(candidate, ringBits)
	}
	return result, nil
}

// referenceFormalGLMRationalOneIteration evaluates the same clipped PWL
// iteration without fixed-point truncation. It is independent of both the
// circuit compiler and the integer-lattice oracle above.
func referenceFormalGLMRationalOneIteration(policy formalGLMPhase1Policy,
	input []*big.Int, ringBits int) ([]*big.Rat, error) {
	parsed, err := parseFormalGLMPhase1Policy(policy)
	if err != nil {
		return nil, err
	}
	p, c := policy.CoefficientCount, policy.Capacity
	if len(input) != c*(p+3) {
		return nil, fmt.Errorf("formal-glm: invalid rational reference input shape")
	}
	integers := make([]*big.Int, len(input))
	for i := range input {
		if input[i] == nil || input[i].Sign() < 0 ||
			input[i].Cmp(exactGCModulus(ringBits)) >= 0 {
			return nil, fmt.Errorf("formal-glm: invalid rational reference residue")
		}
		integers[i] = exactGCReferenceSigned(input[i], ringBits)
	}
	rat := func(value *big.Int) *big.Rat {
		return new(big.Rat).SetFrac(new(big.Int).Set(value),
			new(big.Int).Set(parsed.scale))
	}
	gradient := make([]*big.Rat, p)
	for i := range gradient {
		gradient[i] = new(big.Rat)
	}
	for row := 0; row < c; row++ {
		base := row * (p + 3)
		weightInt := formalGLMClamp(integers[base], big.NewInt(0), parsed.weightUpper)
		valid := true
		xInt := make([]*big.Int, p)
		for j := 0; j < p; j++ {
			xInt[j] = new(big.Int).Set(integers[base+1+j])
			if formalGLMIndicatorKind(policy.XKind[j]) {
				if xInt[j].Sign() != 0 && xInt[j].Cmp(parsed.scale) != 0 {
					valid = false
					xInt[j].SetInt64(0)
				}
			} else {
				xInt[j] = formalGLMClamp(xInt[j], parsed.xLower[j], parsed.xUpper[j])
			}
		}
		yInt := new(big.Int).Set(integers[base+p+1])
		if policy.Family == "binomial" {
			if yInt.Sign() != 0 && yInt.Cmp(parsed.scale) != 0 {
				valid = false
				yInt.SetInt64(0)
			}
		} else if new(big.Int).And(new(big.Int).Set(yInt),
			new(big.Int).Sub(new(big.Int).Set(parsed.scale), big.NewInt(1))).Sign() != 0 {
			valid = false
			yInt.SetInt64(0)
		}
		yInt = formalGLMClamp(yInt, big.NewInt(0), parsed.outcomeUpper)
		offsetInt := formalGLMClamp(integers[base+p+2],
			parsed.offsetLower, parsed.offsetUpper)
		if !valid {
			weightInt.SetInt64(0)
		}
		eta := rat(offsetInt)
		for j := 0; j < p; j++ {
			eta.Add(eta, new(big.Rat).Mul(rat(xInt[j]), rat(parsed.betaStart[j])))
		}
		lower, upper := rat(parsed.knots[0]), rat(parsed.knots[len(parsed.knots)-1])
		if eta.Cmp(lower) < 0 {
			eta.Set(lower)
		}
		if eta.Cmp(upper) > 0 {
			eta.Set(upper)
		}
		segment := 0
		for segment+1 < len(parsed.slopes) && eta.Cmp(rat(parsed.knots[segment+1])) >= 0 {
			segment++
		}
		mu := new(big.Rat).Add(rat(parsed.values[segment]),
			new(big.Rat).Mul(rat(parsed.slopes[segment]),
				new(big.Rat).Sub(eta, rat(parsed.knots[segment]))))
		residual := new(big.Rat).Sub(mu, rat(yInt))
		weighted := new(big.Rat).Mul(rat(weightInt), residual)
		for j := 0; j < p; j++ {
			gradient[j].Add(gradient[j],
				new(big.Rat).Mul(rat(xInt[j]), weighted))
		}
	}
	result := make([]*big.Rat, p)
	capacity := new(big.Rat).SetInt64(int64(c))
	for j := 0; j < p; j++ {
		average := new(big.Rat).Quo(gradient[j], capacity)
		fullGradient := new(big.Rat).Add(average,
			new(big.Rat).Mul(rat(parsed.ridge[j]), rat(parsed.betaStart[j])))
		candidate := new(big.Rat).Sub(rat(parsed.betaStart[j]),
			new(big.Rat).Mul(rat(parsed.alpha), fullGradient))
		lower, upper := new(big.Rat).Neg(rat(parsed.box[j])), rat(parsed.box[j])
		if candidate.Cmp(lower) < 0 {
			candidate.Set(lower)
		}
		if candidate.Cmp(upper) > 0 {
			candidate.Set(upper)
		}
		result[j] = candidate
	}
	return result, nil
}

func reconstructFormalGLMShares(left, right []*big.Int, bits int) ([]*big.Int, error) {
	if len(left) != len(right) {
		return nil, errors.New("formal-glm: output share shape mismatch")
	}
	result := make([]*big.Int, len(left))
	for i := range left {
		result[i] = exactGCReferenceReconstruct(left[i], right[i], bits)
	}
	return result, nil
}
