package main

// Internal bounded-memory plan for the formal Cox kernel.  The signed policy
// retains the complete public capacity and fixed iteration count; only the
// physical rows processed by one exact-GC circuit are adapted.  This file
// registers no command, capability, or remote method.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/markkurossi/mpc/circuit"
)

const formalCoxBlockwiseScoreApproximationVersion = "dsvert-formal-cox-blockwise-score-approximation-v3"

const (
	formalCoxBlockwisePlanVersion = "dsvert-formal-cox-blockwise-plan-v9"
	formalCoxBlockwiseCostVersion = "dsvert-formal-cox-blockwise-cost-v1"
	formalCoxBlockwiseMaxCapacity = 1_000_000
	// The blockwise circuits have a separately reviewed three-coefficient
	// envelope.  The legacy monolithic Phase-1 circuit intentionally remains
	// capped at two; callers cannot silently select it for this larger shape.
	formalCoxBlockwiseMaxCovariates = 3
	formalCoxBlockwiseMaxGridTicks  = 32
	// The R-signed schema supports up to 256 fixed iterations.  Blockwise
	// execution keeps each circuit physically bounded, so it must not inherit
	// the three-iteration limit of the legacy monolithic prototype.
	formalCoxBlockwiseMaxIterations = 256

	// Public per-circuit resource envelopes.  They bound one physical worker
	// step, never the number of rows, analyses, or future releases.
	formalCoxBlockwiseMaxEstimatedWorkingBytes uint64 = 768 << 20
	formalCoxBlockwiseMaxGridRowWork                  = 256
)

type formalCoxBlockwiseCircuitCost struct {
	Version              string `json:"version"`
	CircuitSourceSHA256  string `json:"circuit_source_sha256"`
	Gates                int    `json:"gates"`
	Wires                int    `json:"wires"`
	XORGates             uint64 `json:"xor_gates"`
	NonXORGates          uint64 `json:"non_xor_gates"`
	CompilerRelativeCost uint64 `json:"compiler_relative_cost"`
	GarblerInputBits     int    `json:"garbler_input_bits"`
	EvaluatorInputBits   int    `json:"evaluator_input_bits"`
	OutputBits           int    `json:"output_bits"`
	EstimatedWorkingByte uint64 `json:"estimated_working_bytes"`
}

// formalCoxBlockwiseScoreCert bounds the deterministic,
// per-coordinate discrepancy before one normalized score update.  It does
// not certify the final estimator: repeated updates, projection and DP noise
// still require their own end-to-end accuracy proof.
type formalCoxBlockwiseScoreCert struct {
	Version string `json:"version"`
	// LinearPredictorFixedPointRoundingMaximumAbsSteps bounds the number of
	// lattice steps lost by sum(floor(x_j*beta_j/scale)) versus the exact
	// fixed-grid dot product.
	LinearPredictorFixedPointRoundingMaximumAbsSteps string `json:"linear_predictor_fixed_point_rounding_maximum_abs_steps"`
	// ExpWeightLinearPredictorMaximumAbsErrorSteps bounds the resulting
	// exponential-weight discrepancy in lattice steps.
	ExpWeightLinearPredictorMaximumAbsErrorSteps string `json:"exp_weight_linear_predictor_maximum_abs_error_steps"`
	// ExpWeightMaximumAbsErrorSteps bounds |q - scale*exp(eta_exact)| for the
	// complete committed pipeline: fixed-point eta and monotone step table.
	ExpWeightMaximumAbsErrorSteps string `json:"exp_weight_maximum_abs_error_steps"`
	// MinimumExactWeightSteps is an outward lower bound on scale*exp(eta)
	// over the signed eta domain, including the floor margin covered by the
	// first committed table knot.
	MinimumExactWeightSteps string `json:"minimum_exact_weight_steps"`
	MinimumTableWeightSteps string `json:"minimum_table_weight_steps"`
	// RiskMeanTableMaximumAbsErrorSteps bounds the change in a positive-weight
	// risk mean from the complete committed weight approximation.
	RiskMeanTableMaximumAbsErrorSteps string `json:"risk_mean_table_maximum_abs_error_steps"`
	// RiskMeanFixedPointRoundingMaximumAbsErrorSteps bounds the weighted-X
	// floor and the final secret division floor.
	RiskMeanFixedPointRoundingMaximumAbsErrorSteps string `json:"risk_mean_fixed_point_rounding_maximum_abs_error_steps"`
	// NormalizedScoreFixedPointRoundingMaximumAbsErrorSteps bounds the final
	// floor when the accumulated score is divided by the public capacity.
	NormalizedScoreFixedPointRoundingMaximumAbsErrorSteps string `json:"normalized_score_fixed_point_rounding_maximum_abs_error_steps"`
	// Each patient has at most one event, so the normalized score inherits
	// the sum of the two per-event risk-mean bounds and its final division.
	NormalizedScoreMaximumAbsErrorSteps string `json:"normalized_score_maximum_abs_error_steps"`
}

// formalCoxBlockwiseInformationSensitivityCert is the public, conservative
// bounded-output sensitivity certificate for a future DP release of the
// post-fit observed-information lower triangle.  The information itself stays
// secret: this commits only a bound for floor(H/N), where N is the signed
// public capacity.  It is not an inference release or an allocation of DP
// noise by itself.
type formalCoxBlockwiseInformationSensitivityCert struct {
	Version string `json:"version"`
	// Normalization fixes the integer operation for which this bound applies.
	Normalization                        string `json:"normalization"`
	CoordinateCount                      int    `json:"coordinate_count"`
	PerCoordinateMaximumAbsSteps         string `json:"per_coordinate_maximum_abs_steps"`
	PerCoordinateReplaceSensitivitySteps string `json:"per_coordinate_replace_sensitivity_steps"`
	JointL2ReplaceSensitivitySteps       string `json:"joint_l2_replace_sensitivity_steps"`
}

type formalCoxBlockwisePlan struct {
	Version                 string                                       `json:"version"`
	RunID                   string                                       `json:"run_id"`
	Policy                  formalCoxPhase1Policy                        `json:"policy"`
	PolicySHA256            string                                       `json:"policy_sha256"`
	TotalCapacity           int                                          `json:"total_capacity"`
	BlockCapacity           int                                          `json:"block_capacity"`
	TotalBlocks             int                                          `json:"total_blocks"`
	Iterations              int                                          `json:"iterations"`
	RowWidth                int                                          `json:"row_width"`
	MomentCoordinates       int                                          `json:"moment_coordinates"`
	StateArithmetic         int                                          `json:"state_arithmetic_coordinates"`
	StateCoordinates        int                                          `json:"state_coordinates"`
	PeakResidentCoordinates int                                          `json:"peak_private_resident_coordinates"`
	ScheduleSteps           int                                          `json:"schedule_steps"`
	RingBits                int                                          `json:"ring_bits"`
	ContainerBits           int                                          `json:"container_bits"`
	MaximumSignedMagnitude  string                                       `json:"maximum_signed_magnitude"`
	ProjectionRootUpper     string                                       `json:"projection_root_upper"`
	ProjectionSearchSteps   int                                          `json:"projection_search_steps"`
	ScoreApproximation      formalCoxBlockwiseScoreCert                  `json:"score_approximation"`
	InformationSensitivity  formalCoxBlockwiseInformationSensitivityCert `json:"information_sensitivity"`
	BlockCost               formalCoxBlockwiseCircuitCost                `json:"block_cost"`
	GridCost                formalCoxBlockwiseCircuitCost                `json:"grid_reduction_cost"`
	InformationMomentCost   formalCoxBlockwiseCircuitCost                `json:"observed_information_moment_cost"`
	InformationCost         formalCoxBlockwiseCircuitCost                `json:"observed_information_cost"`
	UpdateCost              formalCoxBlockwiseCircuitCost                `json:"update_cost"`
	ProjectionCost          formalCoxBlockwiseCircuitCost                `json:"projection_coefficient_cost"`
	BackendSelection        string                                       `json:"backend_selection"`
	TranscriptShape         string                                       `json:"transcript_shape"`
	CrashRecovery           string                                       `json:"crash_recovery"`
	Output                  string                                       `json:"output"`
	ProductionReady         bool                                         `json:"production_ready"`

	// NumericCertificateSHA256 commits the finite fixed-grid numerical
	// envelope used by this execution. It makes the plan digest, and therefore
	// every final receipt bound to that digest, fail closed if that envelope is
	// substituted. It is not a continuous-time Cox or inference certificate.
	NumericCertificateSHA256 string `json:"numeric_certificate_sha256"`
}

func formalCoxBlockwiseBuildScoreApproximationCertificate(
	parsed formalCoxParsedPolicy,
) (formalCoxBlockwiseScoreCert, error) {
	if len(parsed.expValues) == 0 || len(parsed.expKnots) == 0 ||
		parsed.policy.CovariateCount < 1 {
		return formalCoxBlockwiseScoreCert{},
			fmt.Errorf("formal-cox: invalid score approximation policy")
	}
	domainLower, err := formalCoxExpDyadic(parsed.expKnots[0], parsed.scale,
		parsed.policy.ExpCertificateBits)
	if err != nil {
		return formalCoxBlockwiseScoreCert{}, err
	}
	minimumExactWeight := new(big.Int).Quo(
		new(big.Int).Mul(domainLower.low, parsed.scale),
		jointDPGaussianDyadicScale(parsed.policy.ExpCertificateBits))
	if minimumExactWeight.Sign() <= 0 {
		return formalCoxBlockwiseScoreCert{},
			fmt.Errorf("formal-cox: non-positive exact lower exp weight")
	}
	minimumTableWeight := parsed.expValues[0]
	minimumWeight := minimumTableWeight
	if minimumExactWeight.Cmp(minimumWeight) < 0 {
		minimumWeight = minimumExactWeight
	}
	// Each p-term fixed-point product is floored before it is summed.  Its
	// eta error is therefore less than p lattice steps.  Exp is increasing
	// and its derivative is bounded by exp at the committed upper endpoint;
	// q_max+E is an outward lattice-scale bound for that value.
	linearRoundingSteps := big.NewInt(int64(parsed.policy.CovariateCount))
	etaWeightError := exactGCCeilDiv(new(big.Int).Mul(
		new(big.Int).Set(linearRoundingSteps),
		new(big.Int).Add(parsed.expValues[len(parsed.expValues)-1], parsed.expError)),
		parsed.scale)
	weightError := new(big.Int).Add(parsed.expError, etaWeightError)
	// For positive table weights q and exact weights w with |q-w| <= E,
	// ||mean_q - mean_w|| is at most 2*Cz*E/min(q_min,w_min).  The
	// expression is in lattice steps because Cz, E and both minima share the
	// policy scale.
	table := exactGCCeilDiv(new(big.Int).Mul(
		new(big.Int).Mul(big.NewInt(2), parsed.xNorm), weightError),
		minimumWeight)
	// Every weighted-X product floors by fewer than one lattice step.  With
	// r at-risk rows, multiplying their total error by scale/(r*q_min)
	// leaves scale/q_min; the final mean division contributes one more step.
	rounding := exactGCCeilDiv(parsed.scale, minimumTableWeight)
	rounding.Add(rounding, big.NewInt(1))
	normalizedRounding := big.NewInt(1)
	score := new(big.Int).Add(new(big.Int).Add(
		new(big.Int).Set(table), rounding), normalizedRounding)
	return formalCoxBlockwiseScoreCert{
		Version: formalCoxBlockwiseScoreApproximationVersion,
		LinearPredictorFixedPointRoundingMaximumAbsSteps:      linearRoundingSteps.String(),
		ExpWeightLinearPredictorMaximumAbsErrorSteps:          etaWeightError.String(),
		ExpWeightMaximumAbsErrorSteps:                         weightError.String(),
		MinimumExactWeightSteps:                               minimumExactWeight.String(),
		MinimumTableWeightSteps:                               minimumTableWeight.String(),
		RiskMeanTableMaximumAbsErrorSteps:                     table.String(),
		RiskMeanFixedPointRoundingMaximumAbsErrorSteps:        rounding.String(),
		NormalizedScoreFixedPointRoundingMaximumAbsErrorSteps: normalizedRounding.String(),
		NormalizedScoreMaximumAbsErrorSteps:                   score.String(),
	}, nil
}

type formalCoxBlockwiseInformationBounds struct {
	maximumCovariateAbs    *big.Int
	weightedXAbs           *big.Int
	weightedXXAbs          *big.Int
	riskMeanAbs            *big.Int
	riskSecondMomentAbs    *big.Int
	riskMeanOuterAbs       *big.Int
	perEventInformationAbs *big.Int
}

// formalCoxBlockwiseInformationBoundsForParsed returns the exact fixed-grid
// magnitude envelope used both by the private observed-information worker and
// by its future normalized-release sensitivity certificate.  Keeping this
// arithmetic in one helper prevents the public certificate drifting away from
// the Ring128 no-wrap envelope.
func formalCoxBlockwiseInformationBoundsForParsed(
	parsed formalCoxParsedPolicy,
) (formalCoxBlockwiseInformationBounds, error) {
	if len(parsed.expValues) == 0 || len(parsed.xLower) != parsed.policy.CovariateCount ||
		len(parsed.xUpper) != parsed.policy.CovariateCount {
		return formalCoxBlockwiseInformationBounds{},
			fmt.Errorf("formal-cox: invalid observed-information bounds policy")
	}
	xMax := new(big.Int)
	for index := 0; index < parsed.policy.CovariateCount; index++ {
		xMax = formalCoxMax(xMax, formalCoxAbs(parsed.xLower[index]),
			formalCoxAbs(parsed.xUpper[index]))
	}
	weightMin := parsed.expValues[0]
	weightMax := parsed.expValues[len(parsed.expValues)-1]
	if weightMin.Sign() <= 0 || weightMax.Sign() <= 0 {
		return formalCoxBlockwiseInformationBounds{},
			fmt.Errorf("formal-cox: non-positive observed-information weight")
	}
	weightedX := new(big.Int).Add(
		formalCoxCeilMulMagnitude(weightMax, xMax, parsed.scale), big.NewInt(1))
	weightedXX := new(big.Int).Add(
		formalCoxCeilMulMagnitude(weightedX, xMax, parsed.scale), big.NewInt(1))
	meanBound := exactGCCeilDiv(
		new(big.Int).Mul(new(big.Int).Set(weightedX), parsed.scale), weightMin)
	secondMeanBound := exactGCCeilDiv(
		new(big.Int).Mul(new(big.Int).Set(weightedXX), parsed.scale), weightMin)
	meanOuterBound := formalCoxCeilMulMagnitude(meanBound, meanBound, parsed.scale)
	return formalCoxBlockwiseInformationBounds{
		maximumCovariateAbs:    xMax,
		weightedXAbs:           weightedX,
		weightedXXAbs:          weightedXX,
		riskMeanAbs:            meanBound,
		riskSecondMomentAbs:    secondMeanBound,
		riskMeanOuterAbs:       meanOuterBound,
		perEventInformationAbs: new(big.Int).Add(secondMeanBound, meanOuterBound),
	}, nil
}

func formalCoxBlockwiseBuildInformationSensitivityCertificate(
	parsed formalCoxParsedPolicy,
) (formalCoxBlockwiseInformationSensitivityCert, error) {
	bounds, err := formalCoxBlockwiseInformationBoundsForParsed(parsed)
	if err != nil {
		return formalCoxBlockwiseInformationSensitivityCert{}, err
	}
	// One patient has at most one event.  Summing the per-event magnitude over
	// the fixed grid and then dividing by the public capacity removes N from the
	// output bound.  One extra lattice step covers the canonical integer floor
	// that a future release circuit must apply.
	maximum := new(big.Int).Mul(bounds.perEventInformationAbs,
		big.NewInt(int64(parsed.policy.GridTickCount)))
	maximum.Add(maximum, big.NewInt(1))
	perCoordinateSensitivity := new(big.Int).Mul(maximum, big.NewInt(2))
	coordinates := formalCoxBlockwiseInformationCoordinates(parsed.policy)
	jointSquared := new(big.Int).Mul(perCoordinateSensitivity,
		perCoordinateSensitivity)
	jointSquared.Mul(jointSquared, big.NewInt(int64(coordinates)))
	return formalCoxBlockwiseInformationSensitivityCert{
		Version:                              formalCoxBlockwiseInformationSensitivityVersion,
		Normalization:                        "divide_private_information_by_public_capacity_floor_v1",
		CoordinateCount:                      coordinates,
		PerCoordinateMaximumAbsSteps:         maximum.String(),
		PerCoordinateReplaceSensitivitySteps: perCoordinateSensitivity.String(),
		JointL2ReplaceSensitivitySteps:       formalCoxCeilSqrt(jointSquared).String(),
	}, nil
}

const formalCoxBlockwiseInformationSensitivityVersion = "dsvert-formal-cox-blockwise-normalized-information-sensitivity-v1"

type formalCoxBlockwiseResourceError struct {
	Code                  string
	MinimumEstimatedBytes uint64
}

func parseFormalCoxBlockwisePolicy(
	policy formalCoxPhase1Policy) (formalCoxParsedPolicy, error) {
	return parseFormalCoxPolicyWithLimits(policy,
		formalCoxBlockwiseMaxCapacity, formalCoxBlockwiseMaxCovariates,
		formalCoxBlockwiseMaxGridTicks,
		formalCoxBlockwiseMaxIterations)
}

func (e *formalCoxBlockwiseResourceError) Error() string {
	return fmt.Sprintf("formal-cox: %s (minimum estimated working bytes %d)",
		e.Code, e.MinimumEstimatedBytes)
}

func formalCoxBlockwisePlanDigest(plan formalCoxBlockwisePlan) ([32]byte, error) {
	encoded, err := json.Marshal(plan)
	if err != nil {
		return [32]byte{}, fmt.Errorf("formal-cox: encode blockwise plan: %w", err)
	}
	return sha256.Sum256(append(
		[]byte("dsVert/formal-cox/blockwise-plan/v1|"), encoded...)), nil
}

func formalCoxBlockwiseMomentCoordinates(policy formalCoxPhase1Policy) int {
	// risk count, event count and S0 per tick, plus S1 and event-X for
	// every tick/covariate pair, and the lower triangle of weighted S2 for
	// each tick.  S2 remains private worker state; it is required later for
	// a DP-protected observed-information release, never an exact opening.
	return 3*policy.GridTickCount +
		2*policy.GridTickCount*policy.CovariateCount +
		policy.GridTickCount*formalCoxBlockwiseSecondMomentCoordinates(policy)
}

func formalCoxBlockwiseSecondMomentCoordinates(policy formalCoxPhase1Policy) int {
	p := policy.CovariateCount
	return p * (p + 1) / 2
}

// formalCoxBlockwiseInformationCoordinates is the lower-triangular observed
// information shape. It is fixed by the signed covariate count, not by data.
func formalCoxBlockwiseInformationCoordinates(policy formalCoxPhase1Policy) int {
	return formalCoxBlockwiseSecondMomentCoordinates(policy)
}

// formalCoxBlockwiseSecondMomentIndex returns a canonical lower-triangular
// coordinate. Callers with public coefficient indexes may pass either order.
func formalCoxBlockwiseSecondMomentIndex(policy formalCoxPhase1Policy,
	left, right int,
) int {
	if left > right {
		left, right = right, left
	}
	p := policy.CovariateCount
	return left*p - left*(left-1)/2 + (right - left)
}

// formalCoxBlockwiseSecondMomentPairAt is the inverse of the canonical
// lower-triangular index. The shape is public and small (it is bounded by the
// signed policy), so the direct scan avoids a second, subtly different index
// formula in the worker.
func formalCoxBlockwiseSecondMomentPairAt(policy formalCoxPhase1Policy,
	index int,
) (int, int, error) {
	if index < 0 || index >= formalCoxBlockwiseSecondMomentCoordinates(policy) {
		return 0, 0, fmt.Errorf("formal-cox: invalid observed-information coordinate")
	}
	for left := 0; left < policy.CovariateCount; left++ {
		for right := left; right < policy.CovariateCount; right++ {
			if formalCoxBlockwiseSecondMomentIndex(policy, left, right) == index {
				return left, right, nil
			}
		}
	}
	return 0, 0, fmt.Errorf("formal-cox: unreachable observed-information coordinate")
}

func formalCoxBlockwiseCost(source string, circ *circuit.Circuit) (
	formalCoxBlockwiseCircuitCost, error) {

	if circ == nil || len(circ.Inputs) != 2 || len(circ.Outputs) != 1 {
		return formalCoxBlockwiseCircuitCost{},
			fmt.Errorf("formal-cox: invalid compiled blockwise circuit")
	}
	digest := sha256.Sum256([]byte(source))
	gates, wires := uint64(circ.NumGates), uint64(circ.NumWires)
	if gates > (^uint64(0))/formalGLMPhase15BytesPerGateEstimate ||
		wires > (^uint64(0))/formalGLMPhase15BytesPerWireEstimate {
		return formalCoxBlockwiseCircuitCost{},
			fmt.Errorf("formal-cox: blockwise circuit resource estimate overflow")
	}
	estimated := gates*formalGLMPhase15BytesPerGateEstimate +
		wires*formalGLMPhase15BytesPerWireEstimate
	return formalCoxBlockwiseCircuitCost{
		Version:             formalCoxBlockwiseCostVersion,
		CircuitSourceSHA256: hex.EncodeToString(digest[:]),
		Gates:               circ.NumGates, Wires: circ.NumWires,
		XORGates: circ.Stats.NumXOR(), NonXORGates: circ.Stats.NumNonXOR(),
		CompilerRelativeCost: circ.Cost(),
		GarblerInputBits:     int(circ.Inputs[0].Type.Bits),
		EvaluatorInputBits:   int(circ.Inputs[1].Type.Bits),
		OutputBits:           circ.Outputs.Size(), EstimatedWorkingByte: estimated,
	}, nil
}

func formalCoxBlockwiseNumericEnvelope(policy formalCoxPhase1Policy) (
	maximum, projectionRoot *big.Int, ringBits int, err error) {

	parsed, err := parseFormalCoxBlockwisePolicy(policy)
	if err != nil {
		return nil, nil, 0, err
	}
	n, p := policy.Capacity, policy.CovariateCount
	informationBounds, err := formalCoxBlockwiseInformationBoundsForParsed(parsed)
	if err != nil {
		return nil, nil, 0, err
	}
	xMax := informationBounds.maximumCovariateAbs
	weightMin := new(big.Int).Set(parsed.expValues[0])
	weightMax := new(big.Int).Set(parsed.expValues[len(parsed.expValues)-1])
	etaBound := formalCoxCeilMulMagnitude(
		parsed.xNorm, parsed.betaNorm, parsed.scale)
	weightedX := informationBounds.weightedXAbs
	weightedXX := informationBounds.weightedXXAbs
	s0Bound := new(big.Int).Mul(big.NewInt(int64(n)), weightMax)
	s1Bound := new(big.Int).Mul(big.NewInt(int64(n)), weightedX)
	s2Bound := new(big.Int).Mul(big.NewInt(int64(n)), weightedXX)
	// At every grid tick, the same r at-risk rows contribute to S0 and S1.
	// The helper cancels r, leaving a per-event information envelope that is
	// independent of N; this raw worker bound then restores the at-most-N event
	// accumulation for the private Ring128 computation.
	meanBound := informationBounds.riskMeanAbs
	secondMeanBound := informationBounds.riskSecondMomentAbs
	meanOuterBound := informationBounds.riskMeanOuterAbs
	informationIncrementBound := new(big.Int).Mul(
		informationBounds.perEventInformationAbs, big.NewInt(int64(n)))
	informationBound := new(big.Int).Mul(
		informationIncrementBound, big.NewInt(int64(policy.GridTickCount)))
	eventXBound := new(big.Int).Mul(big.NewInt(int64(n)), xMax)
	riskTermBound := new(big.Int).Mul(big.NewInt(int64(n)), meanBound)
	scoreBound := new(big.Int).Add(eventXBound, riskTermBound)
	averageScoreBound := exactGCCeilDiv(scoreBound, big.NewInt(int64(n)))
	ridgeBound := formalCoxCeilMulMagnitude(
		parsed.ridge, parsed.betaNorm, parsed.scale)
	gradientBound := new(big.Int).Add(averageScoreBound, ridgeBound)
	gradientBound.Add(gradientBound, parsed.noiseBound)
	updateBound := formalCoxCeilMulMagnitude(
		parsed.alpha, gradientBound, parsed.scale)
	candidateBound := new(big.Int).Add(parsed.betaNorm, updateBound)
	projectionNormSquared := new(big.Int).Mul(candidateBound, candidateBound)
	projectionNormSquared.Mul(projectionNormSquared, big.NewInt(int64(p)))
	projectionRoot = formalCoxCeilSqrt(projectionNormSquared)
	maximum = formalCoxMax(
		parsed.scale, big.NewInt(int64(n)), big.NewInt(int64(policy.GridTickCount)),
		xMax, parsed.xNorm, parsed.betaNorm, parsed.alpha, parsed.ridge,
		parsed.noiseBound, etaBound, weightMin, weightMax, weightedX, weightedXX,
		s0Bound, s1Bound, s2Bound, meanBound, secondMeanBound, meanOuterBound,
		informationIncrementBound, informationBound, eventXBound, riskTermBound,
		scoreBound, averageScoreBound, ridgeBound, gradientBound,
		updateBound, candidateBound, projectionRoot)
	for _, value := range parsed.expKnots {
		maximum = formalCoxMax(maximum, formalCoxAbs(value))
	}
	for _, value := range parsed.expValues {
		maximum = formalCoxMax(maximum, value)
	}
	requiredBits := maximum.BitLen() + 2
	ringBits = 128
	if requiredBits > ringBits {
		ringBits = exactGCTypeBits(requiredBits)
	}
	if ringBits > exactGCMaxRingBits {
		return nil, nil, 0, &formalCoxNumericBackendError{
			Code: "numeric_backend_unrepresentable", RequiredBits: requiredBits}
	}
	return maximum, projectionRoot, ringBits, nil
}

func formalCoxBlockwiseValidateShape(plan formalCoxBlockwisePlan) (
	formalCoxParsedPolicy, error) {

	var zero formalCoxParsedPolicy
	parsed, err := parseFormalCoxBlockwisePolicy(plan.Policy)
	if err != nil {
		return zero, err
	}
	policyDigest, err := formalCoxPolicyDigest(plan.Policy)
	if err != nil {
		return zero, err
	}
	maxInt := int(^uint(0) >> 1)
	stepsPerIteration := plan.TotalBlocks +
		plan.Policy.GridTickCount*plan.Policy.CovariateCount +
		plan.Policy.CovariateCount + 1
	informationSteps := plan.TotalBlocks + 4*
		plan.Policy.GridTickCount*formalCoxBlockwiseInformationCoordinates(plan.Policy)
	scheduleValid := plan.TotalBlocks >= 1 && plan.Iterations >= 1 &&
		stepsPerIteration <= maxInt/plan.Iterations &&
		informationSteps <= maxInt-plan.Iterations*stepsPerIteration &&
		plan.ScheduleSteps == plan.Iterations*stepsPerIteration+informationSteps
	rowWidth := len(plan.Policy.CustodianPeers) + 3 + plan.Policy.CovariateCount
	moments := formalCoxBlockwiseMomentCoordinates(plan.Policy)
	stateArithmetic := plan.Policy.CovariateCount + moments
	peak := plan.BlockCapacity*rowWidth + 3*(stateArithmetic+1) +
		plan.Policy.CovariateCount + 1 +
		4*formalCoxBlockwiseInformationCoordinates(plan.Policy)
	if plan.Version != formalCoxBlockwisePlanVersion ||
		!formalCoxIsSHA256(plan.RunID) ||
		plan.PolicySHA256 != hex.EncodeToString(policyDigest[:]) ||
		plan.TotalCapacity != plan.Policy.Capacity ||
		plan.Iterations != plan.Policy.Iterations ||
		plan.BlockCapacity < 1 || plan.BlockCapacity > plan.TotalCapacity ||
		plan.TotalBlocks != (plan.TotalCapacity+plan.BlockCapacity-1)/plan.BlockCapacity ||
		!scheduleValid || plan.RowWidth != rowWidth ||
		plan.MomentCoordinates != moments ||
		plan.StateArithmetic != stateArithmetic ||
		plan.StateCoordinates != stateArithmetic+1 ||
		plan.PeakResidentCoordinates != peak ||
		plan.RingBits < 128 || plan.RingBits > exactGCMaxRingBits ||
		plan.ContainerBits != exactGCTypeBits(plan.RingBits) ||
		parsed.ridge.Sign() <= 0 ||
		plan.BackendSelection != "streamed_exact_gc_ot_no_runtime_fallback_v1" ||
		plan.TranscriptShape != "fixed_public_iteration_and_postfit_information_schedule_v1" ||
		plan.CrashRecovery != "commit_barrier_or_fresh_session_never_resume_mid_gc_v1" ||
		plan.Output != "sealed_coefficient_additive_shares_and_xor_execution_validity_v1" ||
		plan.ProductionReady {
		return zero, fmt.Errorf("formal-cox: invalid blockwise plan shape")
	}
	if _, err := formalCoxBlockwiseIdealGradientContractFromParsed(parsed); err != nil {
		return zero, err
	}
	scoreApproximation, err :=
		formalCoxBlockwiseBuildScoreApproximationCertificate(parsed)
	if err != nil || plan.ScoreApproximation != scoreApproximation {
		return zero, fmt.Errorf("formal-cox: invalid score approximation certificate")
	}
	informationSensitivity, err :=
		formalCoxBlockwiseBuildInformationSensitivityCertificate(parsed)
	if err != nil || plan.InformationSensitivity != informationSensitivity {
		return zero, fmt.Errorf("formal-cox: invalid information sensitivity certificate")
	}
	return parsed, nil
}

// buildFormalCoxBlockwisePlan reduces only the physical block size.  It does
// not change N, the scientific policy, the fixed transcript, or its privacy
// parameters.
func buildFormalCoxBlockwisePlan(policy formalCoxPhase1Policy,
	requestedBlock int, runID string) (formalCoxBlockwisePlan, error) {

	parsed, err := parseFormalCoxBlockwisePolicy(policy)
	if err != nil {
		return formalCoxBlockwisePlan{}, err
	}
	if parsed.ridge.Sign() <= 0 {
		return formalCoxBlockwisePlan{},
			fmt.Errorf("formal-cox: blockwise release requires positive signed ridge")
	}
	if requestedBlock < 1 || requestedBlock > policy.Capacity ||
		!formalCoxIsSHA256(runID) {
		return formalCoxBlockwisePlan{},
			fmt.Errorf("formal-cox: invalid requested blockwise schedule")
	}
	workPerRow := policy.GridTickCount * (policy.CovariateCount + 1 +
		formalCoxBlockwiseSecondMomentCoordinates(policy))
	analyticBlock := formalCoxBlockwiseMaxGridRowWork / workPerRow
	if analyticBlock < 1 {
		analyticBlock = 1
	}
	if requestedBlock > analyticBlock {
		requestedBlock = analyticBlock
	}
	maximum, projectionRoot, ringBits, err :=
		formalCoxBlockwiseNumericEnvelope(policy)
	if err != nil {
		return formalCoxBlockwisePlan{}, err
	}
	scoreApproximation, err :=
		formalCoxBlockwiseBuildScoreApproximationCertificate(parsed)
	if err != nil {
		return formalCoxBlockwisePlan{}, err
	}
	informationSensitivity, err :=
		formalCoxBlockwiseBuildInformationSensitivityCertificate(parsed)
	if err != nil {
		return formalCoxBlockwisePlan{}, err
	}
	numericCertificate, err := formalCoxBlockwiseNumericCertificateForPolicy(policy)
	if err != nil {
		return formalCoxBlockwisePlan{}, err
	}
	numericCertificateSHA256, err := formalCoxBlockwiseNumericCertificateSHA256(
		numericCertificate)
	if err != nil {
		return formalCoxBlockwisePlan{}, err
	}
	policyDigest, _ := formalCoxPolicyDigest(policy)
	var minimum uint64
	for block := requestedBlock; block >= 1; block-- {
		rowWidth := len(policy.CustodianPeers) + 3 + policy.CovariateCount
		moments := formalCoxBlockwiseMomentCoordinates(policy)
		stateArithmetic := policy.CovariateCount + moments
		plan := formalCoxBlockwisePlan{
			Version: formalCoxBlockwisePlanVersion, RunID: runID,
			Policy: policy, PolicySHA256: hex.EncodeToString(policyDigest[:]),
			NumericCertificateSHA256: numericCertificateSHA256,
			TotalCapacity:            policy.Capacity, BlockCapacity: block,
			TotalBlocks: (policy.Capacity + block - 1) / block,
			Iterations:  policy.Iterations, RowWidth: rowWidth,
			MomentCoordinates: moments, StateArithmetic: stateArithmetic,
			StateCoordinates: stateArithmetic + 1,
			PeakResidentCoordinates: block*rowWidth + 3*(stateArithmetic+1) +
				policy.CovariateCount + 1 +
				4*formalCoxBlockwiseInformationCoordinates(policy),
			RingBits: ringBits, ContainerBits: exactGCTypeBits(ringBits),
			MaximumSignedMagnitude: maximum.String(),
			ProjectionRootUpper:    projectionRoot.String(),
			ProjectionSearchSteps:  projectionRoot.BitLen() + 1,
			ScoreApproximation:     scoreApproximation,
			InformationSensitivity: informationSensitivity,
			BackendSelection:       "streamed_exact_gc_ot_no_runtime_fallback_v1",
			TranscriptShape:        "fixed_public_iteration_and_postfit_information_schedule_v1",
			CrashRecovery:          "commit_barrier_or_fresh_session_never_resume_mid_gc_v1",
			Output:                 "sealed_coefficient_additive_shares_and_xor_execution_validity_v1",
			ProductionReady:        false,
		}
		plan.ScheduleSteps = plan.Iterations*(plan.TotalBlocks+
			policy.GridTickCount*policy.CovariateCount+
			policy.CovariateCount+1) + plan.TotalBlocks + 4*
			policy.GridTickCount*formalCoxBlockwiseInformationCoordinates(policy)
		if _, err := formalCoxBlockwiseValidateShape(plan); err != nil {
			return formalCoxBlockwisePlan{}, err
		}
		blockSource, err := formalCoxBlockwiseBlockCircuitSource(plan)
		if err != nil {
			return formalCoxBlockwisePlan{}, err
		}
		blockCircuit, err := compileFormalCoxBlockwiseSource(
			blockSource, "block update")
		if err != nil {
			return formalCoxBlockwisePlan{}, err
		}
		gridSource, err := formalCoxBlockwiseGridCoefficientCircuitSource(plan)
		if err != nil {
			return formalCoxBlockwisePlan{}, err
		}
		gridCircuit, err := compileFormalCoxBlockwiseSource(
			gridSource, "grid reduction")
		if err != nil {
			return formalCoxBlockwisePlan{}, err
		}
		informationMomentSource, err := formalCoxBlockwiseInformationMomentCircuitSource(plan)
		if err != nil {
			return formalCoxBlockwisePlan{}, err
		}
		informationMomentCircuit, err := compileFormalCoxBlockwiseSource(
			informationMomentSource, "observed information moment")
		if err != nil {
			return formalCoxBlockwisePlan{}, err
		}
		informationSource, err := formalCoxBlockwiseInformationCircuitSource(plan)
		if err != nil {
			return formalCoxBlockwisePlan{}, err
		}
		informationCircuit, err := compileFormalCoxBlockwiseSource(informationSource, "observed information")
		if err != nil {
			return formalCoxBlockwisePlan{}, err
		}
		updateSource, err := formalCoxBlockwiseUpdateCircuitSource(plan)
		if err != nil {
			return formalCoxBlockwisePlan{}, err
		}
		updateCircuit, err := compileFormalCoxBlockwiseSource(
			updateSource, "coefficient update")
		if err != nil {
			return formalCoxBlockwisePlan{}, err
		}
		projectionSource, err := formalCoxBlockwiseProjectionCoefficientCircuitSource(
			plan, 0)
		if err != nil {
			return formalCoxBlockwisePlan{}, err
		}
		projectionCircuit, err := compileFormalCoxBlockwiseSource(
			projectionSource, "coefficient projection")
		if err != nil {
			return formalCoxBlockwisePlan{}, err
		}
		plan.BlockCost, err = formalCoxBlockwiseCost(blockSource, blockCircuit)
		if err != nil {
			return formalCoxBlockwisePlan{}, err
		}
		plan.GridCost, err = formalCoxBlockwiseCost(gridSource, gridCircuit)
		if err != nil {
			return formalCoxBlockwisePlan{}, err
		}
		plan.InformationMomentCost, err = formalCoxBlockwiseCost(
			informationMomentSource, informationMomentCircuit)
		if err != nil {
			return formalCoxBlockwisePlan{}, err
		}
		plan.InformationCost, err = formalCoxBlockwiseCost(
			informationSource, informationCircuit)
		if err != nil {
			return formalCoxBlockwisePlan{}, err
		}
		plan.UpdateCost, err = formalCoxBlockwiseCost(updateSource, updateCircuit)
		if err != nil {
			return formalCoxBlockwisePlan{}, err
		}
		plan.ProjectionCost, err = formalCoxBlockwiseCost(
			projectionSource, projectionCircuit)
		if err != nil {
			return formalCoxBlockwisePlan{}, err
		}
		minimum = plan.BlockCost.EstimatedWorkingByte
		if plan.GridCost.EstimatedWorkingByte > minimum {
			minimum = plan.GridCost.EstimatedWorkingByte
		}
		if plan.InformationCost.EstimatedWorkingByte > minimum {
			minimum = plan.InformationCost.EstimatedWorkingByte
		}
		if plan.InformationMomentCost.EstimatedWorkingByte > minimum {
			minimum = plan.InformationMomentCost.EstimatedWorkingByte
		}
		if plan.UpdateCost.EstimatedWorkingByte > minimum {
			minimum = plan.UpdateCost.EstimatedWorkingByte
		}
		if plan.ProjectionCost.EstimatedWorkingByte > minimum {
			minimum = plan.ProjectionCost.EstimatedWorkingByte
		}
		if minimum <= formalCoxBlockwiseMaxEstimatedWorkingBytes {
			return plan, nil
		}
	}
	return formalCoxBlockwisePlan{}, &formalCoxBlockwiseResourceError{
		Code:                  "minimum_stream_block_exceeds_public_memory_envelope",
		MinimumEstimatedBytes: minimum}
}

func validateFormalCoxBlockwisePlan(plan formalCoxBlockwisePlan) error {
	if _, err := formalCoxBlockwiseValidateShape(plan); err != nil {
		return err
	}
	maximum, projectionRoot, ringBits, err :=
		formalCoxBlockwiseNumericEnvelope(plan.Policy)
	if err != nil {
		return err
	}
	if plan.RingBits != ringBits ||
		plan.MaximumSignedMagnitude != maximum.String() ||
		plan.ProjectionRootUpper != projectionRoot.String() ||
		plan.ProjectionSearchSteps != projectionRoot.BitLen()+1 {
		return fmt.Errorf("formal-cox: invalid blockwise numeric certificate")
	}
	numericCertificate, err := formalCoxBlockwiseNumericCertificateForPolicy(
		plan.Policy)
	if err != nil {
		return err
	}
	numericCertificateSHA256, err := formalCoxBlockwiseNumericCertificateSHA256(
		numericCertificate)
	if err != nil || plan.NumericCertificateSHA256 != numericCertificateSHA256 {
		return fmt.Errorf("formal-cox: invalid blockwise numeric certificate commitment")
	}
	blockSource, err := formalCoxBlockwiseBlockCircuitSource(plan)
	if err != nil {
		return err
	}
	blockCircuit, err := compileFormalCoxBlockwiseSource(blockSource, "block update")
	if err != nil {
		return err
	}
	wantBlock, err := formalCoxBlockwiseCost(blockSource, blockCircuit)
	if err != nil {
		return err
	}
	gridSource, err := formalCoxBlockwiseGridCoefficientCircuitSource(plan)
	if err != nil {
		return err
	}
	gridCircuit, err := compileFormalCoxBlockwiseSource(
		gridSource, "grid reduction")
	if err != nil {
		return err
	}
	wantGrid, err := formalCoxBlockwiseCost(gridSource, gridCircuit)
	if err != nil {
		return err
	}
	informationMomentSource, err := formalCoxBlockwiseInformationMomentCircuitSource(plan)
	if err != nil {
		return err
	}
	informationMomentCircuit, err := compileFormalCoxBlockwiseSource(
		informationMomentSource, "observed information moment")
	if err != nil {
		return err
	}
	wantInformationMoment, err := formalCoxBlockwiseCost(
		informationMomentSource, informationMomentCircuit)
	if err != nil {
		return err
	}
	informationSource, err := formalCoxBlockwiseInformationCircuitSource(plan)
	if err != nil {
		return err
	}
	informationCircuit, err := compileFormalCoxBlockwiseSource(informationSource, "observed information")
	if err != nil {
		return err
	}
	wantInformation, err := formalCoxBlockwiseCost(
		informationSource, informationCircuit)
	if err != nil {
		return err
	}
	updateSource, err := formalCoxBlockwiseUpdateCircuitSource(plan)
	if err != nil {
		return err
	}
	updateCircuit, err := compileFormalCoxBlockwiseSource(
		updateSource, "coefficient update")
	if err != nil {
		return err
	}
	wantUpdate, err := formalCoxBlockwiseCost(updateSource, updateCircuit)
	if err != nil {
		return err
	}
	projectionSource, err := formalCoxBlockwiseProjectionCoefficientCircuitSource(
		plan, 0)
	if err != nil {
		return err
	}
	projectionCircuit, err := compileFormalCoxBlockwiseSource(
		projectionSource, "coefficient projection")
	if err != nil {
		return err
	}
	wantProjection, err := formalCoxBlockwiseCost(
		projectionSource, projectionCircuit)
	if err != nil {
		return err
	}
	if plan.BlockCost != wantBlock || plan.GridCost != wantGrid ||
		plan.InformationMomentCost != wantInformationMoment ||
		plan.InformationCost != wantInformation || plan.UpdateCost != wantUpdate ||
		plan.ProjectionCost != wantProjection ||
		plan.BlockCost.EstimatedWorkingByte > formalCoxBlockwiseMaxEstimatedWorkingBytes ||
		plan.GridCost.EstimatedWorkingByte > formalCoxBlockwiseMaxEstimatedWorkingBytes ||
		plan.InformationMomentCost.EstimatedWorkingByte > formalCoxBlockwiseMaxEstimatedWorkingBytes ||
		plan.InformationCost.EstimatedWorkingByte > formalCoxBlockwiseMaxEstimatedWorkingBytes ||
		plan.UpdateCost.EstimatedWorkingByte > formalCoxBlockwiseMaxEstimatedWorkingBytes ||
		plan.ProjectionCost.EstimatedWorkingByte > formalCoxBlockwiseMaxEstimatedWorkingBytes {
		return fmt.Errorf("formal-cox: invalid or excessive blockwise circuit cost")
	}
	return nil
}
