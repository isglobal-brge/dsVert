package main

// Phase-1.5 sealed-output bridge for a future authenticated joint-DP GLM
// release.  The bridge never opens beta.  It reconstructs each signed,
// possibly multiprecision coefficient only inside exact GC, clips it to the
// cross-signed coefficient box, quantizes it with signed-floor semantics,
// translates it to a non-negative Ring128 coordinate, and emits fresh
// additive shares.
//
// This file deliberately has no command handler.  The common sticky-noise
// capsule does not yet admit the GLM execution manifest, so an actual release
// remains blocked by a typed error below.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/p2p"
)

const (
	exactGCFormalGLMDPBridge                        exactGCOperation = "formal-glm-dp-bridge-v1"
	formalGLMPhase15DPBridgeVersion                                  = "dsvert-formal-glm-phase15-dp-bridge-v1"
	formalGLMPhase15DPSensitivityVersion                             = "dsvert-formal-glm-phase15-dp-sensitivity-v1"
	formalGLMPhase15DPBridgeDomain                                   = "dsVert/formal-glm/phase15/dp-bridge/v1"
	formalGLMPhase15DPReceiptDomain                                  = "dsVert/formal-glm/phase15/final-receipt-pair/v1"
	formalGLMPhase15DPUniversalProof                                 = "projected-quantized-coefficient-box-global-l2-diameter-v2"
	formalGLMPhase15DPTightProof                                     = "exact-fixed-point-coordinate-recurrence-signed-floor-lattice-l2-v1"
	formalGLMPhase15DPSensitivityCertificateVersion                  = "dsvert-formal-glm-phase15-l2-sensitivity-certificate-v1"
	formalGLMPhase15DPSensitivityCertificateDomain                   = "dsVert/joint-dp/machine-proven-integer-lattice-l2-certificate/v1"
	formalGLMPhase15DPReleaseBlockerCode                             = "common_release_capsule_glm_manifest_not_e2e_verified"
)

type formalGLMPhase15DPSensitivity struct {
	Version       string `json:"version"`
	Status        string `json:"status"`
	Proof         string `json:"proof"`
	BoundSteps    string `json:"bound_steps"`
	TheoremSHA256 string `json:"theorem_sha256"`
}

type formalGLMPhase15DPSensitivityStep struct {
	Iteration                  int      `json:"iteration"`
	SourceCoordinateBounds     []string `json:"source_coordinate_bounds"`
	EtaDeltaUpper              string   `json:"eta_delta_upper"`
	MuDeltaUpper               string   `json:"mu_delta_upper"`
	WeightedResidualDeltaUpper string   `json:"weighted_residual_delta_upper"`
	SameDatasetScoreDeltaUpper []string `json:"same_dataset_score_delta_upper"`
	FullGradientDeltaUpper     []string `json:"full_gradient_delta_upper"`
	OptimizerStepDeltaUpper    []string `json:"optimizer_step_delta_upper"`
	NextSourceCoordinateBounds []string `json:"next_source_coordinate_bounds"`
}

// formalGLMPhase15DPSensitivityCertificate is a complete, canonical public
// proof object. Every value is recomputed from the cross-signed fixed-point
// policy. In particular, no caller-provided sensitivity assertion is trusted.
type formalGLMPhase15DPSensitivityCertificate struct {
	Version                   string                              `json:"version"`
	Kind                      string                              `json:"kind"`
	Status                    string                              `json:"status"`
	Norm                      string                              `json:"norm"`
	SelectedProof             string                              `json:"selected_proof"`
	SelectedBoundSteps        string                              `json:"selected_bound_steps"`
	PolicySHA256              string                              `json:"policy_sha256"`
	Phase15PlanSHA256         string                              `json:"phase15_plan_sha256"`
	TheoremSHA256             string                              `json:"theorem_sha256"`
	Adjacency                 string                              `json:"adjacency"`
	ChangedRowFactor          int                                 `json:"changed_row_factor"`
	TotalCapacity             int                                 `json:"total_capacity"`
	Iterations                int                                 `json:"iterations"`
	CoordinateCount           int                                 `json:"coordinate_count"`
	SourceFracBits            int                                 `json:"source_frac_bits"`
	OutputLatticeBits         int                                 `json:"output_lattice_bits"`
	QuantizationShift         int                                 `json:"quantization_shift"`
	SourceScale               string                              `json:"source_scale"`
	QuantizationDenominator   string                              `json:"quantization_denominator"`
	Quantization              string                              `json:"quantization"`
	QuantizationInequality    string                              `json:"quantization_inequality"`
	CoefficientBox            []string                            `json:"coefficient_box"`
	ShiftedUpperBounds        []string                            `json:"shifted_upper_bounds"`
	XMagnitude                []string                            `json:"x_magnitude"`
	WeightUpper               string                              `json:"weight_upper"`
	OutcomeUpper              string                              `json:"outcome_upper"`
	LinkValueLower            string                              `json:"link_value_lower"`
	LinkValueUpper            string                              `json:"link_value_upper"`
	LinkSlopeUpper            string                              `json:"link_slope_upper"`
	LinkSegmentCount          int                                 `json:"link_segment_count"`
	ResidualAbsUpper          string                              `json:"residual_abs_upper"`
	RowScoreAbsUpper          []string                            `json:"row_score_abs_upper"`
	ChangedDataAverageUpper   []string                            `json:"changed_data_average_upper"`
	UniversalCoordinateBounds []string                            `json:"universal_coordinate_bounds"`
	UniversalL2Squared        string                              `json:"universal_l2_squared"`
	UniversalBoundSteps       string                              `json:"universal_bound_steps"`
	Recurrence                []formalGLMPhase15DPSensitivityStep `json:"recurrence"`
	RecurrenceSourceBounds    []string                            `json:"recurrence_source_bounds"`
	RecurrenceQuantizedBounds []string                            `json:"recurrence_quantized_bounds"`
	RecurrenceL2Squared       string                              `json:"recurrence_l2_squared"`
	RecurrenceBoundSteps      string                              `json:"recurrence_bound_steps"`
	Selection                 string                              `json:"selection"`
}

type formalGLMPhase15DPBridgePlan struct {
	Version                              string                                   `json:"version"`
	Phase15PlanSHA256                    string                                   `json:"phase15_plan_sha256"`
	FinalReceiptPairSHA256               string                                   `json:"final_receipt_pair_sha256"`
	ExecutionTranscriptSHA256            string                                   `json:"execution_transcript_sha256"`
	SnapshotSHA256                       string                                   `json:"snapshot_sha256"`
	PinsetSHA256                         string                                   `json:"pinset_sha256"`
	GarblerPeerName                      string                                   `json:"garbler_peer_name"`
	GarblerPeerID                        string                                   `json:"garbler_peer_id"`
	EvaluatorPeerName                    string                                   `json:"evaluator_peer_name"`
	EvaluatorPeerID                      string                                   `json:"evaluator_peer_id"`
	RoleSelection                        string                                   `json:"role_selection"`
	Adjacency                            string                                   `json:"adjacency"`
	SourceRingBits                       int                                      `json:"source_ring_bits"`
	SourceFracBits                       int                                      `json:"source_frac_bits"`
	OutputRingBits                       int                                      `json:"output_ring_bits"`
	OutputLatticeBits                    int                                      `json:"output_lattice_bits"`
	QuantizationShift                    int                                      `json:"quantization_shift"`
	CoordinateCount                      int                                      `json:"coordinate_count"`
	ShiftedUpperBounds                   []string                                 `json:"shifted_upper_bounds"`
	UniversalSensitivity                 formalGLMPhase15DPSensitivity            `json:"universal_sensitivity"`
	TightSensitivity                     formalGLMPhase15DPSensitivity            `json:"tight_sensitivity"`
	SelectedSensitivitySteps             string                                   `json:"selected_sensitivity_steps"`
	SelectedSensitivityProof             string                                   `json:"selected_sensitivity_proof"`
	SelectedSensitivityCertificate       formalGLMPhase15DPSensitivityCertificate `json:"selected_sensitivity_certificate"`
	SelectedSensitivityCertificateSHA256 string                                   `json:"selected_sensitivity_certificate_sha256"`
	SensitivitySelection                 string                                   `json:"sensitivity_selection"`
	Quantization                         string                                   `json:"quantization"`
	IntermediateOutput                   string                                   `json:"intermediate_output"`
	AuthenticatedOpening                 string                                   `json:"authenticated_opening"`
	ProductionReady                      bool                                     `json:"production_ready"`
}

type formalGLMPhase15DPBridgeRoles struct {
	garblerName, garblerID, evaluatorName, evaluatorID string
}

func formalGLMPhase15DPBridgePinnedRoles(plan formalGLMPhase15Plan,
	pins map[string]ed25519.PublicKey) (formalGLMPhase15DPBridgeRoles, error) {
	var zero formalGLMPhase15DPBridgeRoles
	type peer struct{ name, id string }
	peers := make([]peer, len(plan.Kernel.ComputePeers))
	for index, name := range plan.Kernel.ComputePeers {
		pin := pins[name]
		if len(pin) != ed25519.PublicKeySize {
			return zero, fmt.Errorf("formal-glm: missing compute-peer identity pin")
		}
		message := append([]byte("dsVert/peer-capability/v1|"), pin...)
		digest := sha256.Sum256(message)
		peers[index] = peer{name: name, id: "dsv1_" + hex.EncodeToString(digest[:])}
	}
	if len(peers) != 2 || bytes.Equal(
		pins[peers[0].name], pins[peers[1].name]) {
		return zero, fmt.Errorf("formal-glm: invalid distinct compute-peer pins")
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].id < peers[j].id })
	return formalGLMPhase15DPBridgeRoles{
		garblerName: peers[0].name, garblerID: peers[0].id,
		evaluatorName: peers[1].name, evaluatorID: peers[1].id,
	}, nil
}

type formalGLMPhase15DPReleaseBlocker struct {
	Code    string
	Missing []string
}

func (e *formalGLMPhase15DPReleaseBlocker) Error() string {
	return "formal-glm: " + e.Code
}

func formalGLMPhase15FinalReceiptPairDigest(
	receipts []formalGLMPhase15StepReceipt) ([32]byte, error) {
	if len(receipts) != 2 {
		return [32]byte{}, fmt.Errorf("formal-glm: incomplete final receipt pair")
	}
	ordered := append([]formalGLMPhase15StepReceipt(nil), receipts...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Peer < ordered[j].Peer })
	encoded, err := json.Marshal(ordered)
	if err != nil {
		return [32]byte{}, err
	}
	message := formalGLMPhase15AppendString(nil, formalGLMPhase15DPReceiptDomain)
	message = formalGLMPhase15AppendBytes(message, encoded)
	return sha256.Sum256(message), nil
}

func formalGLMPhase15DPBridgePlanDigest(
	bridge formalGLMPhase15DPBridgePlan) ([32]byte, error) {
	encoded, err := json.Marshal(bridge)
	if err != nil {
		return [32]byte{}, err
	}
	message := formalGLMPhase15AppendString(nil, formalGLMPhase15DPBridgeDomain)
	message = formalGLMPhase15AppendBytes(message, encoded)
	return sha256.Sum256(message), nil
}

func formalGLMPhase15DPSensitivityCertificateBytes(
	certificate formalGLMPhase15DPSensitivityCertificate) ([]byte, error) {
	encoded, err := json.Marshal(certificate)
	if err != nil {
		return nil, fmt.Errorf("formal-glm: encode L2 sensitivity certificate: %w", err)
	}
	return encoded, nil
}

func formalGLMPhase15DPSensitivityCertificateDigest(
	certificate formalGLMPhase15DPSensitivityCertificate) ([32]byte, error) {
	encoded, err := formalGLMPhase15DPSensitivityCertificateBytes(certificate)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(append(
		[]byte(formalGLMPhase15DPSensitivityCertificateDomain+"|"), encoded...)), nil
}

func formalGLMPhase15CeilSqrt(value *big.Int) *big.Int {
	if value == nil || value.Sign() <= 0 {
		return new(big.Int)
	}
	result := new(big.Int).Sqrt(value)
	if new(big.Int).Mul(new(big.Int).Set(result), result).Cmp(value) < 0 {
		result.Add(result, big.NewInt(1))
	}
	return result
}

func formalGLMPhase15StringVector(values []*big.Int) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}

func formalGLMPhase15L2Squared(values []*big.Int) *big.Int {
	result := new(big.Int)
	for _, value := range values {
		result.Add(result, new(big.Int).Mul(value, value))
	}
	return result
}

// For integer floor division by positive d,
// |floor(x/d)-floor(y/d)| <= ceil(|x-y|/d). Applying this coordinate by
// coordinate is essential: replacing it by ceil(||x-y||_2/d) misses
// simultaneous bin-boundary crossings.
func formalGLMPhase15QuantizedL2Upper(sourceBounds []*big.Int,
	denominator *big.Int, coordinateCaps []*big.Int) (
	[]*big.Int, *big.Int, *big.Int, error) {

	if denominator == nil || denominator.Sign() <= 0 ||
		len(sourceBounds) < 1 || len(sourceBounds) != len(coordinateCaps) {
		return nil, nil, nil, fmt.Errorf("formal-glm: invalid lattice sensitivity shape")
	}
	quantized := make([]*big.Int, len(sourceBounds))
	for index, source := range sourceBounds {
		if source == nil || source.Sign() < 0 || coordinateCaps[index] == nil ||
			coordinateCaps[index].Sign() < 0 {
			return nil, nil, nil, fmt.Errorf("formal-glm: invalid lattice sensitivity bound")
		}
		quantized[index] = exactGCCeilDiv(source, denominator)
		if quantized[index].Cmp(coordinateCaps[index]) > 0 {
			quantized[index].Set(coordinateCaps[index])
		}
	}
	squared := formalGLMPhase15L2Squared(quantized)
	return quantized, squared, formalGLMPhase15CeilSqrt(squared), nil
}

// The implemented link is a continuous monotone piecewise-linear table with
// one signed floor multiplication per segment. Partitioning an eta interval
// across at most m segments gives ceil(L*delta/S)+(m-1); a per-integer-step
// telescoping bound and the total public link span are also valid. We select
// the smallest of these three machine-derived upper bounds.
func formalGLMPhase15PWLDeltaUpper(parsed formalGLMParsedPolicy,
	etaDelta *big.Int) *big.Int {
	if etaDelta == nil || etaDelta.Sign() <= 0 {
		return new(big.Int)
	}
	knotSpan := new(big.Int).Sub(
		parsed.knots[len(parsed.knots)-1], parsed.knots[0])
	delta := new(big.Int).Set(etaDelta)
	if delta.Cmp(knotSpan) > 0 {
		delta.Set(knotSpan)
	}
	slopeUpper := new(big.Int)
	for _, slope := range parsed.slopes {
		slopeUpper = formalGLMMax(slopeUpper, slope)
	}
	segments := int64(len(parsed.slopes))
	partitioned := formalGLMCeilMul(slopeUpper, delta, parsed.scale)
	if segments > 1 {
		partitioned.Add(partitioned, big.NewInt(segments-1))
	}
	perStep := new(big.Int).Mul(delta,
		formalGLMCeilMul(slopeUpper, big.NewInt(1), parsed.scale))
	span := new(big.Int).Sub(parsed.values[len(parsed.values)-1], parsed.values[0])
	return formalGLMMin(partitioned, perStep, span)
}

func formalGLMMin(values ...*big.Int) *big.Int {
	if len(values) == 0 {
		return new(big.Int)
	}
	result := new(big.Int).Set(values[0])
	for _, value := range values[1:] {
		if value.Cmp(result) < 0 {
			result.Set(value)
		}
	}
	return result
}

// buildFormalGLMPhase15L2SensitivityCertificate proves a recurrence for the
// exact integer DAG, not for an ideal real-valued optimizer. For fixed data it
// repeatedly applies |floor(a/d)-floor(b/d)| <= ceil(|a-b|/d) through eta,
// the link table, weighted residual, score, capacity division, ridge and
// optimizer step. The changed-row term is then added once (twice for
// replace-one), and coordinate clipping is non-expansive. This deliberately
// makes no unproved strong-convexity claim.
func buildFormalGLMPhase15L2SensitivityCertificate(plan formalGLMPhase15Plan,
	parsed formalGLMParsedPolicy, outputLatticeBits int,
	shiftedUpper []*big.Int, planDigest [32]byte) (
	formalGLMPhase15DPSensitivityCertificate, error) {

	var zero formalGLMPhase15DPSensitivityCertificate
	p := plan.Kernel.CoefficientCount
	if p < 1 || len(shiftedUpper) != p {
		return zero, fmt.Errorf("formal-glm: invalid L2 sensitivity certificate shape")
	}
	policyDigest, err := formalGLMPolicyDigest(plan.Kernel)
	if err != nil {
		return zero, err
	}
	denominator := new(big.Int).Lsh(big.NewInt(1),
		uint(plan.Kernel.FracBits-outputLatticeBits))
	xMagnitude := make([]*big.Int, p)
	rowScoreAbs := make([]*big.Int, p)
	changedAverage := make([]*big.Int, p)
	muLower := new(big.Int).Set(parsed.values[0])
	muUpper := new(big.Int).Set(parsed.values[len(parsed.values)-1])
	residualAbs := new(big.Int)
	for _, endpoint := range []*big.Int{
		muLower, muUpper,
		new(big.Int).Sub(muLower, parsed.outcomeUpper),
		new(big.Int).Sub(muUpper, parsed.outcomeUpper),
	} {
		residualAbs = formalGLMMax(residualAbs, formalGLMAbs(endpoint))
	}
	weightedAbs := formalGLMCeilMul(
		parsed.weightUpper, residualAbs, parsed.scale)
	changedRowFactor := int64(1)
	if plan.Kernel.Adjacency == "replace_one" {
		changedRowFactor = 2
	}
	capacity := big.NewInt(int64(plan.TotalCapacity))
	for index := 0; index < p; index++ {
		xMagnitude[index] = formalGLMMax(
			formalGLMAbs(parsed.xLower[index]),
			formalGLMAbs(parsed.xUpper[index]))
		rowScoreAbs[index] = formalGLMCeilMul(
			xMagnitude[index], weightedAbs, parsed.scale)
		changedAverage[index] = exactGCCeilDiv(
			new(big.Int).Mul(rowScoreAbs[index],
				big.NewInt(changedRowFactor)), capacity)
	}

	universalCoordinates := make([]*big.Int, p)
	for index := range shiftedUpper {
		universalCoordinates[index] = new(big.Int).Set(shiftedUpper[index])
	}
	universalSquared := formalGLMPhase15L2Squared(universalCoordinates)
	universalBound := formalGLMPhase15CeilSqrt(universalSquared)

	sourceBounds := make([]*big.Int, p)
	for index := range sourceBounds {
		sourceBounds[index] = new(big.Int)
	}
	recurrence := make([]formalGLMPhase15DPSensitivityStep, 0, plan.Iterations)
	slopeUpper := new(big.Int)
	for _, slope := range parsed.slopes {
		slopeUpper = formalGLMMax(slopeUpper, slope)
	}
	for iteration := 0; iteration < plan.Iterations; iteration++ {
		etaDelta := new(big.Int)
		for index := range sourceBounds {
			etaDelta.Add(etaDelta, formalGLMCeilMul(
				xMagnitude[index], sourceBounds[index], parsed.scale))
		}
		muDelta := formalGLMPhase15PWLDeltaUpper(parsed, etaDelta)
		weightedDelta := formalGLMCeilMul(
			parsed.weightUpper, muDelta, parsed.scale)
		sameScore := make([]*big.Int, p)
		fullGradient := make([]*big.Int, p)
		optimizerStep := make([]*big.Int, p)
		next := make([]*big.Int, p)
		for index := 0; index < p; index++ {
			sameScore[index] = formalGLMCeilMul(
				xMagnitude[index], weightedDelta, parsed.scale)
			ridgeDelta := formalGLMCeilMul(
				parsed.ridge[index], sourceBounds[index], parsed.scale)
			fullGradient[index] = new(big.Int).Add(
				new(big.Int).Add(sameScore[index], changedAverage[index]),
				ridgeDelta)
			optimizerStep[index] = formalGLMCeilMul(
				parsed.alpha, fullGradient[index], parsed.scale)
			next[index] = new(big.Int).Add(sourceBounds[index], optimizerStep[index])
			boxDiameter := new(big.Int).Lsh(new(big.Int).Set(parsed.box[index]), 1)
			if next[index].Cmp(boxDiameter) > 0 {
				next[index].Set(boxDiameter)
			}
		}
		recurrence = append(recurrence, formalGLMPhase15DPSensitivityStep{
			Iteration:              iteration + 1,
			SourceCoordinateBounds: formalGLMPhase15StringVector(sourceBounds),
			EtaDeltaUpper:          etaDelta.String(), MuDeltaUpper: muDelta.String(),
			WeightedResidualDeltaUpper: weightedDelta.String(),
			SameDatasetScoreDeltaUpper: formalGLMPhase15StringVector(sameScore),
			FullGradientDeltaUpper:     formalGLMPhase15StringVector(fullGradient),
			OptimizerStepDeltaUpper:    formalGLMPhase15StringVector(optimizerStep),
			NextSourceCoordinateBounds: formalGLMPhase15StringVector(next),
		})
		sourceBounds = next
	}
	quantized, recurrenceSquared, recurrenceBound, err :=
		formalGLMPhase15QuantizedL2Upper(
			sourceBounds, denominator, shiftedUpper)
	if err != nil {
		return zero, err
	}
	// The Gaussian planner intentionally accepts only positive integer
	// sensitivities. One is still a valid upper bound for a constant query.
	if recurrenceBound.Sign() == 0 {
		recurrenceBound.SetInt64(1)
		recurrenceSquared.SetInt64(1)
	}
	selectedProof := formalGLMPhase15DPTightProof
	selectedBound := new(big.Int).Set(recurrenceBound)
	if universalBound.Cmp(selectedBound) < 0 {
		selectedProof = formalGLMPhase15DPUniversalProof
		selectedBound.Set(universalBound)
	}
	box := make([]string, p)
	upper := make([]string, p)
	for index := range box {
		box[index] = parsed.box[index].String()
		upper[index] = shiftedUpper[index].String()
	}
	return formalGLMPhase15DPSensitivityCertificate{
		Version: formalGLMPhase15DPSensitivityCertificateVersion,
		Kind:    jointDPGaussianOneDrawSensitivityCertificateKind,
		Status:  "machine_proven", Norm: "l2",
		SelectedProof: selectedProof, SelectedBoundSteps: selectedBound.String(),
		PolicySHA256:      hex.EncodeToString(policyDigest[:]),
		Phase15PlanSHA256: hex.EncodeToString(planDigest[:]),
		TheoremSHA256:     plan.Kernel.TheoremSHA256,
		Adjacency:         plan.Kernel.Adjacency, ChangedRowFactor: int(changedRowFactor),
		TotalCapacity: plan.TotalCapacity, Iterations: plan.Iterations,
		CoordinateCount: p, SourceFracBits: plan.Kernel.FracBits,
		OutputLatticeBits: outputLatticeBits,
		QuantizationShift: plan.Kernel.FracBits - outputLatticeBits,
		SourceScale:       parsed.scale.String(), QuantizationDenominator: denominator.String(),
		Quantization:           "clip_box_then_coordinatewise_signed_floor_then_public_translation_v1",
		QuantizationInequality: "abs(floor(x/d)-floor(y/d))<=ceil(abs(x-y)/d)_per_coordinate_v1",
		CoefficientBox:         box, ShiftedUpperBounds: upper,
		XMagnitude:  formalGLMPhase15StringVector(xMagnitude),
		WeightUpper: parsed.weightUpper.String(), OutcomeUpper: parsed.outcomeUpper.String(),
		LinkValueLower: muLower.String(), LinkValueUpper: muUpper.String(),
		LinkSlopeUpper: slopeUpper.String(), LinkSegmentCount: len(parsed.slopes),
		ResidualAbsUpper:          residualAbs.String(),
		RowScoreAbsUpper:          formalGLMPhase15StringVector(rowScoreAbs),
		ChangedDataAverageUpper:   formalGLMPhase15StringVector(changedAverage),
		UniversalCoordinateBounds: formalGLMPhase15StringVector(universalCoordinates),
		UniversalL2Squared:        universalSquared.String(),
		UniversalBoundSteps:       universalBound.String(),
		Recurrence:                recurrence,
		RecurrenceSourceBounds:    formalGLMPhase15StringVector(sourceBounds),
		RecurrenceQuantizedBounds: formalGLMPhase15StringVector(quantized),
		RecurrenceL2Squared:       recurrenceSquared.String(),
		RecurrenceBoundSteps:      recurrenceBound.String(),
		Selection:                 "minimum_of_machine_proven_positive_integer_l2_bounds_v1",
	}, nil
}

func buildFormalGLMPhase15DPBridgePlan(plan formalGLMPhase15Plan,
	receipts []formalGLMPhase15StepReceipt, pins map[string]ed25519.PublicKey,
	outputLatticeBits int) (formalGLMPhase15DPBridgePlan, error) {

	var zero formalGLMPhase15DPBridgePlan
	if err := formalGLMPhase15VerifyReceiptPair(plan, receipts, pins); err != nil {
		return zero, err
	}
	roles, err := formalGLMPhase15DPBridgePinnedRoles(plan, pins)
	if err != nil {
		return zero, err
	}
	if receipts[0].StepIndex != plan.ScheduleSteps-1 ||
		!storeStepIsFinalizer(plan, receipts[0].StepIndex) {
		return zero, fmt.Errorf("formal-glm: receipts do not attest the final fixed step")
	}
	projection, err := buildFormalGLMPreSourceDPProjectionForLatticeV1(
		plan, outputLatticeBits)
	if err != nil {
		return zero, err
	}
	receiptDigest, err := formalGLMPhase15FinalReceiptPairDigest(receipts)
	if err != nil {
		return zero, err
	}
	transcript := receipts[0].TranscriptSHA256
	certificate := projection.SelectedSensitivityCertificate
	return formalGLMPhase15DPBridgePlan{
		Version:                   formalGLMPhase15DPBridgeVersion,
		Phase15PlanSHA256:         projection.Phase15PlanSHA256,
		FinalReceiptPairSHA256:    hex.EncodeToString(receiptDigest[:]),
		ExecutionTranscriptSHA256: transcript,
		SnapshotSHA256:            projection.SnapshotSHA256,
		PinsetSHA256:              projection.PinsetSHA256,
		GarblerPeerName:           roles.garblerName,
		GarblerPeerID:             roles.garblerID,
		EvaluatorPeerName:         roles.evaluatorName,
		EvaluatorPeerID:           roles.evaluatorID,
		RoleSelection:             formalGLMPhase16RoleSelection,
		Adjacency:                 projection.Adjacency,
		SourceRingBits:            projection.SourceRingBits,
		SourceFracBits:            projection.SourceFracBits,
		OutputRingBits:            projection.OutputRingBits,
		OutputLatticeBits:         projection.OutputLatticeBits,
		QuantizationShift:         projection.QuantizationShift,
		CoordinateCount:           projection.CoordinateCount,
		ShiftedUpperBounds: append([]string(nil),
			projection.ShiftedUpperBounds...),
		UniversalSensitivity: formalGLMPhase15DPSensitivity{
			Version:       formalGLMPhase15DPSensitivityVersion,
			Status:        "machine_proven",
			Proof:         formalGLMPhase15DPUniversalProof,
			BoundSteps:    certificate.UniversalBoundSteps,
			TheoremSHA256: plan.Kernel.TheoremSHA256,
		},
		TightSensitivity: formalGLMPhase15DPSensitivity{
			Version:       formalGLMPhase15DPSensitivityVersion,
			Status:        "machine_proven",
			Proof:         formalGLMPhase15DPTightProof,
			BoundSteps:    certificate.RecurrenceBoundSteps,
			TheoremSHA256: plan.Kernel.TheoremSHA256,
		},
		SelectedSensitivitySteps:             projection.SelectedSensitivitySteps,
		SelectedSensitivityProof:             projection.SelectedSensitivityProof,
		SelectedSensitivityCertificate:       certificate,
		SelectedSensitivityCertificateSHA256: projection.SelectedSensitivityCertificateSHA256,
		SensitivitySelection:                 "minimum_of_machine_proven_bounds_only_v1",
		Quantization:                         projection.Quantization,
		IntermediateOutput:                   "sealed_nonnegative_ring128_additive_shares_only_v1",
		AuthenticatedOpening:                 "blocked_until_common_glm_release_capsule_e2e_v1",
		ProductionReady:                      false,
	}, nil
}

func storeStepIsFinalizer(plan formalGLMPhase15Plan, step int) bool {
	return step >= 0 && step%(plan.TotalBlocks+1) == plan.TotalBlocks
}

func validateFormalGLMPhase15DPBridgePlan(plan formalGLMPhase15Plan,
	receipts []formalGLMPhase15StepReceipt, pins map[string]ed25519.PublicKey,
	bridge formalGLMPhase15DPBridgePlan) error {
	expected, err := buildFormalGLMPhase15DPBridgePlan(
		plan, receipts, pins, bridge.OutputLatticeBits)
	if err != nil {
		return err
	}
	want, _ := json.Marshal(expected)
	got, err := json.Marshal(bridge)
	if err != nil || string(got) != string(want) {
		return fmt.Errorf("formal-glm: modified or unproved DP bridge plan")
	}
	return nil
}

// formalGLMPhase15DPBridgeLoadLocalSource accepts only a fully committed local
// checkpoint whose beta and accumulated execution transcript match the final
// cross-signed receipt pair.  It returns one peer's shares, never beta.
func formalGLMPhase15DPBridgeLoadLocalSource(
	store *formalGLMPhase15CheckpointStore,
	receipts []formalGLMPhase15StepReceipt, pins map[string]ed25519.PublicKey,
	bridge formalGLMPhase15DPBridgePlan) ([]*big.Int, error) {
	if store == nil {
		return nil, fmt.Errorf("formal-glm: missing DP bridge checkpoint")
	}
	if err := validateFormalGLMPhase15DPBridgePlan(
		store.plan, receipts, pins, bridge); err != nil {
		return nil, err
	}
	state, err := store.Load()
	if err != nil {
		return nil, err
	}
	if state.NextStep != store.plan.ScheduleSteps || state.Pending != nil ||
		state.TranscriptSHA256 != bridge.ExecutionTranscriptSHA256 {
		return nil, fmt.Errorf("formal-glm: DP bridge requires a completed bound transcript")
	}
	var local *formalGLMPhase15StepReceipt
	for index := range receipts {
		if receipts[index].Peer == store.peer {
			local = &receipts[index]
		}
	}
	if local == nil || local.TranscriptSHA256 != state.TranscriptSHA256 ||
		local.StateSHA256 != formalGLMPhase15StateDigest(state.Beta, nil) {
		return nil, fmt.Errorf("formal-glm: final receipt does not bind local beta shares")
	}
	return formalGLMPhase15DecodeStateValues(
		state.Beta, store.plan.Kernel.CoefficientCount, store.plan.RingBits)
}

func formalGLMPhase15DPBridgeCircuitSource(plan formalGLMPhase15Plan,
	bridge formalGLMPhase15DPBridgePlan) (string, error) {
	parsed, err := formalGLMPhase15ValidateShape(plan)
	if err != nil {
		return "", err
	}
	if bridge.Version != formalGLMPhase15DPBridgeVersion ||
		bridge.SourceRingBits != plan.RingBits || bridge.OutputRingBits != 128 ||
		bridge.SourceFracBits != plan.Kernel.FracBits ||
		bridge.CoordinateCount != plan.Kernel.CoefficientCount ||
		bridge.QuantizationShift != plan.Kernel.FracBits-bridge.OutputLatticeBits ||
		len(bridge.ShiftedUpperBounds) != plan.Kernel.CoefficientCount {
		return "", fmt.Errorf("formal-glm: invalid DP bridge circuit contract")
	}
	upper := make([]*big.Int, bridge.CoordinateCount)
	for index := range upper {
		var ok bool
		upper[index], ok = new(big.Int).SetString(
			bridge.ShiftedUpperBounds[index], 10)
		if !ok {
			return "", fmt.Errorf("formal-glm: invalid shifted DP box")
		}
	}
	return formalGLMPhase15DPBridgeCircuitSourceForBounds(
		plan.RingBits, bridge.QuantizationShift, parsed.box, upper)
}

func formalGLMPhase15DPBridgeInputTypeBits(sourceBits int) int {
	bits := exactGCTypeBits(sourceBits)
	if bits < 128 {
		return 128
	}
	return bits
}

// formalGLMPhase15DPBridgeCircuitSourceForBounds keeps source residues and
// Ring128 output masks in one compiler input type whose width is large enough
// for both.  In particular Ring63/64 source values must never cause the fresh
// Ring128 mask to overlap the next packed field.
func formalGLMPhase15DPBridgeCircuitSourceForBounds(sourceBits,
	quantizationShift int, boxes, shiftedUpperBounds []*big.Int) (string, error) {
	if sourceBits < exactGCMinRingBits || sourceBits > exactGCMaxRingBits ||
		quantizationShift < 0 || quantizationShift >= sourceBits ||
		len(boxes) < 1 || len(boxes) != len(shiftedUpperBounds) {
		return "", fmt.Errorf("formal-glm: invalid DP bridge circuit bounds")
	}
	typeBits := formalGLMPhase15DPBridgeInputTypeBits(sourceBits)
	uintType := fmt.Sprintf("uint%d", typeBits)
	mask := exactGCMask(sourceBits).Text(16)
	sign := new(big.Int).Lsh(big.NewInt(1), uint(sourceBits-1)).Text(16)
	remainderMask := new(big.Int)
	if quantizationShift > 0 {
		remainderMask.Sub(
			new(big.Int).Lsh(big.NewInt(1), uint(quantizationShift)),
			big.NewInt(1))
	}
	constant := func(value *big.Int) string {
		return fmt.Sprintf("%s(0x%s)", uintType,
			formalGLMHex(value, sourceBits))
	}
	var source strings.Builder
	fmt.Fprintf(&source, `package main
func signedLess(a %s, b %s) bool {
	aNeg := (a & %s(0x%s)) != 0
	bNeg := (b & %s(0x%s)) != 0
	if aNeg != bNeg { return aNeg }
	return a < b
}
func main(g [%d]%s, e [%d]%s) [%d]uint128 {
`, uintType, uintType, uintType, sign, uintType, sign,
		2*len(boxes)+1, uintType, len(boxes)+1, uintType, len(boxes))
	fmt.Fprintf(&source,
		"\texecutionValid := ((g[%d] + e[%d]) & %s(1)) != 0\n",
		2*len(boxes), len(boxes), uintType)
	for index := range boxes {
		if boxes[index] == nil || boxes[index].Sign() <= 0 ||
			boxes[index].Cmp(exactGCMaxSigned(sourceBits)) > 0 {
			return "", fmt.Errorf("formal-glm: invalid signed DP box")
		}
		negativeBox := new(big.Int).Neg(new(big.Int).Set(boxes[index]))
		shiftedUpper := shiftedUpperBounds[index]
		if shiftedUpper == nil || shiftedUpper.Sign() <= 0 ||
			shiftedUpper.Bit(0) != 0 ||
			shiftedUpper.Cmp(exactGCMaxSigned(128)) > 0 {
			return "", fmt.Errorf("formal-glm: invalid shifted DP box")
		}
		quantizedBox := new(big.Int).Rsh(shiftedUpper, 1)
		fmt.Fprintf(&source,
			"\tbeta%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			index, index, index, uintType, mask)
		fmt.Fprintf(&source, "\tif signedLess(beta%d, %s) { beta%d = %s }\n",
			index, constant(negativeBox), index, constant(negativeBox))
		fmt.Fprintf(&source, "\tif signedLess(%s, beta%d) { beta%d = %s }\n",
			constant(boxes[index]), index, index, constant(boxes[index]))
		fmt.Fprintf(&source,
			"\tnegative%d := (beta%d & %s(0x%s)) != 0\n",
			index, index, uintType, sign)
		fmt.Fprintf(&source, "\tmagnitude%d := beta%d\n", index, index)
		fmt.Fprintf(&source,
			"\tif negative%d { magnitude%d = (%s(0) - beta%d) & %s(0x%s) }\n",
			index, index, uintType, index, uintType, mask)
		fmt.Fprintf(&source, "\tquantized%d := magnitude%d >> %d\n",
			index, index, quantizationShift)
		if quantizationShift > 0 {
			fmt.Fprintf(&source,
				"\tremainder%d := magnitude%d & %s(0x%s)\n",
				index, index, uintType, remainderMask.Text(16))
			fmt.Fprintf(&source,
				"\tif negative%d && remainder%d != 0 { quantized%d = quantized%d + 1 }\n",
				index, index, index, index)
		}
		fmt.Fprintf(&source,
			"\tif negative%d { quantized%d = (%s(0) - quantized%d) & %s(0x%s) }\n",
			index, index, uintType, index, uintType, mask)
		fmt.Fprintf(&source,
			"\tshifted%d := uint128((quantized%d + %s) & %s(0x%s))\n",
			index, index, constant(quantizedBox), uintType, mask)
		if index == 0 {
			// A failed all-K Phase-1.9 predicate is consumed inside this
			// circuit.  The first translated coordinate becomes the unique
			// public upper bound plus one, so the following Gaussian circuit's
			// hidden bound predicate rejects the whole vector.  Neither peer nor
			// the relay learns the predicate here and no coefficient is opened.
			invalidSentinel := new(big.Int).Add(shiftedUpper, big.NewInt(1))
			fmt.Fprintf(&source,
				"\tif !executionValid { shifted0 = uint128(%s) }\n",
				invalidSentinel.String())
		}
		fmt.Fprintf(&source,
			"\tout%d := shifted%d - uint128(g[%d])\n",
			index, index, len(boxes)+index)
	}
	fmt.Fprintf(&source, "\tvar out [%d]uint128\n", len(boxes))
	for index := range boxes {
		fmt.Fprintf(&source, "\tout[%d] = out%d\n", index, index)
	}
	source.WriteString("\treturn out\n}\n")
	return source.String(), nil
}

func compileFormalGLMPhase15DPBridge(plan formalGLMPhase15Plan,
	bridge formalGLMPhase15DPBridgePlan) (*circuit.Circuit, error) {
	source, err := formalGLMPhase15DPBridgeCircuitSource(plan, bridge)
	if err != nil {
		return nil, err
	}
	circ, err := compileFormalGLMPhase15Source(source, "DP bridge")
	if err != nil {
		return nil, err
	}
	p := plan.Kernel.CoefficientCount
	typeBits := formalGLMPhase15DPBridgeInputTypeBits(plan.RingBits)
	if len(circ.Inputs) != 2 || len(circ.Outputs) != 1 ||
		int(circ.Inputs[0].Type.Bits) != (2*p+1)*typeBits ||
		int(circ.Inputs[1].Type.Bits) != (p+1)*typeBits ||
		circ.Outputs.Size() != p*128 {
		return nil, fmt.Errorf("formal-glm: compiler produced invalid DP bridge arity")
	}
	return circ, nil
}

func formalGLMPhase15DPBridgePurpose(bridge formalGLMPhase15DPBridgePlan,
	attempt [32]byte) (string, error) {
	digest, err := formalGLMPhase15DPBridgePlanDigest(bridge)
	if err != nil {
		return "", err
	}
	return "formal-glm/phase15-dp-bridge-v1/" + hex.EncodeToString(digest[:]) +
		"/attempt/" + hex.EncodeToString(attempt[:]), nil
}

func formalGLMPhase15DPBridgeSession(plan formalGLMPhase15Plan,
	bridge formalGLMPhase15DPBridgePlan, attempt, master [32]byte) (
	exactGCSession, error) {
	purpose, err := formalGLMPhase15DPBridgePurpose(bridge, attempt)
	if err != nil {
		return exactGCSession{}, err
	}
	session := exactGCSession{
		SessionID: attempt, MasterKey: master,
		GarblerID:   bridge.GarblerPeerID,
		EvaluatorID: bridge.EvaluatorPeerID,
		Purpose:     purpose,
		Spec: exactGCCircuitSpec{
			Operation: exactGCFormalGLMDPBridge,
			RingBits:  plan.RingBits, FracBits: plan.Kernel.FracBits,
			VectorLen: plan.Kernel.CoefficientCount,
		},
	}
	if err := session.validate(); err != nil {
		return exactGCSession{}, err
	}
	return session, nil
}

func validateFormalGLMPhase15DPBridgeSession(plan formalGLMPhase15Plan,
	bridge formalGLMPhase15DPBridgePlan, session exactGCSession) error {
	want, err := formalGLMPhase15DPBridgeSession(
		plan, bridge, session.SessionID, session.MasterKey)
	if err != nil {
		return err
	}
	if session.GarblerID != want.GarblerID ||
		session.EvaluatorID != want.EvaluatorID || session.Purpose != want.Purpose ||
		session.Spec.Operation != want.Spec.Operation ||
		session.Spec.RingBits != want.Spec.RingBits ||
		session.Spec.FracBits != want.Spec.FracBits ||
		session.Spec.VectorLen != want.Spec.VectorLen {
		return fmt.Errorf("formal-glm: DP bridge session mismatch")
	}
	return nil
}

func formalGLMPhase15PackDPBridgeGarbler(beta, masks []*big.Int,
	sourceBits int) (*big.Int, error) {
	return formalGLMPhase15PackDPBridgeGarblerWithExecution(
		beta, masks, sourceBits, 1)
}

func formalGLMPhase15PackDPBridgeGarblerWithExecution(beta, masks []*big.Int,
	sourceBits int, executionShare byte) (*big.Int, error) {
	if sourceBits < exactGCMinRingBits || sourceBits > exactGCMaxRingBits ||
		len(beta) != len(masks) || len(beta) < 1 || executionShare > 1 {
		return nil, fmt.Errorf("formal-glm: invalid DP bridge garbler input")
	}
	sourceModulus := exactGCModulus(sourceBits)
	for _, share := range beta {
		if share == nil || share.Sign() < 0 || share.Cmp(sourceModulus) >= 0 {
			return nil, fmt.Errorf("formal-glm: invalid DP bridge source share")
		}
	}
	mask128 := exactGCMask(128)
	for _, mask := range masks {
		if mask == nil || mask.Sign() < 0 || mask.Cmp(mask128) > 0 {
			return nil, fmt.Errorf("formal-glm: invalid DP bridge output mask")
		}
	}
	fields := append(append([]*big.Int(nil), beta...), masks...)
	fields = append(fields, new(big.Int).SetUint64(uint64(executionShare)))
	return exactGCPackChunks(
		fields,
		formalGLMPhase15DPBridgeInputTypeBits(sourceBits)), nil
}

func formalGLMPhase15RunDPBridgeGarbler(rw io.ReadWriter,
	plan formalGLMPhase15Plan, bridge formalGLMPhase15DPBridgePlan,
	session exactGCSession, betaShares []*big.Int) ([]*big.Int, error) {
	return formalGLMPhase15RunDPBridgeGarblerWithExecution(
		rw, plan, bridge, session, betaShares, 1)
}

func formalGLMPhase15RunDPBridgeGarblerWithExecution(rw io.ReadWriter,
	plan formalGLMPhase15Plan, bridge formalGLMPhase15DPBridgePlan,
	session exactGCSession, betaShares []*big.Int,
	executionShare byte) ([]*big.Int, error) {
	if rw == nil {
		return nil, fmt.Errorf("formal-glm: nil DP bridge channel")
	}
	if err := validateFormalGLMPhase15DPBridgeSession(
		plan, bridge, session); err != nil {
		return nil, err
	}
	if err := exactGCValidateShares(betaShares, session.Spec); err != nil {
		return nil, err
	}
	circ, err := compileFormalGLMPhase15DPBridge(plan, bridge)
	if err != nil {
		return nil, err
	}
	masks, err := formalGLMRandomMasks(plan.Kernel.CoefficientCount, 128)
	if err != nil {
		return nil, err
	}
	input, err := formalGLMPhase15PackDPBridgeGarblerWithExecution(
		betaShares, masks, plan.RingBits, executionShare)
	if err != nil {
		return nil, err
	}
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

func formalGLMPhase15RunDPBridgeEvaluator(rw io.ReadWriter,
	plan formalGLMPhase15Plan, bridge formalGLMPhase15DPBridgePlan,
	session exactGCSession, betaShares []*big.Int) ([]*big.Int, error) {
	return formalGLMPhase15RunDPBridgeEvaluatorWithExecution(
		rw, plan, bridge, session, betaShares, 0)
}

func formalGLMPhase15RunDPBridgeEvaluatorWithExecution(rw io.ReadWriter,
	plan formalGLMPhase15Plan, bridge formalGLMPhase15DPBridgePlan,
	session exactGCSession, betaShares []*big.Int,
	executionShare byte) ([]*big.Int, error) {
	if rw == nil {
		return nil, fmt.Errorf("formal-glm: nil DP bridge channel")
	}
	if err := validateFormalGLMPhase15DPBridgeSession(
		plan, bridge, session); err != nil {
		return nil, err
	}
	if err := exactGCValidateShares(betaShares, session.Spec); err != nil ||
		executionShare > 1 {
		if err == nil {
			err = fmt.Errorf("formal-glm: invalid sealed execution share")
		}
		return nil, err
	}
	circ, err := compileFormalGLMPhase15DPBridge(plan, bridge)
	if err != nil {
		return nil, err
	}
	fields := append([]*big.Int(nil), betaShares...)
	fields = append(fields, new(big.Int).SetUint64(uint64(executionShare)))
	input := exactGCPackChunks(fields,
		formalGLMPhase15DPBridgeInputTypeBits(plan.RingBits))
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleEvaluator)
	if err != nil {
		return nil, err
	}
	conn := p2p.NewConn(secure)
	packed, protocolErr := exactGCEvaluatorProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return nil, err
	}
	result := make([]*big.Int, plan.Kernel.CoefficientCount)
	for index := range result {
		result[index] = new(big.Int).Rsh(new(big.Int).Set(packed), uint(index*128))
		result[index].And(result[index], exactGCMask(128))
	}
	return result, nil
}

func referenceFormalGLMPhase15DPBridge(plan formalGLMPhase15Plan,
	bridge formalGLMPhase15DPBridgePlan, beta []*big.Int) ([]*big.Int, error) {
	parsed, err := formalGLMPhase15ValidateShape(plan)
	if err != nil || len(beta) != plan.Kernel.CoefficientCount {
		if err == nil {
			err = fmt.Errorf("formal-glm: invalid DP bridge reference input")
		}
		return nil, err
	}
	denominator := new(big.Int).Lsh(big.NewInt(1), uint(bridge.QuantizationShift))
	result := make([]*big.Int, len(beta))
	for index, residue := range beta {
		value := exactGCReferenceSigned(residue, plan.RingBits)
		if value.Cmp(new(big.Int).Neg(new(big.Int).Set(parsed.box[index]))) < 0 {
			value = new(big.Int).Neg(new(big.Int).Set(parsed.box[index]))
		} else if value.Cmp(parsed.box[index]) > 0 {
			value = new(big.Int).Set(parsed.box[index])
		}
		quantized, remainder := new(big.Int), new(big.Int)
		quantized.QuoRem(value, denominator, remainder)
		if value.Sign() < 0 && remainder.Sign() != 0 {
			quantized.Sub(quantized, big.NewInt(1))
		}
		upper, ok := new(big.Int).SetString(bridge.ShiftedUpperBounds[index], 10)
		if !ok {
			return nil, fmt.Errorf("formal-glm: invalid DP bridge upper bound")
		}
		result[index] = quantized.Add(quantized, upper.Rsh(upper, 1))
	}
	return result, nil
}

// No caller can turn the sealed bridge shares into a release through this
// Phase-1.5-only path. Phase-1.6 compiles the common Gaussian worker after it
// has the complete durable capsule binding; this lower layer still cannot
// authorize or perform an opening by itself.
func formalGLMPhase15CompileAuthenticatedDPRelease(
	plan formalGLMPhase15Plan, receipts []formalGLMPhase15StepReceipt,
	pins map[string]ed25519.PublicKey,
	bridge formalGLMPhase15DPBridgePlan) (jointDPGaussianOneDrawWorkerContractOutput, error) {
	if err := validateFormalGLMPhase15DPBridgePlan(
		plan, receipts, pins, bridge); err != nil {
		return jointDPGaussianOneDrawWorkerContractOutput{}, err
	}
	return jointDPGaussianOneDrawWorkerContractOutput{}, &formalGLMPhase15DPReleaseBlocker{
		Code: formalGLMPhase15DPReleaseBlockerCode,
		Missing: []string{
			"common durable sticky-noise GLM manifest/materializer admission",
			"single-opening authorization through that admitted Phase-1.6 manifest",
		},
	}
}
