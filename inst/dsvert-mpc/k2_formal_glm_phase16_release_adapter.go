package main

// Phase-1.6 data-free contract between the sealed formal-GLM coefficient
// bridge and the common one-draw joint-DP Ring128 Gaussian worker. It
// deliberately registers no command. The capsule manifest/materializer does
// not yet admit a formal-GLM source, so this layer compiles and verifies the
// complete public worker contract but performs zero openings.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"sort"
)

const (
	formalGLMPhase16ReleaseVersion      = "dsvert-formal-glm-phase16-release-adapter-v1"
	formalGLMPhase16ReleaseDomain       = "dsVert/formal-glm/phase16/release-adapter/v1"
	formalGLMPhase16RoleSelection       = "lexicographic_pinned_cryptographic_peer_id_v1"
	formalGLMPhase16RequiredMechanism   = "joint_discrete_gaussian_one_global_draw"
	formalGLMPhase16RequiredAllocation  = "one_stacked_capsule_vector"
	formalGLMPhase16ManifestBlockerCode = "formal_glm_protected_materializer_and_dsi_opening_unavailable"
)

type formalGLMPhase16NoiseCommitment struct {
	ContextSHA256 string `json:"context_sha256"`
	SeedSHA256    string `json:"seed_sha256"`
}

type formalGLMPhase16CapsuleBinding struct {
	CapsuleID             string                                     `json:"capsule_id"`
	ManifestSHA256        string                                     `json:"manifest_sha256"`
	SchemaManifestSHA256  string                                     `json:"schema_manifest_sha256"`
	WorkloadSHA256        string                                     `json:"workload_sha256"`
	SourceContextSHA256   string                                     `json:"source_context_sha256"`
	CoordinateOrderSHA256 string                                     `json:"coordinate_order_sha256"`
	ReleaseInstanceID     string                                     `json:"release_instance_id"`
	ReleaseContractSHA256 string                                     `json:"release_contract_sha256"`
	Mechanism             string                                     `json:"mechanism"`
	Allocation            string                                     `json:"allocation"`
	Epsilon               string                                     `json:"epsilon"`
	AllocatedDelta        string                                     `json:"allocated_delta"`
	NoiseCommitments      map[string]formalGLMPhase16NoiseCommitment `json:"noise_commitments_by_peer_id"`
}

type formalGLMPhase16Roles struct {
	PinsetSHA256      string `json:"pinset_sha256"`
	GarblerPeerName   string `json:"garbler_peer_name"`
	GarblerPeerID     string `json:"garbler_peer_id"`
	EvaluatorPeerName string `json:"evaluator_peer_name"`
	EvaluatorPeerID   string `json:"evaluator_peer_id"`
}

type formalGLMPhase16ReleaseBinding struct {
	Version                         string                                   `json:"version"`
	CapsuleID                       string                                   `json:"capsule_id"`
	ManifestSHA256                  string                                   `json:"manifest_sha256"`
	SchemaManifestSHA256            string                                   `json:"schema_manifest_sha256"`
	WorkloadSHA256                  string                                   `json:"workload_sha256"`
	SourceContextSHA256             string                                   `json:"source_context_sha256"`
	CoordinateOrderSHA256           string                                   `json:"coordinate_order_sha256"`
	ReleaseInstanceID               string                                   `json:"release_instance_id"`
	ReleaseContractSHA256           string                                   `json:"release_contract_sha256"`
	Phase15PlanSHA256               string                                   `json:"phase15_plan_sha256"`
	Phase15BridgeSHA256             string                                   `json:"phase15_bridge_sha256"`
	FinalReceiptPairSHA256          string                                   `json:"final_receipt_pair_sha256"`
	SourceFanInTranscriptSHA256     string                                   `json:"source_fan_in_transcript_sha256"`
	FinalCheckpointTranscriptSHA256 string                                   `json:"final_checkpoint_transcript_sha256"`
	SnapshotSHA256                  string                                   `json:"snapshot_sha256"`
	PinsetSHA256                    string                                   `json:"pinset_sha256"`
	KernelSpecSHA256                string                                   `json:"kernel_spec_sha256"`
	BoundsSHA256                    string                                   `json:"bounds_sha256"`
	QuantizationSHA256              string                                   `json:"quantization_sha256"`
	Family                          string                                   `json:"family"`
	LinkTableSHA256                 string                                   `json:"link_table_sha256"`
	Adjacency                       string                                   `json:"adjacency"`
	Mechanism                       string                                   `json:"mechanism"`
	Allocation                      string                                   `json:"allocation"`
	Epsilon                         string                                   `json:"epsilon"`
	AllocatedDelta                  string                                   `json:"allocated_delta"`
	SourceRingBits                  int                                      `json:"source_ring_bits"`
	CommonRingBits                  int                                      `json:"common_ring_bits"`
	SourceFracBits                  int                                      `json:"source_frac_bits"`
	OutputLatticeBits               int                                      `json:"output_lattice_bits"`
	QuantizationShift               int                                      `json:"quantization_shift"`
	CoordinateCount                 int                                      `json:"coordinate_count"`
	ShiftedUpperBounds              []string                                 `json:"shifted_upper_bounds"`
	SignedLowerBounds               []string                                 `json:"signed_lower_bounds"`
	SignedUpperBounds               []string                                 `json:"signed_upper_bounds"`
	SensitivitySteps                string                                   `json:"sensitivity_steps"`
	SensitivityNorm                 string                                   `json:"sensitivity_norm"`
	SensitivityProof                string                                   `json:"sensitivity_proof"`
	SensitivityCertificateKind      string                                   `json:"sensitivity_certificate_kind"`
	SensitivityCertificateSHA256    string                                   `json:"sensitivity_certificate_sha256"`
	SensitivityCertificate          formalGLMPhase15DPSensitivityCertificate `json:"sensitivity_certificate"`
	TightSensitivityStatus          string                                   `json:"tight_sensitivity_status"`
	GarblerPeerName                 string                                   `json:"garbler_peer_name"`
	GarblerPeerID                   string                                   `json:"garbler_peer_id"`
	EvaluatorPeerName               string                                   `json:"evaluator_peer_name"`
	EvaluatorPeerID                 string                                   `json:"evaluator_peer_id"`
	GarblerCommitmentContext        string                                   `json:"garbler_commitment_context"`
	GarblerSeedCommitment           string                                   `json:"garbler_seed_commitment"`
	EvaluatorCommitmentContext      string                                   `json:"evaluator_commitment_context"`
	EvaluatorSeedCommitment         string                                   `json:"evaluator_seed_commitment"`
	CustodianCount                  int                                      `json:"custodian_count"`
	RoleSelection                   string                                   `json:"role_selection"`
	Quantization                    string                                   `json:"quantization"`
	SignedDecode                    string                                   `json:"signed_decode"`
	QuantizationError               string                                   `json:"quantization_error"`
	RangeCertificate                string                                   `json:"range_certificate"`
	NoWrapCertificate               string                                   `json:"no_wrap_certificate"`
	Noise                           string                                   `json:"noise"`
	OpeningCount                    int                                      `json:"opening_count"`
	Opening                         string                                   `json:"opening"`
	ProductionReady                 bool                                     `json:"production_ready"`
	BindingSHA256                   string                                   `json:"binding_sha256"`
}

type formalGLMPhase16CompiledRelease struct {
	Binding formalGLMPhase16ReleaseBinding              `json:"binding"`
	Worker  *jointDPGaussianOneDrawWorkerContractOutput `json:"common_worker,omitempty"`
}

type formalGLMPhase16ReleaseBlocker struct {
	Code              string
	Missing           []string
	OpeningsPerformed int
}

func (e *formalGLMPhase16ReleaseBlocker) Error() string {
	return "formal-glm: " + e.Code
}

func formalGLMPhase16PeerID(pin ed25519.PublicKey) (string, error) {
	if len(pin) != ed25519.PublicKeySize {
		return "", fmt.Errorf("formal-glm: invalid Ed25519 pin")
	}
	message := append([]byte("dsVert/peer-capability/v1|"), pin...)
	digest := sha256.Sum256(message)
	return "dsv1_" + hex.EncodeToString(digest[:]), nil
}

// This is byte-for-byte the canonical pinset used by the R policy: sorted
// logical names mapped to unpadded base64url Ed25519 keys, encoded as compact
// JSON and SHA-256 hashed.
func formalGLMPhase16PinsetSHA256(pins map[string]ed25519.PublicKey) (string, error) {
	if len(pins) < 2 {
		return "", fmt.Errorf("formal-glm: incomplete pinned consortium")
	}
	canonical := make(map[string]string, len(pins))
	seenPins := make(map[string]bool, len(pins))
	for name, pin := range pins {
		validName := len(name) >= 1 && len(name) <= 128
		for index := 0; validName && index < len(name); index++ {
			value := name[index]
			alphaNumeric := value >= 'A' && value <= 'Z' ||
				value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
			validName = alphaNumeric || index > 0 &&
				(value == '.' || value == '_' || value == '-')
		}
		encodedPin := base64.RawURLEncoding.EncodeToString(pin)
		if !validName || len(pin) != ed25519.PublicKeySize || seenPins[encodedPin] {
			return "", fmt.Errorf("formal-glm: invalid pinned consortium")
		}
		seenPins[encodedPin] = true
		canonical[name] = encodedPin
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPhase16PinnedRoles(plan formalGLMPhase15Plan,
	pins map[string]ed25519.PublicKey) (formalGLMPhase16Roles, error) {
	var zero formalGLMPhase16Roles
	if len(pins) != len(plan.Kernel.CustodianPeers) {
		return zero, fmt.Errorf("formal-glm: pinset does not cover every custodian")
	}
	for _, name := range plan.Kernel.CustodianPeers {
		if len(pins[name]) != ed25519.PublicKeySize {
			return zero, fmt.Errorf("formal-glm: pinset does not cover every custodian")
		}
	}
	pinset, err := formalGLMPhase16PinsetSHA256(pins)
	if err != nil {
		return zero, err
	}
	type peer struct{ name, id string }
	peers := make([]peer, 2)
	for index, name := range plan.Kernel.ComputePeers {
		id, err := formalGLMPhase16PeerID(pins[name])
		if err != nil {
			return zero, err
		}
		peers[index] = peer{name: name, id: id}
	}
	if peers[0].id == peers[1].id {
		return zero, fmt.Errorf("formal-glm: duplicate compute-peer pin")
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].id < peers[j].id })
	return formalGLMPhase16Roles{
		PinsetSHA256:    pinset,
		GarblerPeerName: peers[0].name, GarblerPeerID: peers[0].id,
		EvaluatorPeerName: peers[1].name, EvaluatorPeerID: peers[1].id,
	}, nil
}

func formalGLMPhase16CoefficientOrderSHA256(count int) string {
	coordinates := make([]string, count)
	for index := range coordinates {
		coordinates[index] = fmt.Sprintf("beta[%d]", index)
	}
	encoded, _ := json.Marshal(struct {
		Version     string   `json:"version"`
		Coordinates []string `json:"coordinates"`
	}{"formal-glm-coefficient-order-v1", coordinates})
	digest := sha256.Sum256(append(
		[]byte("dsVert/formal-glm/coefficient-order/v1|"), encoded...))
	return hex.EncodeToString(digest[:])
}

func formalGLMPhase16CommonAdjacency(value string) (string, error) {
	switch value {
	case "add_remove":
		return "add_remove_patient", nil
	case "replace_one":
		return "replace_one_fixed_cohort", nil
	default:
		return "", fmt.Errorf("formal-glm: unsupported DP adjacency")
	}
}

func formalGLMPhase16DomainDigest(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte(domain+"|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPhase16ReleaseBindingDigest(
	binding formalGLMPhase16ReleaseBinding) (string, error) {
	encoded, err := formalGLMPhase16ReleaseBindingPreimage(binding)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMPhase16ReleaseDomain+"|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPhase16ReleaseBindingPreimage(
	binding formalGLMPhase16ReleaseBinding) ([]byte, error) {
	binding.BindingSHA256 = ""
	encoded, err := json.Marshal(binding)
	if err != nil {
		return nil, fmt.Errorf("formal-glm: encode Phase-1.6 release binding: %w", err)
	}
	return encoded, nil
}

func buildFormalGLMPhase16ReleaseBinding(plan formalGLMPhase15Plan,
	receipts []formalGLMPhase15StepReceipt, pins map[string]ed25519.PublicKey,
	bridge formalGLMPhase15DPBridgePlan,
	capsule formalGLMPhase16CapsuleBinding) (formalGLMPhase16ReleaseBinding, error) {
	var zero formalGLMPhase16ReleaseBinding
	if err := validateFormalGLMPhase15DPBridgePlan(
		plan, receipts, pins, bridge); err != nil {
		return zero, err
	}
	roles, err := formalGLMPhase16PinnedRoles(plan, pins)
	if err != nil {
		return zero, err
	}
	if roles.PinsetSHA256 != plan.Kernel.PinsetSHA256 ||
		roles.PinsetSHA256 != bridge.PinsetSHA256 ||
		roles.GarblerPeerName != bridge.GarblerPeerName ||
		roles.GarblerPeerID != bridge.GarblerPeerID ||
		roles.EvaluatorPeerName != bridge.EvaluatorPeerName ||
		roles.EvaluatorPeerID != bridge.EvaluatorPeerID ||
		bridge.RoleSelection != formalGLMPhase16RoleSelection {
		return zero, fmt.Errorf("formal-glm: execution plan does not match the cryptographic pinset")
	}
	hashes := []string{
		capsule.CapsuleID, capsule.ManifestSHA256, capsule.SchemaManifestSHA256,
		capsule.WorkloadSHA256, capsule.SourceContextSHA256,
		capsule.CoordinateOrderSHA256, capsule.ReleaseInstanceID,
		capsule.ReleaseContractSHA256,
	}
	for _, value := range hashes {
		if !formalGLMIsSHA256(value) {
			return zero, fmt.Errorf("formal-glm: invalid common release binding")
		}
	}
	if capsule.CoordinateOrderSHA256 !=
		formalGLMPhase16CoefficientOrderSHA256(plan.Kernel.CoefficientCount) ||
		capsule.Mechanism != formalGLMPhase16RequiredMechanism ||
		capsule.Allocation != formalGLMPhase16RequiredAllocation ||
		len(capsule.NoiseCommitments) != 2 {
		return zero, fmt.Errorf("formal-glm: common release does not match the Phase-0 mechanism, allocation, coordinate order, or peer set")
	}
	if _, err := jointDPParseDecimalRat(capsule.Epsilon, "epsilon", false); err != nil {
		return zero, fmt.Errorf("formal-glm: invalid Phase-0 epsilon: %w", err)
	}
	delta, err := jointDPParseDecimalRat(
		capsule.AllocatedDelta, "allocated_delta", false)
	if err != nil || delta.Cmp(big.NewRat(1, 1)) >= 0 {
		return zero, fmt.Errorf("formal-glm: allocated delta must be in (0,1)")
	}
	garbler, gok := capsule.NoiseCommitments[roles.GarblerPeerID]
	evaluator, eok := capsule.NoiseCommitments[roles.EvaluatorPeerID]
	if !gok || !eok {
		return zero, fmt.Errorf("formal-glm: noise commitments are not keyed by pinned peer ID")
	}
	for _, value := range []string{
		garbler.ContextSHA256, garbler.SeedSHA256,
		evaluator.ContextSHA256, evaluator.SeedSHA256,
	} {
		if !formalGLMIsSHA256(value) {
			return zero, fmt.Errorf("formal-glm: invalid sticky-noise commitment")
		}
	}
	transcriptBytes, err := hex.DecodeString(capsule.ReleaseContractSHA256)
	if err != nil || len(transcriptBytes) != sha256.Size {
		return zero, fmt.Errorf("formal-glm: invalid sticky-noise transcript")
	}
	var noiseTranscript [32]byte
	copy(noiseTranscript[:], transcriptBytes)
	expectedGarblerContext := jointDPCommitmentContext(noiseTranscript,
		jointDPGaussianOneDrawCommitmentPurpose+"/garbler", roles.GarblerPeerID)
	expectedEvaluatorContext := jointDPCommitmentContext(noiseTranscript,
		jointDPGaussianOneDrawCommitmentPurpose+"/evaluator", roles.EvaluatorPeerID)
	if garbler.ContextSHA256 != hex.EncodeToString(expectedGarblerContext[:]) ||
		evaluator.ContextSHA256 != hex.EncodeToString(expectedEvaluatorContext[:]) {
		return zero, fmt.Errorf("formal-glm: sticky-noise context is not bound to the release contract and pinned roles")
	}
	planDigest, _ := formalGLMPhase15PlanDigest(plan)
	bridgeDigest, _ := formalGLMPhase15DPBridgePlanDigest(bridge)
	receiptDigest, _ := formalGLMPhase15FinalReceiptPairDigest(receipts)
	policyDigest, _ := formalGLMPolicyDigest(plan.Kernel)
	boundsDigest, err := formalGLMPhase16BoundsSHA256V1(plan)
	if err != nil {
		return zero, err
	}
	quantDigest, err := formalGLMPhase16QuantizationSHA256V1(
		bridge.SourceFracBits, bridge.OutputLatticeBits,
		bridge.QuantizationShift, bridge.Quantization)
	if err != nil {
		return zero, err
	}
	commonAdjacency, err := formalGLMPhase16CommonAdjacency(plan.Kernel.Adjacency)
	if err != nil {
		return zero, err
	}
	certificateDigest, err := formalGLMPhase15DPSensitivityCertificateDigest(
		bridge.SelectedSensitivityCertificate)
	if err != nil ||
		hex.EncodeToString(certificateDigest[:]) !=
			bridge.SelectedSensitivityCertificateSHA256 ||
		bridge.SelectedSensitivityCertificate.Kind !=
			jointDPGaussianOneDrawSensitivityCertificateKind ||
		bridge.SelectedSensitivityCertificate.Status != "machine_proven" ||
		bridge.SelectedSensitivityCertificate.Norm != "l2" ||
		bridge.SelectedSensitivityCertificate.SelectedBoundSteps !=
			bridge.SelectedSensitivitySteps ||
		bridge.SelectedSensitivityCertificate.SelectedProof !=
			bridge.SelectedSensitivityProof {
		return zero, fmt.Errorf("formal-glm: invalid machine-proven L2 sensitivity certificate")
	}
	l2Sensitivity, ok := new(big.Int).SetString(
		bridge.SelectedSensitivitySteps, 10)
	if !ok || l2Sensitivity.Sign() <= 0 ||
		l2Sensitivity.Cmp(exactGCMaxSigned(128)) > 0 {
		required := 129
		if ok {
			required = l2Sensitivity.BitLen() + 1
		}
		return zero, &formalGLMNumericBackendError{
			Code: "dp_l2_sensitivity_ring128_unrepresentable", RequiredBits: required}
	}
	lower := make([]string, bridge.CoordinateCount)
	upper := make([]string, bridge.CoordinateCount)
	for index, shiftedText := range bridge.ShiftedUpperBounds {
		shifted, ok := new(big.Int).SetString(shiftedText, 10)
		if !ok || shifted.Sign() <= 0 || shifted.Bit(0) != 0 {
			return zero, fmt.Errorf("formal-glm: invalid signed release range")
		}
		bound := new(big.Int).Rsh(shifted, 1)
		upper[index] = bound.String()
		lower[index] = new(big.Int).Neg(bound).String()
	}
	binding := formalGLMPhase16ReleaseBinding{
		Version:   formalGLMPhase16ReleaseVersion,
		CapsuleID: capsule.CapsuleID, ManifestSHA256: capsule.ManifestSHA256,
		SchemaManifestSHA256:            capsule.SchemaManifestSHA256,
		WorkloadSHA256:                  capsule.WorkloadSHA256,
		SourceContextSHA256:             capsule.SourceContextSHA256,
		CoordinateOrderSHA256:           capsule.CoordinateOrderSHA256,
		ReleaseInstanceID:               capsule.ReleaseInstanceID,
		ReleaseContractSHA256:           capsule.ReleaseContractSHA256,
		Phase15PlanSHA256:               hex.EncodeToString(planDigest[:]),
		Phase15BridgeSHA256:             hex.EncodeToString(bridgeDigest[:]),
		FinalReceiptPairSHA256:          hex.EncodeToString(receiptDigest[:]),
		SourceFanInTranscriptSHA256:     bridge.ExecutionTranscriptSHA256,
		FinalCheckpointTranscriptSHA256: bridge.ExecutionTranscriptSHA256,
		SnapshotSHA256:                  bridge.SnapshotSHA256, PinsetSHA256: roles.PinsetSHA256,
		KernelSpecSHA256: hex.EncodeToString(policyDigest[:]),
		BoundsSHA256:     boundsDigest, QuantizationSHA256: quantDigest,
		Family: plan.Kernel.Family, LinkTableSHA256: plan.Kernel.LinkTableSHA256,
		Adjacency: commonAdjacency, SourceRingBits: plan.RingBits,
		Mechanism: capsule.Mechanism, Allocation: capsule.Allocation,
		Epsilon: capsule.Epsilon, AllocatedDelta: capsule.AllocatedDelta,
		CommonRingBits: 128, SourceFracBits: plan.Kernel.FracBits,
		OutputLatticeBits:  bridge.OutputLatticeBits,
		QuantizationShift:  bridge.QuantizationShift,
		CoordinateCount:    bridge.CoordinateCount,
		ShiftedUpperBounds: append([]string(nil), bridge.ShiftedUpperBounds...),
		SignedLowerBounds:  lower, SignedUpperBounds: upper,
		SensitivitySteps:             bridge.SelectedSensitivitySteps,
		SensitivityNorm:              "l2",
		SensitivityProof:             bridge.SelectedSensitivityProof,
		SensitivityCertificateKind:   bridge.SelectedSensitivityCertificate.Kind,
		SensitivityCertificateSHA256: bridge.SelectedSensitivityCertificateSHA256,
		SensitivityCertificate:       bridge.SelectedSensitivityCertificate,
		TightSensitivityStatus:       bridge.TightSensitivity.Status,
		GarblerPeerName:              roles.GarblerPeerName, GarblerPeerID: roles.GarblerPeerID,
		EvaluatorPeerName:          roles.EvaluatorPeerName,
		EvaluatorPeerID:            roles.EvaluatorPeerID,
		GarblerCommitmentContext:   garbler.ContextSHA256,
		GarblerSeedCommitment:      garbler.SeedSHA256,
		EvaluatorCommitmentContext: evaluator.ContextSHA256,
		EvaluatorSeedCommitment:    evaluator.SeedSHA256,
		CustodianCount:             len(plan.Kernel.CustodianPeers),
		RoleSelection:              formalGLMPhase16RoleSelection,
		Quantization:               "signed_floor_inside_exact_gc_then_public_translation_v1",
		SignedDecode:               "subtract_public_quantized_box_after_single_dp_opening_v1",
		QuantizationError:          "0<=exact_coefficient-released_lattice_coefficient<2^-output_lattice_bits_before_dp_noise_v1",
		RangeCertificate:           "translated_coordinate_in_[0,2Bq]_and_signed_release_in_[-Bq,Bq]_v1",
		NoWrapCertificate:          "bridge_coordinates_l2_sensitivity_and_common_gaussian_saturating_clamp_ring128_checked_v1",
		Noise:                      "required_two_pinned_peer_sticky_joint_discrete_gaussian_one_global_draw_v1",
		OpeningCount:               1,
		Opening:                    "blocked_until_common_formal_glm_manifest_materializer_admission_v1",
		ProductionReady:            false,
	}
	binding.BindingSHA256, err = formalGLMPhase16ReleaseBindingDigest(binding)
	if err != nil {
		return zero, err
	}
	return binding, nil
}

func validateFormalGLMPhase16ReleaseBinding(plan formalGLMPhase15Plan,
	receipts []formalGLMPhase15StepReceipt, pins map[string]ed25519.PublicKey,
	bridge formalGLMPhase15DPBridgePlan, capsule formalGLMPhase16CapsuleBinding,
	binding formalGLMPhase16ReleaseBinding) error {
	expected, err := buildFormalGLMPhase16ReleaseBinding(
		plan, receipts, pins, bridge, capsule)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(binding, expected) {
		return fmt.Errorf("formal-glm: modified Phase-1.6 release binding")
	}
	return nil
}

func compileFormalGLMPhase16ReleaseAdapter(plan formalGLMPhase15Plan,
	receipts []formalGLMPhase15StepReceipt, pins map[string]ed25519.PublicKey,
	bridge formalGLMPhase15DPBridgePlan,
	capsule formalGLMPhase16CapsuleBinding) (formalGLMPhase16CompiledRelease, error) {
	compiled, err := formalGLMPhase16CompileSealedWorker(
		plan, receipts, pins, bridge, capsule)
	if err != nil {
		return compiled, err
	}
	return compiled, formalGLMPhase16ReleaseUnavailable()
}

// formalGLMPhase16CompileSealedWorker compiles the common worker but cannot by
// itself authorize an opening.  The productive envelope layer adds the K
// signatures, local source binding, hidden execution-validity consumption and
// durable append-before-release barrier.
func formalGLMPhase16CompileSealedWorker(plan formalGLMPhase15Plan,
	receipts []formalGLMPhase15StepReceipt, pins map[string]ed25519.PublicKey,
	bridge formalGLMPhase15DPBridgePlan,
	capsule formalGLMPhase16CapsuleBinding) (formalGLMPhase16CompiledRelease, error) {
	var zero formalGLMPhase16CompiledRelease
	binding, err := buildFormalGLMPhase16ReleaseBinding(
		plan, receipts, pins, bridge, capsule)
	if err != nil {
		return zero, err
	}
	preimage, err := formalGLMPhase16ReleaseBindingPreimage(binding)
	if err != nil {
		return zero, err
	}
	scaleShifts := make([]int, binding.CoordinateCount)
	worker, err := jointDPCompileGaussianOneDrawWorkerContract(
		jointDPGaussianOneDrawWorkerContractInput{
			Version:  jointDPGaussianOneDrawWorkerContractInputVersion,
			RingBits: 128, FracBits: 0,
			TotalCoordinateCount: binding.CoordinateCount,
			ChunkStart:           0, CoordinateCount: binding.CoordinateCount,
			OutputLatticeBits: binding.OutputLatticeBits,
			Epsilon:           binding.Epsilon, AllocatedDelta: binding.AllocatedDelta,
			L2SensitivitySteps:             binding.SensitivitySteps,
			L2SensitivityCertificateKind:   binding.SensitivityCertificateKind,
			L2SensitivityCertificateSHA256: binding.SensitivityCertificateSHA256,
			ReleaseBindingDomain:           formalGLMPhase16ReleaseDomain,
			ReleaseBindingCanonicalJSON:    string(preimage),
			ScaleShifts:                    scaleShifts,
			RawUpperBounds:                 append([]string(nil), binding.ShiftedUpperBounds...),
			ReleaseBindingSHA256:           binding.BindingSHA256,
			CrossSignedPolicySHA256:        binding.BindingSHA256,
			TranscriptHash:                 binding.ReleaseContractSHA256,
			PinsetSHA256:                   binding.PinsetSHA256,
			CustodianCount:                 binding.CustodianCount,
			DesignatedComputePeerCount:     2,
			GarblerPeerID:                  binding.GarblerPeerID,
			EvaluatorPeerID:                binding.EvaluatorPeerID,
			GarblerCommitmentContext:       binding.GarblerCommitmentContext,
			EvaluatorCommitmentContext:     binding.EvaluatorCommitmentContext,
			GarblerSeedCommitment:          binding.GarblerSeedCommitment,
			EvaluatorSeedCommitment:        binding.EvaluatorSeedCommitment,
		})
	if err != nil {
		return formalGLMPhase16CompiledRelease{Binding: binding}, err
	}
	compiled := formalGLMPhase16CompiledRelease{Binding: binding, Worker: &worker}
	return compiled, nil
}

func formalGLMPhase16ReleaseUnavailable() error {
	return &formalGLMPhase16ReleaseBlocker{
		Code: formalGLMPhase16ManifestBlockerCode,
		Missing: []string{
			"protected Phase-1.8 materializer and production DSI single-opening finalizer",
		},
		OpeningsPerformed: 0,
	}
}

func formalGLMPhase16AuthorizeOpening(
	compiled formalGLMPhase16CompiledRelease) error {
	if compiled.Binding.Version != formalGLMPhase16ReleaseVersion ||
		compiled.Binding.OpeningCount != 1 ||
		compiled.Binding.ProductionReady || compiled.Worker == nil ||
		!compiled.Worker.CapabilityAvailable ||
		compiled.Worker.Mechanism != formalGLMPhase16RequiredMechanism ||
		compiled.Worker.Allocation != formalGLMPhase16RequiredAllocation ||
		compiled.Worker.WorkerPolicy.ReleaseBindingSHA256 !=
			compiled.Binding.BindingSHA256 ||
		compiled.Binding.Mechanism != formalGLMPhase16RequiredMechanism ||
		compiled.Binding.Allocation != formalGLMPhase16RequiredAllocation {
		return fmt.Errorf("formal-glm: invalid Phase-1.6 compiled release")
	}
	return formalGLMPhase16ReleaseUnavailable()
}
