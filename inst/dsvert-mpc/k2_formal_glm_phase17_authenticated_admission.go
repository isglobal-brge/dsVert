package main

// Phase 1.7 is the internal authenticated-admission gate for the sealed formal
// GLM release. It is intentionally absent from main.go, runtime capabilities,
// the R/DSI adapter, package exports, and release binaries.
//
// The gate treats every supplied bridge and sensitivity certificate as an
// assertion only. It rebuilds both from the unanimously approved Phase-1.5
// plan and final signed receipts, compares the canonical bytes, and compiles a
// candidate worker only from that rebuilt state. A generic Gaussian worker is
// therefore not a formal-GLM admission; only the typed result below records a
// successfully verified K-of-K Phase-1.7 signature set.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

const (
	formalGLMPhase17ManifestVersion           = "dsvert-formal-glm-phase17-manifest-binding-v1"
	formalGLMPhase17SourceContributionVersion = "dsvert-formal-glm-phase17-source-contribution-v1"
	formalGLMPhase17AdmissionVersion          = "dsvert-formal-glm-phase17-authenticated-admission-v1"
	formalGLMPhase17SourceContributionDomain  = "dsVert/formal-glm/phase17/source-contribution/v1"
	formalGLMPhase17SourceAttestationDomain   = "dsVert/formal-glm/phase17/source-contribution-attestation/v1"
	formalGLMPhase17AdmissionDomain           = "dsVert/formal-glm/phase17/authenticated-admission/v1"
	formalGLMPhase17SignatureSetDomain        = "dsVert/formal-glm/phase17/signature-set/v1"
	formalGLMPhase17WorkerContractDomain      = "dsVert/formal-glm/phase17/worker-contract/v1"
	formalGLMPhase17AdmissionTokenDomain      = "dsVert/formal-glm/phase17/admission-token/v1"
	formalGLMPhase17MaterializerBlockerCode   = "formal_glm_protected_materializer_and_dsi_opening_unavailable"

	formalGLMPhase17CapacitySemantics   = "fixed_public_total_capacity_zero_weight_padded_slots_v1"
	formalGLMPhase17AdjacencySemantics  = "patient_slot_vs_zero_weight_slot_add_remove_or_two_slots_replace_one_v1"
	formalGLMPhase17PatientContribution = "at_most_one_active_aligned_record_per_patient_all_duplicates_zero_weight_v1"
	formalGLMPhase17MaterializerStatus  = "custodian_signed_claim_protected_data_materializer_e2e_pending_v1"
)

type formalGLMPhase17CustodianSignature struct {
	Signer    string `json:"signer"`
	Signature []byte `json:"signature"`
}

// formalGLMPhase17SourceContributionContract is a complete public claim about
// the source adjacency preconditions used by the sensitivity proof. K-of-K
// signatures authenticate the claim, but do not prove it against protected
// rows; the missing protected-data materializer remains an explicit blocker.
type formalGLMPhase17SourceContributionContract struct {
	Version                     string   `json:"version"`
	PlanSHA256                  string   `json:"plan_sha256"`
	KernelSpecSHA256            string   `json:"kernel_spec_sha256"`
	ManifestSHA256              string   `json:"manifest_sha256"`
	WorkloadSHA256              string   `json:"workload_sha256"`
	SourceContextSHA256         string   `json:"source_context_sha256"`
	SnapshotSHA256              string   `json:"snapshot_sha256"`
	SourceFanInTranscriptSHA256 string   `json:"source_fan_in_transcript_sha256"`
	PinsetSHA256                string   `json:"pinset_sha256"`
	CustodianPeers              []string `json:"custodian_peers"`
	CustodianCount              int      `json:"custodian_count"`
	TotalCapacity               int      `json:"total_capacity"`
	CapacitySemantics           string   `json:"capacity_semantics"`
	Adjacency                   string   `json:"adjacency"`
	AdjacencySemantics          string   `json:"adjacency_semantics"`
	MaximumActiveRowsPerPatient int      `json:"maximum_active_rows_per_patient"`
	PatientContribution         string   `json:"patient_contribution"`
	Missingness                 string   `json:"missingness"`
	PatientCollapse             string   `json:"patient_collapse"`
	MaterializerVerification    string   `json:"materializer_verification"`
	ProtectedDataE2EVerified    bool     `json:"protected_data_e2e_verified"`
	ProductionReady             bool     `json:"production_ready"`
}

type formalGLMPhase17SourceContributionAttestation struct {
	Contract   formalGLMPhase17SourceContributionContract `json:"contract"`
	Signatures []formalGLMPhase17CustodianSignature       `json:"signatures"`
}

// The manifest binding is the server-authoritative projection of the future
// common capsule manifest required by this method. It contains no protected
// values and every field is recomputed or cross-checked before admission.
type formalGLMPhase17ManifestBinding struct {
	Version                         string `json:"version"`
	CapsuleID                       string `json:"capsule_id"`
	ManifestSHA256                  string `json:"manifest_sha256"`
	SchemaManifestSHA256            string `json:"schema_manifest_sha256"`
	WorkloadSHA256                  string `json:"workload_sha256"`
	SourceContextSHA256             string `json:"source_context_sha256"`
	SourceContractSHA256            string `json:"source_contract_sha256"`
	SnapshotSHA256                  string `json:"snapshot_sha256"`
	Phase15PlanSHA256               string `json:"phase15_plan_sha256"`
	KernelSpecSHA256                string `json:"kernel_spec_sha256"`
	BoundsSHA256                    string `json:"bounds_sha256"`
	Phase15BridgeSHA256             string `json:"phase15_bridge_sha256"`
	SensitivityCertificateSHA256    string `json:"sensitivity_certificate_sha256"`
	SourceFanInTranscriptSHA256     string `json:"source_fan_in_transcript_sha256"`
	FinalCheckpointTranscriptSHA256 string `json:"final_checkpoint_transcript_sha256"`
	CoordinateOrderSHA256           string `json:"coordinate_order_sha256"`
	PinsetSHA256                    string `json:"pinset_sha256"`
	CustodianCount                  int    `json:"custodian_count"`
	TotalCapacity                   int    `json:"total_capacity"`
	Adjacency                       string `json:"adjacency"`
	ReleaseInstanceID               string `json:"release_instance_id"`
	ReleaseContractSHA256           string `json:"release_contract_sha256"`
	Mechanism                       string `json:"mechanism"`
	Allocation                      string `json:"allocation"`
	Epsilon                         string `json:"epsilon"`
	AllocatedDelta                  string `json:"allocated_delta"`
	ProductionReady                 bool   `json:"production_ready"`
}

// formalGLMPhase17AdmissionPreimage is the exact object signed by every
// custodian. It binds the scientific plan, source contract, execution state,
// common release, pinned roles, sensitivity proof, and compiled worker.
type formalGLMPhase17AdmissionPreimage struct {
	Version                             string   `json:"version"`
	CapsuleID                           string   `json:"capsule_id"`
	ManifestSHA256                      string   `json:"manifest_sha256"`
	SchemaManifestSHA256                string   `json:"schema_manifest_sha256"`
	WorkloadSHA256                      string   `json:"workload_sha256"`
	SourceContextSHA256                 string   `json:"source_context_sha256"`
	SourceContractSHA256                string   `json:"source_contract_sha256"`
	SourceContributionAttestationSHA256 string   `json:"source_contribution_attestation_sha256"`
	SnapshotSHA256                      string   `json:"snapshot_sha256"`
	Phase15PlanSHA256                   string   `json:"phase15_plan_sha256"`
	KernelSpecSHA256                    string   `json:"kernel_spec_sha256"`
	BoundsSHA256                        string   `json:"bounds_sha256"`
	QuantizationSHA256                  string   `json:"quantization_sha256"`
	Phase15BridgeSHA256                 string   `json:"phase15_bridge_sha256"`
	FinalReceiptPairSHA256              string   `json:"final_receipt_pair_sha256"`
	SensitivityCertificateSHA256        string   `json:"sensitivity_certificate_sha256"`
	SourceFanInTranscriptSHA256         string   `json:"source_fan_in_transcript_sha256"`
	FinalCheckpointTranscriptSHA256     string   `json:"final_checkpoint_transcript_sha256"`
	CoordinateOrderSHA256               string   `json:"coordinate_order_sha256"`
	Phase16ReleaseBindingSHA256         string   `json:"phase16_release_binding_sha256"`
	WorkerContractSHA256                string   `json:"worker_contract_sha256"`
	ReleaseInstanceID                   string   `json:"release_instance_id"`
	ReleaseContractSHA256               string   `json:"release_contract_sha256"`
	WorkerTranscriptSHA256              string   `json:"worker_transcript_sha256"`
	PinsetSHA256                        string   `json:"pinset_sha256"`
	CustodianPeers                      []string `json:"custodian_peers"`
	CustodianCount                      int      `json:"custodian_count"`
	GarblerPeerName                     string   `json:"garbler_peer_name"`
	GarblerPeerID                       string   `json:"garbler_peer_id"`
	EvaluatorPeerName                   string   `json:"evaluator_peer_name"`
	EvaluatorPeerID                     string   `json:"evaluator_peer_id"`
	RoleSelection                       string   `json:"role_selection"`
	TotalCapacity                       int      `json:"total_capacity"`
	CapacitySemantics                   string   `json:"capacity_semantics"`
	Adjacency                           string   `json:"adjacency"`
	AdjacencySemantics                  string   `json:"adjacency_semantics"`
	MaximumActiveRowsPerPatient         int      `json:"maximum_active_rows_per_patient"`
	PatientContribution                 string   `json:"patient_contribution"`
	Missingness                         string   `json:"missingness"`
	PatientCollapse                     string   `json:"patient_collapse"`
	Mechanism                           string   `json:"mechanism"`
	Allocation                          string   `json:"allocation"`
	Epsilon                             string   `json:"epsilon"`
	AllocatedDelta                      string   `json:"allocated_delta"`
	AuthenticatedOpeningCount           int      `json:"authenticated_opening_count"`
	ProtectedDataE2EVerified            bool     `json:"protected_data_e2e_verified"`
	ProductionReady                     bool     `json:"production_ready"`
}

type formalGLMPhase17SignedAdmission struct {
	Preimage   formalGLMPhase17AdmissionPreimage    `json:"preimage"`
	Signatures []formalGLMPhase17CustodianSignature `json:"signatures"`
}

// The worker and seal are deliberately unexported and omitted from JSON. A
// generic worker contract cannot be converted to this typed admission by any
// R/DSI caller. ProductionReady remains false and opening remains blocked.
type formalGLMPhase17AuthenticatedAdmission struct {
	Version                             string `json:"version"`
	PreimageSHA256                      string `json:"preimage_sha256"`
	CustodianSignatureSetSHA256         string `json:"custodian_signature_set_sha256"`
	SourceContributionAttestationSHA256 string `json:"source_contribution_attestation_sha256"`
	WorkerContractSHA256                string `json:"worker_contract_sha256"`
	AdmissionTokenSHA256                string `json:"admission_token_sha256"`
	AuthenticatedGatePassed             bool   `json:"authenticated_gate_passed"`
	ProtectedDataE2EVerified            bool   `json:"protected_data_e2e_verified"`
	OpeningsPerformed                   int    `json:"openings_performed"`
	ProductionReady                     bool   `json:"production_ready"`
	worker                              *jointDPGaussianOneDrawWorkerContractOutput
	seal                                [32]byte
}

type formalGLMPhase17ReleaseBlocker struct {
	Code              string
	Missing           []string
	OpeningsPerformed int
}

func (e *formalGLMPhase17ReleaseBlocker) Error() string {
	return "formal-glm: " + e.Code
}

type formalGLMPhase17Candidate struct {
	preimage formalGLMPhase17AdmissionPreimage
	worker   jointDPGaussianOneDrawWorkerContractOutput
}

func formalGLMPhase17CanonicalBytes(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("formal-glm: encode Phase-1.7 object: %w", err)
	}
	return encoded, nil
}

func formalGLMPhase17DomainMessage(domain string, value any) ([]byte, error) {
	encoded, err := formalGLMPhase17CanonicalBytes(value)
	if err != nil {
		return nil, err
	}
	message := formalGLMPhase15AppendString(nil, domain)
	return formalGLMPhase15AppendBytes(message, encoded), nil
}

func formalGLMPhase17DomainDigest(domain string, value any) ([32]byte, error) {
	message, err := formalGLMPhase17DomainMessage(domain, value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(message), nil
}

func formalGLMPhase17SourceContributionMessage(
	contract formalGLMPhase17SourceContributionContract) ([]byte, error) {
	return formalGLMPhase17DomainMessage(
		formalGLMPhase17SourceContributionDomain, contract)
}

func formalGLMPhase17SourceContributionContractDigest(
	contract formalGLMPhase17SourceContributionContract) ([32]byte, error) {
	return formalGLMPhase17DomainDigest(
		formalGLMPhase17SourceContributionDomain, contract)
}

func formalGLMPhase17AdmissionMessage(
	preimage formalGLMPhase17AdmissionPreimage) ([]byte, error) {
	return formalGLMPhase17DomainMessage(formalGLMPhase17AdmissionDomain, preimage)
}

func formalGLMPhase17AdmissionPreimageDigest(
	preimage formalGLMPhase17AdmissionPreimage) ([32]byte, error) {
	return formalGLMPhase17DomainDigest(formalGLMPhase17AdmissionDomain, preimage)
}

func formalGLMPhase17CanonicalSignatureSet(
	signatures []formalGLMPhase17CustodianSignature) []formalGLMPhase17CustodianSignature {
	result := append([]formalGLMPhase17CustodianSignature(nil), signatures...)
	sort.Slice(result, func(i, j int) bool { return result[i].Signer < result[j].Signer })
	return result
}

func formalGLMPhase17SignatureSetDigest(
	signatures []formalGLMPhase17CustodianSignature) ([32]byte, error) {
	return formalGLMPhase17DomainDigest(formalGLMPhase17SignatureSetDomain,
		formalGLMPhase17CanonicalSignatureSet(signatures))
}

func formalGLMPhase17VerifySignatureSet(message []byte,
	signatures []formalGLMPhase17CustodianSignature, peers []string,
	pins map[string]ed25519.PublicKey, what string) error {

	if len(signatures) != len(peers) {
		return fmt.Errorf("formal-glm: %s is not unanimously signed", what)
	}
	want := make(map[string]bool, len(peers))
	for _, peer := range peers {
		want[peer] = true
	}
	seen := make(map[string]bool, len(signatures))
	for _, signature := range signatures {
		pin, ok := pins[signature.Signer]
		if !ok || !want[signature.Signer] || seen[signature.Signer] ||
			len(pin) != ed25519.PublicKeySize ||
			len(signature.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(pin, message, signature.Signature) {
			return fmt.Errorf("formal-glm: invalid or duplicate %s signature", what)
		}
		seen[signature.Signer] = true
	}
	return nil
}

func formalGLMPhase17SignSourceContribution(
	contract formalGLMPhase17SourceContributionContract, signer string,
	privateKey ed25519.PrivateKey) (formalGLMPhase17CustodianSignature, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return formalGLMPhase17CustodianSignature{},
			fmt.Errorf("formal-glm: invalid source-contribution signing key")
	}
	message, err := formalGLMPhase17SourceContributionMessage(contract)
	if err != nil {
		return formalGLMPhase17CustodianSignature{}, err
	}
	return formalGLMPhase17CustodianSignature{
		Signer: signer, Signature: ed25519.Sign(privateKey, message)}, nil
}

func formalGLMPhase17SignAdmission(preimage formalGLMPhase17AdmissionPreimage,
	signer string, privateKey ed25519.PrivateKey) (
	formalGLMPhase17CustodianSignature, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return formalGLMPhase17CustodianSignature{},
			fmt.Errorf("formal-glm: invalid Phase-1.7 signing key")
	}
	message, err := formalGLMPhase17AdmissionMessage(preimage)
	if err != nil {
		return formalGLMPhase17CustodianSignature{}, err
	}
	return formalGLMPhase17CustodianSignature{
		Signer: signer, Signature: ed25519.Sign(privateKey, message)}, nil
}

func buildFormalGLMPhase17SourceContributionContract(plan formalGLMPhase15Plan,
	bridge formalGLMPhase15DPBridgePlan,
	capsule formalGLMPhase16CapsuleBinding) (
	formalGLMPhase17SourceContributionContract, error) {

	planDigest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil {
		return formalGLMPhase17SourceContributionContract{}, err
	}
	kernelDigest, err := formalGLMPolicyDigest(plan.Kernel)
	if err != nil {
		return formalGLMPhase17SourceContributionContract{}, err
	}
	return formalGLMPhase17SourceContributionContract{
		Version:                     formalGLMPhase17SourceContributionVersion,
		PlanSHA256:                  hex.EncodeToString(planDigest[:]),
		KernelSpecSHA256:            hex.EncodeToString(kernelDigest[:]),
		ManifestSHA256:              capsule.ManifestSHA256,
		WorkloadSHA256:              capsule.WorkloadSHA256,
		SourceContextSHA256:         capsule.SourceContextSHA256,
		SnapshotSHA256:              plan.Kernel.SnapshotSHA256,
		SourceFanInTranscriptSHA256: bridge.ExecutionTranscriptSHA256,
		PinsetSHA256:                plan.Kernel.PinsetSHA256,
		CustodianPeers:              append([]string(nil), plan.Kernel.CustodianPeers...),
		CustodianCount:              len(plan.Kernel.CustodianPeers),
		TotalCapacity:               plan.TotalCapacity,
		CapacitySemantics:           formalGLMPhase17CapacitySemantics,
		Adjacency:                   plan.Kernel.Adjacency,
		AdjacencySemantics:          formalGLMPhase17AdjacencySemantics,
		MaximumActiveRowsPerPatient: 1,
		PatientContribution:         formalGLMPhase17PatientContribution,
		Missingness:                 plan.Kernel.Missingness,
		PatientCollapse:             plan.Kernel.PatientCollapse,
		MaterializerVerification:    formalGLMPhase17MaterializerStatus,
		ProtectedDataE2EVerified:    false,
		ProductionReady:             false,
	}, nil
}

func formalGLMPhase17SourceAttestationDigest(
	attestation formalGLMPhase17SourceContributionAttestation) ([32]byte, error) {
	canonical := attestation
	canonical.Signatures = formalGLMPhase17CanonicalSignatureSet(
		attestation.Signatures)
	return formalGLMPhase17DomainDigest(
		formalGLMPhase17SourceAttestationDomain, canonical)
}

func validateFormalGLMPhase17SourceContribution(plan formalGLMPhase15Plan,
	bridge formalGLMPhase15DPBridgePlan, capsule formalGLMPhase16CapsuleBinding,
	pins map[string]ed25519.PublicKey,
	attestation formalGLMPhase17SourceContributionAttestation) error {

	expected, err := buildFormalGLMPhase17SourceContributionContract(
		plan, bridge, capsule)
	if err != nil {
		return err
	}
	want, _ := formalGLMPhase17CanonicalBytes(expected)
	got, err := formalGLMPhase17CanonicalBytes(attestation.Contract)
	if err != nil || !bytes.Equal(got, want) {
		return fmt.Errorf("formal-glm: modified or incomplete source-contribution contract")
	}
	message, err := formalGLMPhase17SourceContributionMessage(expected)
	if err != nil {
		return err
	}
	return formalGLMPhase17VerifySignatureSet(message, attestation.Signatures,
		plan.Kernel.CustodianPeers, pins, "source-contribution attestation")
}

func buildFormalGLMPhase17ManifestBinding(plan formalGLMPhase15Plan,
	binding formalGLMPhase16ReleaseBinding,
	sourceContractSHA256 string) formalGLMPhase17ManifestBinding {
	return formalGLMPhase17ManifestBinding{
		Version:                         formalGLMPhase17ManifestVersion,
		CapsuleID:                       binding.CapsuleID,
		ManifestSHA256:                  binding.ManifestSHA256,
		SchemaManifestSHA256:            binding.SchemaManifestSHA256,
		WorkloadSHA256:                  binding.WorkloadSHA256,
		SourceContextSHA256:             binding.SourceContextSHA256,
		SourceContractSHA256:            sourceContractSHA256,
		SnapshotSHA256:                  binding.SnapshotSHA256,
		Phase15PlanSHA256:               binding.Phase15PlanSHA256,
		KernelSpecSHA256:                binding.KernelSpecSHA256,
		BoundsSHA256:                    binding.BoundsSHA256,
		Phase15BridgeSHA256:             binding.Phase15BridgeSHA256,
		SensitivityCertificateSHA256:    binding.SensitivityCertificateSHA256,
		SourceFanInTranscriptSHA256:     binding.SourceFanInTranscriptSHA256,
		FinalCheckpointTranscriptSHA256: binding.FinalCheckpointTranscriptSHA256,
		CoordinateOrderSHA256:           binding.CoordinateOrderSHA256,
		PinsetSHA256:                    binding.PinsetSHA256,
		CustodianCount:                  binding.CustodianCount,
		TotalCapacity:                   plan.TotalCapacity,
		Adjacency:                       binding.Adjacency,
		ReleaseInstanceID:               binding.ReleaseInstanceID,
		ReleaseContractSHA256:           binding.ReleaseContractSHA256,
		Mechanism:                       binding.Mechanism,
		Allocation:                      binding.Allocation,
		Epsilon:                         binding.Epsilon,
		AllocatedDelta:                  binding.AllocatedDelta,
		ProductionReady:                 false,
	}
}

func formalGLMPhase17WorkerContractDigest(
	worker jointDPGaussianOneDrawWorkerContractOutput) ([32]byte, error) {
	if !worker.CapabilityAvailable || worker.UnavailableReason != "" ||
		worker.WorkerPolicy.Version != jointDPGaussianOneDrawTemplateVersion {
		return [32]byte{}, fmt.Errorf("formal-glm: invalid Phase-1.7 candidate worker")
	}
	return formalGLMPhase17DomainDigest(formalGLMPhase17WorkerContractDomain, worker)
}

func formalGLMPhase17RebuildBridge(plan formalGLMPhase15Plan,
	receipts []formalGLMPhase15StepReceipt, pins map[string]ed25519.PublicKey,
	supplied formalGLMPhase15DPBridgePlan) (formalGLMPhase15DPBridgePlan, error) {

	rebuilt, err := buildFormalGLMPhase15DPBridgePlan(
		plan, receipts, pins, supplied.OutputLatticeBits)
	if err != nil {
		return formalGLMPhase15DPBridgePlan{}, err
	}
	want, _ := formalGLMPhase17CanonicalBytes(rebuilt)
	got, err := formalGLMPhase17CanonicalBytes(supplied)
	if err != nil || !bytes.Equal(got, want) {
		return formalGLMPhase15DPBridgePlan{},
			fmt.Errorf("formal-glm: caller bridge or L2 certificate differs from authoritative reconstruction")
	}
	return rebuilt, nil
}

func formalGLMPhase17BuildCandidate(plan formalGLMPhase15Plan,
	approvals []formalGLMPhase15Approval, receipts []formalGLMPhase15StepReceipt,
	pins map[string]ed25519.PublicKey, suppliedBridge formalGLMPhase15DPBridgePlan,
	capsule formalGLMPhase16CapsuleBinding,
	manifest formalGLMPhase17ManifestBinding,
	source formalGLMPhase17SourceContributionAttestation) (
	formalGLMPhase17Candidate, error) {

	var zero formalGLMPhase17Candidate
	if err := formalGLMPhase15VerifyPlanApprovals(plan, approvals, pins); err != nil {
		return zero, err
	}
	roles, err := formalGLMPhase16PinnedRoles(plan, pins)
	if err != nil || roles.PinsetSHA256 != plan.Kernel.PinsetSHA256 {
		return zero, fmt.Errorf("formal-glm: Phase-1.7 pinset does not match the approved plan")
	}
	if err := formalGLMPhase15VerifyReceiptPair(plan, receipts, pins); err != nil {
		return zero, err
	}
	bridge, err := formalGLMPhase17RebuildBridge(
		plan, receipts, pins, suppliedBridge)
	if err != nil {
		return zero, err
	}
	if err := validateFormalGLMPhase17SourceContribution(
		plan, bridge, capsule, pins, source); err != nil {
		return zero, err
	}
	sourceContractDigest, err := formalGLMPhase17SourceContributionContractDigest(
		source.Contract)
	if err != nil {
		return zero, err
	}
	sourceContractHex := hex.EncodeToString(sourceContractDigest[:])
	sourceAttestationDigest, err := formalGLMPhase17SourceAttestationDigest(source)
	if err != nil {
		return zero, err
	}

	compiled, compileErr := compileFormalGLMPhase16ReleaseAdapter(
		plan, receipts, pins, bridge, capsule)
	var phase16Blocker *formalGLMPhase16ReleaseBlocker
	if !errors.As(compileErr, &phase16Blocker) ||
		phase16Blocker.Code != formalGLMPhase16ManifestBlockerCode ||
		phase16Blocker.OpeningsPerformed != 0 || compiled.Worker == nil {
		if compileErr != nil {
			return zero, compileErr
		}
		return zero, fmt.Errorf("formal-glm: Phase-1.6 candidate worker is unavailable")
	}
	if err := validateFormalGLMPhase16ReleaseBinding(
		plan, receipts, pins, bridge, capsule, compiled.Binding); err != nil {
		return zero, err
	}
	worker := *compiled.Worker
	workerDigest, err := formalGLMPhase17WorkerContractDigest(worker)
	if err != nil {
		return zero, err
	}
	if compiled.Binding.ReleaseContractSHA256 !=
		worker.WorkerPolicy.TranscriptHash ||
		compiled.Binding.ReleaseContractSHA256 != capsule.ReleaseContractSHA256 {
		return zero, fmt.Errorf("formal-glm: release contract and worker transcript differ")
	}
	expectedManifest := buildFormalGLMPhase17ManifestBinding(
		plan, compiled.Binding, sourceContractHex)
	wantManifest, _ := formalGLMPhase17CanonicalBytes(expectedManifest)
	gotManifest, err := formalGLMPhase17CanonicalBytes(manifest)
	if err != nil || !bytes.Equal(gotManifest, wantManifest) {
		return zero, fmt.Errorf("formal-glm: manifest does not bind the authoritative formal-GLM release")
	}

	preimage := formalGLMPhase17AdmissionPreimage{
		Version:                             formalGLMPhase17AdmissionVersion,
		CapsuleID:                           compiled.Binding.CapsuleID,
		ManifestSHA256:                      compiled.Binding.ManifestSHA256,
		SchemaManifestSHA256:                compiled.Binding.SchemaManifestSHA256,
		WorkloadSHA256:                      compiled.Binding.WorkloadSHA256,
		SourceContextSHA256:                 compiled.Binding.SourceContextSHA256,
		SourceContractSHA256:                sourceContractHex,
		SourceContributionAttestationSHA256: hex.EncodeToString(sourceAttestationDigest[:]),
		SnapshotSHA256:                      compiled.Binding.SnapshotSHA256,
		Phase15PlanSHA256:                   compiled.Binding.Phase15PlanSHA256,
		KernelSpecSHA256:                    compiled.Binding.KernelSpecSHA256,
		BoundsSHA256:                        compiled.Binding.BoundsSHA256,
		QuantizationSHA256:                  compiled.Binding.QuantizationSHA256,
		Phase15BridgeSHA256:                 compiled.Binding.Phase15BridgeSHA256,
		FinalReceiptPairSHA256:              compiled.Binding.FinalReceiptPairSHA256,
		SensitivityCertificateSHA256:        compiled.Binding.SensitivityCertificateSHA256,
		SourceFanInTranscriptSHA256:         compiled.Binding.SourceFanInTranscriptSHA256,
		FinalCheckpointTranscriptSHA256:     compiled.Binding.FinalCheckpointTranscriptSHA256,
		CoordinateOrderSHA256:               compiled.Binding.CoordinateOrderSHA256,
		Phase16ReleaseBindingSHA256:         compiled.Binding.BindingSHA256,
		WorkerContractSHA256:                hex.EncodeToString(workerDigest[:]),
		ReleaseInstanceID:                   compiled.Binding.ReleaseInstanceID,
		ReleaseContractSHA256:               compiled.Binding.ReleaseContractSHA256,
		WorkerTranscriptSHA256:              worker.WorkerPolicy.TranscriptHash,
		PinsetSHA256:                        roles.PinsetSHA256,
		CustodianPeers:                      append([]string(nil), plan.Kernel.CustodianPeers...),
		CustodianCount:                      len(plan.Kernel.CustodianPeers),
		GarblerPeerName:                     roles.GarblerPeerName,
		GarblerPeerID:                       roles.GarblerPeerID,
		EvaluatorPeerName:                   roles.EvaluatorPeerName,
		EvaluatorPeerID:                     roles.EvaluatorPeerID,
		RoleSelection:                       formalGLMPhase16RoleSelection,
		TotalCapacity:                       plan.TotalCapacity,
		CapacitySemantics:                   formalGLMPhase17CapacitySemantics,
		Adjacency:                           plan.Kernel.Adjacency,
		AdjacencySemantics:                  formalGLMPhase17AdjacencySemantics,
		MaximumActiveRowsPerPatient:         1,
		PatientContribution:                 formalGLMPhase17PatientContribution,
		Missingness:                         plan.Kernel.Missingness,
		PatientCollapse:                     plan.Kernel.PatientCollapse,
		Mechanism:                           compiled.Binding.Mechanism,
		Allocation:                          compiled.Binding.Allocation,
		Epsilon:                             compiled.Binding.Epsilon,
		AllocatedDelta:                      compiled.Binding.AllocatedDelta,
		AuthenticatedOpeningCount:           0,
		ProtectedDataE2EVerified:            false,
		ProductionReady:                     false,
	}
	return formalGLMPhase17Candidate{preimage: preimage, worker: worker}, nil
}

// formalGLMPhase17PrepareAdmissionPreimage performs the complete authoritative
// reconstruction but returns no worker. Custodians sign only this result.
func formalGLMPhase17PrepareAdmissionPreimage(plan formalGLMPhase15Plan,
	approvals []formalGLMPhase15Approval, receipts []formalGLMPhase15StepReceipt,
	pins map[string]ed25519.PublicKey, bridge formalGLMPhase15DPBridgePlan,
	capsule formalGLMPhase16CapsuleBinding,
	manifest formalGLMPhase17ManifestBinding,
	source formalGLMPhase17SourceContributionAttestation) (
	formalGLMPhase17AdmissionPreimage, error) {
	candidate, err := formalGLMPhase17BuildCandidate(
		plan, approvals, receipts, pins, bridge, capsule, manifest, source)
	if err != nil {
		return formalGLMPhase17AdmissionPreimage{}, err
	}
	return candidate.preimage, nil
}

func formalGLMPhase17AdmissionSeal(preimage, signatures, source, worker [32]byte) [32]byte {
	message := formalGLMPhase15AppendString(nil, formalGLMPhase17AdmissionTokenDomain)
	message = append(message, preimage[:]...)
	message = append(message, signatures[:]...)
	message = append(message, source[:]...)
	message = append(message, worker[:]...)
	return sha256.Sum256(message)
}

// admitFormalGLMPhase17 is the only constructor of the typed authenticated
// admission. It still returns a zero-opening blocker because the protected-data
// materializer and production DSI finalizer do not yet exist.
func admitFormalGLMPhase17(plan formalGLMPhase15Plan,
	approvals []formalGLMPhase15Approval, receipts []formalGLMPhase15StepReceipt,
	pins map[string]ed25519.PublicKey, bridge formalGLMPhase15DPBridgePlan,
	capsule formalGLMPhase16CapsuleBinding,
	manifest formalGLMPhase17ManifestBinding,
	source formalGLMPhase17SourceContributionAttestation,
	signed formalGLMPhase17SignedAdmission) (
	formalGLMPhase17AuthenticatedAdmission, error) {

	var zero formalGLMPhase17AuthenticatedAdmission
	candidate, err := formalGLMPhase17BuildCandidate(
		plan, approvals, receipts, pins, bridge, capsule, manifest, source)
	if err != nil {
		return zero, err
	}
	want, _ := formalGLMPhase17CanonicalBytes(candidate.preimage)
	got, err := formalGLMPhase17CanonicalBytes(signed.Preimage)
	if err != nil || !bytes.Equal(got, want) {
		return zero, fmt.Errorf("formal-glm: Phase-1.7 signatures target a different preimage")
	}
	message, err := formalGLMPhase17AdmissionMessage(candidate.preimage)
	if err != nil {
		return zero, err
	}
	if err := formalGLMPhase17VerifySignatureSet(message, signed.Signatures,
		plan.Kernel.CustodianPeers, pins, "Phase-1.7 admission"); err != nil {
		return zero, err
	}
	preimageDigest, _ := formalGLMPhase17AdmissionPreimageDigest(candidate.preimage)
	signatureDigest, err := formalGLMPhase17SignatureSetDigest(signed.Signatures)
	if err != nil {
		return zero, err
	}
	sourceDigest, err := formalGLMPhase17SourceAttestationDigest(source)
	if err != nil {
		return zero, err
	}
	workerDigest, err := formalGLMPhase17WorkerContractDigest(candidate.worker)
	if err != nil {
		return zero, err
	}
	seal := formalGLMPhase17AdmissionSeal(
		preimageDigest, signatureDigest, sourceDigest, workerDigest)
	result := formalGLMPhase17AuthenticatedAdmission{
		Version:                             formalGLMPhase17AdmissionVersion,
		PreimageSHA256:                      hex.EncodeToString(preimageDigest[:]),
		CustodianSignatureSetSHA256:         hex.EncodeToString(signatureDigest[:]),
		SourceContributionAttestationSHA256: hex.EncodeToString(sourceDigest[:]),
		WorkerContractSHA256:                hex.EncodeToString(workerDigest[:]),
		AdmissionTokenSHA256:                hex.EncodeToString(seal[:]),
		AuthenticatedGatePassed:             true,
		ProtectedDataE2EVerified:            false,
		OpeningsPerformed:                   0,
		ProductionReady:                     false,
		worker:                              &candidate.worker,
		seal:                                seal,
	}
	return result, formalGLMPhase17ReleaseUnavailable()
}

func validateFormalGLMPhase17AuthenticatedAdmission(
	admission formalGLMPhase17AuthenticatedAdmission) error {
	if admission.Version != formalGLMPhase17AdmissionVersion ||
		!admission.AuthenticatedGatePassed || admission.ProtectedDataE2EVerified ||
		admission.OpeningsPerformed != 0 || admission.ProductionReady ||
		admission.worker == nil || admission.seal == ([32]byte{}) ||
		admission.AdmissionTokenSHA256 != hex.EncodeToString(admission.seal[:]) {
		return fmt.Errorf("formal-glm: invalid or untyped Phase-1.7 admission")
	}
	workerDigest, err := formalGLMPhase17WorkerContractDigest(*admission.worker)
	if err != nil || hex.EncodeToString(workerDigest[:]) != admission.WorkerContractSHA256 {
		return fmt.Errorf("formal-glm: Phase-1.7 worker differs from its authenticated admission")
	}
	values := []string{
		admission.PreimageSHA256, admission.CustodianSignatureSetSHA256,
		admission.SourceContributionAttestationSHA256,
		admission.WorkerContractSHA256, admission.AdmissionTokenSHA256,
	}
	decoded := make([][32]byte, len(values))
	for index, value := range values {
		if !formalGLMIsSHA256(value) {
			return fmt.Errorf("formal-glm: invalid Phase-1.7 admission digest")
		}
		raw, _ := hex.DecodeString(value)
		copy(decoded[index][:], raw)
	}
	expected := formalGLMPhase17AdmissionSeal(
		decoded[0], decoded[1], decoded[2], decoded[3])
	if expected != admission.seal || decoded[4] != admission.seal {
		return fmt.Errorf("formal-glm: Phase-1.7 admission token mismatch")
	}
	return nil
}

func formalGLMPhase17ReleaseUnavailable() error {
	return &formalGLMPhase17ReleaseBlocker{
		Code: formalGLMPhase17MaterializerBlockerCode,
		Missing: []string{
			"protected-data materializer verification of fixed padded capacity and at most one active aligned row per patient",
			"production DSI materialization and authenticated single-opening finalizer",
		},
		OpeningsPerformed: 0,
	}
}

func formalGLMPhase17AuthorizeOpening(
	admission formalGLMPhase17AuthenticatedAdmission) error {
	if err := validateFormalGLMPhase17AuthenticatedAdmission(admission); err != nil {
		return err
	}
	return formalGLMPhase17ReleaseUnavailable()
}
