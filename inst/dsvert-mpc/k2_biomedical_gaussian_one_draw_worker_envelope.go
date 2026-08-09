package main

// Production-shaped, but deliberately sealed, worker admission for the
// biomedical one-draw Gaussian mechanism.
//
// The generic one-draw policy remains useful as an in-process numerical/GC
// harness.  It is not an authority for this route.  A biomedical worker must
// first verify the K-of-K envelope below against a trust root supplied by the
// local server configuration.  Public keys are intentionally absent from the
// signed envelope, so an analyst cannot substitute both a token and its pins.
//
// This phase still performs no opening and does not claim ProductionReady.
// The durable one-common-vector finalizer lives at the next sealed boundary;
// an end-to-end materializer/R-DSI projection and an operational GC cost
// benchmark remain blockers.

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"strings"
)

const (
	jointDPBiomedicalGaussianWorkerEnvelopeVersion = "dsvert-biomedical-gaussian-one-draw-worker-envelope-v1"
	jointDPBiomedicalGaussianWorkerRoute           = "biomedical-gaussian-one-draw-kofk-local-trust-v1"
	jointDPBiomedicalGaussianWorkerEnvelopeDomain  = "dsVert/biomedical-gaussian-one-draw/worker-envelope/v1"
	jointDPBiomedicalGaussianWorkerTrustVersion    = "dsvert-biomedical-gaussian-one-draw-local-trust-v1"
	jointDPBiomedicalGaussianLocalSourceVersion    = "dsvert-biomedical-gaussian-one-draw-local-source-v1"
	jointDPBiomedicalGaussianLocalSourceDomain     = "dsVert/biomedical-gaussian-one-draw/local-source/v1"
	jointDPBiomedicalGaussianSourceShareDomain     = "dsVert/biomedical-gaussian-one-draw/source-share/v1"
	jointDPBiomedicalGaussianReceiptVersion        = "dsvert-biomedical-gaussian-one-draw-receipt-ref-v1"

	jointDPBiomedicalGaussianCommonLattice        = "pre_materialized_common_integer_lattice_shift_zero_v1"
	jointDPBiomedicalGaussianSensitivityAuthority = "machine_derived_exact_typed_domain_pending_materializer_e2e_v1"
	jointDPBiomedicalGaussianOpaqueSnapshotHandle = "server_hmac_memoized_logical_snapshot_handle_release_stable_v1"
	jointDPBiomedicalGaussianOpaqueSourceRoot     = "server_hmac_memoized_release_snapshot_workload_materialization_root_v1"
	jointDPBiomedicalGaussianOpaqueSourceContract = "public_data_independent_contract_digest_or_server_hmac_memoized_handle_v1"
	jointDPBiomedicalGaussianPublicIdentifierRule = "relay_visible_digests_are_explicit_public_projections_or_release_stable_server_hmac_handles_never_unkeyed_patient_derived_v1"
	jointDPBiomedicalGaussianReceiptDigestRule    = "release_stable_idempotent_reservation_digest_or_server_hmac_handle_not_patient_derived_v1"
	jointDPBiomedicalGaussianWorkerTranscriptKind = "release_stable_dp_transcript_not_transport_session_or_ack_v1"

	jointDPBiomedicalGaussianReceiptMaterialization = "materialization"
	jointDPBiomedicalGaussianReceiptSourceContract  = "source_contract"
	jointDPBiomedicalGaussianReceiptPrivacyLedger   = "privacy_ledger_append_reservation"
	jointDPBiomedicalGaussianReceiptFinalizer       = "release_finalizer_reservation"
)

var jointDPBiomedicalGaussianWorkerBlockers = []string{
	"server_authoritative_materializer_enforces_typed_contribution_layout",
	"durable_local_materialization_to_worker_handoff",
	"sampler_gc_cost_and_large_vector_benchmark_budget",
	"r_dsi_projection_of_verified_single_common_vector_opening",
	"semi_honest_two_compute_peer_gc_only",
	"unlimited_distinct_release_composition_has_no_finite_global_dp_bound",
}

var jointDPBiomedicalGaussianRequiredReceiptKinds = []string{
	jointDPBiomedicalGaussianReceiptFinalizer,
	jointDPBiomedicalGaussianReceiptMaterialization,
	jointDPBiomedicalGaussianReceiptPrivacyLedger,
	jointDPBiomedicalGaussianReceiptSourceContract,
}

type jointDPBiomedicalGaussianReceiptReference struct {
	Version    string `json:"version"`
	Kind       string `json:"kind"`
	SHA256     string `json:"sha256"`
	DigestKind string `json:"digest_kind"`
}

// The trust root is local configuration, not token material. PinnedPeers must
// be ordered by Name. The worker implementation digest allows a deployment to
// pin the reviewed worker artifact as well as its custodians.
type jointDPBiomedicalGaussianPinnedPeer struct {
	Name             string `json:"name"`
	Ed25519PublicKey []byte `json:"ed25519_public_key"`
}

type jointDPBiomedicalGaussianWorkerTrustRoot struct {
	Version                    string                                `json:"version"`
	AllowedRoute               string                                `json:"allowed_route"`
	PinsetSHA256               string                                `json:"pinset_sha256"`
	WorkerImplementationSHA256 string                                `json:"worker_implementation_sha256"`
	PinnedPeers                []jointDPBiomedicalGaussianPinnedPeer `json:"pinned_peers"`
}

// The envelope has no public keys and no protected values. Snapshot/source/
// materialization handles are server-HMAC-derived and durably memoized for the
// logical release. They must never be unkeyed hashes of patient identifiers,
// row order, alignment membership or protected values. Reconstructing the same
// release must reproduce the same handles; rotation requires a new composed
// release instance.
type jointDPBiomedicalGaussianWorkerEnvelopePreimage struct {
	Version                  string `json:"version"`
	Route                    string `json:"route"`
	PublicIdentifierContract string `json:"public_identifier_contract"`

	CapsuleID                   string `json:"capsule_id"`
	ManifestSHA256              string `json:"manifest_sha256"`
	SchemaManifestSHA256        string `json:"schema_manifest_sha256"`
	WorkloadSHA256              string `json:"workload_sha256"`
	LogicalSnapshotHandleSHA256 string `json:"logical_snapshot_handle_sha256"`
	LogicalSnapshotHandleKind   string `json:"logical_snapshot_handle_kind"`
	PrivacyEpochSHA256          string `json:"privacy_epoch_sha256"`
	ReleaseInstanceID           string `json:"release_instance_id"`
	ReleaseContractSHA256       string `json:"release_contract_sha256"`
	WorkerTranscriptSHA256      string `json:"worker_transcript_sha256"`
	WorkerTranscriptKind        string `json:"worker_transcript_kind"`

	Mechanism  string `json:"mechanism"`
	Allocation string `json:"allocation"`
	Adjacency  string `json:"adjacency"`

	Epsilon            string `json:"epsilon"`
	EpsilonNumerator   string `json:"epsilon_numerator"`
	EpsilonDenominator string `json:"epsilon_denominator"`
	Delta              string `json:"delta"`
	DeltaNumerator     string `json:"delta_numerator"`
	DeltaDenominator   string `json:"delta_denominator"`

	PinsetSHA256           string   `json:"pinset_sha256"`
	CustodianPeers         []string `json:"custodian_peers"`
	CustodianCount         int      `json:"custodian_count"`
	GarblerPeerName        string   `json:"garbler_peer_name"`
	GarblerPeerID          string   `json:"garbler_peer_id"`
	EvaluatorPeerName      string   `json:"evaluator_peer_name"`
	EvaluatorPeerID        string   `json:"evaluator_peer_id"`
	DesignatedComputeCount int      `json:"designated_compute_count"`

	CoordinateOrderSHA256     string   `json:"coordinate_order_sha256"`
	LatticeTransformSHA256    string   `json:"lattice_transform_sha256"`
	CommonLattice             string   `json:"common_lattice"`
	OutputLatticeBits         int      `json:"output_lattice_bits"`
	TotalCoordinateCount      int      `json:"total_coordinate_count"`
	ChunkStart                int      `json:"chunk_start"`
	CoordinateCount           int      `json:"coordinate_count"`
	CommonLatticeUpperBounds  []string `json:"common_lattice_upper_bounds"`
	L2SensitivitySteps        string   `json:"l2_sensitivity_steps"`
	SensitivityAuthority      string   `json:"sensitivity_authority"`
	SensitivityCertificateSHA string   `json:"sensitivity_certificate_sha256"`
	WorkerSensitivitySHA256   string   `json:"worker_sensitivity_sha256"`

	PlanSHA256                 string `json:"plan_sha256"`
	CircuitShapeSHA256         string `json:"circuit_shape_sha256"`
	WorkerPublicPolicySHA256   string `json:"worker_public_policy_sha256"`
	WorkerContractSHA256       string `json:"worker_contract_sha256"`
	WorkerImplementationSHA256 string `json:"worker_implementation_sha256"`
	ProductiveStreamSHA256     string `json:"productive_stream_sha256"`

	MaterializationRootSHA256  string                                      `json:"materialization_root_sha256"`
	MaterializationRootKind    string                                      `json:"materialization_root_kind"`
	SourceContractHandleSHA256 string                                      `json:"source_contract_handle_sha256"`
	SourceContractHandleKind   string                                      `json:"source_contract_handle_kind"`
	RunNonceSHA256             string                                      `json:"run_nonce_sha256"`
	ReceiptReferences          []jointDPBiomedicalGaussianReceiptReference `json:"receipt_references"`

	GenericMachineProvenAuthorizes bool     `json:"generic_machine_proven_authorizes"`
	SourceShareMayBeUnbound        bool     `json:"source_share_may_be_unbound"`
	OperationLimit                 bool     `json:"operation_limit"`
	RequestLimit                   bool     `json:"request_limit"`
	HistoryCanDenyOperation        bool     `json:"history_can_deny_operation"`
	OpeningsAuthorized             int      `json:"openings_authorized"`
	ProductionReady                bool     `json:"production_ready"`
	Blockers                       []string `json:"blockers"`
}

type jointDPBiomedicalGaussianSignedWorkerEnvelope struct {
	Preimage jointDPBiomedicalGaussianWorkerEnvelopePreimage `json:"preimage"`
	// WorkerPolicy is local handoff state. Only its K-signed digest belongs in
	// the relay-visible envelope.
	WorkerPolicy jointDPGaussianOneDrawWorkerPolicy   `json:"-"`
	Signatures   []jointDPBiomedicalGaussianSignature `json:"signatures"`
}

type jointDPBiomedicalGaussianWorkerEnvelopeRequest struct {
	LogicalSnapshotHandleSHA256 string
	SourceContractHandleSHA256  string
	PrivacyEpochSHA256          string
	MaterializationRootSHA256   string
	RunNonceSHA256              string
	WorkerImplementationSHA256  string
	ReceiptReferences           []jointDPBiomedicalGaussianReceiptReference
}

// This binding is written by the local authoritative materializer into the
// same private worker handoff as SourceShare. It is deliberately not supplied
// by the relay. Its digest prevents accidental partial mutation; authority
// comes from the local handoff boundary, not from this unkeyed digest.
type jointDPBiomedicalGaussianLocalSourceBinding struct {
	Version                     string                                    `json:"version"`
	EnvelopePreimageSHA256      string                                    `json:"envelope_preimage_sha256"`
	LocalPeerName               string                                    `json:"local_peer_name"`
	Role                        string                                    `json:"role"`
	LogicalSnapshotHandleSHA256 string                                    `json:"logical_snapshot_handle_sha256"`
	LocalSnapshotContractSHA256 string                                    `json:"local_snapshot_contract_sha256"`
	PrivacyEpochSHA256          string                                    `json:"privacy_epoch_sha256"`
	ReleaseInstanceID           string                                    `json:"release_instance_id"`
	MaterializationRootSHA256   string                                    `json:"materialization_root_sha256"`
	SourceContractHandleSHA256  string                                    `json:"source_contract_handle_sha256"`
	LocalSourceContractSHA256   string                                    `json:"local_source_contract_sha256"`
	RunNonceSHA256              string                                    `json:"run_nonce_sha256"`
	SourceShareSHA256           string                                    `json:"source_share_sha256"`
	MaterializationReceipt      jointDPBiomedicalGaussianReceiptReference `json:"materialization_receipt"`
	BindingSHA256               string                                    `json:"binding_sha256"`
}

func jointDPBiomedicalGaussianCanonicalDecimal(value, what string) (*big.Rat, error) {
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "eE+-/") {
		return nil, fmt.Errorf("joint-dp-biomedical-gaussian: non-canonical %s", what)
	}
	parts := strings.Split(value, ".")
	if len(parts) > 2 || parts[0] == "" ||
		(len(parts[0]) > 1 && parts[0][0] == '0') {
		return nil, fmt.Errorf("joint-dp-biomedical-gaussian: non-canonical %s", what)
	}
	for _, character := range parts[0] {
		if character < '0' || character > '9' {
			return nil, fmt.Errorf("joint-dp-biomedical-gaussian: non-canonical %s", what)
		}
	}
	if len(parts) == 2 {
		if parts[1] == "" || parts[1][len(parts[1])-1] == '0' {
			return nil, fmt.Errorf("joint-dp-biomedical-gaussian: non-canonical %s", what)
		}
		for _, character := range parts[1] {
			if character < '0' || character > '9' {
				return nil, fmt.Errorf("joint-dp-biomedical-gaussian: non-canonical %s", what)
			}
		}
	}
	parsed, err := jointDPParseDecimalRat(value, what, false)
	if err != nil || parsed.Sign() <= 0 {
		return nil, fmt.Errorf("joint-dp-biomedical-gaussian: invalid %s", what)
	}
	return parsed, nil
}

func jointDPBiomedicalGaussianValidateCanonicalRatFields(value *big.Rat,
	numeratorText, denominatorText, what string,
) error {
	numerator, numeratorErr := jointDPBiomedicalGaussianParseCanonicalInt(
		numeratorText, what+" numerator", false)
	denominator, denominatorErr := jointDPBiomedicalGaussianParseCanonicalInt(
		denominatorText, what+" denominator", true)
	if numeratorErr != nil || denominatorErr != nil || numerator.Sign() <= 0 ||
		new(big.Int).GCD(nil, nil, numerator, denominator).Cmp(big.NewInt(1)) != 0 ||
		new(big.Rat).SetFrac(numerator, denominator).Cmp(value) != 0 {
		return fmt.Errorf("joint-dp-biomedical-gaussian: non-canonical %s rational", what)
	}
	return nil
}

func jointDPBiomedicalGaussianValidateReceiptReferences(
	receipts []jointDPBiomedicalGaussianReceiptReference,
) error {
	if len(receipts) != len(jointDPBiomedicalGaussianRequiredReceiptKinds) {
		return fmt.Errorf("joint-dp-biomedical-gaussian: incomplete typed receipt references")
	}
	for index, receipt := range receipts {
		if receipt.Version != jointDPBiomedicalGaussianReceiptVersion ||
			receipt.Kind != jointDPBiomedicalGaussianRequiredReceiptKinds[index] ||
			receipt.DigestKind != jointDPBiomedicalGaussianReceiptDigestRule ||
			!jointDPBiomedicalGaussianIsSHA256(receipt.SHA256) {
			return fmt.Errorf("joint-dp-biomedical-gaussian: invalid typed receipt reference")
		}
	}
	return nil
}

func jointDPBiomedicalGaussianReceiptByKind(
	receipts []jointDPBiomedicalGaussianReceiptReference, kind string,
) (jointDPBiomedicalGaussianReceiptReference, bool) {
	for _, receipt := range receipts {
		if receipt.Kind == kind {
			return receipt, true
		}
	}
	return jointDPBiomedicalGaussianReceiptReference{}, false
}

func jointDPBiomedicalGaussianTrustPins(
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
) (map[string]ed25519.PublicKey, []string, error) {
	if trust.Version != jointDPBiomedicalGaussianWorkerTrustVersion ||
		trust.AllowedRoute != jointDPBiomedicalGaussianWorkerRoute ||
		!jointDPBiomedicalGaussianIsSHA256(trust.PinsetSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(trust.WorkerImplementationSHA256) ||
		len(trust.PinnedPeers) < 2 {
		return nil, nil, fmt.Errorf("joint-dp-biomedical-gaussian: invalid local worker trust root")
	}
	pins := make(map[string]ed25519.PublicKey, len(trust.PinnedPeers))
	peers := make([]string, len(trust.PinnedPeers))
	prior := ""
	for index, peer := range trust.PinnedPeers {
		if !jointDPBiomedicalGaussianValidPeerName(peer.Name) ||
			(index > 0 && peer.Name <= prior) ||
			len(peer.Ed25519PublicKey) != ed25519.PublicKeySize {
			return nil, nil, fmt.Errorf("joint-dp-biomedical-gaussian: invalid local pinned peer")
		}
		peers[index] = peer.Name
		pins[peer.Name] = append(ed25519.PublicKey(nil), peer.Ed25519PublicKey...)
		prior = peer.Name
	}
	digest, err := formalGLMPhase16PinsetSHA256(pins)
	if err != nil || digest != trust.PinsetSHA256 {
		return nil, nil, fmt.Errorf("joint-dp-biomedical-gaussian: local pinset digest mismatch")
	}
	return pins, peers, nil
}

// PublicWorkerPolicySHA256 is an explicit allow-list projection. In
// particular, it excludes ReleaseBindingCanonicalJSON, its two unkeyed
// digests, and the full circuit digest because those values commit to the
// server-local snapshot/source binding. The complete policy remains local and
// is independently validated before execution.
func jointDPBiomedicalGaussianPublicWorkerPolicySHA256(
	policy jointDPGaussianOneDrawWorkerPolicy,
	planSHA256, circuitShapeSHA256 string,
) (string, error) {
	return jointDPBiomedicalGaussianHash(struct {
		Version                        string   `json:"version"`
		Mechanism                      string   `json:"mechanism"`
		Allocation                     string   `json:"allocation"`
		RingBits                       int      `json:"ring_bits"`
		FracBits                       int      `json:"frac_bits"`
		TotalCoordinateCount           int      `json:"total_coordinate_count"`
		ChunkStart                     int      `json:"chunk_start"`
		CoordinateCount                int      `json:"coordinate_count"`
		OutputLatticeBits              int      `json:"output_lattice_bits"`
		Epsilon                        string   `json:"epsilon"`
		AllocatedDelta                 string   `json:"allocated_delta"`
		L2SensitivitySteps             string   `json:"l2_sensitivity_steps"`
		L2SensitivityCertificateKind   string   `json:"l2_sensitivity_certificate_kind"`
		L2SensitivityCertificateSHA256 string   `json:"l2_sensitivity_certificate_sha256"`
		ReleaseBindingDomain           string   `json:"release_binding_domain"`
		ScaleShifts                    []int    `json:"scale_shifts"`
		RawUpperBounds                 []string `json:"raw_upper_bounds"`
		TranscriptHash                 string   `json:"transcript_hash"`
		PinsetSHA256                   string   `json:"pinset_sha256"`
		CustodianCount                 int      `json:"custodian_count"`
		DesignatedComputePeerCount     int      `json:"designated_compute_peer_count"`
		GarblerPeerID                  string   `json:"garbler_peer_id"`
		EvaluatorPeerID                string   `json:"evaluator_peer_id"`
		GarblerCommitmentContext       string   `json:"garbler_commitment_context"`
		EvaluatorCommitmentContext     string   `json:"evaluator_commitment_context"`
		GarblerSeedCommitment          string   `json:"garbler_seed_commitment"`
		EvaluatorSeedCommitment        string   `json:"evaluator_seed_commitment"`
		PlanSHA256                     string   `json:"plan_sha256"`
		CircuitShapeSHA256             string   `json:"circuit_shape_sha256"`
	}{
		policy.Version, policy.Mechanism, policy.Allocation,
		policy.RingBits, policy.FracBits, policy.TotalCoordinateCount,
		policy.ChunkStart, policy.CoordinateCount, policy.OutputLatticeBits,
		policy.Epsilon, policy.AllocatedDelta, policy.L2SensitivitySteps,
		policy.L2SensitivityCertificateKind,
		policy.L2SensitivityCertificateSHA256, policy.ReleaseBindingDomain,
		append([]int(nil), policy.ScaleShifts...),
		append([]string(nil), policy.RawUpperBounds...),
		policy.TranscriptHash, policy.PinsetSHA256, policy.CustodianCount,
		policy.DesignatedComputePeerCount, policy.GarblerPeerID,
		policy.EvaluatorPeerID, policy.GarblerCommitmentContext,
		policy.EvaluatorCommitmentContext, policy.GarblerSeedCommitment,
		policy.EvaluatorSeedCommitment, planSHA256, circuitShapeSHA256,
	})
}

func jointDPBiomedicalGaussianWorkerContractSHA256(publicPolicySHA256,
	planSHA256, circuitShapeSHA256, implementationSHA256 string,
) (string, error) {
	digest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianWorkerEnvelopeDomain+"/worker-contract", struct {
			Route                      string `json:"route"`
			CircuitOperation           string `json:"circuit_operation"`
			WorkerPublicPolicySHA256   string `json:"worker_public_policy_sha256"`
			PlanSHA256                 string `json:"plan_sha256"`
			CircuitShapeSHA256         string `json:"circuit_shape_sha256"`
			WorkerImplementationSHA256 string `json:"worker_implementation_sha256"`
		}{jointDPBiomedicalGaussianWorkerRoute,
			string(jointDPGaussianOneDrawOperation), publicPolicySHA256,
			planSHA256, circuitShapeSHA256, implementationSHA256})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

// ProductiveStreamSHA256 excludes chunk geometry and the per-session run
// nonce, so rechunking/retry cannot reroll noise. It includes the release,
// epoch and release-stable opaque source/materialization handles. A durable
// registry must reproduce those handles for the same release; a legitimate
// root rotation is a new, composition-accounted release instance and therefore
// cannot reuse the old productive stream.
func jointDPBiomedicalGaussianProductiveStreamSHA256(
	preimage jointDPBiomedicalGaussianWorkerEnvelopePreimage,
) (string, error) {
	digest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianWorkerEnvelopeDomain+"/productive-stream", struct {
			Version, Route, PublicIdentifierContract                           string
			CapsuleID, ManifestSHA256, SchemaManifestSHA256, WorkloadSHA256    string
			LogicalSnapshotHandleSHA256, LogicalSnapshotHandleKind             string
			PrivacyEpochSHA256, ReleaseInstanceID, ReleaseContractSHA256       string
			WorkerTranscriptSHA256, WorkerTranscriptKind                       string
			Mechanism, Allocation, Adjacency                                   string
			Epsilon, EpsilonNumerator, EpsilonDenominator                      string
			Delta, DeltaNumerator, DeltaDenominator                            string
			PinsetSHA256                                                       string
			CustodianPeers                                                     []string
			CustodianCount                                                     int
			GarblerPeerName, GarblerPeerID, EvaluatorPeerName, EvaluatorPeerID string
			CoordinateOrderSHA256, LatticeTransformSHA256, CommonLattice       string
			OutputLatticeBits, TotalCoordinateCount                            int
			CommonLatticeUpperBounds                                           []string
			L2SensitivitySteps, SensitivityAuthority                           string
			SensitivityCertificateSHA, WorkerSensitivitySHA256, PlanSHA256     string
			WorkerImplementationSHA256                                         string
			MaterializationRootSHA256, MaterializationRootKind                 string
			SourceContractHandleSHA256, SourceContractHandleKind               string
			ReceiptReferences                                                  []jointDPBiomedicalGaussianReceiptReference
		}{
			preimage.Version, preimage.Route, preimage.PublicIdentifierContract,
			preimage.CapsuleID, preimage.ManifestSHA256,
			preimage.SchemaManifestSHA256, preimage.WorkloadSHA256,
			preimage.LogicalSnapshotHandleSHA256,
			preimage.LogicalSnapshotHandleKind,
			preimage.PrivacyEpochSHA256, preimage.ReleaseInstanceID,
			preimage.ReleaseContractSHA256, preimage.WorkerTranscriptSHA256,
			preimage.WorkerTranscriptKind,
			preimage.Mechanism, preimage.Allocation, preimage.Adjacency,
			preimage.Epsilon, preimage.EpsilonNumerator,
			preimage.EpsilonDenominator, preimage.Delta,
			preimage.DeltaNumerator, preimage.DeltaDenominator,
			preimage.PinsetSHA256, preimage.CustodianPeers,
			preimage.CustodianCount, preimage.GarblerPeerName,
			preimage.GarblerPeerID, preimage.EvaluatorPeerName,
			preimage.EvaluatorPeerID, preimage.CoordinateOrderSHA256,
			preimage.LatticeTransformSHA256, preimage.CommonLattice,
			preimage.OutputLatticeBits, preimage.TotalCoordinateCount,
			preimage.CommonLatticeUpperBounds, preimage.L2SensitivitySteps,
			preimage.SensitivityAuthority,
			preimage.SensitivityCertificateSHA,
			preimage.WorkerSensitivitySHA256, preimage.PlanSHA256,
			preimage.WorkerImplementationSHA256,
			preimage.MaterializationRootSHA256,
			preimage.MaterializationRootKind,
			preimage.SourceContractHandleSHA256,
			preimage.SourceContractHandleKind, preimage.ReceiptReferences,
		})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func jointDPBiomedicalGaussianProductivePrivateInputs(root [32]byte,
	spec jointDPGaussianOneDrawSpec, role,
	productiveStreamSHA256 string,
) ([]*big.Int, []bool, error) {
	stream, err := jointDPGaussianOneDrawDecodeHex(
		productiveStreamSHA256, "productive stream")
	if err != nil {
		return nil, nil, err
	}
	return jointDPGaussianOneDrawPrivateInputsBound(root, spec, role, &stream)
}

func jointDPBiomedicalGaussianBuildWorkerEnvelope(
	admission jointDPBiomedicalGaussianAuthenticatedAdmission,
	chunk jointDPBiomedicalGaussianAdmittedChunk,
	request jointDPBiomedicalGaussianWorkerEnvelopeRequest,
) (jointDPBiomedicalGaussianSignedWorkerEnvelope, error) {
	var zero jointDPBiomedicalGaussianSignedWorkerEnvelope
	if err := validateJointDPBiomedicalGaussianChunk(admission, chunk); err != nil {
		return zero, err
	}
	if !jointDPBiomedicalGaussianIsSHA256(request.LogicalSnapshotHandleSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(request.SourceContractHandleSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(request.PrivacyEpochSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(request.MaterializationRootSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(request.RunNonceSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(request.WorkerImplementationSHA256) ||
		jointDPBiomedicalGaussianValidateReceiptReferences(request.ReceiptReferences) != nil {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: invalid productive worker request")
	}
	candidate := admission.candidate
	manifest := candidate.manifest
	if chunk.worker == nil || len(manifest.ScaleShifts) != manifest.TotalCoordinateCount {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: missing sealed worker state")
	}
	upper := make([]string, manifest.TotalCoordinateCount)
	for index := range upper {
		bound, err := jointDPBiomedicalGaussianParseCanonicalInt(
			manifest.RawUpperBounds[index], "common-lattice upper bound", false)
		if err != nil || manifest.ScaleShifts[index] != 0 ||
			candidate.certificate.ShiftedUpperBounds[index] != bound.String() {
			return zero, fmt.Errorf("joint-dp-biomedical-gaussian: productive route requires a unique pre-materialized common lattice")
		}
		upper[index] = bound.String()
	}
	epsilon, err := jointDPBiomedicalGaussianCanonicalDecimal(
		candidate.release.Epsilon, "epsilon")
	if err != nil {
		return zero, err
	}
	delta, err := jointDPBiomedicalGaussianCanonicalDecimal(
		candidate.release.AllocatedDelta, "delta")
	if err != nil || delta.Cmp(big.NewRat(1, 1)) >= 0 {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: invalid canonical delta")
	}
	planSHA256, err := jointDPBiomedicalGaussianHash(chunk.worker.Plan)
	if err != nil {
		return zero, err
	}
	spec, err := jointDPGaussianOneDrawPolicySpec(chunk.worker.WorkerPolicy)
	if err != nil {
		return zero, err
	}
	fullCircuitDigest := spec.digest()
	if chunk.worker.WorkerPolicy.CircuitDigest !=
		hex.EncodeToString(fullCircuitDigest[:]) ||
		chunk.CircuitDigest != chunk.worker.WorkerPolicy.CircuitDigest ||
		chunk.Purpose != spec.purpose() {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: invalid local sealed worker circuit")
	}
	circuitShape := spec.circuitShapeDigest()
	circuitShapeSHA256 := hex.EncodeToString(circuitShape[:])
	workerPublicPolicySHA256, err :=
		jointDPBiomedicalGaussianPublicWorkerPolicySHA256(
			chunk.worker.WorkerPolicy, planSHA256, circuitShapeSHA256)
	if err != nil {
		return zero, err
	}
	workerContractSHA256, err := jointDPBiomedicalGaussianWorkerContractSHA256(
		workerPublicPolicySHA256, planSHA256, circuitShapeSHA256,
		request.WorkerImplementationSHA256)
	if err != nil {
		return zero, err
	}
	preimage := jointDPBiomedicalGaussianWorkerEnvelopePreimage{
		Version:                     jointDPBiomedicalGaussianWorkerEnvelopeVersion,
		Route:                       jointDPBiomedicalGaussianWorkerRoute,
		PublicIdentifierContract:    jointDPBiomedicalGaussianPublicIdentifierRule,
		CapsuleID:                   candidate.preimage.CapsuleID,
		ManifestSHA256:              candidate.preimage.ManifestSHA256,
		SchemaManifestSHA256:        candidate.preimage.SchemaManifestSHA256,
		WorkloadSHA256:              candidate.preimage.WorkloadSHA256,
		LogicalSnapshotHandleSHA256: request.LogicalSnapshotHandleSHA256,
		LogicalSnapshotHandleKind:   jointDPBiomedicalGaussianOpaqueSnapshotHandle,
		PrivacyEpochSHA256:          request.PrivacyEpochSHA256,
		ReleaseInstanceID:           candidate.preimage.ReleaseInstanceID,
		ReleaseContractSHA256:       candidate.preimage.ReleaseContractSHA256,
		WorkerTranscriptSHA256:      candidate.preimage.WorkerTranscriptSHA256,
		WorkerTranscriptKind:        jointDPBiomedicalGaussianWorkerTranscriptKind,
		Mechanism:                   candidate.preimage.Mechanism,
		Allocation:                  candidate.preimage.Allocation,
		Adjacency:                   manifest.Adjacency,
		Epsilon:                     candidate.release.Epsilon,
		EpsilonNumerator:            epsilon.Num().String(),
		EpsilonDenominator:          epsilon.Denom().String(),
		Delta:                       candidate.release.AllocatedDelta,
		DeltaNumerator:              delta.Num().String(),
		DeltaDenominator:            delta.Denom().String(),
		PinsetSHA256:                candidate.preimage.PinsetSHA256,
		CustodianPeers:              append([]string(nil), candidate.preimage.CustodianPeers...),
		CustodianCount:              candidate.preimage.CustodianCount,
		GarblerPeerName:             candidate.preimage.GarblerPeerName,
		GarblerPeerID:               candidate.preimage.GarblerPeerID,
		EvaluatorPeerName:           candidate.preimage.EvaluatorPeerName,
		EvaluatorPeerID:             candidate.preimage.EvaluatorPeerID,
		DesignatedComputeCount:      2,
		CoordinateOrderSHA256:       candidate.preimage.CoordinateOrderSHA256,
		LatticeTransformSHA256:      candidate.preimage.LatticeTransformSHA256,
		CommonLattice:               jointDPBiomedicalGaussianCommonLattice,
		OutputLatticeBits:           candidate.preimage.OutputLatticeBits,
		TotalCoordinateCount:        candidate.preimage.TotalCoordinateCount,
		ChunkStart:                  chunk.ChunkStart,
		CoordinateCount:             chunk.CoordinateCount,
		CommonLatticeUpperBounds:    upper,
		L2SensitivitySteps:          candidate.preimage.L2SensitivitySteps,
		SensitivityAuthority:        jointDPBiomedicalGaussianSensitivityAuthority,
		SensitivityCertificateSHA:   candidate.preimage.SensitivityCertificateSHA256,
		WorkerSensitivitySHA256:     candidate.preimage.WorkerSensitivitySHA256,
		PlanSHA256:                  planSHA256,
		CircuitShapeSHA256:          circuitShapeSHA256,
		WorkerPublicPolicySHA256:    workerPublicPolicySHA256,
		WorkerContractSHA256:        workerContractSHA256,
		WorkerImplementationSHA256:  request.WorkerImplementationSHA256,
		MaterializationRootSHA256:   request.MaterializationRootSHA256,
		MaterializationRootKind:     jointDPBiomedicalGaussianOpaqueSourceRoot,
		SourceContractHandleSHA256:  request.SourceContractHandleSHA256,
		SourceContractHandleKind:    jointDPBiomedicalGaussianOpaqueSourceContract,
		RunNonceSHA256:              request.RunNonceSHA256,
		ReceiptReferences: append([]jointDPBiomedicalGaussianReceiptReference(nil),
			request.ReceiptReferences...),
		GenericMachineProvenAuthorizes: false,
		SourceShareMayBeUnbound:        false,
		OperationLimit:                 false,
		RequestLimit:                   false,
		HistoryCanDenyOperation:        false,
		OpeningsAuthorized:             0,
		ProductionReady:                false,
		Blockers:                       append([]string(nil), jointDPBiomedicalGaussianWorkerBlockers...),
	}
	preimage.ProductiveStreamSHA256, err =
		jointDPBiomedicalGaussianProductiveStreamSHA256(preimage)
	if err != nil {
		return zero, err
	}
	return jointDPBiomedicalGaussianSignedWorkerEnvelope{
		Preimage: preimage, WorkerPolicy: chunk.worker.WorkerPolicy,
	}, nil
}

func jointDPBiomedicalGaussianWorkerEnvelopeMessage(
	preimage jointDPBiomedicalGaussianWorkerEnvelopePreimage,
) ([]byte, error) {
	return jointDPBiomedicalGaussianDomainMessage(
		jointDPBiomedicalGaussianWorkerEnvelopeDomain, preimage)
}

func jointDPBiomedicalGaussianValidateWorkerEnvelope(
	signed jointDPBiomedicalGaussianSignedWorkerEnvelope,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
) (jointDPGaussianOneDrawSpec, error) {
	var zero jointDPGaussianOneDrawSpec
	pins, trustedPeers, err := jointDPBiomedicalGaussianTrustPins(trust)
	if err != nil {
		return zero, err
	}
	preimage := signed.Preimage
	hashes := []string{
		preimage.CapsuleID, preimage.ManifestSHA256,
		preimage.SchemaManifestSHA256, preimage.WorkloadSHA256,
		preimage.LogicalSnapshotHandleSHA256, preimage.PrivacyEpochSHA256,
		preimage.ReleaseInstanceID, preimage.ReleaseContractSHA256,
		preimage.WorkerTranscriptSHA256, preimage.PinsetSHA256,
		preimage.CoordinateOrderSHA256, preimage.LatticeTransformSHA256,
		preimage.SensitivityCertificateSHA, preimage.WorkerSensitivitySHA256,
		preimage.PlanSHA256,
		preimage.CircuitShapeSHA256, preimage.WorkerPublicPolicySHA256,
		preimage.WorkerContractSHA256, preimage.WorkerImplementationSHA256,
		preimage.ProductiveStreamSHA256,
		preimage.MaterializationRootSHA256,
		preimage.SourceContractHandleSHA256,
		preimage.RunNonceSHA256,
	}
	for _, value := range hashes {
		if !jointDPBiomedicalGaussianIsSHA256(value) {
			return zero, fmt.Errorf("joint-dp-biomedical-gaussian: invalid worker-envelope digest")
		}
	}
	if preimage.Version != jointDPBiomedicalGaussianWorkerEnvelopeVersion ||
		preimage.Route != jointDPBiomedicalGaussianWorkerRoute ||
		preimage.PublicIdentifierContract !=
			jointDPBiomedicalGaussianPublicIdentifierRule ||
		preimage.Mechanism != jointDPGaussianOneDrawMechanism ||
		preimage.Allocation != jointDPGaussianOneDrawAllocation ||
		(preimage.Adjacency != "add_remove_patient" &&
			preimage.Adjacency != "replace_one_fixed_cohort") ||
		preimage.PinsetSHA256 != trust.PinsetSHA256 ||
		preimage.WorkerImplementationSHA256 != trust.WorkerImplementationSHA256 ||
		preimage.CustodianCount != len(trustedPeers) ||
		!reflect.DeepEqual(preimage.CustodianPeers, trustedPeers) ||
		preimage.DesignatedComputeCount != 2 ||
		preimage.CommonLattice != jointDPBiomedicalGaussianCommonLattice ||
		preimage.LogicalSnapshotHandleKind !=
			jointDPBiomedicalGaussianOpaqueSnapshotHandle ||
		preimage.MaterializationRootKind !=
			jointDPBiomedicalGaussianOpaqueSourceRoot ||
		preimage.WorkerTranscriptKind !=
			jointDPBiomedicalGaussianWorkerTranscriptKind ||
		preimage.SourceContractHandleKind !=
			jointDPBiomedicalGaussianOpaqueSourceContract ||
		preimage.OutputLatticeBits < 1 || preimage.OutputLatticeBits > 62 ||
		preimage.TotalCoordinateCount < 1 || preimage.ChunkStart < 0 ||
		preimage.CoordinateCount < 1 ||
		preimage.ChunkStart > preimage.TotalCoordinateCount-preimage.CoordinateCount ||
		len(preimage.CommonLatticeUpperBounds) != preimage.TotalCoordinateCount ||
		preimage.SensitivityAuthority != jointDPBiomedicalGaussianSensitivityAuthority ||
		preimage.GenericMachineProvenAuthorizes || preimage.SourceShareMayBeUnbound ||
		preimage.OperationLimit || preimage.RequestLimit ||
		preimage.HistoryCanDenyOperation || preimage.OpeningsAuthorized != 0 ||
		preimage.ProductionReady ||
		!reflect.DeepEqual(preimage.Blockers, jointDPBiomedicalGaussianWorkerBlockers) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: invalid sealed productive worker envelope")
	}
	if err := jointDPBiomedicalGaussianValidateReceiptReferences(
		preimage.ReceiptReferences); err != nil {
		return zero, err
	}
	productiveStreamSHA256, err :=
		jointDPBiomedicalGaussianProductiveStreamSHA256(preimage)
	if err != nil || productiveStreamSHA256 != preimage.ProductiveStreamSHA256 {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: productive stream binding mismatch")
	}
	epsilon, err := jointDPBiomedicalGaussianCanonicalDecimal(preimage.Epsilon, "epsilon")
	if err != nil || jointDPBiomedicalGaussianValidateCanonicalRatFields(
		epsilon, preimage.EpsilonNumerator, preimage.EpsilonDenominator,
		"epsilon") != nil {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: invalid canonical epsilon")
	}
	delta, err := jointDPBiomedicalGaussianCanonicalDecimal(preimage.Delta, "delta")
	if err != nil || delta.Cmp(big.NewRat(1, 1)) >= 0 ||
		jointDPBiomedicalGaussianValidateCanonicalRatFields(
			delta, preimage.DeltaNumerator, preimage.DeltaDenominator,
			"delta") != nil {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: invalid canonical delta")
	}
	for _, boundText := range preimage.CommonLatticeUpperBounds {
		if _, err := jointDPBiomedicalGaussianParseCanonicalInt(
			boundText, "common-lattice upper bound", false); err != nil {
			return zero, err
		}
	}
	message, err := jointDPBiomedicalGaussianWorkerEnvelopeMessage(preimage)
	if err != nil {
		return zero, err
	}
	if err := jointDPBiomedicalGaussianVerifySignatures(message,
		signed.Signatures, trustedPeers, pins, "productive worker envelope"); err != nil {
		return zero, err
	}
	planSHA256, err := jointDPBiomedicalGaussianHash(signed.WorkerPolicy.Plan)
	if err != nil || planSHA256 != preimage.PlanSHA256 {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: privacy plan digest mismatch")
	}
	policy := signed.WorkerPolicy
	if policy.Mechanism != preimage.Mechanism ||
		policy.Allocation != preimage.Allocation ||
		policy.Epsilon != preimage.Epsilon ||
		policy.AllocatedDelta != preimage.Delta ||
		policy.L2SensitivitySteps != preimage.L2SensitivitySteps ||
		policy.L2SensitivityCertificateSHA256 != preimage.WorkerSensitivitySHA256 ||
		policy.PinsetSHA256 != preimage.PinsetSHA256 ||
		policy.CustodianCount != preimage.CustodianCount ||
		policy.TotalCoordinateCount != preimage.TotalCoordinateCount ||
		policy.ChunkStart != preimage.ChunkStart ||
		policy.CoordinateCount != preimage.CoordinateCount ||
		policy.OutputLatticeBits != preimage.OutputLatticeBits ||
		policy.GarblerPeerID != preimage.GarblerPeerID ||
		policy.EvaluatorPeerID != preimage.EvaluatorPeerID ||
		policy.TranscriptHash != preimage.WorkerTranscriptSHA256 ||
		len(policy.ScaleShifts) != preimage.CoordinateCount ||
		len(policy.RawUpperBounds) != preimage.CoordinateCount {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: worker policy escaped its envelope")
	}
	for local := 0; local < preimage.CoordinateCount; local++ {
		absolute := preimage.ChunkStart + local
		if policy.ScaleShifts[local] != 0 ||
			policy.RawUpperBounds[local] != preimage.CommonLatticeUpperBounds[absolute] {
			return zero, fmt.Errorf("joint-dp-biomedical-gaussian: alternate raw/shift factorization rejected")
		}
	}
	binding, err := jointDPGaussianOneDrawReleaseBindingViewFromPolicy(policy)
	if err != nil {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: invalid embedded release binding")
	}
	if binding.CapsuleID != preimage.CapsuleID ||
		binding.ManifestSHA256 != preimage.ManifestSHA256 ||
		binding.SchemaManifestSHA256 != preimage.SchemaManifestSHA256 ||
		binding.WorkloadSHA256 != preimage.WorkloadSHA256 ||
		binding.ReleaseInstanceID != preimage.ReleaseInstanceID ||
		binding.FinalReceiptPairSHA256 != preimage.ReleaseContractSHA256 ||
		binding.Adjacency != preimage.Adjacency ||
		binding.CoordinateOrderSHA256 != preimage.CoordinateOrderSHA256 ||
		binding.QuantizationSHA256 != preimage.LatticeTransformSHA256 ||
		binding.GarblerPeerName != preimage.GarblerPeerName ||
		binding.GarblerPeerID != preimage.GarblerPeerID ||
		binding.EvaluatorPeerName != preimage.EvaluatorPeerName ||
		binding.EvaluatorPeerID != preimage.EvaluatorPeerID ||
		!binding.SensitivityStatusAllowed ||
		!reflect.DeepEqual(binding.ShiftedUpperBounds,
			preimage.CommonLatticeUpperBounds) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: release/source/materialization binding mismatch")
	}
	for _, role := range []struct{ name, id string }{
		{preimage.GarblerPeerName, preimage.GarblerPeerID},
		{preimage.EvaluatorPeerName, preimage.EvaluatorPeerID},
	} {
		pin, ok := pins[role.name]
		id, idErr := formalGLMPhase16PeerID(pin)
		if !ok || idErr != nil || id != role.id {
			return zero, fmt.Errorf("joint-dp-biomedical-gaussian: designated role is not locally pinned")
		}
	}
	spec, err := jointDPGaussianOneDrawPolicySpec(policy)
	if err != nil {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: sealed worker circuit is invalid")
	}
	fullCircuitDigest := spec.digest()
	if policy.CircuitDigest != hex.EncodeToString(fullCircuitDigest[:]) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: local worker circuit digest mismatch")
	}
	circuitShape := spec.circuitShapeDigest()
	circuitShapeSHA256 := hex.EncodeToString(circuitShape[:])
	if circuitShapeSHA256 != preimage.CircuitShapeSHA256 {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: public circuit shape mismatch")
	}
	workerPublicPolicySHA256, err :=
		jointDPBiomedicalGaussianPublicWorkerPolicySHA256(
			policy, preimage.PlanSHA256, circuitShapeSHA256)
	if err != nil || workerPublicPolicySHA256 !=
		preimage.WorkerPublicPolicySHA256 {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: public worker policy digest mismatch")
	}
	workerContractSHA256, err := jointDPBiomedicalGaussianWorkerContractSHA256(
		preimage.WorkerPublicPolicySHA256, preimage.PlanSHA256,
		preimage.CircuitShapeSHA256, preimage.WorkerImplementationSHA256)
	if err != nil || workerContractSHA256 != preimage.WorkerContractSHA256 {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: worker contract digest mismatch")
	}
	return spec, nil
}

func jointDPBiomedicalGaussianWorkerSensitivityStatusAllowed(
	binding formalGLMPhase16ReleaseBinding) bool {
	switch binding.Family {
	case "binomial", "poisson":
		return binding.SensitivityCertificate.Status == "machine_proven"
	case "biomedical_capsule_vector":
		return binding.SensitivityCertificate.Status ==
			jointDPBiomedicalGaussianWorkerSensitivityStatus &&
			binding.SensitivityProof == jointDPBiomedicalGaussianL2Proof
	default:
		return false
	}
}

func jointDPBiomedicalGaussianEnvelopePreimageSHA256(
	preimage jointDPBiomedicalGaussianWorkerEnvelopePreimage,
) (string, error) {
	digest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianWorkerEnvelopeDomain, preimage)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func jointDPBiomedicalGaussianSourceShareSHA256(preimageSHA256,
	localPeerName, role, sourceShare string,
) (string, error) {
	digest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianSourceShareDomain, struct {
			EnvelopePreimageSHA256 string `json:"envelope_preimage_sha256"`
			LocalPeerName          string `json:"local_peer_name"`
			Role                   string `json:"role"`
			SourceShare            string `json:"source_share"`
		}{preimageSHA256, localPeerName, role, sourceShare})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func jointDPBiomedicalGaussianLocalSourceBindingSHA256(
	binding jointDPBiomedicalGaussianLocalSourceBinding,
) (string, error) {
	binding.BindingSHA256 = ""
	digest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianLocalSourceDomain, binding)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func jointDPBiomedicalGaussianBuildLocalSourceBinding(
	preimage jointDPBiomedicalGaussianWorkerEnvelopePreimage,
	localSnapshotContractSHA256, localSourceContractSHA256,
	localPeerName, role, sourceShare string,
) (jointDPBiomedicalGaussianLocalSourceBinding, error) {
	var zero jointDPBiomedicalGaussianLocalSourceBinding
	if !jointDPBiomedicalGaussianIsSHA256(localSnapshotContractSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(localSourceContractSHA256) ||
		(role != "garbler" && role != "evaluator") {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: invalid local worker role")
	}
	preimageSHA256, err := jointDPBiomedicalGaussianEnvelopePreimageSHA256(preimage)
	if err != nil {
		return zero, err
	}
	shareSHA256, err := jointDPBiomedicalGaussianSourceShareSHA256(
		preimageSHA256, localPeerName, role, sourceShare)
	if err != nil {
		return zero, err
	}
	materializationReceipt, ok := jointDPBiomedicalGaussianReceiptByKind(
		preimage.ReceiptReferences, jointDPBiomedicalGaussianReceiptMaterialization)
	if !ok {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: missing materialization receipt")
	}
	binding := jointDPBiomedicalGaussianLocalSourceBinding{
		Version:                     jointDPBiomedicalGaussianLocalSourceVersion,
		EnvelopePreimageSHA256:      preimageSHA256,
		LocalPeerName:               localPeerName,
		Role:                        role,
		LogicalSnapshotHandleSHA256: preimage.LogicalSnapshotHandleSHA256,
		LocalSnapshotContractSHA256: localSnapshotContractSHA256,
		PrivacyEpochSHA256:          preimage.PrivacyEpochSHA256,
		ReleaseInstanceID:           preimage.ReleaseInstanceID,
		MaterializationRootSHA256:   preimage.MaterializationRootSHA256,
		SourceContractHandleSHA256:  preimage.SourceContractHandleSHA256,
		LocalSourceContractSHA256:   localSourceContractSHA256,
		RunNonceSHA256:              preimage.RunNonceSHA256,
		SourceShareSHA256:           shareSHA256,
		MaterializationReceipt:      materializationReceipt,
	}
	binding.BindingSHA256, err =
		jointDPBiomedicalGaussianLocalSourceBindingSHA256(binding)
	if err != nil {
		return zero, err
	}
	return binding, nil
}

// jointDPBiomedicalGaussianVerifyProductiveWorkerInput is the worker-side
// fail-closed boundary. It verifies local pins before signatures, then binds
// the exact SourceShare and run/session nonce before returning any private
// seed to the GC runner. It performs no opening.
func jointDPBiomedicalGaussianVerifyProductiveWorkerInput(
	signed jointDPBiomedicalGaussianSignedWorkerEnvelope,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
	local jointDPBiomedicalGaussianLocalSourceBinding,
	session exactGCSession, role, sourceShare, privateSeed string,
) (jointDPGaussianOneDrawSpec, [32]byte, error) {
	var zeroSpec jointDPGaussianOneDrawSpec
	var zeroSeed [32]byte
	spec, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(signed, trust)
	if err != nil {
		return zeroSpec, zeroSeed, err
	}
	if err := jointDPGaussianOneDrawValidateSession(session, spec); err != nil {
		return zeroSpec, zeroSeed, err
	}
	preimage := signed.Preimage
	preimageSHA256, err := jointDPBiomedicalGaussianEnvelopePreimageSHA256(preimage)
	if err != nil {
		return zeroSpec, zeroSeed, err
	}
	wantLocalSHA256, err := jointDPBiomedicalGaussianLocalSourceBindingSHA256(local)
	if err != nil {
		return zeroSpec, zeroSeed, err
	}
	materializationReceipt, _ := jointDPBiomedicalGaussianReceiptByKind(
		preimage.ReceiptReferences, jointDPBiomedicalGaussianReceiptMaterialization)
	releaseBinding, err := jointDPGaussianOneDrawReleaseBindingViewFromPolicy(
		signed.WorkerPolicy)
	if err != nil {
		return zeroSpec, zeroSeed,
			fmt.Errorf("joint-dp-biomedical-gaussian: invalid local release binding")
	}
	expectedName := preimage.GarblerPeerName
	expectedID := preimage.GarblerPeerID
	commitment := spec.GarblerSeedCommitment
	context := spec.GarblerCommitmentContext
	if role == "evaluator" {
		expectedName = preimage.EvaluatorPeerName
		expectedID = preimage.EvaluatorPeerID
		commitment = spec.EvaluatorSeedCommitment
		context = spec.EvaluatorCommitmentContext
	} else if role != "garbler" {
		return zeroSpec, zeroSeed, fmt.Errorf("joint-dp-biomedical-gaussian: invalid worker role")
	}
	if hex.EncodeToString(session.SessionID[:]) != preimage.RunNonceSHA256 ||
		local.Version != jointDPBiomedicalGaussianLocalSourceVersion ||
		local.BindingSHA256 != wantLocalSHA256 ||
		local.EnvelopePreimageSHA256 != preimageSHA256 ||
		local.LocalPeerName != expectedName || local.Role != role ||
		local.LogicalSnapshotHandleSHA256 !=
			preimage.LogicalSnapshotHandleSHA256 ||
		local.LocalSnapshotContractSHA256 != releaseBinding.SnapshotSHA256 ||
		local.PrivacyEpochSHA256 != preimage.PrivacyEpochSHA256 ||
		local.ReleaseInstanceID != preimage.ReleaseInstanceID ||
		local.MaterializationRootSHA256 != preimage.MaterializationRootSHA256 ||
		local.SourceContractHandleSHA256 !=
			preimage.SourceContractHandleSHA256 ||
		local.LocalSourceContractSHA256 !=
			releaseBinding.SourceFanInTranscriptSHA256 ||
		local.RunNonceSHA256 != preimage.RunNonceSHA256 ||
		!reflect.DeepEqual(local.MaterializationReceipt, materializationReceipt) {
		return zeroSpec, zeroSeed, fmt.Errorf("joint-dp-biomedical-gaussian: local materialization binding mismatch")
	}
	shareSHA256, err := jointDPBiomedicalGaussianSourceShareSHA256(
		preimageSHA256, expectedName, role, sourceShare)
	if err != nil || shareSHA256 != local.SourceShareSHA256 {
		return zeroSpec, zeroSeed, fmt.Errorf("joint-dp-biomedical-gaussian: unbound or swapped SourceShare")
	}
	decoded, err := exactGCDecodeWorkerShares(sourceShare, session.Spec)
	if err != nil {
		return zeroSpec, zeroSeed, err
	}
	exactGCZeroBigInts(decoded)
	seedBytes, err := exactGCStrictBase64(privateSeed, 32)
	if err != nil {
		return zeroSpec, zeroSeed, fmt.Errorf("joint-dp-biomedical-gaussian: invalid private seed")
	}
	var seed [32]byte
	copy(seed[:], seedBytes)
	clear(seedBytes)
	if (role == "garbler" && session.GarblerID != expectedID) ||
		(role == "evaluator" && session.EvaluatorID != expectedID) ||
		jointDPSeedCommitment(context, seed) != commitment {
		clear(seed[:])
		return zeroSpec, zeroSeed,
			fmt.Errorf("joint-dp-biomedical-gaussian: local pinned seed binding mismatch")
	}
	return spec, seed, nil
}

// These runners are the only execution-shaped entry points for the sealed
// biomedical route. They reverify the typed envelope and local SourceShare,
// then bind both peers' noise streams and the garbler output masks to the
// release-stable productive stream. They return additive shares only and
// perform no reconstruction/opening.
func jointDPBiomedicalGaussianRunProductiveGarbler(rw io.ReadWriter,
	signed jointDPBiomedicalGaussianSignedWorkerEnvelope,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
	local jointDPBiomedicalGaussianLocalSourceBinding,
	session exactGCSession, sourceShare, privateSeed string,
) ([]*big.Int, error) {
	return jointDPBiomedicalGaussianRunProductive(
		rw, signed, trust, local, session, "garbler", sourceShare, privateSeed)
}

func jointDPBiomedicalGaussianRunProductiveEvaluator(rw io.ReadWriter,
	signed jointDPBiomedicalGaussianSignedWorkerEnvelope,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
	local jointDPBiomedicalGaussianLocalSourceBinding,
	session exactGCSession, sourceShare, privateSeed string,
) ([]*big.Int, error) {
	return jointDPBiomedicalGaussianRunProductive(
		rw, signed, trust, local, session, "evaluator", sourceShare, privateSeed)
}

func jointDPBiomedicalGaussianRunProductive(rw io.ReadWriter,
	signed jointDPBiomedicalGaussianSignedWorkerEnvelope,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
	local jointDPBiomedicalGaussianLocalSourceBinding,
	session exactGCSession, role, sourceShare, privateSeed string,
) ([]*big.Int, error) {
	spec, seed, err := jointDPBiomedicalGaussianVerifyProductiveWorkerInput(
		signed, trust, local, session, role, sourceShare, privateSeed)
	if err != nil {
		return nil, err
	}
	defer clear(seed[:])
	productiveStream, err := jointDPGaussianOneDrawDecodeHex(
		signed.Preimage.ProductiveStreamSHA256, "productive stream")
	if err != nil {
		return nil, err
	}
	shares, err := exactGCDecodeWorkerShares(sourceShare, session.Spec)
	if err != nil {
		return nil, err
	}
	defer exactGCZeroBigInts(shares)
	if role == "garbler" {
		return jointDPGaussianOneDrawRunGarblerBound(
			rw, session, spec, shares, seed, &productiveStream)
	}
	return jointDPGaussianOneDrawRunEvaluatorBound(
		rw, session, spec, shares, seed, &productiveStream)
}

func jointDPBiomedicalGaussianSignWorkerEnvelope(
	preimage jointDPBiomedicalGaussianWorkerEnvelopePreimage,
	signer string, privateKey ed25519.PrivateKey,
) (jointDPBiomedicalGaussianSignature, error) {
	return jointDPBiomedicalGaussianSign(
		jointDPBiomedicalGaussianWorkerEnvelopeDomain,
		preimage, signer, privateKey)
}
