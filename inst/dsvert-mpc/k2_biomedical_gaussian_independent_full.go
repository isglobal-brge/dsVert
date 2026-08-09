package main

// Internal biomedical admission for the scalable two-independent-full-draw
// Gaussian backend.  This file intentionally registers no command and grants
// no opening.  Every custodian signs the exact backend and release identity;
// the one-draw exact-GC route remains a separate sealed reference and is never
// selected as a fallback.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"reflect"

	"golang.org/x/crypto/hkdf"
)

const (
	jointDPBiomedicalGaussianFullSelectionVersion        = "dsvert-biomedical-gaussian-independent-full-selection-v1"
	jointDPBiomedicalGaussianFullSelectionDomain         = "dsVert/biomedical-gaussian/independent-full/selection/v1"
	jointDPBiomedicalGaussianFullReleaseIdentityDomain   = "dsVert/biomedical-gaussian/independent-full/release-identity/v1"
	jointDPBiomedicalGaussianFullReleaseInstanceDomain   = "dsVert/biomedical-gaussian/independent-full/release-instance/v1"
	jointDPBiomedicalGaussianFullWorkerTranscriptDomain  = "dsVert/biomedical-gaussian/independent-full/worker-transcript/v1"
	jointDPBiomedicalGaussianFullRootEpochDomain         = "dsVert/biomedical-gaussian/independent-full/noise-root-epoch/v1"
	jointDPBiomedicalGaussianFullSeedDomain              = "dsVert/biomedical-gaussian/independent-full/sticky-seed/v1"
	jointDPBiomedicalGaussianFullAdmissionVersion        = "dsvert-biomedical-gaussian-independent-full-admission-v1"
	jointDPBiomedicalGaussianFullAdmissionSealDomain     = "dsVert/biomedical-gaussian/independent-full/admission-seal/v1"
	jointDPBiomedicalGaussianFullCertificateVersion      = "dsvert-biomedical-gaussian-independent-full-certificate-v1"
	jointDPBiomedicalGaussianFullFinalizerHandoffVersion = "dsvert-biomedical-gaussian-independent-full-finalizer-handoff-v1"
	jointDPBiomedicalGaussianFullLocalSourceVersion      = "dsvert-biomedical-gaussian-independent-full-local-source-v1"
	jointDPBiomedicalGaussianFullLocalSourceDomain       = "dsVert/biomedical-gaussian/independent-full/local-source/v1"
	jointDPBiomedicalGaussianFullPeerShareVersion        = "dsvert-biomedical-gaussian-independent-full-peer-share-v1"
	jointDPBiomedicalGaussianFullPeerShareDomain         = "dsVert/biomedical-gaussian/independent-full/peer-share/v1"

	jointDPBiomedicalGaussianFullBackendSelection = "all_k_server_authoritative_cross_signed_exact_backend_v1"
	jointDPBiomedicalGaussianFullNoWrap           = "exact_bigint_source_upper_plus_two_peer_finite_noise_inside_signed_ring128_v1"
)

var jointDPBiomedicalGaussianFullCertificateBlockers = []string{
	"phase18_recipient_specific_alignment_handoff_not_yet_linked_e2e",
	"r_dsi_append_before_release_receipt_verifier_not_yet_linked",
	"r_dsi_exactly_once_finalizer_not_yet_linked",
	"single_common_dp_vector_opening_not_authorized",
}

var jointDPBiomedicalGaussianFullFinalizerBlockers = []string{
	"phase18_recipient_specific_alignment_finalizer_is_still_a_typed_boundary",
	"durable_r_ledger_receipt_must_be_verified_before_any_public_release",
	"exactly_once_r_dsi_release_memoization_must_be_linked_before_opening",
}

type jointDPBiomedicalGaussianNoiseRootEpoch struct {
	PeerName    string `json:"peer_name"`
	EpochSHA256 string `json:"epoch_sha256"`
}

type jointDPBiomedicalGaussianFullNoiseCommitment struct {
	PeerName      string `json:"peer_name"`
	ContextSHA256 string `json:"context_sha256"`
	SeedSHA256    string `json:"seed_sha256"`
}

// The request deliberately has no backend or sensitivity field.  Both are
// fixed/derived by the server-side builder.  NoiseRootEpochs and commitments
// are opaque values contributed by the two designated peers; no root or seed
// crosses this boundary.
type jointDPBiomedicalGaussianFullSelectionRequest struct {
	LogicalReleaseSHA256      string
	PrivacyEpochSHA256        string
	MaterializationRootSHA256 string
	ReservationSHA256         string
	Epsilon                   string
	Delta                     string
	NoiseRootEpochs           []jointDPBiomedicalGaussianNoiseRootEpoch
	NoiseCommitments          []jointDPBiomedicalGaussianFullNoiseCommitment
	ReceiptReferences         []jointDPBiomedicalGaussianReceiptReference
}

type jointDPBiomedicalGaussianFullSelectionContract struct {
	Version                  string `json:"version"`
	Backend                  string `json:"backend"`
	BackendSelection         string `json:"backend_selection"`
	PublicIdentifierContract string `json:"public_identifier_contract"`

	ManifestAttestationSHA256 string   `json:"manifest_attestation_sha256"`
	CapsuleID                 string   `json:"capsule_id"`
	ManifestSHA256            string   `json:"manifest_sha256"`
	WorkloadSHA256            string   `json:"workload_sha256"`
	PinsetSHA256              string   `json:"pinset_sha256"`
	CustodianPeers            []string `json:"custodian_peers"`
	CustodianCount            int      `json:"custodian_count"`
	DesignatedComputePeers    []string `json:"designated_compute_peers"`

	LogicalReleaseSHA256        string `json:"logical_release_sha256"`
	PrivacyEpochSHA256          string `json:"privacy_epoch_sha256"`
	LogicalSnapshotHandleSHA256 string `json:"logical_snapshot_handle_sha256"`
	LogicalSnapshotHandleKind   string `json:"logical_snapshot_handle_kind"`
	SourceContractHandleSHA256  string `json:"source_contract_handle_sha256"`
	SourceContractHandleKind    string `json:"source_contract_handle_kind"`
	MaterializationRootSHA256   string `json:"materialization_root_sha256"`
	MaterializationRootKind     string `json:"materialization_root_kind"`
	ReservationSHA256           string `json:"reservation_sha256"`
	ReservationDigestKind       string `json:"reservation_digest_kind"`
	ReleaseInstanceID           string `json:"release_instance_id"`
	ReleaseContractSHA256       string `json:"release_contract_sha256"`
	WorkerTranscriptSHA256      string `json:"worker_transcript_sha256"`

	Epsilon                           string                                         `json:"epsilon"`
	Delta                             string                                         `json:"delta"`
	PlanSHA256                        string                                         `json:"plan_sha256"`
	PlanRequestBindingSHA256          string                                         `json:"plan_request_binding_sha256"`
	SensitivityCertificateSHA256      string                                         `json:"sensitivity_certificate_sha256"`
	RingBits                          int                                            `json:"ring_bits"`
	OutputLatticeBits                 int                                            `json:"output_lattice_bits"`
	TotalCoordinateCount              int                                            `json:"total_coordinate_count"`
	MaximumChunkCoordinates           int                                            `json:"maximum_chunk_coordinates"`
	NoiseRootEpochs                   []jointDPBiomedicalGaussianNoiseRootEpoch      `json:"noise_root_epochs"`
	NoiseCommitments                  []jointDPBiomedicalGaussianFullNoiseCommitment `json:"noise_commitments"`
	ReceiptReferences                 []jointDPBiomedicalGaussianReceiptReference    `json:"receipt_references"`
	LedgerAppendBeforeReleaseReserved bool                                           `json:"ledger_append_before_release_reserved"`
	ExactlyOnceFinalizerReserved      bool                                           `json:"exactly_once_finalizer_reserved"`
	OperationLimit                    bool                                           `json:"operation_limit"`
	RequestLimit                      bool                                           `json:"request_limit"`
	HistoryCanDenyOperation           bool                                           `json:"history_can_deny_operation"`
	OpeningsAuthorized                int                                            `json:"openings_authorized"`
}

type jointDPBiomedicalGaussianFullSelectionAttestation struct {
	Contract   jointDPBiomedicalGaussianFullSelectionContract `json:"contract"`
	Signatures []jointDPBiomedicalGaussianSignature           `json:"signatures"`
}

type jointDPBiomedicalGaussianFullReleaseIdentity struct {
	Backend                     string                                      `json:"backend"`
	ManifestAttestationSHA256   string                                      `json:"manifest_attestation_sha256"`
	ManifestSHA256              string                                      `json:"manifest_sha256"`
	WorkloadSHA256              string                                      `json:"workload_sha256"`
	PinsetSHA256                string                                      `json:"pinset_sha256"`
	DesignatedComputePeers      []string                                    `json:"designated_compute_peers"`
	LogicalReleaseSHA256        string                                      `json:"logical_release_sha256"`
	PrivacyEpochSHA256          string                                      `json:"privacy_epoch_sha256"`
	LogicalSnapshotHandleSHA256 string                                      `json:"logical_snapshot_handle_sha256"`
	SourceContractHandleSHA256  string                                      `json:"source_contract_handle_sha256"`
	MaterializationRootSHA256   string                                      `json:"materialization_root_sha256"`
	ReservationSHA256           string                                      `json:"reservation_sha256"`
	Epsilon                     string                                      `json:"epsilon"`
	Delta                       string                                      `json:"delta"`
	PlanRequestBindingSHA256    string                                      `json:"plan_request_binding_sha256"`
	NoiseRootEpochs             []jointDPBiomedicalGaussianNoiseRootEpoch   `json:"noise_root_epochs"`
	ReceiptReferences           []jointDPBiomedicalGaussianReceiptReference `json:"receipt_references"`
	ReleaseInstanceID           string                                      `json:"release_instance_id"`
	WorkerTranscriptSHA256      string                                      `json:"worker_transcript_sha256"`
}

type jointDPBiomedicalGaussianFullCertificate struct {
	Version                                string   `json:"version"`
	Backend                                string   `json:"backend"`
	BackendSelection                       string   `json:"backend_selection"`
	Mechanism                              string   `json:"mechanism"`
	Sampler                                string   `json:"sampler"`
	ReleaseInstanceID                      string   `json:"release_instance_id"`
	ReleaseContractSHA256                  string   `json:"release_contract_sha256"`
	SensitivityCertificateSHA256           string   `json:"sensitivity_certificate_sha256"`
	DerivedSensitivitySteps                string   `json:"derived_sensitivity_steps"`
	EpsilonPerPeer                         string   `json:"epsilon_per_peer"`
	EpsilonPerPeerNumerator                string   `json:"epsilon_per_peer_numerator"`
	EpsilonPerPeerDenominator              string   `json:"epsilon_per_peer_denominator"`
	DeltaPerPeer                           string   `json:"delta_per_peer"`
	DeltaPerPeerNumerator                  string   `json:"delta_per_peer_numerator"`
	DeltaPerPeerDenominator                string   `json:"delta_per_peer_denominator"`
	CompleteEpsilonDeltaPerPeer            bool     `json:"complete_epsilon_delta_per_peer"`
	EpsilonDividedByPeerCount              bool     `json:"epsilon_divided_by_peer_count"`
	ReleaseDeltaAggregation                string   `json:"release_delta_aggregation"`
	NominalVarianceMultiplier              int      `json:"nominal_variance_multiplier"`
	NominalStandardDeviationFactor         string   `json:"nominal_standard_deviation_factor"`
	ThreatModel                            string   `json:"threat_model"`
	RequiresAtLeastOneHonestDesignatedPeer bool     `json:"requires_at_least_one_honest_designated_peer"`
	IndependentNoiseRootCustodyRequired    bool     `json:"independent_noise_root_custody_required"`
	DistinctNoiseRootEpochsVerified        bool     `json:"distinct_noise_root_epochs_verified"`
	MaximumColludingDesignatedPeers        int      `json:"maximum_colluding_designated_peers"`
	BothDesignatedCollusionProtected       bool     `json:"both_designated_collusion_protected"`
	MaliciousCustodianSecurityClaim        bool     `json:"malicious_custodian_security_claim"`
	RelayTamperDetection                   bool     `json:"relay_tamper_detection"`
	RelayAvailabilityGuaranteed            bool     `json:"relay_availability_guaranteed"`
	AdversaryView                          string   `json:"adversary_view"`
	AdversaryViewPrivacyArgument           string   `json:"adversary_view_privacy_argument"`
	PrivacyTheorem                         string   `json:"privacy_theorem"`
	SourceShareHidingPrecondition          string   `json:"source_share_hiding_precondition"`
	FiniteSupportTransferCharged           bool     `json:"finite_support_transfer_charged"`
	FixedWorkSampler                       bool     `json:"fixed_work_sampler"`
	HostConstantTimeClaim                  bool     `json:"host_constant_time_claim"`
	TranscriptDPClaim                      bool     `json:"transcript_dp_claim"`
	LogicalTranscriptFixedShape            bool     `json:"logical_transcript_fixed_shape"`
	PhysicalTimingDPClaim                  bool     `json:"physical_timing_dp_claim"`
	NoWrapCertificate                      string   `json:"no_wrap_certificate"`
	NoWrapHeadroomCertified                bool     `json:"no_wrap_headroom_certified"`
	StickyIdentity                         string   `json:"sticky_identity"`
	LedgerAppendBeforeReleaseBound         bool     `json:"ledger_append_before_release_bound"`
	ExactlyOnceFinalizerBound              bool     `json:"exactly_once_finalizer_bound"`
	AutomaticFallbackUsed                  bool     `json:"automatic_fallback_used"`
	OneDrawSubstituted                     bool     `json:"one_draw_substituted"`
	OpeningsPerformed                      int      `json:"openings_performed"`
	ProductionReady                        bool     `json:"production_ready"`
	Blockers                               []string `json:"blockers"`
}

type jointDPBiomedicalGaussianFullAdmission struct {
	Version                   string                                   `json:"version"`
	SelectionContractSHA256   string                                   `json:"selection_contract_sha256"`
	Certificate               jointDPBiomedicalGaussianFullCertificate `json:"certificate"`
	selection                 jointDPBiomedicalGaussianFullSelectionAttestation
	manifest                  jointDPBiomedicalGaussianManifestAttestation
	certificate               jointDPBiomedicalGaussianSensitivityCertificate
	plan                      jointDPGaussianPlanOutput
	manifestAttestationSHA256 string
	planSHA256                string
	publicCertificateSHA256   string
	seal                      [32]byte
	// Non-nil only for the formal-GLM automatic fallback.  The ordinary
	// biomedical admission continues to be reconstructed from its typed
	// manifest.  The fallback instead carries its machine-proven Phase-1.5
	// certificate and K-signed backend decision as process-local authority.
	formalSelection *formalGLMPhase16BackendSelectionAttestation
	formalBinding   *formalGLMPhase16ReleaseBinding
	formalToken     *formalGLMPhase19PostExecutionToken
}

type jointDPBiomedicalGaussianFullFinalizerHandoff struct {
	Version                    string   `json:"version"`
	Backend                    string   `json:"backend"`
	ReleaseInstanceID          string   `json:"release_instance_id"`
	ReleaseContractSHA256      string   `json:"release_contract_sha256"`
	LedgerReservationSHA256    string   `json:"ledger_reservation_sha256"`
	FinalizerReservationSHA256 string   `json:"finalizer_reservation_sha256"`
	OpeningAuthorized          bool     `json:"opening_authorized"`
	OpeningsPerformed          int      `json:"openings_performed"`
	ProductionReady            bool     `json:"production_ready"`
	Blockers                   []string `json:"blockers"`
	finalizerInput             jointDPGaussianFinalizerInput
}

// This object is created inside the authoritative local materializer handoff.
// All fields are deliberately excluded from JSON: an analyst/relay cannot
// manufacture or replace it at a remote command boundary.
type jointDPBiomedicalGaussianFullLocalSourceBinding struct {
	Version                     string                                    `json:"-"`
	SelectionContractSHA256     string                                    `json:"-"`
	LocalPeerName               string                                    `json:"-"`
	ChunkStart                  int                                       `json:"-"`
	CoordinateCount             int                                       `json:"-"`
	ReleaseInstanceID           string                                    `json:"-"`
	LogicalSnapshotHandleSHA256 string                                    `json:"-"`
	LocalSnapshotContractSHA256 string                                    `json:"-"`
	SourceContractHandleSHA256  string                                    `json:"-"`
	LocalSourceContractSHA256   string                                    `json:"-"`
	MaterializationRootSHA256   string                                    `json:"-"`
	ReservationSHA256           string                                    `json:"-"`
	SourceShareSHA256           string                                    `json:"-"`
	MaterializationReceipt      jointDPBiomedicalGaussianReceiptReference `json:"-"`
	SourceContractReceipt       jointDPBiomedicalGaussianReceiptReference `json:"-"`
	BindingSHA256               string                                    `json:"-"`
}

// A peer share is signed by the pinned local identity. The actual noised share
// and its binding remain private until an authenticated/encrypted peer channel
// transports them. JSON therefore contains only non-disclosive routing data.
type jointDPBiomedicalGaussianFullPeerShare struct {
	Version               string `json:"version"`
	Backend               string `json:"backend"`
	ReleaseInstanceID     string `json:"release_instance_id"`
	ReleaseContractSHA256 string `json:"release_contract_sha256"`
	PeerName              string `json:"peer_name"`
	ChunkStart            int    `json:"chunk_start"`
	CoordinateCount       int    `json:"coordinate_count"`
	OutputSHA256          string `json:"-"`
	SourceBindingSHA256   string `json:"-"`
	Signature             []byte `json:"-"`
	output                jointDPGaussianShareOutput
	binding               jointDPBiomedicalGaussianFullLocalSourceBinding
}

func jointDPBiomedicalGaussianFullManifestAttestationSHA256(
	manifest jointDPBiomedicalGaussianManifestAttestation,
) (string, error) {
	manifestDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianManifestDomain, manifest.Contract)
	if err != nil {
		return "", err
	}
	signatures, err := jointDPBiomedicalGaussianSignatureSetDigest(
		manifest.Signatures)
	if err != nil {
		return "", err
	}
	digest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianManifestDomain+"/attestation", struct {
			ManifestSHA256     string `json:"manifest_sha256"`
			SignatureSetSHA256 string `json:"signature_set_sha256"`
		}{hex.EncodeToString(manifestDigest[:]), hex.EncodeToString(signatures[:])})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func jointDPBiomedicalGaussianFullNoiseRootEpoch(root [32]byte,
	peerName string,
) (string, error) {
	if root == ([32]byte{}) || !jointDPBiomedicalGaussianValidPeerName(peerName) {
		return "", fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid local noise root")
	}
	mac := hmac.New(sha256.New, root[:])
	mac.Write([]byte(jointDPBiomedicalGaussianFullRootEpochDomain))
	// This is deliberately a peer-independent, high-entropy root fingerprint:
	// it lets the K-signed admission reject an accidentally cloned root while
	// revealing neither the root nor any release-specific seed material.
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func jointDPBiomedicalGaussianFullReceipt(
	receipts []jointDPBiomedicalGaussianReceiptReference, kind string,
) (jointDPBiomedicalGaussianReceiptReference, error) {
	receipt, ok := jointDPBiomedicalGaussianReceiptByKind(receipts, kind)
	if !ok {
		return jointDPBiomedicalGaussianReceiptReference{},
			fmt.Errorf("joint-dp-biomedical-gaussian-full: missing %s receipt", kind)
	}
	return receipt, nil
}

func jointDPBiomedicalGaussianFullValidateEpochs(
	epochs []jointDPBiomedicalGaussianNoiseRootEpoch, peers []string,
) error {
	if len(epochs) != 2 || len(peers) != 2 {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: exactly two noise-root epochs are required")
	}
	for index := range peers {
		if epochs[index].PeerName != peers[index] ||
			!jointDPBiomedicalGaussianIsSHA256(epochs[index].EpochSHA256) {
			return fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid ordered noise-root epoch")
		}
	}
	if hmac.Equal([]byte(epochs[0].EpochSHA256), []byte(epochs[1].EpochSHA256)) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: designated peers must not share a noise root")
	}
	return nil
}

func jointDPBiomedicalGaussianFullPlan(
	manifest jointDPBiomedicalGaussianManifestAttestation,
	pins map[string]ed25519.PublicKey, epsilon, delta string,
) (jointDPBiomedicalGaussianSensitivityCertificate,
	jointDPGaussianPlanOutput, string, string, error) {
	var zeroCertificate jointDPBiomedicalGaussianSensitivityCertificate
	var zeroPlan jointDPGaussianPlanOutput
	certificate, err := jointDPBiomedicalGaussianValidateManifestAttestation(
		manifest, pins)
	if err != nil {
		return zeroCertificate, zeroPlan, "", "", err
	}
	if _, err := jointDPBiomedicalGaussianCanonicalDecimal(epsilon, "epsilon"); err != nil {
		return zeroCertificate, zeroPlan, "", "", err
	}
	deltaRat, err := jointDPBiomedicalGaussianCanonicalDecimal(delta, "delta")
	if err != nil || deltaRat.Cmp(big.NewRat(1, 1)) >= 0 {
		return zeroCertificate, zeroPlan, "", "",
			fmt.Errorf("joint-dp-biomedical-gaussian-full: delta must be in (0,1)")
	}
	plan, err := jointDPPlanVectorGaussian(jointDPGaussianPlanInput{
		Epsilon: epsilon, Delta: delta,
		L2SensitivitySteps:   certificate.SelectedBoundSteps,
		TotalCoordinateCount: manifest.Contract.TotalCoordinateCount,
	})
	if err != nil || !plan.CapabilityAvailable ||
		plan.IndependentNoisePeerCount != 2 || !plan.CompleteEpsilonPerPeer ||
		plan.EpsilonDividedByPeerCount || plan.NominalVarianceMultiplier != 2 {
		return zeroCertificate, zeroPlan, "", "",
			fmt.Errorf("joint-dp-biomedical-gaussian-full: productive Gaussian plan unavailable")
	}
	certificateSHA256, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianSensitivityDomain, certificate)
	if err != nil {
		return zeroCertificate, zeroPlan, "", "", err
	}
	planSHA256, err := jointDPBiomedicalGaussianHash(plan)
	if err != nil {
		return zeroCertificate, zeroPlan, "", "", err
	}
	maximumNoise, ok := new(big.Int).SetString(
		plan.MaximumNoiseMagnitudeTwoPeers, 10)
	if !ok || maximumNoise.Sign() < 0 {
		return zeroCertificate, zeroPlan, "", "",
			fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid noise headroom certificate")
	}
	maximumSigned := exactGCMaxSigned(128)
	for _, boundText := range certificate.ShiftedUpperBounds {
		bound, parseErr := jointDPBiomedicalGaussianParseCanonicalInt(
			boundText, "shifted coordinate upper bound", false)
		if parseErr != nil ||
			new(big.Int).Add(bound, maximumNoise).Cmp(maximumSigned) > 0 {
			return zeroCertificate, zeroPlan, "", "",
				exactGCFailure(exactGCFailureBoundExceeded,
					fmt.Errorf("joint-dp-biomedical-gaussian-full: Ring128 no-wrap headroom unavailable"))
		}
	}
	return certificate, plan, hex.EncodeToString(certificateSHA256[:]),
		planSHA256, nil
}

func jointDPBiomedicalGaussianFullReleaseIdentityForRequest(
	manifest jointDPBiomedicalGaussianManifestAttestation,
	pins map[string]ed25519.PublicKey,
	request jointDPBiomedicalGaussianFullSelectionRequest,
) (jointDPBiomedicalGaussianFullReleaseIdentity, error) {
	var zero jointDPBiomedicalGaussianFullReleaseIdentity
	_, plan, _, _, err := jointDPBiomedicalGaussianFullPlan(
		manifest, pins, request.Epsilon, request.Delta)
	if err != nil {
		return zero, err
	}
	hashes := []string{
		request.LogicalReleaseSHA256, request.PrivacyEpochSHA256,
		request.MaterializationRootSHA256, request.ReservationSHA256,
		manifest.Contract.LogicalSnapshotSHA256,
		manifest.Contract.SourceContractSHA256,
	}
	for _, value := range hashes {
		if !jointDPBiomedicalGaussianIsSHA256(value) {
			return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid release identity handle")
		}
	}
	if err := jointDPBiomedicalGaussianFullValidateEpochs(
		request.NoiseRootEpochs,
		manifest.Contract.DesignatedComputePeers); err != nil {
		return zero, err
	}
	if err := jointDPBiomedicalGaussianValidateReceiptReferences(
		request.ReceiptReferences); err != nil {
		return zero, err
	}
	ledger, _ := jointDPBiomedicalGaussianFullReceipt(
		request.ReceiptReferences, jointDPBiomedicalGaussianReceiptPrivacyLedger)
	if ledger.SHA256 != request.ReservationSHA256 {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: ledger reservation is not release-bound")
	}
	manifestAttestationSHA256, err :=
		jointDPBiomedicalGaussianFullManifestAttestationSHA256(manifest)
	if err != nil {
		return zero, err
	}
	identity := jointDPBiomedicalGaussianFullReleaseIdentity{
		Backend:                   jointDPGaussianBackend,
		ManifestAttestationSHA256: manifestAttestationSHA256,
		ManifestSHA256:            manifest.Contract.ManifestSHA256,
		WorkloadSHA256:            manifest.Contract.WorkloadSHA256,
		PinsetSHA256:              manifest.Contract.PinsetSHA256,
		DesignatedComputePeers: append([]string(nil),
			manifest.Contract.DesignatedComputePeers...),
		LogicalReleaseSHA256:        request.LogicalReleaseSHA256,
		PrivacyEpochSHA256:          request.PrivacyEpochSHA256,
		LogicalSnapshotHandleSHA256: manifest.Contract.LogicalSnapshotSHA256,
		SourceContractHandleSHA256:  manifest.Contract.SourceContractSHA256,
		MaterializationRootSHA256:   request.MaterializationRootSHA256,
		ReservationSHA256:           request.ReservationSHA256,
		Epsilon:                     request.Epsilon, Delta: request.Delta,
		PlanRequestBindingSHA256: plan.RequestBindingSHA256,
		NoiseRootEpochs: append([]jointDPBiomedicalGaussianNoiseRootEpoch(nil),
			request.NoiseRootEpochs...),
		ReceiptReferences: append([]jointDPBiomedicalGaussianReceiptReference(nil),
			request.ReceiptReferences...),
	}
	releaseDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullReleaseInstanceDomain, identity)
	if err != nil {
		return zero, err
	}
	identity.ReleaseInstanceID = hex.EncodeToString(releaseDigest[:])
	transcriptDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullWorkerTranscriptDomain, identity)
	if err != nil {
		return zero, err
	}
	identity.WorkerTranscriptSHA256 = hex.EncodeToString(transcriptDigest[:])
	return identity, nil
}

func jointDPBiomedicalGaussianFullSeedMaterial(root [32]byte, peerName string,
	identity jointDPBiomedicalGaussianFullReleaseIdentity,
) ([32]byte, string, string, error) {
	var zero [32]byte
	epoch, err := jointDPBiomedicalGaussianFullNoiseRootEpoch(root, peerName)
	if err != nil {
		return zero, "", "", err
	}
	found := false
	for _, candidate := range identity.NoiseRootEpochs {
		if candidate.PeerName == peerName {
			found = candidate.EpochSHA256 == epoch
			break
		}
	}
	if !found || identity.Backend != jointDPGaussianBackend ||
		!jointDPBiomedicalGaussianIsSHA256(identity.ReleaseInstanceID) ||
		!jointDPBiomedicalGaussianIsSHA256(identity.WorkerTranscriptSHA256) {
		return zero, "", "",
			fmt.Errorf("joint-dp-biomedical-gaussian-full: root epoch requires a new release instance")
	}
	identityMessage, err := jointDPBiomedicalGaussianDomainMessage(
		jointDPBiomedicalGaussianFullSeedDomain, struct {
			Identity jointDPBiomedicalGaussianFullReleaseIdentity `json:"identity"`
			PeerName string                                       `json:"peer_name"`
		}{identity, peerName})
	if err != nil {
		return zero, "", "", err
	}
	releaseSalt, err := hex.DecodeString(identity.ReleaseInstanceID)
	if err != nil || len(releaseSalt) != 32 {
		return zero, "", "", fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid release salt")
	}
	reader := hkdf.New(sha256.New, root[:], releaseSalt, identityMessage)
	var seed [32]byte
	if _, err := io.ReadFull(reader, seed[:]); err != nil {
		clear(releaseSalt)
		clear(identityMessage)
		return zero, "", "", err
	}
	clear(releaseSalt)
	clear(identityMessage)
	transcript, err := jointDPDecodeHex32(
		identity.WorkerTranscriptSHA256, "worker transcript")
	if err != nil {
		clear(seed[:])
		return zero, "", "", err
	}
	context := jointDPCommitmentContext(
		transcript, jointDPGaussianCommitmentPurpose, peerName)
	commitment := jointDPSeedCommitment(context, seed)
	return seed, hex.EncodeToString(context[:]),
		hex.EncodeToString(commitment[:]), nil
}

func jointDPBiomedicalGaussianBuildFullSelectionContract(
	manifest jointDPBiomedicalGaussianManifestAttestation,
	pins map[string]ed25519.PublicKey,
	request jointDPBiomedicalGaussianFullSelectionRequest,
) (jointDPBiomedicalGaussianFullSelectionContract, error) {
	var zero jointDPBiomedicalGaussianFullSelectionContract
	_, plan, certificateSHA256, planSHA256, err :=
		jointDPBiomedicalGaussianFullPlan(
			manifest, pins, request.Epsilon, request.Delta)
	if err != nil {
		return zero, err
	}
	identity, err := jointDPBiomedicalGaussianFullReleaseIdentityForRequest(
		manifest, pins, request)
	if err != nil {
		return zero, err
	}
	if len(request.NoiseCommitments) != 2 {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: exactly two noise commitments are required")
	}
	transcript, err := jointDPDecodeHex32(
		identity.WorkerTranscriptSHA256, "worker transcript")
	if err != nil {
		return zero, err
	}
	for index, peer := range manifest.Contract.DesignatedComputePeers {
		commitment := request.NoiseCommitments[index]
		expectedContext := jointDPCommitmentContext(
			transcript, jointDPGaussianCommitmentPurpose, peer)
		if commitment.PeerName != peer ||
			commitment.ContextSHA256 != hex.EncodeToString(expectedContext[:]) ||
			!jointDPBiomedicalGaussianIsSHA256(commitment.SeedSHA256) {
			return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid ordered noise commitment")
		}
	}
	contract := jointDPBiomedicalGaussianFullSelectionContract{
		Version:                   jointDPBiomedicalGaussianFullSelectionVersion,
		Backend:                   jointDPGaussianBackend,
		BackendSelection:          jointDPBiomedicalGaussianFullBackendSelection,
		PublicIdentifierContract:  jointDPBiomedicalGaussianPublicIdentifierRule,
		ManifestAttestationSHA256: identity.ManifestAttestationSHA256,
		CapsuleID:                 manifest.Contract.CapsuleID,
		ManifestSHA256:            manifest.Contract.ManifestSHA256,
		WorkloadSHA256:            manifest.Contract.WorkloadSHA256,
		PinsetSHA256:              manifest.Contract.PinsetSHA256,
		CustodianPeers:            append([]string(nil), manifest.Contract.CustodianPeers...),
		CustodianCount:            manifest.Contract.CustodianCount,
		DesignatedComputePeers: append([]string(nil),
			manifest.Contract.DesignatedComputePeers...),
		LogicalReleaseSHA256:        identity.LogicalReleaseSHA256,
		PrivacyEpochSHA256:          identity.PrivacyEpochSHA256,
		LogicalSnapshotHandleSHA256: identity.LogicalSnapshotHandleSHA256,
		LogicalSnapshotHandleKind:   jointDPBiomedicalGaussianOpaqueSnapshotHandle,
		SourceContractHandleSHA256:  identity.SourceContractHandleSHA256,
		SourceContractHandleKind:    jointDPBiomedicalGaussianOpaqueSourceContract,
		MaterializationRootSHA256:   identity.MaterializationRootSHA256,
		MaterializationRootKind:     jointDPBiomedicalGaussianOpaqueSourceRoot,
		ReservationSHA256:           identity.ReservationSHA256,
		ReservationDigestKind:       jointDPBiomedicalGaussianReceiptDigestRule,
		ReleaseInstanceID:           identity.ReleaseInstanceID,
		WorkerTranscriptSHA256:      identity.WorkerTranscriptSHA256,
		Epsilon:                     request.Epsilon, Delta: request.Delta,
		PlanSHA256:                   planSHA256,
		PlanRequestBindingSHA256:     plan.RequestBindingSHA256,
		SensitivityCertificateSHA256: certificateSHA256,
		RingBits:                     128,
		OutputLatticeBits:            manifest.Contract.OutputLatticeBits,
		TotalCoordinateCount:         manifest.Contract.TotalCoordinateCount,
		MaximumChunkCoordinates:      plan.MaximumChunkCoordinates,
		NoiseRootEpochs: append([]jointDPBiomedicalGaussianNoiseRootEpoch(nil),
			request.NoiseRootEpochs...),
		NoiseCommitments: append([]jointDPBiomedicalGaussianFullNoiseCommitment(nil),
			request.NoiseCommitments...),
		ReceiptReferences: append([]jointDPBiomedicalGaussianReceiptReference(nil),
			request.ReceiptReferences...),
		LedgerAppendBeforeReleaseReserved: true,
		ExactlyOnceFinalizerReserved:      true,
		OperationLimit:                    false, RequestLimit: false,
		HistoryCanDenyOperation: false, OpeningsAuthorized: 0,
	}
	contractDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullReleaseIdentityDomain, contract)
	if err != nil {
		return zero, err
	}
	contract.ReleaseContractSHA256 = hex.EncodeToString(contractDigest[:])
	return contract, nil
}

func jointDPBiomedicalGaussianValidateFullSelection(
	manifest jointDPBiomedicalGaussianManifestAttestation,
	selection jointDPBiomedicalGaussianFullSelectionAttestation,
	pins map[string]ed25519.PublicKey,
) (jointDPBiomedicalGaussianSensitivityCertificate,
	jointDPGaussianPlanOutput, error) {
	var zeroCertificate jointDPBiomedicalGaussianSensitivityCertificate
	var zeroPlan jointDPGaussianPlanOutput
	contract := selection.Contract
	request := jointDPBiomedicalGaussianFullSelectionRequest{
		LogicalReleaseSHA256:      contract.LogicalReleaseSHA256,
		PrivacyEpochSHA256:        contract.PrivacyEpochSHA256,
		MaterializationRootSHA256: contract.MaterializationRootSHA256,
		ReservationSHA256:         contract.ReservationSHA256,
		Epsilon:                   contract.Epsilon, Delta: contract.Delta,
		NoiseRootEpochs: append([]jointDPBiomedicalGaussianNoiseRootEpoch(nil),
			contract.NoiseRootEpochs...),
		NoiseCommitments: append([]jointDPBiomedicalGaussianFullNoiseCommitment(nil),
			contract.NoiseCommitments...),
		ReceiptReferences: append([]jointDPBiomedicalGaussianReceiptReference(nil),
			contract.ReceiptReferences...),
	}
	expected, err := jointDPBiomedicalGaussianBuildFullSelectionContract(
		manifest, pins, request)
	if err != nil {
		return zeroCertificate, zeroPlan, err
	}
	if !reflect.DeepEqual(contract, expected) ||
		contract.Version != jointDPBiomedicalGaussianFullSelectionVersion ||
		contract.Backend != jointDPGaussianBackend ||
		contract.BackendSelection != jointDPBiomedicalGaussianFullBackendSelection ||
		contract.OperationLimit || contract.RequestLimit ||
		contract.HistoryCanDenyOperation || contract.OpeningsAuthorized != 0 {
		return zeroCertificate, zeroPlan,
			fmt.Errorf("joint-dp-biomedical-gaussian-full: backend or release contract substitution")
	}
	message, err := jointDPBiomedicalGaussianDomainMessage(
		jointDPBiomedicalGaussianFullSelectionDomain, contract)
	if err != nil {
		return zeroCertificate, zeroPlan, err
	}
	if err := jointDPBiomedicalGaussianVerifySignatures(
		message, selection.Signatures, contract.CustodianPeers, pins,
		"independent-full backend selection"); err != nil {
		return zeroCertificate, zeroPlan, err
	}
	certificate, plan, _, _, err := jointDPBiomedicalGaussianFullPlan(
		manifest, pins, contract.Epsilon, contract.Delta)
	return certificate, plan, err
}

func jointDPBiomedicalGaussianFullPublicCertificate(
	contract jointDPBiomedicalGaussianFullSelectionContract,
	certificate jointDPBiomedicalGaussianSensitivityCertificate,
	plan jointDPGaussianPlanOutput,
) jointDPBiomedicalGaussianFullCertificate {
	return jointDPBiomedicalGaussianFullCertificate{
		Version:          jointDPBiomedicalGaussianFullCertificateVersion,
		Backend:          jointDPGaussianBackend,
		BackendSelection: jointDPBiomedicalGaussianFullBackendSelection,
		Mechanism:        jointDPGaussianMechanism, Sampler: jointDPGaussianSampler,
		ReleaseInstanceID:            contract.ReleaseInstanceID,
		ReleaseContractSHA256:        contract.ReleaseContractSHA256,
		SensitivityCertificateSHA256: contract.SensitivityCertificateSHA256,
		DerivedSensitivitySteps:      certificate.SelectedBoundSteps,
		EpsilonPerPeer:               contract.Epsilon,
		EpsilonPerPeerNumerator:      plan.EpsilonNumerator,
		EpsilonPerPeerDenominator:    plan.EpsilonDenominator,
		DeltaPerPeer:                 contract.Delta,
		DeltaPerPeerNumerator:        plan.AllocatedDeltaNumerator,
		DeltaPerPeerDenominator:      plan.AllocatedDeltaDenominator,
		CompleteEpsilonDeltaPerPeer:  true, EpsilonDividedByPeerCount: false,
		ReleaseDeltaAggregation:                "max_per_peer_not_sum",
		NominalVarianceMultiplier:              2,
		NominalStandardDeviationFactor:         "sqrt(2)_relative_to_one_full_draw",
		ThreatModel:                            "authenticated_semi_honest_pinned_custodians_two_designated_noise_peers_one_honest_noncolluding_v1",
		RequiresAtLeastOneHonestDesignatedPeer: true,
		IndependentNoiseRootCustodyRequired:    true,
		DistinctNoiseRootEpochsVerified:        true,
		MaximumColludingDesignatedPeers:        1,
		BothDesignatedCollusionProtected:       false,
		MaliciousCustodianSecurityClaim:        false,
		RelayTamperDetection:                   true,
		RelayAvailabilityGuaranteed:            false,
		AdversaryView:                          plan.AdversaryView,
		AdversaryViewPrivacyArgument:           plan.AdversaryViewPrivacyArgument,
		PrivacyTheorem:                         plan.PrivacyTheorem,
		SourceShareHidingPrecondition:          plan.SourceShareHidingPrecondition,
		FiniteSupportTransferCharged:           plan.FiniteSupportTransferCharged,
		FixedWorkSampler:                       plan.FixedWorkSampler,
		HostConstantTimeClaim:                  plan.HostConstantTimeClaim,
		TranscriptDPClaim:                      plan.TranscriptDPClaim,
		LogicalTranscriptFixedShape:            plan.LogicalTranscriptFixedShape,
		PhysicalTimingDPClaim:                  plan.PhysicalTimingDPClaim,
		NoWrapCertificate:                      jointDPBiomedicalGaussianFullNoWrap,
		NoWrapHeadroomCertified:                true,
		StickyIdentity:                         "release_materialization_snapshot_source_reservation_root_epochs_absolute_coordinate_v1",
		LedgerAppendBeforeReleaseBound:         true,
		ExactlyOnceFinalizerBound:              true,
		AutomaticFallbackUsed:                  false, OneDrawSubstituted: false,
		OpeningsPerformed: 0, ProductionReady: false,
		Blockers: append([]string(nil),
			jointDPBiomedicalGaussianFullCertificateBlockers...),
	}
}

func jointDPBiomedicalGaussianFullCloneSignatures(
	signatures []jointDPBiomedicalGaussianSignature,
) []jointDPBiomedicalGaussianSignature {
	result := make([]jointDPBiomedicalGaussianSignature, len(signatures))
	for index, signature := range signatures {
		result[index] = jointDPBiomedicalGaussianSignature{
			Signer:    signature.Signer,
			Signature: append([]byte(nil), signature.Signature...),
		}
	}
	return result
}

func jointDPBiomedicalGaussianFullCloneSelection(
	selection jointDPBiomedicalGaussianFullSelectionAttestation,
) jointDPBiomedicalGaussianFullSelectionAttestation {
	result := selection
	result.Contract.CustodianPeers = append([]string(nil),
		selection.Contract.CustodianPeers...)
	result.Contract.DesignatedComputePeers = append([]string(nil),
		selection.Contract.DesignatedComputePeers...)
	result.Contract.NoiseRootEpochs = append(
		[]jointDPBiomedicalGaussianNoiseRootEpoch(nil),
		selection.Contract.NoiseRootEpochs...)
	result.Contract.NoiseCommitments = append(
		[]jointDPBiomedicalGaussianFullNoiseCommitment(nil),
		selection.Contract.NoiseCommitments...)
	result.Contract.ReceiptReferences = append(
		[]jointDPBiomedicalGaussianReceiptReference(nil),
		selection.Contract.ReceiptReferences...)
	result.Signatures = jointDPBiomedicalGaussianFullCloneSignatures(
		selection.Signatures)
	return result
}

func jointDPBiomedicalGaussianFullCloneManifest(
	manifest jointDPBiomedicalGaussianManifestAttestation,
) jointDPBiomedicalGaussianManifestAttestation {
	result := manifest
	result.Contract.CustodianPeers = append([]string(nil),
		manifest.Contract.CustodianPeers...)
	result.Contract.DesignatedComputePeers = append([]string(nil),
		manifest.Contract.DesignatedComputePeers...)
	result.Contract.ScaleShifts = append([]int(nil),
		manifest.Contract.ScaleShifts...)
	result.Contract.RawUpperBounds = append([]string(nil),
		manifest.Contract.RawUpperBounds...)
	result.Contract.ContributionLayout =
		jointDPBiomedicalGaussianCloneContributionLayout(
			manifest.Contract.ContributionLayout)
	result.Signatures = jointDPBiomedicalGaussianFullCloneSignatures(
		manifest.Signatures)
	return result
}

func jointDPBiomedicalGaussianFullCloneCertificate(
	certificate jointDPBiomedicalGaussianSensitivityCertificate,
) jointDPBiomedicalGaussianSensitivityCertificate {
	result := certificate
	result.ContributionLayout =
		jointDPBiomedicalGaussianCloneContributionLayout(
			certificate.ContributionLayout)
	result.Components = append([]jointDPBiomedicalGaussianL2Component(nil),
		certificate.Components...)
	result.ShiftedUpperBounds = append([]string(nil),
		certificate.ShiftedUpperBounds...)
	return result
}

func jointDPBiomedicalGaussianFullAdmissionSeal(
	admission jointDPBiomedicalGaussianFullAdmission,
) ([32]byte, error) {
	contract := admission.selection.Contract
	formalSelectionSHA256 := ""
	if admission.formalSelection != nil {
		var err error
		formalSelectionSHA256, err = formalGLMPhase16BackendSelectionSHA256(
			*admission.formalSelection)
		if err != nil {
			return [32]byte{}, err
		}
	}
	return jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullAdmissionSealDomain, struct {
			SelectionContractSHA256   string `json:"selection_contract_sha256"`
			ManifestAttestationSHA256 string `json:"manifest_attestation_sha256"`
			SensitivitySHA256         string `json:"sensitivity_sha256"`
			PlanSHA256                string `json:"plan_sha256"`
			PublicCertificateSHA256   string `json:"public_certificate_sha256"`
			ReleaseInstanceID         string `json:"release_instance_id"`
			ReleaseContractSHA256     string `json:"release_contract_sha256"`
			PinsetSHA256              string `json:"pinset_sha256"`
			FormalSelectionSHA256     string `json:"formal_selection_sha256"`
		}{
			admission.SelectionContractSHA256,
			admission.manifestAttestationSHA256,
			contract.SensitivityCertificateSHA256,
			admission.planSHA256,
			admission.publicCertificateSHA256,
			contract.ReleaseInstanceID,
			contract.ReleaseContractSHA256,
			contract.PinsetSHA256,
			formalSelectionSHA256,
		})
}

func jointDPBiomedicalGaussianAdmitFullSelection(
	manifest jointDPBiomedicalGaussianManifestAttestation,
	selection jointDPBiomedicalGaussianFullSelectionAttestation,
	pins map[string]ed25519.PublicKey,
) (jointDPBiomedicalGaussianFullAdmission, error) {
	var zero jointDPBiomedicalGaussianFullAdmission
	certificate, plan, err := jointDPBiomedicalGaussianValidateFullSelection(
		manifest, selection, pins)
	if err != nil {
		return zero, err
	}
	selectionSHA256, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullSelectionDomain, selection.Contract)
	if err != nil {
		return zero, err
	}
	manifestAttestationSHA256, err :=
		jointDPBiomedicalGaussianFullManifestAttestationSHA256(manifest)
	if err != nil {
		return zero, err
	}
	planSHA256, err := jointDPBiomedicalGaussianHash(plan)
	if err != nil {
		return zero, err
	}
	publicCertificate := jointDPBiomedicalGaussianFullPublicCertificate(
		selection.Contract, certificate, plan)
	publicCertificateSHA256, err := jointDPBiomedicalGaussianHash(
		publicCertificate)
	if err != nil {
		return zero, err
	}
	admission := jointDPBiomedicalGaussianFullAdmission{
		Version:                   jointDPBiomedicalGaussianFullAdmissionVersion,
		SelectionContractSHA256:   hex.EncodeToString(selectionSHA256[:]),
		Certificate:               publicCertificate,
		selection:                 jointDPBiomedicalGaussianFullCloneSelection(selection),
		manifest:                  jointDPBiomedicalGaussianFullCloneManifest(manifest),
		certificate:               jointDPBiomedicalGaussianFullCloneCertificate(certificate),
		plan:                      plan,
		manifestAttestationSHA256: manifestAttestationSHA256,
		planSHA256:                planSHA256,
		publicCertificateSHA256:   publicCertificateSHA256,
	}
	admission.seal, err = jointDPBiomedicalGaussianFullAdmissionSeal(admission)
	if err != nil {
		return zero, err
	}
	return admission, nil
}

func jointDPBiomedicalGaussianValidateFullAdmission(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
) error {
	if admission.Version != jointDPBiomedicalGaussianFullAdmissionVersion {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid admission version")
	}
	if admission.formalSelection != nil || admission.formalBinding != nil ||
		admission.formalToken != nil {
		return jointDPBiomedicalGaussianValidateFullAdmissionCached(
			admission, pins)
	}
	certificate, plan, err := jointDPBiomedicalGaussianValidateFullSelection(
		admission.manifest, admission.selection, pins)
	if err != nil {
		return err
	}
	digest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullSelectionDomain,
		admission.selection.Contract)
	manifestAttestationSHA256, manifestErr :=
		jointDPBiomedicalGaussianFullManifestAttestationSHA256(
			admission.manifest)
	planSHA256, planErr := jointDPBiomedicalGaussianHash(plan)
	publicCertificate := jointDPBiomedicalGaussianFullPublicCertificate(
		admission.selection.Contract, certificate, plan)
	publicCertificateSHA256, publicErr :=
		jointDPBiomedicalGaussianHash(publicCertificate)
	seal, sealErr := jointDPBiomedicalGaussianFullAdmissionSeal(admission)
	if err != nil || manifestErr != nil || planErr != nil || publicErr != nil ||
		sealErr != nil || admission.SelectionContractSHA256 !=
		hex.EncodeToString(digest[:]) ||
		admission.manifestAttestationSHA256 != manifestAttestationSHA256 ||
		admission.planSHA256 != planSHA256 ||
		admission.publicCertificateSHA256 != publicCertificateSHA256 ||
		admission.seal != seal ||
		!reflect.DeepEqual(admission.certificate, certificate) ||
		!reflect.DeepEqual(admission.plan, plan) ||
		!reflect.DeepEqual(admission.Certificate, publicCertificate) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: mutated admission")
	}
	return nil
}

// A FullAdmission can only be constructed by the full K-of-K validator above;
// all private fields are absent from JSON.  Chunk workers therefore verify a
// compact in-process seal and the current local pinset instead of re-deriving
// an O(total-coordinate) sensitivity certificate for every 8192-coordinate
// chunk.  Cross-process reconstruction must call AdmitFullSelection again.
func jointDPBiomedicalGaussianValidateFullAdmissionCached(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
) error {
	contract := admission.selection.Contract
	pinsetSHA256, err := formalGLMPhase16PinsetSHA256(pins)
	if err != nil {
		return err
	}
	publicCertificateSHA256, publicErr :=
		jointDPBiomedicalGaussianHash(admission.Certificate)
	planSHA256, planErr := jointDPBiomedicalGaussianHash(admission.plan)
	selectionDigest, selectionErr := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullSelectionDomain, contract)
	seal, sealErr := jointDPBiomedicalGaussianFullAdmissionSeal(admission)
	formalFallback := admission.formalSelection != nil ||
		admission.formalBinding != nil || admission.formalToken != nil
	formalValid := !formalFallback
	if formalFallback && admission.formalSelection != nil &&
		admission.formalBinding != nil && admission.formalToken != nil {
		plans, formalErr := formalGLMPhase16ValidateBackendSelection(
			*admission.formalSelection, *admission.formalBinding,
			*admission.formalToken, pins)
		fullMessage, fullMessageErr := jointDPBiomedicalGaussianDomainMessage(
			formalGLMPhase16FullFallbackContractDomain, contract)
		fullSignatureErr := fullMessageErr
		if fullSignatureErr == nil {
			fullSignatureErr = jointDPBiomedicalGaussianVerifySignatures(
				fullMessage, admission.selection.Signatures,
				contract.CustodianPeers, pins,
				"formal GLM independent-full release contract")
		}
		binding := admission.formalBinding
		formalValid = formalErr == nil &&
			fullSignatureErr == nil &&
			admission.formalSelection.Contract.SelectedBackend ==
				formalGLMPhase16BackendFull &&
			reflect.DeepEqual(admission.plan, plans.Full) &&
			contract.BackendSelection ==
				formalGLMPhase16BackendSelectionPolicy &&
			contract.SensitivityCertificateSHA256 ==
				binding.SensitivityCertificateSHA256 &&
			admission.certificate.Kind ==
				binding.SensitivityCertificateKind &&
			admission.certificate.Status == "machine_proven" &&
			admission.certificate.Norm == "l2" &&
			admission.certificate.SelectedBoundSteps ==
				binding.SensitivitySteps &&
			reflect.DeepEqual(admission.certificate.ShiftedUpperBounds,
				binding.ShiftedUpperBounds) &&
			admission.Certificate.AutomaticFallbackUsed &&
			admission.Certificate.OneDrawSubstituted
	}
	standardValid := formalFallback ||
		(contract.BackendSelection ==
			jointDPBiomedicalGaussianFullBackendSelection &&
			!admission.Certificate.AutomaticFallbackUsed &&
			!admission.Certificate.OneDrawSubstituted)
	if publicErr != nil || planErr != nil || selectionErr != nil ||
		sealErr != nil || admission.SelectionContractSHA256 !=
		hex.EncodeToString(selectionDigest[:]) ||
		admission.Version != jointDPBiomedicalGaussianFullAdmissionVersion ||
		contract.Version != jointDPBiomedicalGaussianFullSelectionVersion ||
		contract.Backend != jointDPGaussianBackend ||
		!standardValid || !formalValid ||
		contract.PinsetSHA256 != pinsetSHA256 ||
		contract.ManifestAttestationSHA256 !=
			admission.manifestAttestationSHA256 ||
		contract.PlanSHA256 != admission.planSHA256 ||
		planSHA256 != admission.planSHA256 ||
		publicCertificateSHA256 != admission.publicCertificateSHA256 ||
		admission.Certificate.Backend != jointDPGaussianBackend ||
		admission.Certificate.ReleaseInstanceID != contract.ReleaseInstanceID ||
		admission.Certificate.ReleaseContractSHA256 !=
			contract.ReleaseContractSHA256 ||
		admission.Certificate.DerivedSensitivitySteps !=
			admission.certificate.SelectedBoundSteps ||
		admission.Certificate.OpeningsPerformed != 0 ||
		admission.Certificate.ProductionReady || admission.seal != seal {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid cached admission")
	}
	return nil
}

func jointDPBiomedicalGaussianFullIdentityFromContract(
	contract jointDPBiomedicalGaussianFullSelectionContract,
) jointDPBiomedicalGaussianFullReleaseIdentity {
	return jointDPBiomedicalGaussianFullReleaseIdentity{
		Backend:                   contract.Backend,
		ManifestAttestationSHA256: contract.ManifestAttestationSHA256,
		ManifestSHA256:            contract.ManifestSHA256,
		WorkloadSHA256:            contract.WorkloadSHA256,
		PinsetSHA256:              contract.PinsetSHA256,
		DesignatedComputePeers: append([]string(nil),
			contract.DesignatedComputePeers...),
		LogicalReleaseSHA256:        contract.LogicalReleaseSHA256,
		PrivacyEpochSHA256:          contract.PrivacyEpochSHA256,
		LogicalSnapshotHandleSHA256: contract.LogicalSnapshotHandleSHA256,
		SourceContractHandleSHA256:  contract.SourceContractHandleSHA256,
		MaterializationRootSHA256:   contract.MaterializationRootSHA256,
		ReservationSHA256:           contract.ReservationSHA256,
		Epsilon:                     contract.Epsilon, Delta: contract.Delta,
		PlanRequestBindingSHA256: contract.PlanRequestBindingSHA256,
		NoiseRootEpochs: append([]jointDPBiomedicalGaussianNoiseRootEpoch(nil),
			contract.NoiseRootEpochs...),
		ReceiptReferences: append([]jointDPBiomedicalGaussianReceiptReference(nil),
			contract.ReceiptReferences...),
		ReleaseInstanceID:      contract.ReleaseInstanceID,
		WorkerTranscriptSHA256: contract.WorkerTranscriptSHA256,
	}
}

func jointDPBiomedicalGaussianFullCommitment(
	contract jointDPBiomedicalGaussianFullSelectionContract, peerName string,
) (jointDPBiomedicalGaussianFullNoiseCommitment, error) {
	for _, commitment := range contract.NoiseCommitments {
		if commitment.PeerName == peerName {
			return commitment, nil
		}
	}
	return jointDPBiomedicalGaussianFullNoiseCommitment{},
		fmt.Errorf("joint-dp-biomedical-gaussian-full: peer is not a designated noise peer")
}

func jointDPBiomedicalGaussianFullSourceShareSHA256(
	admission jointDPBiomedicalGaussianFullAdmission, peerName string,
	chunkStart, coordinateCount int, sourceShare string,
) (string, error) {
	digest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullLocalSourceDomain+"/share", struct {
			SelectionContractSHA256 string `json:"selection_contract_sha256"`
			PeerName                string `json:"peer_name"`
			ChunkStart              int    `json:"chunk_start"`
			CoordinateCount         int    `json:"coordinate_count"`
			SourceShare             string `json:"source_share"`
		}{admission.SelectionContractSHA256, peerName, chunkStart,
			coordinateCount, sourceShare})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func jointDPBiomedicalGaussianFullLocalSourceBindingSHA256(
	binding jointDPBiomedicalGaussianFullLocalSourceBinding,
) (string, error) {
	digest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullLocalSourceDomain, struct {
			Version                     string                                    `json:"version"`
			SelectionContractSHA256     string                                    `json:"selection_contract_sha256"`
			LocalPeerName               string                                    `json:"local_peer_name"`
			ChunkStart                  int                                       `json:"chunk_start"`
			CoordinateCount             int                                       `json:"coordinate_count"`
			ReleaseInstanceID           string                                    `json:"release_instance_id"`
			LogicalSnapshotHandleSHA256 string                                    `json:"logical_snapshot_handle_sha256"`
			LocalSnapshotContractSHA256 string                                    `json:"local_snapshot_contract_sha256"`
			SourceContractHandleSHA256  string                                    `json:"source_contract_handle_sha256"`
			LocalSourceContractSHA256   string                                    `json:"local_source_contract_sha256"`
			MaterializationRootSHA256   string                                    `json:"materialization_root_sha256"`
			ReservationSHA256           string                                    `json:"reservation_sha256"`
			SourceShareSHA256           string                                    `json:"source_share_sha256"`
			MaterializationReceipt      jointDPBiomedicalGaussianReceiptReference `json:"materialization_receipt"`
			SourceContractReceipt       jointDPBiomedicalGaussianReceiptReference `json:"source_contract_receipt"`
		}{
			binding.Version, binding.SelectionContractSHA256,
			binding.LocalPeerName, binding.ChunkStart, binding.CoordinateCount,
			binding.ReleaseInstanceID, binding.LogicalSnapshotHandleSHA256,
			binding.LocalSnapshotContractSHA256,
			binding.SourceContractHandleSHA256,
			binding.LocalSourceContractSHA256,
			binding.MaterializationRootSHA256, binding.ReservationSHA256,
			binding.SourceShareSHA256, binding.MaterializationReceipt,
			binding.SourceContractReceipt,
		})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func jointDPBiomedicalGaussianBuildFullLocalSourceBinding(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	peerName, localSnapshotContractSHA256,
	localSourceContractSHA256 string,
	chunkStart, coordinateCount int, sourceShare string,
) (jointDPBiomedicalGaussianFullLocalSourceBinding, error) {
	var zero jointDPBiomedicalGaussianFullLocalSourceBinding
	if err := jointDPBiomedicalGaussianValidateFullAdmissionCached(
		admission, pins); err != nil {
		return zero, err
	}
	contract := admission.selection.Contract
	if _, err := jointDPBiomedicalGaussianFullCommitment(
		contract, peerName); err != nil {
		return zero, err
	}
	if !jointDPBiomedicalGaussianIsSHA256(localSnapshotContractSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(localSourceContractSHA256) ||
		coordinateCount < 1 || coordinateCount > contract.MaximumChunkCoordinates ||
		chunkStart < 0 ||
		chunkStart > contract.TotalCoordinateCount-coordinateCount {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid local source handoff")
	}
	decoded, err := jointDPVectorConvolutionCanonicalBase64(
		sourceShare, "biomedical Gaussian local source share",
		16*coordinateCount)
	if err != nil {
		return zero, err
	}
	clear(decoded)
	shareSHA256, err := jointDPBiomedicalGaussianFullSourceShareSHA256(
		admission, peerName, chunkStart, coordinateCount, sourceShare)
	if err != nil {
		return zero, err
	}
	materialization, err := jointDPBiomedicalGaussianFullReceipt(
		contract.ReceiptReferences,
		jointDPBiomedicalGaussianReceiptMaterialization)
	if err != nil {
		return zero, err
	}
	sourceContract, err := jointDPBiomedicalGaussianFullReceipt(
		contract.ReceiptReferences,
		jointDPBiomedicalGaussianReceiptSourceContract)
	if err != nil {
		return zero, err
	}
	binding := jointDPBiomedicalGaussianFullLocalSourceBinding{
		Version:                 jointDPBiomedicalGaussianFullLocalSourceVersion,
		SelectionContractSHA256: admission.SelectionContractSHA256,
		LocalPeerName:           peerName,
		ChunkStart:              chunkStart, CoordinateCount: coordinateCount,
		ReleaseInstanceID:           contract.ReleaseInstanceID,
		LogicalSnapshotHandleSHA256: contract.LogicalSnapshotHandleSHA256,
		LocalSnapshotContractSHA256: localSnapshotContractSHA256,
		SourceContractHandleSHA256:  contract.SourceContractHandleSHA256,
		LocalSourceContractSHA256:   localSourceContractSHA256,
		MaterializationRootSHA256:   contract.MaterializationRootSHA256,
		ReservationSHA256:           contract.ReservationSHA256,
		SourceShareSHA256:           shareSHA256,
		MaterializationReceipt:      materialization,
		SourceContractReceipt:       sourceContract,
	}
	binding.BindingSHA256, err =
		jointDPBiomedicalGaussianFullLocalSourceBindingSHA256(binding)
	if err != nil {
		return zero, err
	}
	return binding, nil
}

func jointDPBiomedicalGaussianValidateFullLocalSourceBinding(
	admission jointDPBiomedicalGaussianFullAdmission,
	binding jointDPBiomedicalGaussianFullLocalSourceBinding,
	peerName, sourceShare string,
) error {
	contract := admission.selection.Contract
	wantBindingSHA256, err :=
		jointDPBiomedicalGaussianFullLocalSourceBindingSHA256(binding)
	if err != nil {
		return err
	}
	wantShareSHA256, err := jointDPBiomedicalGaussianFullSourceShareSHA256(
		admission, peerName, binding.ChunkStart,
		binding.CoordinateCount, sourceShare)
	if err != nil {
		return err
	}
	materialization, _ := jointDPBiomedicalGaussianFullReceipt(
		contract.ReceiptReferences,
		jointDPBiomedicalGaussianReceiptMaterialization)
	sourceContract, _ := jointDPBiomedicalGaussianFullReceipt(
		contract.ReceiptReferences,
		jointDPBiomedicalGaussianReceiptSourceContract)
	if binding.Version != jointDPBiomedicalGaussianFullLocalSourceVersion ||
		binding.BindingSHA256 != wantBindingSHA256 ||
		binding.SelectionContractSHA256 != admission.SelectionContractSHA256 ||
		binding.LocalPeerName != peerName ||
		binding.ReleaseInstanceID != contract.ReleaseInstanceID ||
		binding.LogicalSnapshotHandleSHA256 !=
			contract.LogicalSnapshotHandleSHA256 ||
		!jointDPBiomedicalGaussianIsSHA256(
			binding.LocalSnapshotContractSHA256) ||
		binding.SourceContractHandleSHA256 !=
			contract.SourceContractHandleSHA256 ||
		!jointDPBiomedicalGaussianIsSHA256(
			binding.LocalSourceContractSHA256) ||
		binding.MaterializationRootSHA256 != contract.MaterializationRootSHA256 ||
		binding.ReservationSHA256 != contract.ReservationSHA256 ||
		binding.SourceShareSHA256 != wantShareSHA256 ||
		!reflect.DeepEqual(binding.MaterializationReceipt, materialization) ||
		!reflect.DeepEqual(binding.SourceContractReceipt, sourceContract) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: unbound or substituted local source share")
	}
	return nil
}

func jointDPBiomedicalGaussianFullShareInput(
	admission jointDPBiomedicalGaussianFullAdmission,
	binding jointDPBiomedicalGaussianFullLocalSourceBinding,
	peerName string, root [32]byte, sourceShare string,
) (jointDPGaussianShareInput, error) {
	contract := admission.selection.Contract
	chunkStart := binding.ChunkStart
	coordinateCount := binding.CoordinateCount
	if err := jointDPBiomedicalGaussianValidateFullLocalSourceBinding(
		admission, binding, peerName, sourceShare); err != nil {
		return jointDPGaussianShareInput{}, err
	}
	if coordinateCount < 1 || coordinateCount > contract.MaximumChunkCoordinates ||
		chunkStart < 0 ||
		chunkStart > contract.TotalCoordinateCount-coordinateCount {
		return jointDPGaussianShareInput{},
			fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid chunk geometry")
	}
	commitment, err := jointDPBiomedicalGaussianFullCommitment(contract, peerName)
	if err != nil {
		return jointDPGaussianShareInput{}, err
	}
	seed, context, seedCommitment, err :=
		jointDPBiomedicalGaussianFullSeedMaterial(
			root, peerName,
			jointDPBiomedicalGaussianFullIdentityFromContract(contract))
	if err != nil {
		return jointDPGaussianShareInput{}, err
	}
	defer clear(seed[:])
	if context != commitment.ContextSHA256 ||
		seedCommitment != commitment.SeedSHA256 {
		return jointDPGaussianShareInput{},
			fmt.Errorf("joint-dp-biomedical-gaussian-full: local root does not match the K-signed commitment")
	}
	shifts := make([]int, coordinateCount)
	bounds := append([]string(nil),
		admission.certificate.ShiftedUpperBounds[chunkStart:chunkStart+coordinateCount]...)
	return jointDPGaussianShareInput{
		Version: jointDPGaussianInputVersion, RingBits: 128, FracBits: 0,
		TotalCoordinateCount: contract.TotalCoordinateCount,
		ChunkStart:           chunkStart, CoordinateCount: coordinateCount,
		OutputLatticeBits: contract.OutputLatticeBits,
		Epsilon:           contract.Epsilon, AllocatedDelta: contract.Delta,
		L2SensitivitySteps: admission.certificate.SelectedBoundSteps,
		ScaleShifts:        shifts, RawUpperBounds: bounds,
		ReleaseContractHash: contract.ReleaseContractSHA256,
		TranscriptHash:      contract.WorkerTranscriptSHA256,
		PeerName:            peerName, CommitmentContext: context,
		SeedCommitment: seedCommitment, PrivateSeed: hex.EncodeToString(seed[:]),
		SourceShare: sourceShare,
	}, nil
}

func jointDPBiomedicalGaussianValidateFullPeerOutput(
	admission jointDPBiomedicalGaussianFullAdmission,
	output jointDPGaussianShareOutput,
) error {
	contract := admission.selection.Contract
	commitment, err := jointDPBiomedicalGaussianFullCommitment(
		contract, output.PeerName)
	if err != nil {
		return err
	}
	if output.Version != jointDPGaussianOutputVersion ||
		output.Backend != jointDPGaussianBackend ||
		output.Mechanism != jointDPGaussianMechanism ||
		output.Sampler != jointDPGaussianSampler ||
		output.ReleaseContractHash != contract.ReleaseContractSHA256 ||
		output.TranscriptHash != contract.WorkerTranscriptSHA256 ||
		output.SeedCommitment != commitment.SeedSHA256 ||
		output.RingBits != 128 || output.FracBits != 0 ||
		output.TotalCoordinateCount != contract.TotalCoordinateCount ||
		output.CoordinateCount < 1 || output.ChunkStart < 0 ||
		output.ChunkStart > contract.TotalCoordinateCount-output.CoordinateCount ||
		!output.FullCapsuleParametersPerPeer || output.EpsilonDividedByPeerCount ||
		output.SourceValuesReturned || output.NoiseValuesReturned ||
		output.PrivateSeedReturned || output.PreclampValuesReturned ||
		!output.NoWrapHeadroomCertified || !output.TailTruncationApplied ||
		!output.FixedWorkShapeVerified || output.NominalVarianceMultiplier != 2 ||
		!reflect.DeepEqual(output.Plan, admission.plan) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: substituted or malformed peer output")
	}
	shifts := make([]int, output.CoordinateCount)
	bounds := append([]string(nil), admission.certificate.ShiftedUpperBounds[output.ChunkStart:output.ChunkStart+output.CoordinateCount]...)
	expectedDigest := jointDPGaussianContractDigest(jointDPGaussianShareInput{
		RingBits: 128, FracBits: 0,
		TotalCoordinateCount: contract.TotalCoordinateCount,
		OutputLatticeBits:    contract.OutputLatticeBits,
		Epsilon:              contract.Epsilon, AllocatedDelta: contract.Delta,
		L2SensitivitySteps: admission.certificate.SelectedBoundSteps,
		ScaleShifts:        shifts, RawUpperBounds: bounds,
		ReleaseContractHash: contract.ReleaseContractSHA256,
		TranscriptHash:      contract.WorkerTranscriptSHA256,
		PeerName:            output.PeerName,
		CommitmentContext:   commitment.ContextSHA256,
		SeedCommitment:      commitment.SeedSHA256,
	}, admission.plan)
	if output.SamplerContractHash != hex.EncodeToString(expectedDigest[:]) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: sampler contract substitution")
	}
	decoded, err := jointDPVectorConvolutionCanonicalBase64(
		output.NoisedShare, "biomedical Gaussian noised share",
		16*output.CoordinateCount)
	if err != nil {
		return err
	}
	clear(decoded)
	return nil
}

func jointDPBiomedicalGaussianFullPeerShareMessage(
	share jointDPBiomedicalGaussianFullPeerShare,
) ([]byte, error) {
	return jointDPBiomedicalGaussianDomainMessage(
		jointDPBiomedicalGaussianFullPeerShareDomain, struct {
			Version                 string `json:"version"`
			Backend                 string `json:"backend"`
			SelectionContractSHA256 string `json:"selection_contract_sha256"`
			ReleaseInstanceID       string `json:"release_instance_id"`
			ReleaseContractSHA256   string `json:"release_contract_sha256"`
			PeerName                string `json:"peer_name"`
			ChunkStart              int    `json:"chunk_start"`
			CoordinateCount         int    `json:"coordinate_count"`
			OutputSHA256            string `json:"output_sha256"`
			SourceBindingSHA256     string `json:"source_binding_sha256"`
		}{
			share.Version, share.Backend,
			share.binding.SelectionContractSHA256,
			share.ReleaseInstanceID, share.ReleaseContractSHA256,
			share.PeerName, share.ChunkStart, share.CoordinateCount,
			share.OutputSHA256, share.SourceBindingSHA256,
		})
}

func jointDPBiomedicalGaussianValidateFullPeerShare(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	share jointDPBiomedicalGaussianFullPeerShare,
) error {
	contract := admission.selection.Contract
	if share.Version != jointDPBiomedicalGaussianFullPeerShareVersion ||
		share.Backend != jointDPGaussianBackend ||
		share.ReleaseInstanceID != contract.ReleaseInstanceID ||
		share.ReleaseContractSHA256 != contract.ReleaseContractSHA256 ||
		share.PeerName != share.output.PeerName ||
		share.ChunkStart != share.output.ChunkStart ||
		share.CoordinateCount != share.output.CoordinateCount ||
		share.binding.SelectionContractSHA256 !=
			admission.SelectionContractSHA256 ||
		share.binding.LocalPeerName != share.PeerName ||
		share.binding.ChunkStart != share.ChunkStart ||
		share.binding.CoordinateCount != share.CoordinateCount ||
		len(share.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: malformed signed peer share")
	}
	if err := jointDPBiomedicalGaussianValidateFullPeerOutput(
		admission, share.output); err != nil {
		return err
	}
	outputSHA256, err := jointDPBiomedicalGaussianHash(share.output)
	if err != nil || outputSHA256 != share.OutputSHA256 {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: peer output digest mismatch")
	}
	bindingSHA256, err :=
		jointDPBiomedicalGaussianFullLocalSourceBindingSHA256(share.binding)
	if err != nil || bindingSHA256 != share.SourceBindingSHA256 ||
		bindingSHA256 != share.binding.BindingSHA256 {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: peer source binding mismatch")
	}
	pin, ok := pins[share.PeerName]
	message, messageErr := jointDPBiomedicalGaussianFullPeerShareMessage(share)
	if !ok || len(pin) != ed25519.PublicKeySize || messageErr != nil ||
		!ed25519.Verify(pin, message, share.Signature) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: peer share signature verification failed")
	}
	return nil
}

func jointDPBiomedicalGaussianRunFullPeer(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	binding jointDPBiomedicalGaussianFullLocalSourceBinding,
	peerName string, root [32]byte, signer ed25519.PrivateKey,
	sourceShare string,
) (jointDPBiomedicalGaussianFullPeerShare, error) {
	var zero jointDPBiomedicalGaussianFullPeerShare
	if err := jointDPBiomedicalGaussianValidateFullAdmissionCached(
		admission, pins); err != nil {
		return zero, err
	}
	if len(signer) != ed25519.PrivateKeySize {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid local peer signer")
	}
	publicKey, ok := signer.Public().(ed25519.PublicKey)
	if !ok || !hmac.Equal(publicKey, pins[peerName]) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: local signer is not the pinned peer")
	}
	input, err := jointDPBiomedicalGaussianFullShareInput(
		admission, binding, peerName, root, sourceShare)
	if err != nil {
		return zero, err
	}
	output, err := jointDPGaussianSampleShare(input)
	input.PrivateSeed = ""
	input.SourceShare = ""
	if err != nil {
		return zero, err
	}
	if err := jointDPBiomedicalGaussianValidateFullPeerOutput(
		admission, output); err != nil {
		return zero, err
	}
	outputSHA256, err := jointDPBiomedicalGaussianHash(output)
	if err != nil {
		return zero, err
	}
	share := jointDPBiomedicalGaussianFullPeerShare{
		Version:               jointDPBiomedicalGaussianFullPeerShareVersion,
		Backend:               jointDPGaussianBackend,
		ReleaseInstanceID:     admission.selection.Contract.ReleaseInstanceID,
		ReleaseContractSHA256: admission.selection.Contract.ReleaseContractSHA256,
		PeerName:              peerName, ChunkStart: binding.ChunkStart,
		CoordinateCount:     binding.CoordinateCount,
		OutputSHA256:        outputSHA256,
		SourceBindingSHA256: binding.BindingSHA256,
		output:              output, binding: binding,
	}
	message, err := jointDPBiomedicalGaussianFullPeerShareMessage(share)
	if err != nil {
		return zero, err
	}
	share.Signature = ed25519.Sign(signer, message)
	if err := jointDPBiomedicalGaussianValidateFullPeerShare(
		admission, pins, share); err != nil {
		return zero, err
	}
	return share, nil
}

func jointDPBiomedicalGaussianBuildFullFinalizerHandoff(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	first, second jointDPBiomedicalGaussianFullPeerShare,
) (jointDPBiomedicalGaussianFullFinalizerHandoff, error) {
	var zero jointDPBiomedicalGaussianFullFinalizerHandoff
	if err := jointDPBiomedicalGaussianValidateFullAdmissionCached(
		admission, pins); err != nil {
		return zero, err
	}
	if err := jointDPBiomedicalGaussianValidateFullPeerShare(
		admission, pins, first); err != nil {
		return zero, err
	}
	if err := jointDPBiomedicalGaussianValidateFullPeerShare(
		admission, pins, second); err != nil {
		return zero, err
	}
	contract := admission.selection.Contract
	peers := contract.DesignatedComputePeers
	outputs := map[string]jointDPBiomedicalGaussianFullPeerShare{
		first.PeerName: first, second.PeerName: second,
	}
	left, leftOK := outputs[peers[0]]
	right, rightOK := outputs[peers[1]]
	if !leftOK || !rightOK || len(outputs) != 2 ||
		left.ChunkStart != right.ChunkStart ||
		left.CoordinateCount != right.CoordinateCount {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: incomplete or mismatched peer outputs")
	}
	ledger, err := jointDPBiomedicalGaussianFullReceipt(
		contract.ReceiptReferences, jointDPBiomedicalGaussianReceiptPrivacyLedger)
	if err != nil || ledger.SHA256 != contract.ReservationSHA256 {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: append-before-release reservation mismatch")
	}
	finalizer, err := jointDPBiomedicalGaussianFullReceipt(
		contract.ReceiptReferences, jointDPBiomedicalGaussianReceiptFinalizer)
	if err != nil {
		return zero, err
	}
	leftOutput := left.output
	rightOutput := right.output
	shifts := make([]int, left.CoordinateCount)
	bounds := append([]string(nil), admission.certificate.ShiftedUpperBounds[left.ChunkStart:left.ChunkStart+left.CoordinateCount]...)
	return jointDPBiomedicalGaussianFullFinalizerHandoff{
		Version:                    jointDPBiomedicalGaussianFullFinalizerHandoffVersion,
		Backend:                    jointDPGaussianBackend,
		ReleaseInstanceID:          contract.ReleaseInstanceID,
		ReleaseContractSHA256:      contract.ReleaseContractSHA256,
		LedgerReservationSHA256:    ledger.SHA256,
		FinalizerReservationSHA256: finalizer.SHA256,
		OpeningAuthorized:          false, OpeningsPerformed: 0, ProductionReady: false,
		Blockers: append([]string(nil),
			jointDPBiomedicalGaussianFullFinalizerBlockers...),
		finalizerInput: jointDPGaussianFinalizerInput{
			Version:  jointDPGaussianFinalizerInputVersion,
			RingBits: 128, FracBits: 0,
			TotalCoordinateCount: contract.TotalCoordinateCount,
			ChunkStart:           left.ChunkStart,
			CoordinateCount:      left.CoordinateCount,
			OutputLatticeBits:    contract.OutputLatticeBits,
			Epsilon:              contract.Epsilon, AllocatedDelta: contract.Delta,
			L2SensitivitySteps: admission.certificate.SelectedBoundSteps,
			ScaleShifts:        shifts, RawUpperBounds: bounds,
			ReleaseContractHash: contract.ReleaseContractSHA256,
			TranscriptHash:      contract.WorkerTranscriptSHA256,
			LeftNoisedShare:     leftOutput.NoisedShare,
			RightNoisedShare:    rightOutput.NoisedShare,
		},
	}, nil
}
