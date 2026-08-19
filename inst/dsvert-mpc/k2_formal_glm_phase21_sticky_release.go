package main

// Purpose-bound, server-local publication of the Phase-2.1 formal-GLM DP
// result.  The store contains only a clean public projection signed by both
// designated noise authorities.  The legacy finalizer certificate is
// validated in memory and represented here only by a domain-separated hash;
// its reservation records and all protected shares remain outside this store.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/hkdf"
)

const (
	formalGLMPhase21StickyVersion        = "formal-glm-sticky-release-v1"
	formalGLMPhase21StickyPurpose        = "formal_glm_canonical_artifact_public_dp_release_v1"
	formalGLMPhase21StickyDomain         = "dsVert/formal-glm/phase21/sticky-release/v1"
	formalGLMPhase21StickyRecordVersion  = "dsvert-formal-glm-phase21-sticky-record-v1"
	formalGLMPhase21StickySignerVersion  = "dsvert-formal-glm-phase21-sticky-signer-v1"
	formalGLMPhase21StickyMaxBytes       = 4 << 20
	formalGLMPhase21StickySignerMaxBytes = 32 << 10

	formalGLMPhase21SamplerV2Version       = "dsvert-formal-glm-sampler-contract-v2"
	formalGLMPhase21SamplerV2Purpose       = "formal_glm_canonical_artifact_sampler_v2"
	formalGLMPhase21SamplerV2Domain        = "dsVert/formal-glm/phase21/sampler/v2"
	formalGLMPhase21SamplerV2GuardVersion  = "dsvert-formal-glm-sampler-guard-v2"
	formalGLMPhase21SamplerV2GuardMaxBytes = 128 << 10

	formalGLMPhase21DurableV2Version  = "dsvert-formal-glm-durable-publication-v2"
	formalGLMPhase21DurableV2Purpose  = "formal_glm_canonical_artifact_durable_publication_v2"
	formalGLMPhase21DurableV2Domain   = "dsVert/formal-glm/phase21/durable-publication/v2"
	formalGLMPhase21DurableV2MaxBytes = 4 << 20
)

const (
	formalGLMPhase21SamplerV2OneDraw = "one_draw_exact_gc_v2"
	formalGLMPhase21SamplerV2Full    = "independent_full_v2"
)

type formalGLMPhase21SamplerV2Commitment struct {
	Role                    string `json:"role"`
	PeerName                string `json:"peer_name"`
	PeerID                  string `json:"peer_id"`
	SamplerPurpose          string `json:"sampler_purpose"`
	CommitmentContextSHA256 string `json:"commitment_context_sha256"`
	SeedCommitmentSHA256    string `json:"seed_commitment_sha256"`
}

type formalGLMPhase21SamplerV2Authorization struct {
	Version                        string `json:"version"`
	Purpose                        string `json:"purpose"`
	ArtifactID                     string `json:"artifact_id"`
	ContractSHA256                 string `json:"contract_sha256"`
	PeerName                       string `json:"peer_name"`
	Role                           string `json:"role"`
	PredecessorAuthorizationSHA256 string `json:"predecessor_authorization_sha256,omitempty"`
	Signature                      []byte `json:"signature"`
}

// formalGLMPhase21SamplerV2Contract is the K-of-K public authorization for
// exactly one purpose-bound sampler implementation. Operational run IDs,
// epochs, reservations, backend handoffs and legacy receipt references are
// deliberately absent: they remain evidence of the first execution only.
type formalGLMPhase21SamplerV2Contract struct {
	Version             string                                `json:"version"`
	Purpose             string                                `json:"purpose"`
	ArtifactID          string                                `json:"artifact_id"`
	Artifact            formalGLMPhase21StickyArtifact        `json:"artifact"`
	SamplerMode         string                                `json:"sampler_mode"`
	PinsetSHA256        string                                `json:"pinset_sha256"`
	CustodianPeers      []string                              `json:"custodian_peers"`
	CustodianCount      int                                   `json:"custodian_count"`
	NoiseCommitments    []formalGLMPhase21SamplerV2Commitment `json:"noise_commitments"`
	ProductionReady     bool                                  `json:"production_ready"`
	CustodianSignatures []jointDPBiomedicalGaussianSignature  `json:"custodian_signatures"`
}

type formalGLMPhase21SamplerV2GuardRecord struct {
	Version                        string                                 `json:"version"`
	Purpose                        string                                 `json:"purpose"`
	Peer                           string                                 `json:"peer"`
	Role                           string                                 `json:"role"`
	ArtifactID                     string                                 `json:"artifact_id"`
	ContractSHA256                 string                                 `json:"contract_sha256"`
	ContractJSON                   string                                 `json:"contract_json"`
	PredecessorAuthorizationSHA256 string                                 `json:"predecessor_authorization_sha256,omitempty"`
	Authorization                  formalGLMPhase21SamplerV2Authorization `json:"authorization"`
	RecordMAC                      string                                 `json:"record_mac"`
}

type formalGLMPhase21SamplerV2HandoffResult struct {
	Publication formalGLMPhase21StickyPublication
	Handoff     formalGLMPhase20HandoffCommit
	Replayed    bool
}

type formalGLMPhase21StickyNoiseAuthority struct {
	Role     string `json:"role"`
	PeerName string `json:"peer_name"`
	PeerID   string `json:"peer_id"`
}

type formalGLMPhase21StickyNoiseEvidence struct {
	Role                    string `json:"role"`
	PeerName                string `json:"peer_name"`
	PeerID                  string `json:"peer_id"`
	CommitmentContextSHA256 string `json:"commitment_context_sha256"`
	SeedCommitmentSHA256    string `json:"seed_commitment_sha256"`
}

type formalGLMPhase21CanonicalPlan struct {
	Version                string   `json:"version"`
	CanonicalScienceSHA256 string   `json:"canonical_science_sha256"`
	CanonicalLinkSHA256    string   `json:"canonical_link_sha256"`
	Family                 string   `json:"family"`
	TotalCapacity          int      `json:"total_capacity"`
	Iterations             int      `json:"iterations"`
	CoordinateOwners       []string `json:"coordinate_owners"`
	FractionBits           int      `json:"fraction_bits"`
	CoefficientCount       int      `json:"coefficient_count"`
	ReductionOrder         string   `json:"reduction_order"`
	Truncation             string   `json:"truncation"`
	Missingness            string   `json:"missingness"`
	PatientCollapse        string   `json:"patient_collapse"`
}

// CanonicalScienceSHA256 is the separately validated Phase-0 projection of
// formula, estimand, factor domains, optimizer, numeric grid and DP semantics.
// The full signed Phase-0 artifact remains publication evidence, but its
// compiler/status/capsule fields cannot split this sticky identity.
type formalGLMPhase21StickyArtifact struct {
	Version                 string                                 `json:"version"`
	Purpose                 string                                 `json:"purpose"`
	CanonicalScienceSHA256  string                                 `json:"canonical_science_sha256"`
	DescriptorCoreSHA256    string                                 `json:"descriptor_core_sha256,omitempty"`
	ScientificArtifactScope string                                 `json:"scientific_artifact_scope"`
	CanonicalPlanSHA256     string                                 `json:"canonical_plan_sha256"`
	SchemaManifestSHA256    string                                 `json:"schema_manifest_sha256"`
	SnapshotSHA256          string                                 `json:"snapshot_sha256"`
	PinsetSHA256            string                                 `json:"pinset_sha256"`
	CustodianPeers          []string                               `json:"custodian_peers"`
	CustodianCount          int                                    `json:"custodian_count"`
	DesignatedComputePeers  []string                               `json:"designated_compute_peers"`
	NoiseAuthorities        []formalGLMPhase21StickyNoiseAuthority `json:"noise_authorities"`
	Family                  string                                 `json:"family"`
	Adjacency               string                                 `json:"adjacency"`
	Mechanism               string                                 `json:"mechanism"`
	Allocation              string                                 `json:"allocation"`
	EpsilonRational         string                                 `json:"epsilon_rational"`
	DeltaRational           string                                 `json:"delta_rational"`
	SensitivitySteps        string                                 `json:"l2_sensitivity_steps"`
	BoundsSHA256            string                                 `json:"bounds_sha256"`
	QuantizationSHA256      string                                 `json:"quantization_sha256"`
	CanonicalLinkSHA256     string                                 `json:"canonical_link_sha256"`
	CoordinateOrderSHA256   string                                 `json:"coordinate_order_sha256"`
	CoordinateCount         int                                    `json:"coordinate_count"`
	SourceFractionBits      int                                    `json:"source_fraction_bits"`
	QuantizationShift       int                                    `json:"quantization_shift"`
	OutputLatticeBits       int                                    `json:"output_lattice_bits"`
}

type formalGLMPhase21StickyCertificate struct {
	Version                        string                                `json:"version"`
	Purpose                        string                                `json:"purpose"`
	ArtifactID                     string                                `json:"artifact_id"`
	Artifact                       formalGLMPhase21StickyArtifact        `json:"artifact"`
	SamplerV2Contract              *formalGLMPhase21SamplerV2Contract    `json:"sampler_v2_contract,omitempty"`
	SourceScientificArtifactSHA256 string                                `json:"source_scientific_artifact_sha256"`
	SourceWorkloadSHA256           string                                `json:"source_workload_sha256"`
	SourceContextSHA256            string                                `json:"source_context_sha256"`
	SourceLinkTableSHA256          string                                `json:"source_link_table_sha256"`
	Phase15PlanSHA256              string                                `json:"phase15_plan_sha256"`
	KernelSpecSHA256               string                                `json:"kernel_spec_sha256"`
	CapsuleID                      string                                `json:"capsule_id"`
	ManifestSHA256                 string                                `json:"manifest_sha256"`
	ReleaseBindingSHA256           string                                `json:"release_binding_sha256"`
	BackendSelectionSHA256         string                                `json:"backend_selection_sha256"`
	SourceReleaseContractSHA256    string                                `json:"source_release_contract_sha256"`
	NoiseCommitmentEvidence        []formalGLMPhase21StickyNoiseEvidence `json:"noise_commitment_evidence"`
	SourceCertificateSHA256        string                                `json:"source_certificate_sha256"`
	CustodianApprovalSetSHA256     string                                `json:"custodian_approval_set_sha256"`
	SourceAuthoritySetSHA256       string                                `json:"source_authority_set_sha256"`
	SourceReleaseInstanceID        string                                `json:"source_release_instance_id"`
	DPReleaseInstanceID            string                                `json:"dp_release_instance_id"`
	ReleaseContractSHA256          string                                `json:"release_contract_sha256"`
	Family                         string                                `json:"family"`
	SelectedBackend                string                                `json:"selected_backend"`
	SelectionReason                string                                `json:"selection_reason"`
	NominalVarianceMultiplier      int                                   `json:"nominal_variance_multiplier"`
	NominalStandardDeviation       string                                `json:"nominal_standard_deviation_factor"`
	Simultaneous95AbsSteps         string                                `json:"simultaneous_95_abs_steps"`
	Epsilon                        string                                `json:"epsilon"`
	Delta                          string                                `json:"delta"`
	L2SensitivitySteps             string                                `json:"l2_sensitivity_steps"`
	SensitivityCertificateSHA256   string                                `json:"sensitivity_certificate_sha256"`
	OutputLatticeBits              int                                   `json:"output_lattice_bits"`
	NoWrapCertificate              string                                `json:"no_wrap_certificate"`
	VectorSHA256                   string                                `json:"vector_sha256"`
	ClampedScaledValues            []string                              `json:"clamped_scaled_values"`
	PrivacyScope                   string                                `json:"privacy_scope"`
	GlobalCompositionClaim         bool                                  `json:"global_composition_claim"`
	SingleCommonDPVector           bool                                  `json:"single_common_dp_vector"`
	ExactlyOnceDPOpening           bool                                  `json:"exactly_once_dp_opening"`
	DurablePublicationProtocol     string                                `json:"durable_publication_protocol,omitempty"`
	UnlimitedDeterministicReplay   bool                                  `json:"unlimited_deterministic_replay"`
	UnlimitedPostprocessing        bool                                  `json:"unlimited_postprocessing"`
	HistoryCanDenyOperation        bool                                  `json:"history_can_deny_operation"`
	AdmissionPolicy                string                                `json:"admission_policy"`
	OpeningsPerformed              int                                   `json:"openings_performed"`
	ReplayReadsSource              bool                                  `json:"replay_reads_source"`
	ReplayInvokesSampler           bool                                  `json:"replay_invokes_sampler"`
	ReplayInvokesFinalizer         bool                                  `json:"replay_invokes_finalizer"`
	ProductionReady                bool                                  `json:"production_ready"`
	Blockers                       []string                              `json:"blockers"`
	AuthorityReceipts              []jointDPBiomedicalGaussianSignature  `json:"authority_receipts"`
}

type formalGLMPhase21StickyRecord struct {
	Version           string `json:"version"`
	Purpose           string `json:"purpose"`
	Peer              string `json:"peer"`
	ArtifactID        string `json:"artifact_id"`
	CertificateSHA256 string `json:"certificate_sha256"`
	CertificateJSON   string `json:"certificate_json"`
	RecordMAC         string `json:"record_mac"`
}

type formalGLMPhase21StickySignerRecord struct {
	Version                  string `json:"version"`
	Purpose                  string `json:"purpose"`
	Peer                     string `json:"peer"`
	Role                     string `json:"role"`
	ArtifactID               string `json:"artifact_id"`
	CertificateSHA256        string `json:"certificate_sha256"`
	PredecessorReceiptSHA256 string `json:"predecessor_receipt_sha256,omitempty"`
	Signature                []byte `json:"signature"`
	RecordMAC                string `json:"record_mac"`
}

type formalGLMPhase21StickyPublication struct {
	ArtifactID        string
	CertificateSHA256 string
	Certificate       []byte
	Replayed          bool
}

type formalGLMPhase21DurableV2SpoolRecord struct {
	Version           string `json:"version"`
	Purpose           string `json:"purpose"`
	Peer              string `json:"peer"`
	ArtifactID        string `json:"artifact_id"`
	ContractSHA256    string `json:"contract_sha256"`
	CertificateSHA256 string `json:"certificate_sha256"`
	Nonce             string `json:"nonce"`
	Ciphertext        string `json:"ciphertext"`
}

type formalGLMPhase21DurableV2AckRecord struct {
	Version           string `json:"version"`
	Purpose           string `json:"purpose"`
	Peer              string `json:"peer"`
	ArtifactID        string `json:"artifact_id"`
	CertificateSHA256 string `json:"certificate_sha256"`
	RecordMAC         string `json:"record_mac"`
}

type formalGLMPhase21StickyReleaseStore struct {
	mu      sync.Mutex
	dir     string
	records string
	signers string
	guards  string
	peer    string
	key     [32]byte
	pins    map[string]ed25519.PublicKey
	root    *os.Root
}

func formalGLMPhase21PromoteDurableV2(
	certificate formalGLMPhase21StickyCertificate,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase21StickyCertificate, error) {
	if len(certificate.AuthorityReceipts) != 0 ||
		certificate.SamplerV2Contract == nil ||
		certificate.DurablePublicationProtocol != "" ||
		certificate.ExactlyOnceDPOpening ||
		formalGLMPhase21ValidateStickyCertificateCore(certificate, pins) != nil {
		return formalGLMPhase21StickyCertificate{},
			fmt.Errorf("formal-glm: invalid sampler-v2 finalizer candidate")
	}
	const inflight = "formal_glm_phase21_sampler_v2_inflight_output_not_durable_by_canonical_artifact_v1"
	if !formalGLMPhase19Contains(certificate.Blockers, inflight) {
		return formalGLMPhase21StickyCertificate{},
			fmt.Errorf("formal-glm: sampler-v2 finalizer candidate has no durability blocker")
	}
	promoted := certificate
	promoted.Blockers = make([]string, 0, len(certificate.Blockers)-1)
	for _, blocker := range certificate.Blockers {
		if blocker != inflight {
			promoted.Blockers = append(promoted.Blockers, blocker)
		}
	}
	promoted.ExactlyOnceDPOpening = true
	promoted.DurablePublicationProtocol = formalGLMPhase21DurableV2Version
	if err := formalGLMPhase21ValidateStickyCertificateCore(
		promoted, pins); err != nil {
		return formalGLMPhase21StickyCertificate{}, err
	}
	return promoted, nil
}

func formalGLMPhase21DurableV2CertificateSHA256(encoded []byte) string {
	digest := sha256.Sum256(append(
		[]byte(formalGLMPhase21DurableV2Domain+"/certificate|"), encoded...))
	return hex.EncodeToString(digest[:])
}

func formalGLMPhase21DurableV2SpoolKey(storeKey [32]byte,
	artifactID, peer string,
) ([32]byte, error) {
	var result [32]byte
	artifact, err := hex.DecodeString(artifactID)
	if err != nil || len(artifact) != sha256.Size ||
		!formalGLMPhase19KeyValid(storeKey) ||
		!jointDPBiomedicalGaussianValidPeerName(peer) {
		clear(artifact)
		return result, fmt.Errorf("formal-glm: invalid durable spool key binding")
	}
	reader := hkdf.New(sha256.New, storeKey[:], artifact,
		[]byte(formalGLMPhase21DurableV2Domain+"/spool-aead/"+peer))
	clear(artifact)
	if _, err := io.ReadFull(reader, result[:]); err != nil ||
		!formalGLMPhase19KeyValid(result) {
		clear(result[:])
		return result, fmt.Errorf("formal-glm: durable spool key derivation failed")
	}
	return result, nil
}

func formalGLMPhase21DurableV2SpoolAAD(
	record formalGLMPhase21DurableV2SpoolRecord,
) ([]byte, error) {
	record.Ciphertext = ""
	return json.Marshal(record)
}

func (store *formalGLMPhase21StickyReleaseStore) encodeDurableV2Spool(
	certificate formalGLMPhase21StickyCertificate,
) ([]byte, error) {
	if store == nil || certificate.SamplerV2Contract == nil ||
		len(certificate.AuthorityReceipts) != 0 ||
		certificate.DurablePublicationProtocol != formalGLMPhase21DurableV2Version ||
		formalGLMPhase21ValidateStickyCertificateCore(certificate, store.pins) != nil {
		return nil, fmt.Errorf("formal-glm: invalid durable spool certificate")
	}
	plaintext, err := json.Marshal(certificate)
	if err != nil || len(plaintext) > formalGLMPhase21DurableV2MaxBytes/2 {
		clear(plaintext)
		return nil, fmt.Errorf("formal-glm: durable spool certificate too large")
	}
	defer clear(plaintext)
	contractSHA256, err := formalGLMPhase21SamplerV2ContractSHA256(
		*certificate.SamplerV2Contract)
	if err != nil {
		return nil, err
	}
	key, err := formalGLMPhase21DurableV2SpoolKey(
		store.key, certificate.ArtifactID, store.peer)
	if err != nil {
		return nil, err
	}
	defer clear(key[:])
	aead, err := formalGLMPhase20HandoffAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		clear(nonce)
		return nil, err
	}
	record := formalGLMPhase21DurableV2SpoolRecord{
		Version: formalGLMPhase21DurableV2Version,
		Purpose: formalGLMPhase21DurableV2Purpose,
		Peer:    store.peer, ArtifactID: certificate.ArtifactID,
		ContractSHA256:    contractSHA256,
		CertificateSHA256: formalGLMPhase21DurableV2CertificateSHA256(plaintext),
		Nonce:             base64.StdEncoding.EncodeToString(nonce),
	}
	aad, err := formalGLMPhase21DurableV2SpoolAAD(record)
	if err != nil {
		clear(nonce)
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	record.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	clear(nonce)
	clear(aad)
	clear(ciphertext)
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > formalGLMPhase21DurableV2MaxBytes {
		clear(encoded)
		if err == nil {
			err = fmt.Errorf("formal-glm: durable spool record too large")
		}
		return nil, err
	}
	return encoded, nil
}

func (store *formalGLMPhase21StickyReleaseStore) decodeDurableV2Spool(
	encoded []byte,
) (formalGLMPhase21StickyCertificate, error) {
	var zero formalGLMPhase21StickyCertificate
	if store == nil || len(encoded) < 64 ||
		len(encoded) > formalGLMPhase21DurableV2MaxBytes {
		return zero, fmt.Errorf("formal-glm: invalid durable spool size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record formalGLMPhase21DurableV2SpoolRecord
	if err := decoder.Decode(&record); err != nil {
		return zero, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return zero, fmt.Errorf("formal-glm: trailing durable spool data")
	}
	canonicalRecord, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonicalRecord, encoded) ||
		record.Version != formalGLMPhase21DurableV2Version ||
		record.Purpose != formalGLMPhase21DurableV2Purpose ||
		record.Peer != store.peer || !formalGLMIsSHA256(record.ArtifactID) ||
		!formalGLMIsSHA256(record.ContractSHA256) ||
		!formalGLMIsSHA256(record.CertificateSHA256) {
		return zero, fmt.Errorf("formal-glm: invalid durable spool record")
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(record.Nonce)
	if err != nil || base64.StdEncoding.EncodeToString(nonce) != record.Nonce {
		clear(nonce)
		return zero, fmt.Errorf("formal-glm: invalid durable spool nonce")
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(record.Ciphertext)
	if err != nil || base64.StdEncoding.EncodeToString(ciphertext) !=
		record.Ciphertext {
		clear(nonce)
		clear(ciphertext)
		return zero, fmt.Errorf("formal-glm: invalid durable spool ciphertext")
	}
	key, err := formalGLMPhase21DurableV2SpoolKey(
		store.key, record.ArtifactID, store.peer)
	if err != nil {
		clear(nonce)
		clear(ciphertext)
		return zero, err
	}
	defer clear(key[:])
	aead, err := formalGLMPhase20HandoffAEAD(key)
	if err != nil || len(nonce) != aead.NonceSize() ||
		len(ciphertext) < aead.Overhead() {
		clear(nonce)
		clear(ciphertext)
		return zero, fmt.Errorf("formal-glm: invalid durable spool AEAD")
	}
	aad, err := formalGLMPhase21DurableV2SpoolAAD(record)
	if err != nil {
		clear(nonce)
		clear(ciphertext)
		return zero, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	clear(nonce)
	clear(ciphertext)
	clear(aad)
	if err != nil || len(plaintext) == 0 ||
		formalGLMPhase21DurableV2CertificateSHA256(plaintext) !=
			record.CertificateSHA256 {
		clear(plaintext)
		return zero, fmt.Errorf("formal-glm: durable spool authentication failed")
	}
	defer clear(plaintext)
	certificateDecoder := json.NewDecoder(bytes.NewReader(plaintext))
	certificateDecoder.DisallowUnknownFields()
	var certificate formalGLMPhase21StickyCertificate
	if err := certificateDecoder.Decode(&certificate); err != nil ||
		certificateDecoder.Decode(&trailing) != io.EOF {
		return zero, fmt.Errorf("formal-glm: invalid durable spool certificate")
	}
	canonicalCertificate, err := json.Marshal(certificate)
	if err != nil || !bytes.Equal(canonicalCertificate, plaintext) ||
		certificate.ArtifactID != record.ArtifactID ||
		certificate.SamplerV2Contract == nil ||
		len(certificate.AuthorityReceipts) != 0 ||
		certificate.DurablePublicationProtocol != formalGLMPhase21DurableV2Version ||
		formalGLMPhase21ValidateStickyCertificateCore(certificate, store.pins) != nil {
		return zero, fmt.Errorf("formal-glm: invalid durable spool certificate")
	}
	contractSHA256, err := formalGLMPhase21SamplerV2ContractSHA256(
		*certificate.SamplerV2Contract)
	if err != nil || contractSHA256 != record.ContractSHA256 {
		return zero, fmt.Errorf("formal-glm: durable spool contract mismatch")
	}
	return certificate, nil
}

func (store *formalGLMPhase21StickyReleaseStore) loadDurableV2Candidate(
	artifactID string,
) (formalGLMPhase21StickyCertificate, error) {
	var zero formalGLMPhase21StickyCertificate
	relative, err := store.durableV2SpoolRelativePath(artifactID, false)
	if err != nil {
		return zero, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	encoded, err := formalGLMPhase21RootReadRecord(
		store.root, relative, formalGLMPhase21DurableV2MaxBytes)
	if err != nil {
		return zero, err
	}
	return store.decodeDurableV2Spool(encoded)
}

func (store *formalGLMPhase21StickyReleaseStore) stageDurableV2Candidate(
	certificate formalGLMPhase21StickyCertificate,
) (formalGLMPhase21StickyCertificate, bool, error) {
	var zero formalGLMPhase21StickyCertificate
	encoded, err := store.encodeDurableV2Spool(certificate)
	if err != nil {
		return zero, false, err
	}
	defer clear(encoded)
	relative, err := store.durableV2SpoolRelativePath(
		certificate.ArtifactID, true)
	if err != nil {
		return zero, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	created, err := formalGLMPhase21RootCreateRecord(store.root, relative, encoded)
	if err != nil {
		return zero, false, err
	}
	existingBytes, err := formalGLMPhase21RootReadRecord(
		store.root, relative, formalGLMPhase21DurableV2MaxBytes)
	if err != nil {
		return zero, false, err
	}
	existing, err := store.decodeDurableV2Spool(existingBytes)
	if err != nil {
		return zero, false, err
	}
	if !reflect.DeepEqual(existing, certificate) {
		return zero, false, fmt.Errorf("formal-glm: conflicting durable finalizer candidate")
	}
	return existing, !created, nil
}

func (store *formalGLMPhase21StickyReleaseStore) FinalizeSamplerV2Once(
	contract formalGLMPhase21SamplerV2Contract,
	finalizer func() (formalGLMPhase21StickyCertificate, error),
	phaseHook func(string) error,
) (formalGLMPhase21StickyCertificate, bool, error) {
	var zero formalGLMPhase21StickyCertificate
	if store == nil || store.root == nil ||
		formalGLMPhase21ValidateSamplerV2Contract(contract, store.pins) != nil {
		return zero, false, fmt.Errorf("formal-glm: invalid durable finalizer store")
	}
	authority := false
	for _, candidate := range contract.Artifact.NoiseAuthorities {
		authority = authority || candidate.PeerName == store.peer
	}
	if !authority {
		return zero, false, fmt.Errorf("formal-glm: durable finalizer is not an authority")
	}
	existing, err := store.loadDurableV2Candidate(contract.ArtifactID)
	if err == nil {
		if existing.SamplerV2Contract == nil ||
			!reflect.DeepEqual(*existing.SamplerV2Contract, contract) {
			return zero, false, fmt.Errorf("formal-glm: conflicting durable sampler-v2 contract")
		}
		return existing, true, nil
	}
	if !os.IsNotExist(err) {
		return zero, false, err
	}
	if finalizer == nil {
		return zero, false, fmt.Errorf("formal-glm: missing durable sampler-v2 finalizer")
	}
	base, err := finalizer()
	if err != nil {
		return zero, false, err
	}
	if base.SamplerV2Contract == nil ||
		!reflect.DeepEqual(*base.SamplerV2Contract, contract) {
		return zero, false, fmt.Errorf("formal-glm: finalizer returned another sampler-v2 contract")
	}
	promoted, err := formalGLMPhase21PromoteDurableV2(base, store.pins)
	if err != nil {
		return zero, false, err
	}
	if phaseHook != nil {
		if err := phaseHook("after_finalizer_before_durable_spool"); err != nil {
			return zero, false, err
		}
	}
	staged, replayed, err := store.stageDurableV2Candidate(promoted)
	if err != nil {
		return zero, false, err
	}
	if phaseHook != nil {
		if err := phaseHook("after_durable_spool"); err != nil {
			return staged, replayed, err
		}
	}
	return staged, replayed, nil
}

func formalGLMPhase21DurableV2AckMAC(key [32]byte,
	record formalGLMPhase21DurableV2AckRecord,
) (string, error) {
	record.RecordMAC = ""
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(formalGLMPhase21DurableV2Domain + "/ack|"))
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func formalGLMPhase21DurableV2EncodeAck(key [32]byte,
	record formalGLMPhase21DurableV2AckRecord,
) ([]byte, error) {
	mac, err := formalGLMPhase21DurableV2AckMAC(key, record)
	if err != nil {
		return nil, err
	}
	record.RecordMAC = mac
	return json.Marshal(record)
}

func (store *formalGLMPhase21StickyReleaseStore) decodeDurableV2Ack(
	encoded []byte,
) (formalGLMPhase21DurableV2AckRecord, error) {
	var zero formalGLMPhase21DurableV2AckRecord
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record formalGLMPhase21DurableV2AckRecord
	if err := decoder.Decode(&record); err != nil {
		return zero, err
	}
	var trailing any
	want, err := formalGLMPhase21DurableV2AckMAC(store.key, record)
	canonical, canonicalErr := formalGLMPhase21DurableV2EncodeAck(store.key, record)
	if decoder.Decode(&trailing) != io.EOF || err != nil || canonicalErr != nil ||
		!bytes.Equal(canonical, encoded) ||
		!hmac.Equal([]byte(want), []byte(record.RecordMAC)) ||
		record.Version != formalGLMPhase21DurableV2Version ||
		record.Purpose != formalGLMPhase21DurableV2Purpose ||
		record.Peer != store.peer || !formalGLMIsSHA256(record.ArtifactID) ||
		!formalGLMIsSHA256(record.CertificateSHA256) {
		return zero, fmt.Errorf("formal-glm: durable acknowledgment authentication failed")
	}
	return record, nil
}

func (store *formalGLMPhase21StickyReleaseStore) AckDurableV2(
	publication formalGLMPhase21StickyPublication,
) (bool, error) {
	if store == nil || store.root == nil ||
		!formalGLMIsSHA256(publication.ArtifactID) {
		return false, fmt.Errorf("formal-glm: invalid durable acknowledgment store")
	}
	existingPublication, err := store.Replay(publication.ArtifactID)
	if err != nil || existingPublication.CertificateSHA256 !=
		publication.CertificateSHA256 ||
		!bytes.Equal(existingPublication.Certificate, publication.Certificate) {
		return false, fmt.Errorf("formal-glm: durable acknowledgment targets another publication")
	}
	certificate, err := formalGLMPhase21DecodeStickyPublication(existingPublication)
	if err != nil || certificate.DurablePublicationProtocol !=
		formalGLMPhase21DurableV2Version || !certificate.ExactlyOnceDPOpening {
		return false, fmt.Errorf("formal-glm: acknowledgment requires durable sampler-v2 publication")
	}
	record := formalGLMPhase21DurableV2AckRecord{
		Version: formalGLMPhase21DurableV2Version,
		Purpose: formalGLMPhase21DurableV2Purpose,
		Peer:    store.peer, ArtifactID: publication.ArtifactID,
		CertificateSHA256: publication.CertificateSHA256,
	}
	encoded, err := formalGLMPhase21DurableV2EncodeAck(store.key, record)
	if err != nil {
		return false, err
	}
	relative, err := store.durableV2AckRelativePath(publication.ArtifactID, true)
	if err != nil {
		return false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	created, err := formalGLMPhase21RootCreateRecord(store.root, relative, encoded)
	if err != nil {
		return false, err
	}
	existingBytes, err := formalGLMPhase21RootReadRecord(
		store.root, relative, formalGLMPhase21StickySignerMaxBytes)
	if err != nil {
		return false, err
	}
	existing, err := store.decodeDurableV2Ack(existingBytes)
	if err != nil || existing.ArtifactID != record.ArtifactID ||
		existing.CertificateSHA256 != record.CertificateSHA256 {
		return false, fmt.Errorf("formal-glm: conflicting durable acknowledgment")
	}
	return !created, nil
}

func (store *formalGLMPhase21StickyReleaseStore) PublishDurableV2(
	certificate formalGLMPhase21StickyCertificate,
	phaseHook func(string) error,
) (formalGLMPhase21StickyPublication, bool, error) {
	publication, err := store.Commit(certificate)
	if err != nil {
		return formalGLMPhase21StickyPublication{}, false, err
	}
	if phaseHook != nil {
		if err := phaseHook("after_durable_commit_before_ack"); err != nil {
			return publication, false, err
		}
	}
	ackReplayed, err := store.AckDurableV2(publication)
	if err != nil {
		return publication, false, err
	}
	if phaseHook != nil {
		if err := phaseHook("after_durable_ack"); err != nil {
			return publication, ackReplayed, err
		}
	}
	return publication, ackReplayed, nil
}

func (store *formalGLMPhase21StickyReleaseStore) durableV2SpoolRelativePath(
	artifactID string, create bool,
) (string, error) {
	if store == nil || !formalGLMIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-glm: invalid durable sampler-v2 artifact")
	}
	shard := filepath.Join("finalized-v2", artifactID[:2], artifactID[2:4])
	if create {
		if err := formalGLMPhase21EnsureRootPrivateDir(store.root, shard); err != nil {
			return "", err
		}
	} else if err := formalGLMPhase21ValidateRootPrivateDir(
		store.root, shard, false); err != nil {
		return "", err
	}
	return filepath.Join(shard,
		"candidate-"+store.peer+"-"+artifactID+".bin"), nil
}

func (store *formalGLMPhase21StickyReleaseStore) durableV2AckRelativePath(
	artifactID string, create bool,
) (string, error) {
	if store == nil || !formalGLMIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-glm: invalid durable sampler-v2 artifact")
	}
	shard := filepath.Join("acks-v2", artifactID[:2], artifactID[2:4])
	if create {
		if err := formalGLMPhase21EnsureRootPrivateDir(store.root, shard); err != nil {
			return "", err
		}
	} else if err := formalGLMPhase21ValidateRootPrivateDir(
		store.root, shard, false); err != nil {
		return "", err
	}
	return filepath.Join(shard,
		"ack-"+store.peer+"-"+artifactID+".json"), nil
}

func formalGLMPhase21SamplerV2Context(artifactID, samplerMode, role,
	peerName, peerID string,
) ([32]byte, error) {
	var zero [32]byte
	artifactBytes, err := hex.DecodeString(artifactID)
	if err != nil || len(artifactBytes) != sha256.Size {
		clear(artifactBytes)
		return zero, fmt.Errorf("formal-glm: invalid sampler-v2 context artifact")
	}
	var artifact [32]byte
	copy(artifact[:], artifactBytes)
	clear(artifactBytes)
	switch samplerMode {
	case formalGLMPhase21SamplerV2OneDraw:
		return jointDPCommitmentContext(artifact,
			jointDPGaussianOneDrawCommitmentPurpose+"/"+role, peerID), nil
	case formalGLMPhase21SamplerV2Full:
		return jointDPCommitmentContext(
			artifact, jointDPGaussianCommitmentPurpose, peerName), nil
	default:
		return zero, fmt.Errorf("formal-glm: invalid sampler-v2 mode")
	}
}

func formalGLMPhase21SamplerV2Derive(
	root [32]byte,
	artifactID, samplerMode, role, peerName, peerID string,
) ([32]byte, formalGLMPhase21SamplerV2Commitment, error) {
	var zero [32]byte
	var zeroCommitment formalGLMPhase21SamplerV2Commitment
	if !formalGLMPhase19KeyValid(root) || !formalGLMIsSHA256(artifactID) ||
		(samplerMode != formalGLMPhase21SamplerV2OneDraw &&
			samplerMode != formalGLMPhase21SamplerV2Full) ||
		(role != "garbler" && role != "evaluator") ||
		!jointDPBiomedicalGaussianValidPeerName(peerName) ||
		!jointDPGaussianOneDrawPinnedPeer.MatchString(peerID) {
		return zero, zeroCommitment,
			fmt.Errorf("formal-glm: invalid sampler-v2 authority binding")
	}
	artifactBytes, err := hex.DecodeString(artifactID)
	if err != nil || len(artifactBytes) != sha256.Size {
		clear(artifactBytes)
		return zero, zeroCommitment,
			fmt.Errorf("formal-glm: invalid sampler-v2 artifact id")
	}
	purpose := formalGLMPhase21SamplerV2Purpose + "/" + samplerMode + "/" + role
	info := formalGLMPhase15AppendString(nil,
		formalGLMPhase21SamplerV2Domain+"/authority-root-hkdf")
	for _, value := range []string{artifactID, purpose, peerName, peerID} {
		info = formalGLMPhase15AppendString(info, value)
	}
	reader := hkdf.New(sha256.New, root[:], artifactBytes, info)
	var seed [32]byte
	_, err = io.ReadFull(reader, seed[:])
	clear(artifactBytes)
	clear(info)
	if err != nil || !formalGLMPhase19KeyValid(seed) {
		clear(seed[:])
		return zero, zeroCommitment,
			fmt.Errorf("formal-glm: sampler-v2 seed derivation failed")
	}
	context, err := formalGLMPhase21SamplerV2Context(
		artifactID, samplerMode, role, peerName, peerID)
	if err != nil {
		clear(seed[:])
		return zero, zeroCommitment, err
	}
	commitment := jointDPSeedCommitment(context, seed)
	return seed, formalGLMPhase21SamplerV2Commitment{
		Role: role, PeerName: peerName, PeerID: peerID,
		SamplerPurpose:          purpose,
		CommitmentContextSHA256: hex.EncodeToString(context[:]),
		SeedCommitmentSHA256:    hex.EncodeToString(commitment[:]),
	}, nil
}

func formalGLMPhase21ValidateSamplerV2ContractCore(
	contract formalGLMPhase21SamplerV2Contract,
	pins map[string]ed25519.PublicKey,
) error {
	if err := formalGLMPhase21ValidateStickyArtifact(
		contract.Artifact, pins); err != nil {
		return err
	}
	artifactID, err := formalGLMPhase21StickyArtifactID(contract.Artifact)
	if err != nil || artifactID != contract.ArtifactID ||
		contract.Version != formalGLMPhase21SamplerV2Version ||
		contract.Purpose != formalGLMPhase21SamplerV2Purpose ||
		(contract.SamplerMode != formalGLMPhase21SamplerV2OneDraw &&
			contract.SamplerMode != formalGLMPhase21SamplerV2Full) ||
		contract.PinsetSHA256 != contract.Artifact.PinsetSHA256 ||
		contract.CustodianCount != contract.Artifact.CustodianCount ||
		!reflect.DeepEqual(contract.CustodianPeers,
			contract.Artifact.CustodianPeers) ||
		len(contract.NoiseCommitments) != 2 || contract.ProductionReady {
		return fmt.Errorf("formal-glm: invalid sampler-v2 contract identity")
	}
	for index, commitment := range contract.NoiseCommitments {
		authority := contract.Artifact.NoiseAuthorities[index]
		purpose := formalGLMPhase21SamplerV2Purpose + "/" +
			contract.SamplerMode + "/" + authority.Role
		contextValue, contextErr := formalGLMPhase21SamplerV2Context(
			contract.ArtifactID, contract.SamplerMode, authority.Role,
			authority.PeerName, authority.PeerID)
		context := hex.EncodeToString(contextValue[:])
		if contextErr != nil || commitment.Role != authority.Role ||
			commitment.PeerName != authority.PeerName ||
			commitment.PeerID != authority.PeerID ||
			commitment.SamplerPurpose != purpose ||
			commitment.CommitmentContextSHA256 != context ||
			!formalGLMIsSHA256(commitment.SeedCommitmentSHA256) {
			return fmt.Errorf("formal-glm: invalid sampler-v2 noise commitment")
		}
	}
	return nil
}

func formalGLMPhase21SamplerV2ContractMessage(
	contract formalGLMPhase21SamplerV2Contract,
) ([]byte, error) {
	contract.CustodianSignatures = nil
	encoded, err := json.Marshal(contract)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMPhase21SamplerV2Domain+"/custodian|"),
		encoded...), nil
}

func formalGLMPhase21BuildSamplerV2Contract(
	artifact formalGLMPhase21StickyArtifact,
	artifactID, samplerMode string,
	commitments []formalGLMPhase21SamplerV2Commitment,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase21SamplerV2Contract, error) {
	contract := formalGLMPhase21SamplerV2Contract{
		Version:    formalGLMPhase21SamplerV2Version,
		Purpose:    formalGLMPhase21SamplerV2Purpose,
		ArtifactID: artifactID, Artifact: artifact, SamplerMode: samplerMode,
		PinsetSHA256:   artifact.PinsetSHA256,
		CustodianPeers: append([]string(nil), artifact.CustodianPeers...),
		CustodianCount: artifact.CustodianCount,
		NoiseCommitments: append(
			[]formalGLMPhase21SamplerV2Commitment(nil), commitments...),
		ProductionReady: false, CustodianSignatures: nil,
	}
	if err := formalGLMPhase21ValidateSamplerV2ContractCore(
		contract, pins); err != nil {
		return formalGLMPhase21SamplerV2Contract{}, err
	}
	return contract, nil
}

func formalGLMPhase21SignSamplerV2Contract(
	contract formalGLMPhase21SamplerV2Contract,
	signer string,
	privateKey ed25519.PrivateKey,
) (jointDPBiomedicalGaussianSignature, error) {
	var zero jointDPBiomedicalGaussianSignature
	if len(contract.CustodianSignatures) != 0 ||
		len(privateKey) != ed25519.PrivateKeySize ||
		!sort.StringsAreSorted(contract.CustodianPeers) {
		return zero, fmt.Errorf("formal-glm: invalid unsigned sampler-v2 contract")
	}
	found := false
	for _, peer := range contract.CustodianPeers {
		found = found || peer == signer
	}
	if !found {
		return zero, fmt.Errorf("formal-glm: sampler-v2 signer is not a custodian")
	}
	message, err := formalGLMPhase21SamplerV2ContractMessage(contract)
	if err != nil {
		return zero, err
	}
	return jointDPBiomedicalGaussianSignature{
		Signer: signer, Signature: ed25519.Sign(privateKey, message),
	}, nil
}

func formalGLMPhase21SealSamplerV2Contract(
	contract formalGLMPhase21SamplerV2Contract,
	signatures []jointDPBiomedicalGaussianSignature,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase21SamplerV2Contract, error) {
	if len(contract.CustodianSignatures) != 0 {
		return formalGLMPhase21SamplerV2Contract{},
			fmt.Errorf("formal-glm: sampler-v2 contract is already sealed")
	}
	if err := formalGLMPhase21ValidateSamplerV2ContractCore(
		contract, pins); err != nil {
		return formalGLMPhase21SamplerV2Contract{}, err
	}
	message, err := formalGLMPhase21SamplerV2ContractMessage(contract)
	if err != nil {
		return formalGLMPhase21SamplerV2Contract{}, err
	}
	if len(signatures) != contract.CustodianCount {
		return formalGLMPhase21SamplerV2Contract{},
			fmt.Errorf("formal-glm: sampler-v2 contract requires K-of-K signatures")
	}
	sealed := contract
	sealed.CustodianSignatures = make(
		[]jointDPBiomedicalGaussianSignature, len(signatures))
	for index, peer := range contract.CustodianPeers {
		signature := signatures[index]
		if signature.Signer != peer || len(signature.Signature) != ed25519.SignatureSize ||
			len(pins[peer]) != ed25519.PublicKeySize ||
			!ed25519.Verify(pins[peer], message, signature.Signature) {
			return formalGLMPhase21SamplerV2Contract{},
				fmt.Errorf("formal-glm: invalid sampler-v2 custodian signature")
		}
		sealed.CustodianSignatures[index] = jointDPBiomedicalGaussianSignature{
			Signer: peer, Signature: append([]byte(nil), signature.Signature...),
		}
	}
	if err := formalGLMPhase21ValidateSamplerV2Contract(
		sealed, pins); err != nil {
		return formalGLMPhase21SamplerV2Contract{}, err
	}
	return sealed, nil
}

func formalGLMPhase21ValidateSamplerV2Contract(
	contract formalGLMPhase21SamplerV2Contract,
	pins map[string]ed25519.PublicKey,
) error {
	if err := formalGLMPhase21ValidateSamplerV2ContractCore(
		contract, pins); err != nil {
		return err
	}
	if len(contract.CustodianSignatures) != contract.CustodianCount {
		return fmt.Errorf("formal-glm: sampler-v2 contract is not K-of-K signed")
	}
	message, err := formalGLMPhase21SamplerV2ContractMessage(contract)
	if err != nil {
		return err
	}
	for index, peer := range contract.CustodianPeers {
		signature := contract.CustodianSignatures[index]
		if signature.Signer != peer || len(signature.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(pins[peer], message, signature.Signature) {
			return fmt.Errorf("formal-glm: sampler-v2 contract signature verification failed")
		}
	}
	return nil
}

func formalGLMPhase21SamplerV2ContractSHA256(
	contract formalGLMPhase21SamplerV2Contract,
) (string, error) {
	return formalGLMPhase21StickyHash(
		formalGLMPhase21SamplerV2Domain+"/sealed-contract", contract)
}

func formalGLMPhase21SamplerV2AuthorizationMessage(
	authorization formalGLMPhase21SamplerV2Authorization,
) ([]byte, error) {
	authorization.Signature = nil
	encoded, err := json.Marshal(authorization)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMPhase21SamplerV2Domain+"/authorization|"),
		encoded...), nil
}

func formalGLMPhase21SamplerV2AuthorizationSHA256(
	authorization formalGLMPhase21SamplerV2Authorization,
) (string, error) {
	return formalGLMPhase21StickyHash(
		formalGLMPhase21SamplerV2Domain+"/authorization-receipt", authorization)
}

func formalGLMPhase21ValidateSamplerV2AuthorizationAt(
	contract formalGLMPhase21SamplerV2Contract,
	authorization formalGLMPhase21SamplerV2Authorization,
	position int,
	expectedPredecessor string,
	pins map[string]ed25519.PublicKey,
) error {
	if position < 0 || position >= len(contract.Artifact.NoiseAuthorities) {
		return fmt.Errorf("formal-glm: invalid sampler-v2 authorization position")
	}
	contractSHA256, err := formalGLMPhase21SamplerV2ContractSHA256(contract)
	if err != nil {
		return err
	}
	authority := contract.Artifact.NoiseAuthorities[position]
	if authorization.Version != formalGLMPhase21SamplerV2GuardVersion ||
		authorization.Purpose != formalGLMPhase21SamplerV2Purpose ||
		authorization.ArtifactID != contract.ArtifactID ||
		authorization.ContractSHA256 != contractSHA256 ||
		authorization.PeerName != authority.PeerName ||
		authorization.Role != authority.Role ||
		authorization.PredecessorAuthorizationSHA256 != expectedPredecessor ||
		len(authorization.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("formal-glm: sampler-v2 authorization binding mismatch")
	}
	message, err := formalGLMPhase21SamplerV2AuthorizationMessage(authorization)
	if err != nil || !ed25519.Verify(
		pins[authority.PeerName], message, authorization.Signature) {
		return fmt.Errorf("formal-glm: sampler-v2 authorization signature failed")
	}
	return nil
}

func formalGLMPhase21SamplerV2GuardMAC(key [32]byte,
	record formalGLMPhase21SamplerV2GuardRecord,
) (string, error) {
	record.RecordMAC = ""
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(formalGLMPhase21SamplerV2Domain + "/guard-record|"))
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func formalGLMPhase21SamplerV2EncodeGuard(key [32]byte,
	record formalGLMPhase21SamplerV2GuardRecord,
) ([]byte, error) {
	mac, err := formalGLMPhase21SamplerV2GuardMAC(key, record)
	if err != nil {
		return nil, err
	}
	record.RecordMAC = mac
	return json.Marshal(record)
}

func (store *formalGLMPhase21StickyReleaseStore) decodeSamplerV2Guard(
	encoded []byte,
) (formalGLMPhase21SamplerV2GuardRecord, error) {
	var zero formalGLMPhase21SamplerV2GuardRecord
	if len(encoded) < 64 || len(encoded) > formalGLMPhase21SamplerV2GuardMaxBytes {
		return zero, fmt.Errorf("formal-glm: invalid sampler-v2 guard size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record formalGLMPhase21SamplerV2GuardRecord
	if err := decoder.Decode(&record); err != nil {
		return zero, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return zero, fmt.Errorf("formal-glm: trailing sampler-v2 guard data")
	}
	wantMAC, err := formalGLMPhase21SamplerV2GuardMAC(store.key, record)
	if err != nil || !hmac.Equal([]byte(wantMAC), []byte(record.RecordMAC)) ||
		record.Version != formalGLMPhase21SamplerV2GuardVersion ||
		record.Purpose != formalGLMPhase21SamplerV2Purpose ||
		record.Peer != store.peer ||
		(record.Role != "garbler" && record.Role != "evaluator") ||
		!formalGLMIsSHA256(record.ArtifactID) ||
		!formalGLMIsSHA256(record.ContractSHA256) ||
		len(record.Authorization.Signature) != ed25519.SignatureSize ||
		(record.Role == "garbler" && record.PredecessorAuthorizationSHA256 != "") ||
		(record.Role == "evaluator" &&
			!formalGLMIsSHA256(record.PredecessorAuthorizationSHA256)) {
		return zero, fmt.Errorf("formal-glm: sampler-v2 guard authentication failed")
	}
	var contract formalGLMPhase21SamplerV2Contract
	contractDecoder := json.NewDecoder(strings.NewReader(record.ContractJSON))
	contractDecoder.DisallowUnknownFields()
	if err := contractDecoder.Decode(&contract); err != nil ||
		contractDecoder.Decode(&trailing) != io.EOF {
		return zero, fmt.Errorf("formal-glm: invalid sampler-v2 guard contract")
	}
	canonicalContract, err := json.Marshal(contract)
	if err != nil || !bytes.Equal(canonicalContract, []byte(record.ContractJSON)) ||
		formalGLMPhase21ValidateSamplerV2Contract(contract, store.pins) != nil ||
		contract.ArtifactID != record.ArtifactID {
		return zero, fmt.Errorf("formal-glm: non-canonical sampler-v2 guard contract")
	}
	contractSHA256, err := formalGLMPhase21SamplerV2ContractSHA256(contract)
	if err != nil || contractSHA256 != record.ContractSHA256 {
		return zero, fmt.Errorf("formal-glm: sampler-v2 guard contract digest mismatch")
	}
	position := 0
	if record.Role == "evaluator" {
		position = 1
	}
	if record.PredecessorAuthorizationSHA256 !=
		record.Authorization.PredecessorAuthorizationSHA256 ||
		formalGLMPhase21ValidateSamplerV2AuthorizationAt(
			contract, record.Authorization, position,
			record.PredecessorAuthorizationSHA256, store.pins) != nil {
		return zero, fmt.Errorf("formal-glm: sampler-v2 guard authorization failed")
	}
	canonical, err := formalGLMPhase21SamplerV2EncodeGuard(store.key, record)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return zero, fmt.Errorf("formal-glm: non-canonical sampler-v2 guard")
	}
	return record, nil
}

func (store *formalGLMPhase21StickyReleaseStore) AuthorizeSamplerV2Once(
	contract formalGLMPhase21SamplerV2Contract,
	authorityRoot [32]byte,
	privateKey ed25519.PrivateKey,
	predecessors []formalGLMPhase21SamplerV2Authorization,
) (formalGLMPhase21SamplerV2Authorization, bool, error) {
	var zero formalGLMPhase21SamplerV2Authorization
	if store == nil || store.root == nil ||
		!formalGLMPhase19KeyValid(store.key) {
		return zero, false, fmt.Errorf("formal-glm: closed sampler-v2 guard store")
	}
	if err := formalGLMPhase21ValidateSamplerV2Contract(
		contract, store.pins); err != nil {
		return zero, false, err
	}
	position := -1
	for index, authority := range contract.Artifact.NoiseAuthorities {
		if authority.PeerName == store.peer {
			position = index
		}
	}
	if position < 0 || len(privateKey) != ed25519.PrivateKeySize {
		return zero, false, fmt.Errorf("formal-glm: sampler-v2 signer is not an authority")
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || !hmac.Equal(publicKey, store.pins[store.peer]) {
		return zero, false, fmt.Errorf("formal-glm: sampler-v2 authority key is not pinned")
	}
	authority := contract.Artifact.NoiseAuthorities[position]
	seed, commitment, err := formalGLMPhase21SamplerV2Derive(
		authorityRoot, contract.ArtifactID, contract.SamplerMode,
		authority.Role, authority.PeerName, authority.PeerID)
	clear(seed[:])
	if err != nil || !reflect.DeepEqual(commitment,
		contract.NoiseCommitments[position]) {
		return zero, false,
			fmt.Errorf("formal-glm: authority root differs from sampler-v2 contract")
	}
	predecessorHash := ""
	if position == 0 {
		if len(predecessors) != 0 {
			return zero, false, fmt.Errorf("formal-glm: sampler-v2 garbler has a predecessor")
		}
	} else {
		if len(predecessors) != 1 ||
			formalGLMPhase21ValidateSamplerV2AuthorizationAt(
				contract, predecessors[0], 0, "", store.pins) != nil {
			return zero, false,
				fmt.Errorf("formal-glm: sampler-v2 evaluator lacks exact garbler authorization")
		}
		predecessorHash, err = formalGLMPhase21SamplerV2AuthorizationSHA256(
			predecessors[0])
		if err != nil {
			return zero, false, err
		}
	}
	contractJSON, err := json.Marshal(contract)
	if err != nil {
		return zero, false, err
	}
	contractSHA256, err := formalGLMPhase21SamplerV2ContractSHA256(contract)
	if err != nil {
		return zero, false, err
	}
	authorization := formalGLMPhase21SamplerV2Authorization{
		Version:    formalGLMPhase21SamplerV2GuardVersion,
		Purpose:    formalGLMPhase21SamplerV2Purpose,
		ArtifactID: contract.ArtifactID, ContractSHA256: contractSHA256,
		PeerName: store.peer, Role: authority.Role,
		PredecessorAuthorizationSHA256: predecessorHash,
	}
	message, err := formalGLMPhase21SamplerV2AuthorizationMessage(authorization)
	if err != nil {
		return zero, false, err
	}
	authorization.Signature = ed25519.Sign(privateKey, message)
	record := formalGLMPhase21SamplerV2GuardRecord{
		Version: formalGLMPhase21SamplerV2GuardVersion,
		Purpose: formalGLMPhase21SamplerV2Purpose,
		Peer:    store.peer, Role: authority.Role,
		ArtifactID: contract.ArtifactID, ContractSHA256: contractSHA256,
		ContractJSON:                   string(contractJSON),
		PredecessorAuthorizationSHA256: predecessorHash,
		Authorization:                  authorization,
	}
	encoded, err := formalGLMPhase21SamplerV2EncodeGuard(store.key, record)
	if err != nil {
		return zero, false, err
	}
	path, err := store.samplerV2GuardRelativePath(contract.ArtifactID, true)
	if err != nil {
		return zero, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	created, err := formalGLMPhase21RootCreateRecord(store.root, path, encoded)
	if err != nil {
		return zero, false, err
	}
	existingBytes, err := formalGLMPhase21RootReadRecord(
		store.root, path, formalGLMPhase21SamplerV2GuardMaxBytes)
	if err != nil {
		return zero, false, err
	}
	existing, err := store.decodeSamplerV2Guard(existingBytes)
	if err != nil {
		return zero, false, err
	}
	if existing.ArtifactID != record.ArtifactID ||
		existing.ContractSHA256 != record.ContractSHA256 ||
		existing.PredecessorAuthorizationSHA256 !=
			record.PredecessorAuthorizationSHA256 ||
		existing.Role != record.Role ||
		!reflect.DeepEqual(existing.Authorization, record.Authorization) {
		return zero, false, fmt.Errorf("formal-glm: conflicting sampler-v2 authorization")
	}
	return existing.Authorization, !created, nil
}

func (store *formalGLMPhase21StickyReleaseStore) samplerV2GuardRelativePath(
	artifactID string, create bool,
) (string, error) {
	if store == nil || store.root == nil || !formalGLMIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-glm: invalid sampler-v2 guard artifact id")
	}
	shard := filepath.Join("guards-v2", artifactID[:2], artifactID[2:4])
	if create {
		if err := formalGLMPhase21EnsureRootPrivateDir(store.root, shard); err != nil {
			return "", err
		}
	} else if err := formalGLMPhase21ValidateRootPrivateDir(
		store.root, shard, false); err != nil {
		return "", err
	}
	return filepath.Join(shard,
		"guard-"+store.peer+"-"+artifactID+".json"), nil
}

func formalGLMPhase21ValidateSamplerV2Authorizations(
	contract formalGLMPhase21SamplerV2Contract,
	authorizations []formalGLMPhase21SamplerV2Authorization,
	pins map[string]ed25519.PublicKey,
) error {
	if err := formalGLMPhase21ValidateSamplerV2Contract(
		contract, pins); err != nil {
		return err
	}
	if len(authorizations) != 2 {
		return fmt.Errorf("formal-glm: sampler-v2 requires both noise authorities")
	}
	predecessor := ""
	for index := range contract.Artifact.NoiseAuthorities {
		if err := formalGLMPhase21ValidateSamplerV2AuthorizationAt(
			contract, authorizations[index], index, predecessor, pins); err != nil {
			return err
		}
		var err error
		predecessor, err = formalGLMPhase21SamplerV2AuthorizationSHA256(
			authorizations[index])
		if err != nil {
			return err
		}
	}
	return nil
}

func formalGLMPhase21PreflightOrCommitHandoffV2(
	publicationStore *formalGLMPhase21StickyReleaseStore,
	handoffStore *formalGLMPhase20HandoffStore,
	binding formalGLMPhase16ReleaseBinding,
	plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context,
	result formalGLMPhase19ScheduleResult,
	contract formalGLMPhase21SamplerV2Contract,
	authorizations []formalGLMPhase21SamplerV2Authorization,
	phaseHook func(string) error,
) (formalGLMPhase21SamplerV2HandoffResult, error) {
	var zero formalGLMPhase21SamplerV2HandoffResult
	if publicationStore == nil {
		return zero, fmt.Errorf("formal-glm: missing sampler-v2 publication store")
	}
	artifact, artifactID, publication, found, err :=
		publicationStore.Preflight(binding, plan)
	if err != nil {
		return zero, err
	}
	if found {
		return formalGLMPhase21SamplerV2HandoffResult{
			Publication: publication, Replayed: true,
		}, nil
	}
	if handoffStore == nil || handoffStore.peer != publicationStore.peer ||
		contract.ArtifactID != artifactID ||
		!reflect.DeepEqual(contract.Artifact, artifact) {
		return zero, fmt.Errorf("formal-glm: sampler-v2 handoff targets another artifact")
	}
	if err := formalGLMPhase21ValidateSamplerV2Authorizations(
		contract, authorizations, publicationStore.pins); err != nil {
		return zero, err
	}
	if phaseHook != nil {
		if err := phaseHook("after_sampler_v2_guard_before_phase20"); err != nil {
			return zero, err
		}
	}
	commit, err := handoffStore.Commit(plan, ctx, result)
	if err != nil {
		return zero, err
	}
	if phaseHook != nil {
		if err := phaseHook("after_phase20_commit_before_sampler"); err != nil {
			return formalGLMPhase21SamplerV2HandoffResult{Handoff: commit}, err
		}
	}
	return formalGLMPhase21SamplerV2HandoffResult{Handoff: commit}, nil
}

func formalGLMPhase21StickyHash(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte(domain+"|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPhase21StickyArtifactID(
	artifact formalGLMPhase21StickyArtifact) (string, error) {
	return formalGLMPhase21StickyHash(
		formalGLMPhase21StickyDomain+"/artifact", artifact)
}

func formalGLMPhase21CanonicalRational(value, what string) (string, error) {
	parsed, err := jointDPParseDecimalRat(value, what, false)
	if err != nil {
		return "", err
	}
	return parsed.RatString(), nil
}

func formalGLMPhase21CanonicalLinkSHA256(
	kernel formalGLMPhase1Policy,
) (string, error) {
	projection := struct {
		Version    string   `json:"version"`
		Family     string   `json:"family"`
		Knots      []string `json:"knots"`
		Values     []string `json:"values"`
		Slopes     []string `json:"slopes"`
		ErrorUpper string   `json:"error_upper"`
	}{
		Version: "formal-glm-canonical-link-v1", Family: kernel.Family,
		Knots:      append([]string(nil), kernel.LinkKnots...),
		Values:     append([]string(nil), kernel.LinkValues...),
		Slopes:     append([]string(nil), kernel.LinkSlopes...),
		ErrorUpper: kernel.LinkErrorUpper,
	}
	return formalGLMPhase21StickyHash(
		formalGLMPhase21StickyDomain+"/canonical-link", projection)
}

func formalGLMPhase21CanonicalPlanSHA256(plan formalGLMPhase15Plan) (
	string, error,
) {
	canonicalLink, err := formalGLMPhase21CanonicalLinkSHA256(plan.Kernel)
	if err != nil {
		return "", err
	}
	projection := formalGLMPhase21CanonicalPlan{
		Version:                "formal-glm-canonical-scientific-plan-v1",
		CanonicalScienceSHA256: plan.Kernel.CanonicalScienceSHA256,
		CanonicalLinkSHA256:    canonicalLink,
		Family:                 plan.Kernel.Family,
		TotalCapacity:          plan.TotalCapacity,
		Iterations:             plan.Iterations,
		CoordinateOwners: append([]string(nil),
			plan.CoordinateOwners...),
		FractionBits:     plan.Kernel.FracBits,
		CoefficientCount: plan.Kernel.CoefficientCount,
		ReductionOrder:   plan.Kernel.ReductionOrder,
		Truncation:       plan.Kernel.Truncation,
		Missingness:      plan.Kernel.Missingness,
		PatientCollapse:  plan.Kernel.PatientCollapse,
	}
	return formalGLMPhase21StickyHash(
		formalGLMPhase21StickyDomain+"/canonical-plan", projection)
}

// BuildCanonicalArtifact deliberately excludes execution attempts, physical
// block/chunk geometry, broad capsule-workload/catalog hashes,
// backend/finalizer identities, reservations, epochs, receipts, proof
// encodings and rotating noise commitments. It is therefore computable before
// a DP sampler or finalizer is invoked and is the sole sticky-store key.
func formalGLMPhase21BuildCanonicalArtifact(
	binding formalGLMPhase16ReleaseBinding,
	plan formalGLMPhase15Plan,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase21StickyArtifact, string, error) {
	var zero formalGLMPhase21StickyArtifact
	if _, err := formalGLMPhase15ValidateShape(plan); err != nil {
		return zero, "", err
	}
	roles, err := formalGLMPhase16PinnedRoles(plan, pins)
	if err != nil || roles.PinsetSHA256 != binding.PinsetSHA256 ||
		roles.PinsetSHA256 != plan.Kernel.PinsetSHA256 ||
		roles.GarblerPeerName != binding.GarblerPeerName ||
		roles.GarblerPeerID != binding.GarblerPeerID ||
		roles.EvaluatorPeerName != binding.EvaluatorPeerName ||
		roles.EvaluatorPeerID != binding.EvaluatorPeerID {
		return zero, "", fmt.Errorf("formal-glm: canonical sticky pinset mismatch")
	}
	custodians := make([]string, 0, len(pins))
	for name := range pins {
		custodians = append(custodians, name)
	}
	sort.Strings(custodians)
	if len(custodians) != binding.CustodianCount ||
		!reflect.DeepEqual(custodians, plan.Kernel.CustodianPeers) ||
		plan.Kernel.ArtifactSHA256 == "" ||
		!formalGLMIsSHA256(plan.Kernel.CanonicalScienceSHA256) ||
		plan.Kernel.CapsuleSHA256 != binding.CapsuleID ||
		plan.Kernel.SnapshotSHA256 != binding.SnapshotSHA256 ||
		plan.Kernel.Family != binding.Family ||
		plan.Kernel.LinkTableSHA256 != binding.LinkTableSHA256 ||
		plan.Kernel.CoefficientCount != binding.CoordinateCount {
		return zero, "", fmt.Errorf("formal-glm: canonical sticky scientific mismatch")
	}
	epsilon, err := formalGLMPhase21CanonicalRational(
		binding.Epsilon, "canonical sticky epsilon")
	if err != nil {
		return zero, "", err
	}
	delta, err := formalGLMPhase21CanonicalRational(
		binding.AllocatedDelta, "canonical sticky delta")
	if err != nil {
		return zero, "", err
	}
	deltaRat, _ := jointDPParseDecimalRat(
		binding.AllocatedDelta, "canonical sticky delta", false)
	if deltaRat.Num().Cmp(deltaRat.Denom()) >= 0 {
		return zero, "", fmt.Errorf("formal-glm: canonical sticky delta is not below one")
	}
	sensitivity, err := jointDPBiomedicalGaussianParseCanonicalInt(
		binding.SensitivitySteps, "canonical sticky sensitivity", true)
	if err != nil {
		return zero, "", err
	}
	canonicalPlan, err := formalGLMPhase21CanonicalPlanSHA256(plan)
	if err != nil {
		return zero, "", err
	}
	canonicalLink, err := formalGLMPhase21CanonicalLinkSHA256(plan.Kernel)
	if err != nil {
		return zero, "", err
	}
	for _, value := range []string{
		plan.Kernel.CanonicalScienceSHA256, canonicalPlan, canonicalLink,
		binding.SchemaManifestSHA256, binding.SnapshotSHA256,
		binding.PinsetSHA256, binding.BoundsSHA256,
		binding.QuantizationSHA256, binding.CoordinateOrderSHA256,
	} {
		if !formalGLMIsSHA256(value) {
			return zero, "", fmt.Errorf("formal-glm: invalid canonical sticky hash")
		}
	}
	artifact := formalGLMPhase21StickyArtifact{
		Version:                 formalGLMPhase21StickyVersion,
		Purpose:                 formalGLMPhase21StickyPurpose,
		CanonicalScienceSHA256:  plan.Kernel.CanonicalScienceSHA256,
		ScientificArtifactScope: "phase0_formula_estimand_adjacency_optimizer_link_numeric_dp_projection_v1",
		CanonicalPlanSHA256:     canonicalPlan,
		SchemaManifestSHA256:    binding.SchemaManifestSHA256,
		SnapshotSHA256:          binding.SnapshotSHA256,
		PinsetSHA256:            roles.PinsetSHA256,
		CustodianPeers:          custodians,
		CustodianCount:          len(custodians),
		DesignatedComputePeers: []string{
			roles.GarblerPeerName, roles.EvaluatorPeerName,
		},
		NoiseAuthorities: []formalGLMPhase21StickyNoiseAuthority{
			{Role: "garbler", PeerName: roles.GarblerPeerName,
				PeerID: roles.GarblerPeerID},
			{Role: "evaluator", PeerName: roles.EvaluatorPeerName,
				PeerID: roles.EvaluatorPeerID},
		},
		Family: binding.Family, Adjacency: binding.Adjacency,
		Mechanism: binding.Mechanism, Allocation: binding.Allocation,
		EpsilonRational: epsilon, DeltaRational: delta,
		SensitivitySteps:      sensitivity.String(),
		BoundsSHA256:          binding.BoundsSHA256,
		QuantizationSHA256:    binding.QuantizationSHA256,
		CanonicalLinkSHA256:   canonicalLink,
		CoordinateOrderSHA256: binding.CoordinateOrderSHA256,
		CoordinateCount:       binding.CoordinateCount,
		SourceFractionBits:    binding.SourceFracBits,
		QuantizationShift:     binding.QuantizationShift,
		OutputLatticeBits:     binding.OutputLatticeBits,
	}
	id, err := formalGLMPhase21StickyArtifactID(artifact)
	return artifact, id, err
}

func formalGLMPhase21BuildStickyArtifact(
	release formalGLMPhase16CertifiedRelease,
	binding formalGLMPhase16ReleaseBinding,
	plan formalGLMPhase15Plan,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase21StickyArtifact, string, error) {
	var zero formalGLMPhase21StickyArtifact
	planDigest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil || hex.EncodeToString(planDigest[:]) != binding.Phase15PlanSHA256 {
		return zero, "", fmt.Errorf("formal-glm: sticky artifact plan binding mismatch")
	}
	kernelDigest, err := formalGLMPolicyDigest(plan.Kernel)
	if err != nil || hex.EncodeToString(kernelDigest[:]) != binding.KernelSpecSHA256 ||
		plan.Kernel.ArtifactSHA256 == "" ||
		!formalGLMIsSHA256(plan.Kernel.ArtifactSHA256) ||
		plan.Kernel.CapsuleSHA256 != binding.CapsuleID ||
		plan.Kernel.SnapshotSHA256 != binding.SnapshotSHA256 ||
		plan.Kernel.PinsetSHA256 != binding.PinsetSHA256 ||
		plan.Kernel.Family != binding.Family {
		return zero, "", fmt.Errorf("formal-glm: sticky artifact scientific binding mismatch")
	}
	selectionSHA256, err := formalGLMPhase16BackendSelectionSHA256(
		release.BackendSelection)
	if err != nil || selectionSHA256 != release.BackendSelectionSHA256 {
		return zero, "", fmt.Errorf("formal-glm: sticky artifact backend authority mismatch")
	}
	contract := release.BackendSelection.Contract
	custodians := append([]string(nil), contract.CustodianPeers...)
	designated := append([]string(nil), contract.DesignatedComputePeers...)
	if contract.ReleaseBindingSHA256 != binding.BindingSHA256 ||
		contract.PinsetSHA256 != binding.PinsetSHA256 ||
		contract.CustodianCount != binding.CustodianCount ||
		len(custodians) != binding.CustodianCount ||
		!sort.StringsAreSorted(custodians) ||
		!reflect.DeepEqual(designated,
			[]string{binding.GarblerPeerName, binding.EvaluatorPeerName}) {
		return zero, "", fmt.Errorf("formal-glm: sticky artifact consortium binding mismatch")
	}
	return formalGLMPhase21BuildCanonicalArtifact(binding, plan, pins)
}

func formalGLMPhase21BuildStickyCertificate(
	release formalGLMPhase16CertifiedRelease,
	binding formalGLMPhase16ReleaseBinding,
	token formalGLMPhase19PostExecutionToken,
	plan formalGLMPhase15Plan,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase21StickyCertificate, error) {
	var zero formalGLMPhase21StickyCertificate
	if err := formalGLMPhase16ValidateCertifiedRelease(
		release, binding, token, pins); err != nil {
		return zero, err
	}
	artifact, artifactID, err := formalGLMPhase21BuildStickyArtifact(
		release, binding, plan, pins)
	if err != nil {
		return zero, err
	}
	sourceBytes, err := json.Marshal(release)
	if err != nil {
		return zero, err
	}
	sourceDigest := sha256.Sum256(append(
		[]byte(formalGLMPhase21StickyDomain+"/source-certificate|"),
		sourceBytes...))
	approvalHash, err := formalGLMPhase21StickyHash(
		formalGLMPhase21StickyDomain+"/custodian-approvals",
		release.BackendSelection.Signatures)
	if err != nil {
		return zero, err
	}
	var sourceAuthorities []jointDPBiomedicalGaussianSignature
	if release.OneDraw != nil {
		sourceAuthorities = release.OneDraw.Signatures
	} else if release.IndependentFull != nil {
		sourceAuthorities = release.IndependentFull.Signatures
	}
	sourceAuthorityHash, err := formalGLMPhase21StickyHash(
		formalGLMPhase21StickyDomain+"/source-authorities", sourceAuthorities)
	if err != nil {
		return zero, err
	}
	blockers := append([]string(nil), release.Blockers...)
	for _, blocker := range []string{
		"formal_glm_phase21_preflight_not_wired_before_phase20_v1",
		"formal_glm_phase21_noise_purpose_not_derived_from_canonical_artifact_id_v1",
	} {
		if !formalGLMPhase19Contains(blockers, blocker) {
			blockers = append(blockers, blocker)
		}
	}
	noiseEvidence := []formalGLMPhase21StickyNoiseEvidence{
		{Role: "garbler", PeerName: binding.GarblerPeerName,
			PeerID:                  binding.GarblerPeerID,
			CommitmentContextSHA256: binding.GarblerCommitmentContext,
			SeedCommitmentSHA256:    binding.GarblerSeedCommitment},
		{Role: "evaluator", PeerName: binding.EvaluatorPeerName,
			PeerID:                  binding.EvaluatorPeerID,
			CommitmentContextSHA256: binding.EvaluatorCommitmentContext,
			SeedCommitmentSHA256:    binding.EvaluatorSeedCommitment},
	}
	certificate := formalGLMPhase21StickyCertificate{
		Version: formalGLMPhase21StickyVersion, Purpose: formalGLMPhase21StickyPurpose,
		ArtifactID: artifactID, Artifact: artifact,
		SourceScientificArtifactSHA256: plan.Kernel.ArtifactSHA256,
		SourceWorkloadSHA256:           binding.WorkloadSHA256,
		SourceContextSHA256:            binding.SourceContextSHA256,
		SourceLinkTableSHA256:          binding.LinkTableSHA256,
		Phase15PlanSHA256:              binding.Phase15PlanSHA256,
		KernelSpecSHA256:               binding.KernelSpecSHA256,
		CapsuleID:                      binding.CapsuleID,
		ManifestSHA256:                 binding.ManifestSHA256,
		ReleaseBindingSHA256:           binding.BindingSHA256,
		BackendSelectionSHA256:         release.BackendSelectionSHA256,
		SourceReleaseContractSHA256:    binding.ReleaseContractSHA256,
		NoiseCommitmentEvidence:        noiseEvidence,
		SourceCertificateSHA256:        hex.EncodeToString(sourceDigest[:]),
		CustodianApprovalSetSHA256:     approvalHash,
		SourceAuthoritySetSHA256:       sourceAuthorityHash,
		SourceReleaseInstanceID:        release.SourceReleaseInstanceID,
		DPReleaseInstanceID:            release.DPReleaseInstanceID,
		ReleaseContractSHA256:          release.ReleaseContractSHA256,
		Family:                         release.Family, SelectedBackend: release.SelectedBackend,
		SelectionReason:           release.SelectionReason,
		NominalVarianceMultiplier: release.NominalVarianceMultiplier,
		NominalStandardDeviation:  release.NominalStandardDeviation,
		Simultaneous95AbsSteps:    release.Simultaneous95AbsSteps,
		Epsilon:                   release.Epsilon, Delta: release.Delta,
		L2SensitivitySteps:           release.L2SensitivitySteps,
		SensitivityCertificateSHA256: release.SensitivityCertificateSHA256,
		OutputLatticeBits:            release.OutputLatticeBits,
		NoWrapCertificate:            release.NoWrapCertificate,
		VectorSHA256:                 release.VectorSHA256,
		ClampedScaledValues:          append([]string(nil), release.ClampedScaledValues...),
		PrivacyScope:                 "per_canonical_artifact_v1", GlobalCompositionClaim: false,
		SingleCommonDPVector: true, ExactlyOnceDPOpening: false,
		UnlimitedDeterministicReplay: true, UnlimitedPostprocessing: true,
		HistoryCanDenyOperation: false, AdmissionPolicy: "none_v1",
		OpeningsPerformed: 1, ReplayReadsSource: false,
		ReplayInvokesSampler: false, ReplayInvokesFinalizer: false,
		ProductionReady:   false,
		Blockers:          blockers,
		AuthorityReceipts: nil,
	}
	if err := formalGLMPhase21ValidateStickyCertificateCore(
		certificate, pins); err != nil {
		return zero, err
	}
	return certificate, nil
}

func formalGLMPhase21BuildStickyCertificateV2(
	release formalGLMPhase16CertifiedRelease,
	binding formalGLMPhase16ReleaseBinding,
	token formalGLMPhase19PostExecutionToken,
	plan formalGLMPhase15Plan,
	pins map[string]ed25519.PublicKey,
	contract formalGLMPhase21SamplerV2Contract,
) (formalGLMPhase21StickyCertificate, error) {
	return formalGLMPhase21BuildStickyCertificateV2WithResolution(
		release, binding, token, plan, pins, contract, nil)
}

func formalGLMPhase21BuildStickyCertificateV2WithResolution(
	release formalGLMPhase16CertifiedRelease,
	binding formalGLMPhase16ReleaseBinding,
	token formalGLMPhase19PostExecutionToken,
	plan formalGLMPhase15Plan,
	pins map[string]ed25519.PublicKey,
	contract formalGLMPhase21SamplerV2Contract,
	resolution *formalGLMArtifactRegistryResolutionV1,
) (formalGLMPhase21StickyCertificate, error) {
	certificate, err := formalGLMPhase21BuildStickyCertificate(
		release, binding, token, plan, pins)
	if err != nil {
		return formalGLMPhase21StickyCertificate{}, err
	}
	if err := formalGLMPhase21ValidateSamplerV2Contract(
		contract, pins); err != nil {
		return formalGLMPhase21StickyCertificate{},
			fmt.Errorf("formal-glm: sampler-v2 contract differs from sticky artifact")
	}
	if contract.Artifact.DescriptorCoreSHA256 != "" && resolution != nil {
		certificate.Artifact, certificate.ArtifactID, err =
			formalGLMPhase21ProjectRegisteredArtifactV1(
				certificate.Artifact, contract.Artifact, *resolution, pins)
		if err != nil {
			return formalGLMPhase21StickyCertificate{}, err
		}
	} else if contract.Artifact.DescriptorCoreSHA256 != "" || resolution != nil {
		return formalGLMPhase21StickyCertificate{},
			fmt.Errorf("formal-glm: sampler-v2 contract differs from sticky artifact")
	}
	if contract.ArtifactID != certificate.ArtifactID ||
		!reflect.DeepEqual(contract.Artifact, certificate.Artifact) {
		return formalGLMPhase21StickyCertificate{},
			fmt.Errorf("formal-glm: sampler-v2 contract differs from sticky artifact")
	}
	encodedContract, err := json.Marshal(contract)
	if err != nil {
		return formalGLMPhase21StickyCertificate{}, err
	}
	var contractCopy formalGLMPhase21SamplerV2Contract
	if err := json.Unmarshal(encodedContract, &contractCopy); err != nil {
		return formalGLMPhase21StickyCertificate{}, err
	}
	certificate.SamplerV2Contract = &contractCopy
	certificate.NoiseCommitmentEvidence = make(
		[]formalGLMPhase21StickyNoiseEvidence, len(contract.NoiseCommitments))
	for index, commitment := range contract.NoiseCommitments {
		certificate.NoiseCommitmentEvidence[index] =
			formalGLMPhase21StickyNoiseEvidence{
				Role: commitment.Role, PeerName: commitment.PeerName,
				PeerID:                  commitment.PeerID,
				CommitmentContextSHA256: commitment.CommitmentContextSHA256,
				SeedCommitmentSHA256:    commitment.SeedCommitmentSHA256,
			}
	}
	certificate.ExactlyOnceDPOpening = false
	filtered := make([]string, 0, len(certificate.Blockers))
	for _, blocker := range certificate.Blockers {
		if blocker != "formal_glm_phase21_preflight_not_wired_before_phase20_v1" &&
			blocker != "formal_glm_phase21_noise_purpose_not_derived_from_canonical_artifact_id_v1" {
			filtered = append(filtered, blocker)
		}
	}
	const inflightBlocker = "formal_glm_phase21_sampler_v2_inflight_output_not_durable_by_canonical_artifact_v1"
	if !formalGLMPhase19Contains(filtered, inflightBlocker) {
		filtered = append(filtered, inflightBlocker)
	}
	certificate.Blockers = filtered
	if err := formalGLMPhase21ValidateStickyCertificateCore(
		certificate, pins); err != nil {
		return formalGLMPhase21StickyCertificate{}, err
	}
	return certificate, nil
}

func formalGLMPhase21ValidateCanonicalRational(value, what string,
	belowOne bool,
) error {
	parsed := new(big.Rat)
	if _, ok := parsed.SetString(value); !ok || parsed.Sign() <= 0 ||
		parsed.RatString() != value ||
		(belowOne && parsed.Num().Cmp(parsed.Denom()) >= 0) {
		return fmt.Errorf("formal-glm: invalid canonical sticky %s", what)
	}
	return nil
}

func formalGLMPhase21ValidateStickyArtifact(
	artifact formalGLMPhase21StickyArtifact,
	pins map[string]ed25519.PublicKey,
) error {
	hashes := []string{
		artifact.CanonicalScienceSHA256, artifact.CanonicalPlanSHA256,
		artifact.SchemaManifestSHA256, artifact.SnapshotSHA256,
		artifact.PinsetSHA256, artifact.BoundsSHA256,
		artifact.QuantizationSHA256, artifact.CanonicalLinkSHA256,
		artifact.CoordinateOrderSHA256,
	}
	if artifact.DescriptorCoreSHA256 != "" {
		hashes = append(hashes, artifact.DescriptorCoreSHA256)
	}
	pinset, pinErr := formalGLMPhase16PinsetSHA256(pins)
	if artifact.Version != formalGLMPhase21StickyVersion ||
		artifact.Purpose != formalGLMPhase21StickyPurpose ||
		artifact.ScientificArtifactScope !=
			"phase0_formula_estimand_adjacency_optimizer_link_numeric_dp_projection_v1" ||
		artifact.CustodianCount < 2 ||
		len(artifact.CustodianPeers) != artifact.CustodianCount ||
		len(pins) != artifact.CustodianCount || pinErr != nil ||
		pinset != artifact.PinsetSHA256 ||
		!sort.StringsAreSorted(artifact.CustodianPeers) ||
		len(artifact.DesignatedComputePeers) != 2 ||
		len(artifact.NoiseAuthorities) != 2 ||
		artifact.CoordinateCount < 1 || artifact.OutputLatticeBits < 0 ||
		artifact.SourceFractionBits < 0 || artifact.QuantizationShift < 0 ||
		(artifact.Family != "binomial" && artifact.Family != "poisson") ||
		(artifact.Adjacency != "add_remove_patient" &&
			artifact.Adjacency != "replace_one_fixed_cohort") ||
		artifact.Mechanism != formalGLMPhase16RequiredMechanism ||
		artifact.Allocation != formalGLMPhase16RequiredAllocation {
		return fmt.Errorf("formal-glm: invalid sticky artifact")
	}
	for _, value := range hashes {
		if !formalGLMIsSHA256(value) {
			return fmt.Errorf("formal-glm: invalid sticky artifact hash")
		}
	}
	if err := formalGLMPhase21ValidateCanonicalRational(
		artifact.EpsilonRational, "epsilon", false); err != nil {
		return err
	}
	if err := formalGLMPhase21ValidateCanonicalRational(
		artifact.DeltaRational, "delta", true); err != nil {
		return err
	}
	if _, err := jointDPBiomedicalGaussianParseCanonicalInt(
		artifact.SensitivitySteps, "sticky canonical sensitivity", true); err != nil {
		return err
	}
	for index, peer := range artifact.CustodianPeers {
		if !jointDPBiomedicalGaussianValidPeerName(peer) ||
			len(pins[peer]) != ed25519.PublicKeySize ||
			(index > 0 && artifact.CustodianPeers[index-1] >= peer) {
			return fmt.Errorf("formal-glm: sticky custodian pinset is not canonical")
		}
	}
	seen := make(map[string]bool, 2)
	for index, authority := range artifact.NoiseAuthorities {
		role := []string{"garbler", "evaluator"}[index]
		if authority.Role != role ||
			authority.PeerName != artifact.DesignatedComputePeers[index] ||
			seen[authority.PeerName] ||
			!jointDPGaussianOneDrawPinnedPeer.MatchString(authority.PeerID) {
			return fmt.Errorf("formal-glm: invalid sticky noise authority")
		}
		pin := pins[authority.PeerName]
		peerID, err := formalGLMPhase16PeerID(pin)
		if err != nil || peerID != authority.PeerID {
			return fmt.Errorf("formal-glm: sticky noise authority is not pinned")
		}
		seen[authority.PeerName] = true
	}
	return nil
}

// BindDescriptorCore makes the public semantic descriptor part of the sticky
// ArtifactID before any source or sampler operation. Legacy callers keep an
// empty descriptor hash and therefore retain byte-for-byte artifact identity.
func formalGLMPhase21BindDescriptorCore(
	artifact formalGLMPhase21StickyArtifact,
	descriptorCoreSHA256 string,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase21StickyArtifact, string, error) {
	var zero formalGLMPhase21StickyArtifact
	if artifact.DescriptorCoreSHA256 != "" ||
		!formalGLMIsSHA256(descriptorCoreSHA256) ||
		formalGLMPhase21ValidateStickyArtifact(artifact, pins) != nil {
		return zero, "", fmt.Errorf("formal-glm: invalid sticky descriptor binding")
	}
	artifact.DescriptorCoreSHA256 = descriptorCoreSHA256
	if err := formalGLMPhase21ValidateStickyArtifact(artifact, pins); err != nil {
		return zero, "", err
	}
	id, err := formalGLMPhase21StickyArtifactID(artifact)
	if err != nil {
		return zero, "", err
	}
	return artifact, id, nil
}

func formalGLMPhase21ValidateStickyCertificateCore(
	certificate formalGLMPhase21StickyCertificate,
	pins map[string]ed25519.PublicKey,
) error {
	if err := formalGLMPhase21ValidateStickyArtifact(
		certificate.Artifact, pins); err != nil {
		return err
	}
	id, err := formalGLMPhase21StickyArtifactID(certificate.Artifact)
	if err != nil || id != certificate.ArtifactID {
		return fmt.Errorf("formal-glm: sticky artifact id mismatch")
	}
	for _, value := range []string{
		certificate.SourceScientificArtifactSHA256,
		certificate.SourceWorkloadSHA256,
		certificate.SourceContextSHA256,
		certificate.SourceLinkTableSHA256,
		certificate.Phase15PlanSHA256,
		certificate.KernelSpecSHA256,
		certificate.CapsuleID,
		certificate.ManifestSHA256,
		certificate.ReleaseBindingSHA256,
		certificate.BackendSelectionSHA256,
		certificate.SourceReleaseContractSHA256,
		certificate.SourceCertificateSHA256,
		certificate.CustodianApprovalSetSHA256,
		certificate.SourceAuthoritySetSHA256,
		certificate.SourceReleaseInstanceID,
		certificate.DPReleaseInstanceID,
		certificate.ReleaseContractSHA256,
		certificate.SensitivityCertificateSHA256,
		certificate.VectorSHA256,
	} {
		if !formalGLMIsSHA256(value) {
			return fmt.Errorf("formal-glm: invalid sticky certificate hash")
		}
	}
	artifact := certificate.Artifact
	epsilon, epsilonErr := formalGLMPhase21CanonicalRational(
		certificate.Epsilon, "sticky certificate epsilon")
	delta, deltaErr := formalGLMPhase21CanonicalRational(
		certificate.Delta, "sticky certificate delta")
	vectorSHA256 := ""
	var vectorErr error
	if certificate.SelectedBackend == formalGLMPhase16BackendOneDraw {
		vectorSHA256, vectorErr = jointDPBiomedicalGaussianOneDrawVectorSHA256(
			certificate.ClampedScaledValues)
	} else if certificate.SelectedBackend == formalGLMPhase16BackendFull {
		var digest [32]byte
		digest, vectorErr = jointDPBiomedicalGaussianDomainDigest(
			jointDPBiomedicalGaussianFullLocalReleaseDomain+"/vector",
			certificate.ClampedScaledValues)
		vectorSHA256 = hex.EncodeToString(digest[:])
	}
	if certificate.Version != formalGLMPhase21StickyVersion ||
		certificate.Purpose != formalGLMPhase21StickyPurpose ||
		certificate.Family != artifact.Family ||
		(certificate.SelectedBackend != formalGLMPhase16BackendOneDraw &&
			certificate.SelectedBackend != formalGLMPhase16BackendFull) ||
		epsilonErr != nil || epsilon != artifact.EpsilonRational ||
		deltaErr != nil || delta != artifact.DeltaRational ||
		certificate.L2SensitivitySteps != artifact.SensitivitySteps ||
		certificate.OutputLatticeBits != artifact.OutputLatticeBits ||
		len(certificate.ClampedScaledValues) != artifact.CoordinateCount ||
		vectorErr != nil || vectorSHA256 != certificate.VectorSHA256 ||
		len(certificate.NoiseCommitmentEvidence) != 2 {
		return fmt.Errorf("formal-glm: sticky certificate identity mismatch")
	}
	for index, evidence := range certificate.NoiseCommitmentEvidence {
		authority := artifact.NoiseAuthorities[index]
		if evidence.Role != authority.Role ||
			evidence.PeerName != authority.PeerName ||
			evidence.PeerID != authority.PeerID ||
			!formalGLMIsSHA256(evidence.CommitmentContextSHA256) ||
			!formalGLMIsSHA256(evidence.SeedCommitmentSHA256) {
			return fmt.Errorf("formal-glm: invalid sticky noise evidence")
		}
	}
	if certificate.PrivacyScope != "per_canonical_artifact_v1" ||
		certificate.GlobalCompositionClaim || !certificate.SingleCommonDPVector ||
		!certificate.UnlimitedDeterministicReplay ||
		!certificate.UnlimitedPostprocessing ||
		certificate.HistoryCanDenyOperation ||
		certificate.AdmissionPolicy != "none_v1" ||
		certificate.OpeningsPerformed != 1 || certificate.ReplayReadsSource ||
		certificate.ReplayInvokesSampler || certificate.ReplayInvokesFinalizer ||
		certificate.ProductionReady {
		return fmt.Errorf("formal-glm: invalid sticky certificate lifecycle contract")
	}
	if certificate.SamplerV2Contract == nil {
		if certificate.ExactlyOnceDPOpening ||
			certificate.DurablePublicationProtocol != "" ||
			len(certificate.Blockers) == 0 ||
			!formalGLMPhase19Contains(certificate.Blockers,
				"formal_glm_phase21_preflight_not_wired_before_phase20_v1") ||
			!formalGLMPhase19Contains(certificate.Blockers,
				"formal_glm_phase21_noise_purpose_not_derived_from_canonical_artifact_id_v1") {
			return fmt.Errorf("formal-glm: invalid legacy sticky lifecycle contract")
		}
	} else {
		contract := *certificate.SamplerV2Contract
		modeMatches := certificate.SelectedBackend == formalGLMPhase16BackendOneDraw &&
			contract.SamplerMode == formalGLMPhase21SamplerV2OneDraw ||
			certificate.SelectedBackend == formalGLMPhase16BackendFull &&
				contract.SamplerMode == formalGLMPhase21SamplerV2Full
		if !modeMatches ||
			contract.ArtifactID != certificate.ArtifactID ||
			!reflect.DeepEqual(contract.Artifact, certificate.Artifact) ||
			formalGLMPhase21ValidateSamplerV2Contract(contract, pins) != nil ||
			formalGLMPhase19Contains(certificate.Blockers,
				"formal_glm_phase21_preflight_not_wired_before_phase20_v1") ||
			formalGLMPhase19Contains(certificate.Blockers,
				"formal_glm_phase21_noise_purpose_not_derived_from_canonical_artifact_id_v1") {
			return fmt.Errorf("formal-glm: invalid sampler-v2 sticky lifecycle contract")
		}
		for index, commitment := range contract.NoiseCommitments {
			evidence := certificate.NoiseCommitmentEvidence[index]
			if evidence.Role != commitment.Role ||
				evidence.PeerName != commitment.PeerName ||
				evidence.PeerID != commitment.PeerID ||
				evidence.CommitmentContextSHA256 !=
					commitment.CommitmentContextSHA256 ||
				evidence.SeedCommitmentSHA256 !=
					commitment.SeedCommitmentSHA256 {
				return fmt.Errorf("formal-glm: sampler-v2 noise evidence mismatch")
			}
		}
		const inflight = "formal_glm_phase21_sampler_v2_inflight_output_not_durable_by_canonical_artifact_v1"
		durable := certificate.DurablePublicationProtocol ==
			formalGLMPhase21DurableV2Version
		if certificate.DurablePublicationProtocol != "" && !durable {
			return fmt.Errorf("formal-glm: unknown sampler-v2 durability protocol")
		}
		if durable {
			if !certificate.ExactlyOnceDPOpening ||
				formalGLMPhase19Contains(certificate.Blockers, inflight) {
				return fmt.Errorf("formal-glm: invalid durable sampler-v2 lifecycle")
			}
		} else if certificate.ExactlyOnceDPOpening ||
			!formalGLMPhase19Contains(certificate.Blockers, inflight) {
			return fmt.Errorf("formal-glm: sampler-v2 inflight durability is overstated")
		}
	}
	for _, text := range certificate.ClampedScaledValues {
		if _, err := jointDPBiomedicalGaussianParseCanonicalInt(
			text, "sticky public coordinate", false); err != nil {
			return err
		}
	}
	return nil
}

func formalGLMPhase21StickyCertificateMessage(
	certificate formalGLMPhase21StickyCertificate,
) ([]byte, error) {
	certificate.AuthorityReceipts = nil
	encoded, err := json.Marshal(certificate)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMPhase21StickyDomain+"/authority|"),
		encoded...), nil
}

func formalGLMPhase21StickySignerRecordMAC(key [32]byte,
	record formalGLMPhase21StickySignerRecord,
) (string, error) {
	record.RecordMAC = ""
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(formalGLMPhase21StickyDomain + "/signer-record|"))
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func formalGLMPhase21StickyEncodeSignerRecord(key [32]byte,
	record formalGLMPhase21StickySignerRecord,
) ([]byte, error) {
	mac, err := formalGLMPhase21StickySignerRecordMAC(key, record)
	if err != nil {
		return nil, err
	}
	record.RecordMAC = mac
	return json.Marshal(record)
}

func (store *formalGLMPhase21StickyReleaseStore) decodeSignerRecord(
	encoded []byte,
) (formalGLMPhase21StickySignerRecord, error) {
	var zero formalGLMPhase21StickySignerRecord
	if len(encoded) < 64 || len(encoded) > formalGLMPhase21StickySignerMaxBytes {
		return zero, fmt.Errorf("formal-glm: invalid sticky signer record size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record formalGLMPhase21StickySignerRecord
	if err := decoder.Decode(&record); err != nil {
		return zero, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return zero, fmt.Errorf("formal-glm: trailing sticky signer record data")
	}
	want, err := formalGLMPhase21StickySignerRecordMAC(store.key, record)
	if err != nil || !hmac.Equal([]byte(want), []byte(record.RecordMAC)) ||
		record.Version != formalGLMPhase21StickySignerVersion ||
		record.Purpose != formalGLMPhase21StickyPurpose ||
		record.Peer != store.peer ||
		(record.Role != "garbler" && record.Role != "evaluator") ||
		!formalGLMIsSHA256(record.ArtifactID) ||
		!formalGLMIsSHA256(record.CertificateSHA256) ||
		(record.Role == "garbler" && record.PredecessorReceiptSHA256 != "") ||
		(record.Role == "evaluator" &&
			!formalGLMIsSHA256(record.PredecessorReceiptSHA256)) ||
		len(record.Signature) != ed25519.SignatureSize {
		return zero, fmt.Errorf("formal-glm: sticky signer authentication failed")
	}
	canonical, err := formalGLMPhase21StickyEncodeSignerRecord(store.key, record)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return zero, fmt.Errorf("formal-glm: non-canonical sticky signer record")
	}
	return record, nil
}

// SignOnce is deliberately ordered and durable.  The garbler is the sole
// first signer; the evaluator signs only the exact certificate carrying a
// valid garbler receipt.  The canonical artifact ID is the CAS key, so two
// different candidates cannot both collect the two required receipts.
func (store *formalGLMPhase21StickyReleaseStore) SignOnce(
	certificate formalGLMPhase21StickyCertificate,
	privateKey ed25519.PrivateKey,
	predecessors []jointDPBiomedicalGaussianSignature,
) (jointDPBiomedicalGaussianSignature, bool, error) {
	var zero jointDPBiomedicalGaussianSignature
	if store == nil || store.root == nil ||
		!formalGLMPhase19KeyValid(store.key) ||
		len(certificate.AuthorityReceipts) != 0 {
		return zero, false, fmt.Errorf("formal-glm: invalid sticky SignOnce state")
	}
	if err := formalGLMPhase21ValidateStickyCertificateCore(
		certificate, store.pins); err != nil {
		return zero, false, err
	}
	if certificate.DurablePublicationProtocol == formalGLMPhase21DurableV2Version {
		staged, err := store.loadDurableV2Candidate(certificate.ArtifactID)
		if err != nil || !reflect.DeepEqual(staged, certificate) {
			return zero, false,
				fmt.Errorf("formal-glm: durable SignOnce lacks exact local spool")
		}
	}
	position := -1
	for index, authority := range certificate.Artifact.NoiseAuthorities {
		if authority.PeerName == store.peer {
			position = index
		}
	}
	public, ok := privateKey.Public().(ed25519.PublicKey)
	if position < 0 || !ok || !hmac.Equal(public, store.pins[store.peer]) {
		return zero, false,
			fmt.Errorf("formal-glm: sticky SignOnce signer is not pinned")
	}
	message, err := formalGLMPhase21StickyCertificateMessage(certificate)
	if err != nil {
		return zero, false, err
	}
	predecessorSHA256 := ""
	if position == 0 {
		if len(predecessors) != 0 {
			return zero, false,
				fmt.Errorf("formal-glm: garbler SignOnce has a predecessor")
		}
	} else {
		if len(predecessors) != 1 {
			return zero, false,
				fmt.Errorf("formal-glm: evaluator SignOnce lacks garbler receipt")
		}
		predecessor := predecessors[0]
		garbler := certificate.Artifact.NoiseAuthorities[0]
		if predecessor.Signer != garbler.PeerName ||
			len(predecessor.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(store.pins[garbler.PeerName], message,
				predecessor.Signature) {
			return zero, false,
				fmt.Errorf("formal-glm: evaluator SignOnce predecessor is invalid")
		}
		predecessorSHA256, err = formalGLMPhase21StickyHash(
			formalGLMPhase21StickyDomain+"/predecessor-receipt", predecessor)
		if err != nil {
			return zero, false, err
		}
	}
	certificateSHA256 := sha256.Sum256(append(
		[]byte(formalGLMPhase21StickyDomain+"/sign-once-certificate|"),
		message...))
	record := formalGLMPhase21StickySignerRecord{
		Version: formalGLMPhase21StickySignerVersion,
		Purpose: formalGLMPhase21StickyPurpose,
		Peer:    store.peer, Role: []string{"garbler", "evaluator"}[position],
		ArtifactID:               certificate.ArtifactID,
		CertificateSHA256:        hex.EncodeToString(certificateSHA256[:]),
		PredecessorReceiptSHA256: predecessorSHA256,
		Signature:                ed25519.Sign(privateKey, message),
	}
	encoded, err := formalGLMPhase21StickyEncodeSignerRecord(store.key, record)
	if err != nil {
		return zero, false, err
	}
	relative, err := store.signerRelativePath(certificate.ArtifactID, true)
	if err != nil {
		return zero, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	created, err := formalGLMPhase21RootCreateRecord(store.root, relative, encoded)
	if err != nil {
		return zero, false, err
	}
	existingBytes, err := formalGLMPhase21RootReadRecord(
		store.root, relative, formalGLMPhase21StickySignerMaxBytes)
	if err != nil {
		return zero, false, err
	}
	existing, err := store.decodeSignerRecord(existingBytes)
	if err != nil {
		return zero, false, err
	}
	if existing.ArtifactID != record.ArtifactID ||
		existing.CertificateSHA256 != record.CertificateSHA256 ||
		existing.PredecessorReceiptSHA256 != record.PredecessorReceiptSHA256 ||
		existing.Role != record.Role ||
		!ed25519.Verify(store.pins[store.peer], message, existing.Signature) {
		return zero, false, fmt.Errorf("formal-glm: conflicting sticky SignOnce")
	}
	return jointDPBiomedicalGaussianSignature{
		Signer:    store.peer,
		Signature: append([]byte(nil), existing.Signature...),
	}, !created, nil
}

func (store *formalGLMPhase21StickyReleaseStore) validateDurableV2LocalSigner(
	certificate formalGLMPhase21StickyCertificate,
) error {
	if store == nil || certificate.DurablePublicationProtocol !=
		formalGLMPhase21DurableV2Version || len(certificate.AuthorityReceipts) != 2 {
		return fmt.Errorf("formal-glm: invalid durable local signer check")
	}
	unsigned := certificate
	unsigned.AuthorityReceipts = nil
	staged, err := store.loadDurableV2Candidate(certificate.ArtifactID)
	if err != nil || !reflect.DeepEqual(staged, unsigned) {
		return fmt.Errorf("formal-glm: durable publication lacks exact local spool")
	}
	position := -1
	for index, authority := range certificate.Artifact.NoiseAuthorities {
		if authority.PeerName == store.peer {
			position = index
		}
	}
	if position < 0 {
		return fmt.Errorf("formal-glm: durable publisher is not an authority")
	}
	relative, err := store.signerRelativePath(certificate.ArtifactID, false)
	if err != nil {
		return err
	}
	encoded, err := formalGLMPhase21RootReadRecord(
		store.root, relative, formalGLMPhase21StickySignerMaxBytes)
	if err != nil {
		return err
	}
	record, err := store.decodeSignerRecord(encoded)
	if err != nil {
		return err
	}
	message, err := formalGLMPhase21StickyCertificateMessage(unsigned)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMPhase21StickyDomain+"/sign-once-certificate|"),
		message...))
	expectedPredecessor := ""
	if position == 1 {
		expectedPredecessor, err = formalGLMPhase21StickyHash(
			formalGLMPhase21StickyDomain+"/predecessor-receipt",
			certificate.AuthorityReceipts[0])
		if err != nil {
			return err
		}
	}
	receipt := certificate.AuthorityReceipts[position]
	if record.ArtifactID != certificate.ArtifactID ||
		record.CertificateSHA256 != hex.EncodeToString(digest[:]) ||
		record.PredecessorReceiptSHA256 != expectedPredecessor ||
		record.Role != certificate.Artifact.NoiseAuthorities[position].Role ||
		receipt.Signer != store.peer ||
		!hmac.Equal(record.Signature, receipt.Signature) ||
		!ed25519.Verify(store.pins[store.peer], message, record.Signature) {
		return fmt.Errorf("formal-glm: durable publication lacks local SignOnce CAS")
	}
	return nil
}

func formalGLMPhase21SealStickyCertificate(
	certificate formalGLMPhase21StickyCertificate,
	receipts []jointDPBiomedicalGaussianSignature,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase21StickyCertificate, error) {
	certificate.AuthorityReceipts = make(
		[]jointDPBiomedicalGaussianSignature, len(receipts))
	for index := range receipts {
		certificate.AuthorityReceipts[index] = jointDPBiomedicalGaussianSignature{
			Signer:    receipts[index].Signer,
			Signature: append([]byte(nil), receipts[index].Signature...),
		}
	}
	if err := formalGLMPhase21ValidateStickyCertificate(
		certificate, pins); err != nil {
		return formalGLMPhase21StickyCertificate{}, err
	}
	return certificate, nil
}

func formalGLMPhase21ValidateStickyCertificate(
	certificate formalGLMPhase21StickyCertificate,
	pins map[string]ed25519.PublicKey,
) error {
	if err := formalGLMPhase21ValidateStickyCertificateCore(
		certificate, pins); err != nil {
		return err
	}
	if len(certificate.AuthorityReceipts) != 2 {
		return fmt.Errorf("formal-glm: sticky certificate lacks both authorities")
	}
	message, err := formalGLMPhase21StickyCertificateMessage(certificate)
	if err != nil {
		return err
	}
	for index, authority := range certificate.Artifact.NoiseAuthorities {
		receipt := certificate.AuthorityReceipts[index]
		if receipt.Signer != authority.PeerName ||
			len(receipt.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(pins[receipt.Signer], message, receipt.Signature) {
			return fmt.Errorf("formal-glm: sticky authority receipt verification failed")
		}
	}
	return nil
}

func formalGLMPhase21StickyStoreKey(storageRoot [32]byte, peer string) (
	[32]byte, error) {
	var result [32]byte
	if !formalGLMPhase19KeyValid(storageRoot) ||
		!jointDPBiomedicalGaussianValidPeerName(peer) {
		return result, fmt.Errorf("formal-glm: invalid sticky store identity")
	}
	salt := sha256.Sum256([]byte(formalGLMPhase21StickyDomain + "/store/" + peer))
	reader := hkdf.New(sha256.New, storageRoot[:], salt[:],
		[]byte(formalGLMPhase21StickyPurpose))
	if _, err := io.ReadFull(reader, result[:]); err != nil ||
		!formalGLMPhase19KeyValid(result) {
		clear(result[:])
		return result, fmt.Errorf("formal-glm: sticky store key derivation failed")
	}
	return result, nil
}

func formalGLMPhase21EnsureRootPrivateDir(root *os.Root, name string) error {
	if root == nil || name == "" || filepath.IsAbs(name) ||
		filepath.Clean(name) != name {
		return fmt.Errorf("formal-glm: invalid rooted sticky directory")
	}
	if err := root.MkdirAll(name, 0o700); err != nil {
		return err
	}
	return formalGLMPhase21ValidateRootPrivateDir(root, name, true)
}

func formalGLMPhase21ValidateRootPrivateDir(root *os.Root, name string,
	chmod bool,
) error {
	if root == nil || name == "" || filepath.IsAbs(name) ||
		filepath.Clean(name) != name {
		return fmt.Errorf("formal-glm: invalid rooted sticky directory")
	}
	parts := strings.Split(filepath.ToSlash(name), "/")
	current := ""
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("formal-glm: invalid rooted sticky directory")
		}
		current = filepath.Join(current, part)
		if chmod {
			if info, err := root.Lstat(current); err != nil || !info.IsDir() ||
				info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("formal-glm: unsafe rooted sticky directory")
			}
		}
		if chmod {
			if err := root.Chmod(current, 0o700); err != nil {
				return err
			}
		}
		info, err := root.Lstat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("formal-glm: unsafe rooted sticky directory")
		}
	}
	return nil
}

func newFormalGLMPhase21StickyReleaseStore(
	dir, peer string, storageRoot [32]byte,
	pins map[string]ed25519.PublicKey,
) (*formalGLMPhase21StickyReleaseStore, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir ||
		len(pins[peer]) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("formal-glm: invalid sticky store path or peer")
	}
	if info, err := os.Lstat(dir); err == nil &&
		(info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
		return nil, fmt.Errorf("formal-glm: unsafe sticky store root")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := formalGLMPhase18EnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil || !filepath.IsAbs(resolvedDir) {
		return nil, fmt.Errorf("formal-glm: sticky store root cannot be resolved")
	}
	dir = filepath.Clean(resolvedDir)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	if err := formalGLMPhase21EnsureRootPrivateDir(root, "records-v1"); err != nil {
		_ = root.Close()
		return nil, err
	}
	if err := formalGLMPhase21EnsureRootPrivateDir(root, "signatures-v1"); err != nil {
		_ = root.Close()
		return nil, err
	}
	if err := formalGLMPhase21EnsureRootPrivateDir(root, "guards-v2"); err != nil {
		_ = root.Close()
		return nil, err
	}
	if err := formalGLMPhase21EnsureRootPrivateDir(root, "public-v2"); err != nil {
		_ = root.Close()
		return nil, err
	}
	key, err := formalGLMPhase21StickyStoreKey(storageRoot, peer)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	copyPins := make(map[string]ed25519.PublicKey, len(pins))
	for name, pin := range pins {
		if len(pin) != ed25519.PublicKeySize {
			clear(key[:])
			_ = root.Close()
			return nil, fmt.Errorf("formal-glm: invalid sticky store pinset")
		}
		copyPins[name] = append(ed25519.PublicKey(nil), pin...)
	}
	return &formalGLMPhase21StickyReleaseStore{
		dir: dir, records: filepath.Join(dir, "records-v1"),
		signers: filepath.Join(dir, "signatures-v1"),
		guards:  filepath.Join(dir, "guards-v2"),
		peer:    peer, key: key, pins: copyPins, root: root,
	}, nil
}

func (store *formalGLMPhase21StickyReleaseStore) close() {
	if store != nil {
		clear(store.key[:])
		if store.root != nil {
			_ = store.root.Close()
			store.root = nil
		}
	}
}

func (store *formalGLMPhase21StickyReleaseStore) recordPath(
	artifactID string, create bool) (string, error) {
	relative, err := store.recordRelativePath(artifactID, create)
	if err != nil {
		return "", err
	}
	return filepath.Join(store.dir, relative), nil
}

func (store *formalGLMPhase21StickyReleaseStore) recordRelativePath(
	artifactID string, create bool) (string, error) {
	if !formalGLMIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-glm: invalid sticky artifact id")
	}
	shard := filepath.Join("records-v1", artifactID[:2], artifactID[2:4])
	if create {
		if err := formalGLMPhase21EnsureRootPrivateDir(store.root, shard); err != nil {
			return "", err
		}
	} else if err := formalGLMPhase21ValidateRootPrivateDir(
		store.root, shard, false); err != nil {
		return "", err
	}
	return filepath.Join(shard, "release-"+artifactID+".json"), nil
}

func (store *formalGLMPhase21StickyReleaseStore) signerRelativePath(
	artifactID string, create bool) (string, error) {
	if !formalGLMIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-glm: invalid sticky signer artifact id")
	}
	shard := filepath.Join("signatures-v1", artifactID[:2], artifactID[2:4])
	if create {
		if err := formalGLMPhase21EnsureRootPrivateDir(store.root, shard); err != nil {
			return "", err
		}
	} else if err := formalGLMPhase21ValidateRootPrivateDir(
		store.root, shard, false); err != nil {
		return "", err
	}
	return filepath.Join(shard,
		"signature-"+store.peer+"-"+artifactID+".json"), nil
}

func formalGLMPhase21RootSyncDir(root *os.Root, relative string) error {
	directory, err := root.Open(filepath.Dir(relative))
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func formalGLMPhase21RootCreateRecord(root *os.Root, relative string,
	encoded []byte,
) (bool, error) {
	if root == nil || filepath.IsAbs(relative) ||
		filepath.Clean(relative) != relative {
		return false, fmt.Errorf("formal-glm: invalid rooted sticky record")
	}
	var random [16]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return false, err
	}
	temporary := filepath.Join(filepath.Dir(relative),
		".formal-glm-sticky-"+hex.EncodeToString(random[:]))
	file, err := root.OpenFile(temporary,
		os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = root.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return false, err
	}
	if err := exactGCWriteFull(file, encoded); err != nil {
		_ = file.Close()
		return false, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return false, err
	}
	if err := file.Close(); err != nil {
		return false, err
	}
	if err := root.Link(temporary, relative); err != nil {
		if !os.IsExist(err) {
			return false, err
		}
		return false, nil
	}
	if err := root.Remove(temporary); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	removeTemporary = false
	if err := formalGLMPhase21RootSyncDir(root, relative); err != nil {
		return false, err
	}
	return true, nil
}

func formalGLMPhase21RootReapCommittedTemp(root *os.Root,
	relative string, target os.FileInfo,
) (bool, error) {
	directoryName := filepath.Dir(relative)
	directory, err := root.Open(directoryName)
	if err != nil {
		return false, err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil {
		return false, readErr
	}
	if closeErr != nil {
		return false, closeErr
	}
	for _, entry := range entries {
		if entry.IsDir() ||
			!strings.HasPrefix(entry.Name(), ".formal-glm-sticky-") {
			continue
		}
		candidate := filepath.Join(directoryName, entry.Name())
		info, err := root.Lstat(candidate)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false, err
		}
		if !os.SameFile(target, info) {
			continue
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o077 != 0 || info.Size() != target.Size() {
			return false, fmt.Errorf("formal-glm: unsafe linked sticky temporary")
		}
		if err := root.Remove(candidate); err != nil && !os.IsNotExist(err) {
			return false, err
		}
		if err := formalGLMPhase21RootSyncDir(root, relative); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func formalGLMPhase21RootReadRecord(root *os.Root, relative string,
	maximum int64,
) ([]byte, error) {
	for attempt := 0; attempt < 32; attempt++ {
		info, err := root.Lstat(relative)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o077 != 0 || info.Size() < 64 ||
			info.Size() > maximum {
			return nil, fmt.Errorf("formal-glm: unsafe rooted sticky record")
		}
		if !exactGCPrivateOwnedRegular(info) {
			reaped, reapErr := formalGLMPhase21RootReapCommittedTemp(
				root, relative, info)
			if reapErr != nil {
				return nil, reapErr
			}
			if reaped {
				continue
			}
			runtime.Gosched()
			continue
		}
		file, err := root.Open(relative)
		if err != nil {
			return nil, err
		}
		opened, err := file.Stat()
		if err != nil || !os.SameFile(info, opened) ||
			!exactGCPrivateOwnedRegular(opened) ||
			opened.Size() != info.Size() || opened.Size() < 64 ||
			opened.Size() > maximum {
			_ = file.Close()
			if err != nil {
				return nil, err
			}
			runtime.Gosched()
			continue
		}
		value := make([]byte, opened.Size())
		_, readErr := io.ReadFull(file, value)
		closeErr := file.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		return value, nil
	}
	return nil, fmt.Errorf("formal-glm: rooted sticky record did not stabilize")
}

func formalGLMPhase21StickyRecordMAC(key [32]byte,
	record formalGLMPhase21StickyRecord) (string, error) {
	record.RecordMAC = ""
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(formalGLMPhase21StickyDomain + "/record|"))
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func formalGLMPhase21StickyEncodeRecord(key [32]byte,
	record formalGLMPhase21StickyRecord) ([]byte, error) {
	mac, err := formalGLMPhase21StickyRecordMAC(key, record)
	if err != nil {
		return nil, err
	}
	record.RecordMAC = mac
	return json.Marshal(record)
}

func (store *formalGLMPhase21StickyReleaseStore) decodeRecord(
	encoded []byte) (formalGLMPhase21StickyRecord,
	formalGLMPhase21StickyCertificate, []byte, error) {
	var zeroRecord formalGLMPhase21StickyRecord
	var zeroCertificate formalGLMPhase21StickyCertificate
	if len(encoded) < 64 || len(encoded) > formalGLMPhase21StickyMaxBytes {
		return zeroRecord, zeroCertificate, nil,
			fmt.Errorf("formal-glm: invalid sticky record size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record formalGLMPhase21StickyRecord
	if err := decoder.Decode(&record); err != nil {
		return zeroRecord, zeroCertificate, nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return zeroRecord, zeroCertificate, nil,
			fmt.Errorf("formal-glm: trailing sticky record data")
	}
	want, err := formalGLMPhase21StickyRecordMAC(store.key, record)
	if err != nil || !hmac.Equal([]byte(want), []byte(record.RecordMAC)) ||
		record.Version != formalGLMPhase21StickyRecordVersion ||
		record.Purpose != formalGLMPhase21StickyPurpose ||
		record.Peer != store.peer || !formalGLMIsSHA256(record.ArtifactID) ||
		!formalGLMIsSHA256(record.CertificateSHA256) ||
		len(record.CertificateJSON) == 0 {
		return zeroRecord, zeroCertificate, nil,
			fmt.Errorf("formal-glm: sticky record authentication failed")
	}
	canonicalRecord, err := formalGLMPhase21StickyEncodeRecord(store.key, record)
	if err != nil || !bytes.Equal(canonicalRecord, encoded) {
		return zeroRecord, zeroCertificate, nil,
			fmt.Errorf("formal-glm: non-canonical sticky record")
	}
	certificateBytes := []byte(record.CertificateJSON)
	digest := sha256.Sum256(append(
		[]byte(formalGLMPhase21StickyDomain+"/certificate|"),
		certificateBytes...))
	if hex.EncodeToString(digest[:]) != record.CertificateSHA256 {
		return zeroRecord, zeroCertificate, nil,
			fmt.Errorf("formal-glm: sticky certificate digest mismatch")
	}
	certificateDecoder := json.NewDecoder(bytes.NewReader(certificateBytes))
	certificateDecoder.DisallowUnknownFields()
	var certificate formalGLMPhase21StickyCertificate
	if err := certificateDecoder.Decode(&certificate); err != nil {
		return zeroRecord, zeroCertificate, nil, err
	}
	if err := certificateDecoder.Decode(&trailing); err != io.EOF {
		return zeroRecord, zeroCertificate, nil,
			fmt.Errorf("formal-glm: trailing sticky certificate data")
	}
	canonicalCertificate, err := json.Marshal(certificate)
	if err != nil || !bytes.Equal(canonicalCertificate, certificateBytes) ||
		certificate.ArtifactID != record.ArtifactID {
		return zeroRecord, zeroCertificate, nil,
			fmt.Errorf("formal-glm: non-canonical sticky certificate")
	}
	if err := formalGLMPhase21ValidateStickyCertificate(
		certificate, store.pins); err != nil {
		return zeroRecord, zeroCertificate, nil, err
	}
	return record, certificate, certificateBytes, nil
}

func (store *formalGLMPhase21StickyReleaseStore) Commit(
	certificate formalGLMPhase21StickyCertificate,
) (formalGLMPhase21StickyPublication, error) {
	var zero formalGLMPhase21StickyPublication
	if store == nil || store.root == nil ||
		!formalGLMPhase19KeyValid(store.key) {
		return zero, fmt.Errorf("formal-glm: closed sticky store")
	}
	if err := formalGLMPhase21ValidateStickyCertificate(
		certificate, store.pins); err != nil {
		return zero, err
	}
	if certificate.DurablePublicationProtocol == formalGLMPhase21DurableV2Version {
		if err := store.validateDurableV2LocalSigner(certificate); err != nil {
			return zero, err
		}
	}
	certificateBytes, err := json.Marshal(certificate)
	if err != nil || len(certificateBytes) > formalGLMPhase21StickyMaxBytes/2 {
		return zero, fmt.Errorf("formal-glm: sticky certificate too large")
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMPhase21StickyDomain+"/certificate|"),
		certificateBytes...))
	record := formalGLMPhase21StickyRecord{
		Version: formalGLMPhase21StickyRecordVersion,
		Purpose: formalGLMPhase21StickyPurpose, Peer: store.peer,
		ArtifactID:        certificate.ArtifactID,
		CertificateSHA256: hex.EncodeToString(digest[:]),
		CertificateJSON:   string(certificateBytes),
	}
	encoded, err := formalGLMPhase21StickyEncodeRecord(store.key, record)
	if err != nil {
		return zero, err
	}
	path, err := store.recordRelativePath(certificate.ArtifactID, true)
	if err != nil {
		return zero, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	created, err := formalGLMPhase21RootCreateRecord(store.root, path, encoded)
	if err != nil {
		return zero, err
	}
	existingBytes, err := formalGLMPhase21RootReadRecord(
		store.root, path, formalGLMPhase21StickyMaxBytes)
	if err != nil {
		return zero, err
	}
	existing, _, publicBytes, err := store.decodeRecord(existingBytes)
	if err != nil {
		return zero, err
	}
	if existing.ArtifactID != record.ArtifactID ||
		existing.CertificateSHA256 != record.CertificateSHA256 ||
		!bytes.Equal(publicBytes, certificateBytes) {
		return zero, fmt.Errorf("formal-glm: conflicting sticky release")
	}
	return formalGLMPhase21StickyPublication{
		ArtifactID:        existing.ArtifactID,
		CertificateSHA256: existing.CertificateSHA256,
		Certificate:       append([]byte(nil), publicBytes...), Replayed: !created,
	}, nil
}

func (store *formalGLMPhase21StickyReleaseStore) Replay(
	artifactID string) (formalGLMPhase21StickyPublication, error) {
	var zero formalGLMPhase21StickyPublication
	if store == nil || store.root == nil ||
		!formalGLMPhase19KeyValid(store.key) {
		return zero, fmt.Errorf("formal-glm: closed sticky store")
	}
	path, err := store.recordRelativePath(artifactID, false)
	if err != nil {
		return zero, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	encoded, err := formalGLMPhase21RootReadRecord(
		store.root, path, formalGLMPhase21StickyMaxBytes)
	if err != nil {
		return zero, err
	}
	record, _, certificate, err := store.decodeRecord(encoded)
	if err != nil {
		return zero, err
	}
	return formalGLMPhase21StickyPublication{
		ArtifactID:        record.ArtifactID,
		CertificateSHA256: record.CertificateSHA256,
		Certificate:       append([]byte(nil), certificate...), Replayed: true,
	}, nil
}

// Preflight computes only the canonical scientific/DP identity and consults
// the sticky store.  It needs no released vector, source handoff, sampler,
// finalizer, reservation, epoch or receipt.
func (store *formalGLMPhase21StickyReleaseStore) Preflight(
	binding formalGLMPhase16ReleaseBinding,
	plan formalGLMPhase15Plan,
) (formalGLMPhase21StickyArtifact, string,
	formalGLMPhase21StickyPublication, bool, error) {
	var zeroPublication formalGLMPhase21StickyPublication
	if store == nil || store.root == nil ||
		!formalGLMPhase19KeyValid(store.key) {
		return formalGLMPhase21StickyArtifact{}, "", zeroPublication, false,
			fmt.Errorf("formal-glm: closed sticky preflight store")
	}
	artifact, artifactID, err := formalGLMPhase21BuildCanonicalArtifact(
		binding, plan, store.pins)
	if err != nil {
		return formalGLMPhase21StickyArtifact{}, "", zeroPublication, false, err
	}
	publication, err := store.Replay(artifactID)
	if os.IsNotExist(err) {
		return artifact, artifactID, zeroPublication, false, nil
	}
	if err != nil {
		return formalGLMPhase21StickyArtifact{}, "", zeroPublication, false, err
	}
	return artifact, artifactID, publication, true, nil
}

func formalGLMPhase21DecodeStickyPublication(
	publication formalGLMPhase21StickyPublication,
) (formalGLMPhase21StickyCertificate, error) {
	var zero formalGLMPhase21StickyCertificate
	decoder := json.NewDecoder(bytes.NewReader(publication.Certificate))
	decoder.DisallowUnknownFields()
	var certificate formalGLMPhase21StickyCertificate
	if err := decoder.Decode(&certificate); err != nil {
		return zero, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return zero, fmt.Errorf("formal-glm: trailing replay certificate")
	}
	if certificate.ArtifactID != publication.ArtifactID {
		return zero, fmt.Errorf("formal-glm: replay artifact mismatch")
	}
	return certificate, nil
}

func formalGLMPhase21CommitOneDrawAndCleanup(
	publicationStore *formalGLMPhase21StickyReleaseStore,
	sourceStore *formalGLMPhase20HandoffStore,
	output formalGLMPhase21OneDrawLocalOutput,
	release formalGLMPhase16CertifiedRelease,
	certificate formalGLMPhase21StickyCertificate,
	phaseHook func(string) error,
) (formalGLMPhase21StickyPublication, int64, error) {
	var zero formalGLMPhase21StickyPublication
	if publicationStore == nil || sourceStore == nil ||
		publicationStore.peer != output.Peer || sourceStore.peer != output.Peer {
		return zero, 0, fmt.Errorf("formal-glm: misrouted sticky publication")
	}
	if err := formalGLMPhase21ValidateLocalOutputSource(
		sourceStore, output); err != nil {
		return zero, 0, err
	}
	source, _, err := sourceStore.Load()
	if err != nil {
		return zero, 0, err
	}
	plan := source.Plan
	source.clear()
	var expected formalGLMPhase21StickyCertificate
	if certificate.SamplerV2Contract == nil {
		expected, err = formalGLMPhase21BuildStickyCertificate(
			release, output.Admission.Compiled.Binding,
			output.Admission.Token, plan, sourceStore.pins)
	} else {
		expected, err = formalGLMPhase21BuildStickyCertificateV2(
			release, output.Admission.Compiled.Binding,
			output.Admission.Token, plan, sourceStore.pins,
			*certificate.SamplerV2Contract)
	}
	if err != nil {
		return zero, 0, err
	}
	if certificate.DurablePublicationProtocol == formalGLMPhase21DurableV2Version {
		expected, err = formalGLMPhase21PromoteDurableV2(
			expected, sourceStore.pins)
		if err != nil {
			return zero, 0, err
		}
	}
	probe := certificate
	probe.AuthorityReceipts = nil
	if !reflect.DeepEqual(expected, probe) {
		return zero, 0, fmt.Errorf("formal-glm: sticky projection differs from certified release")
	}
	publication, err := publicationStore.Commit(certificate)
	if err != nil {
		return zero, 0, err
	}
	if phaseHook != nil {
		if err := phaseHook("after_sticky_commit_before_source_consume"); err != nil {
			return publication, 0, err
		}
	}
	removed, err := formalGLMPhase21CleanupReleasedSource(
		sourceStore, output, release)
	if err != nil || certificate.DurablePublicationProtocol !=
		formalGLMPhase21DurableV2Version {
		return publication, removed, err
	}
	if phaseHook != nil {
		if err := phaseHook("after_source_consume_before_durable_ack"); err != nil {
			return publication, removed, err
		}
	}
	_, err = publicationStore.AckDurableV2(publication)
	if err != nil {
		return publication, removed, err
	}
	if phaseHook != nil {
		if err := phaseHook("after_durable_ack"); err != nil {
			return publication, removed, err
		}
	}
	return publication, removed, nil
}

// CleanupCommittedOneDraw resumes the only crash window after publication.
// It verifies the federated public certificate, reloads only public authority
// from Phase20, and consumes the matching sealed source without invoking GC,
// the sampler, or either finalizer.
func formalGLMPhase21CleanupCommittedOneDraw(
	publicationStore *formalGLMPhase21StickyReleaseStore,
	sourceStore *formalGLMPhase20HandoffStore,
	artifactID string,
	capsule formalGLMPhase16CapsuleBinding,
	request formalGLMPhase16ProductiveRequest,
	backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature,
) (int64, error) {
	if publicationStore == nil || sourceStore == nil ||
		publicationStore.peer != sourceStore.peer {
		return 0, fmt.Errorf("formal-glm: misrouted sticky cleanup")
	}
	publication, err := publicationStore.Replay(artifactID)
	if err != nil {
		return 0, err
	}
	certificate, err := formalGLMPhase21DecodeStickyPublication(publication)
	if err != nil {
		return 0, err
	}
	if _, statErr := os.Lstat(sourceStore.recordPath); os.IsNotExist(statErr) &&
		certificate.DurablePublicationProtocol == formalGLMPhase21DurableV2Version {
		_, ackErr := publicationStore.AckDurableV2(publication)
		return 0, ackErr
	}
	runtime, commit, err := formalGLMPhase21LoadAndAdmit(
		sourceStore, capsule, request, backendSignatures, workerSignatures)
	if err != nil {
		return 0, err
	}
	defer runtime.clear()
	binding := runtime.Admission.Productive.Compiled.Binding
	probeRelease := formalGLMPhase16CertifiedRelease{
		BackendSelectionSHA256: certificate.BackendSelectionSHA256,
		BackendSelection:       runtime.Admission.Productive.BackendSelection,
		SelectedBackend:        certificate.SelectedBackend,
		DPReleaseInstanceID:    certificate.DPReleaseInstanceID,
		ReleaseContractSHA256:  certificate.ReleaseContractSHA256,
	}
	expectedArtifact, expectedID, err := formalGLMPhase21BuildStickyArtifact(
		probeRelease, binding, runtime.Source.Plan, sourceStore.pins)
	if err != nil || expectedID != artifactID ||
		!reflect.DeepEqual(expectedArtifact, certificate.Artifact) ||
		certificate.SourceReleaseInstanceID != binding.ReleaseInstanceID ||
		certificate.SourceReleaseContractSHA256 != binding.ReleaseContractSHA256 {
		return 0, fmt.Errorf("formal-glm: committed sticky release targets another source")
	}
	removed, err := sourceStore.Consume(commit.SHA256)
	if err != nil || certificate.DurablePublicationProtocol !=
		formalGLMPhase21DurableV2Version {
		return removed, err
	}
	_, err = publicationStore.AckDurableV2(publication)
	return removed, err
}

func formalGLMPhase21CommitFullAndCleanup(
	publicationStore *formalGLMPhase21StickyReleaseStore,
	sourceStore *formalGLMPhase20HandoffStore,
	output formalGLMPhase21FullLocalOutput,
	release formalGLMPhase16CertifiedRelease,
	certificate formalGLMPhase21StickyCertificate,
	phaseHook func(string) error,
) (formalGLMPhase21StickyPublication, int64, error) {
	var zero formalGLMPhase21StickyPublication
	if publicationStore == nil || sourceStore == nil ||
		publicationStore.peer != output.Peer || sourceStore.peer != output.Peer ||
		output.Admission.formalBinding == nil ||
		output.Admission.formalToken == nil {
		return zero, 0, fmt.Errorf("formal-glm: misrouted sticky full publication")
	}
	if err := formalGLMPhase21ValidateFullLocalOutputSource(
		sourceStore, output); err != nil {
		return zero, 0, err
	}
	source, _, err := sourceStore.Load()
	if err != nil {
		return zero, 0, err
	}
	plan := source.Plan
	source.clear()
	var expected formalGLMPhase21StickyCertificate
	if certificate.SamplerV2Contract == nil {
		expected, err = formalGLMPhase21BuildStickyCertificate(
			release, *output.Admission.formalBinding,
			*output.Admission.formalToken, plan, sourceStore.pins)
	} else {
		expected, err = formalGLMPhase21BuildStickyCertificateV2(
			release, *output.Admission.formalBinding,
			*output.Admission.formalToken, plan, sourceStore.pins,
			*certificate.SamplerV2Contract)
	}
	if err != nil {
		return zero, 0, err
	}
	if certificate.DurablePublicationProtocol == formalGLMPhase21DurableV2Version {
		expected, err = formalGLMPhase21PromoteDurableV2(
			expected, sourceStore.pins)
		if err != nil {
			return zero, 0, err
		}
	}
	probe := certificate
	probe.AuthorityReceipts = nil
	if !reflect.DeepEqual(expected, probe) {
		return zero, 0,
			fmt.Errorf("formal-glm: sticky full projection differs from certified release")
	}
	publication, err := publicationStore.Commit(certificate)
	if err != nil {
		return zero, 0, err
	}
	if phaseHook != nil {
		if err := phaseHook("after_sticky_commit_before_source_consume"); err != nil {
			return publication, 0, err
		}
	}
	removed, err := formalGLMPhase21CleanupFullReleasedSource(
		sourceStore, output, release)
	if err != nil || certificate.DurablePublicationProtocol !=
		formalGLMPhase21DurableV2Version {
		return publication, removed, err
	}
	if phaseHook != nil {
		if err := phaseHook("after_source_consume_before_durable_ack"); err != nil {
			return publication, removed, err
		}
	}
	_, err = publicationStore.AckDurableV2(publication)
	if err != nil {
		return publication, removed, err
	}
	if phaseHook != nil {
		if err := phaseHook("after_durable_ack"); err != nil {
			return publication, removed, err
		}
	}
	return publication, removed, nil
}

func formalGLMPhase21CleanupCommittedFull(
	publicationStore *formalGLMPhase21StickyReleaseStore,
	sourceStore *formalGLMPhase20HandoffStore,
	artifactID string,
	capsule formalGLMPhase16CapsuleBinding,
	request formalGLMPhase16ProductiveRequest,
	backendSignatures []jointDPBiomedicalGaussianSignature,
	fullRequest formalGLMPhase16FullFallbackRequest,
	attestation formalGLMPhase16FullFallbackContractAttestation,
) (int64, error) {
	if publicationStore == nil || sourceStore == nil ||
		publicationStore.peer != sourceStore.peer {
		return 0, fmt.Errorf("formal-glm: misrouted sticky full cleanup")
	}
	publication, err := publicationStore.Replay(artifactID)
	if err != nil {
		return 0, err
	}
	certificate, err := formalGLMPhase21DecodeStickyPublication(publication)
	if err != nil {
		return 0, err
	}
	if _, statErr := os.Lstat(sourceStore.recordPath); os.IsNotExist(statErr) &&
		certificate.DurablePublicationProtocol == formalGLMPhase21DurableV2Version {
		_, ackErr := publicationStore.AckDurableV2(publication)
		return 0, ackErr
	}
	runtime, commit, err := formalGLMPhase21LoadAndAdmitFull(
		sourceStore, capsule, request, backendSignatures,
		fullRequest, attestation)
	if err != nil {
		return 0, err
	}
	defer runtime.clear()
	if runtime.Admission.Full == nil ||
		runtime.Admission.Full.formalBinding == nil {
		return 0, fmt.Errorf("formal-glm: missing sticky full cleanup authority")
	}
	binding := *runtime.Admission.Full.formalBinding
	probeRelease := formalGLMPhase16CertifiedRelease{
		BackendSelectionSHA256: certificate.BackendSelectionSHA256,
		BackendSelection:       runtime.Admission.Productive.BackendSelection,
		SelectedBackend:        certificate.SelectedBackend,
		DPReleaseInstanceID:    certificate.DPReleaseInstanceID,
		ReleaseContractSHA256:  certificate.ReleaseContractSHA256,
	}
	expectedArtifact, expectedID, err := formalGLMPhase21BuildStickyArtifact(
		probeRelease, binding, runtime.Source.Plan, sourceStore.pins)
	if err != nil || expectedID != artifactID ||
		!reflect.DeepEqual(expectedArtifact, certificate.Artifact) ||
		certificate.SourceReleaseInstanceID != binding.ReleaseInstanceID ||
		certificate.SourceReleaseContractSHA256 != binding.ReleaseContractSHA256 {
		return 0,
			fmt.Errorf("formal-glm: committed sticky full release targets another source")
	}
	removed, err := sourceStore.Consume(commit.SHA256)
	if err != nil || certificate.DurablePublicationProtocol !=
		formalGLMPhase21DurableV2Version {
		return removed, err
	}
	_, err = publicationStore.AckDurableV2(publication)
	return removed, err
}

// Read-only crash recovery for a local finalizer that reached its durable
// released state before the common sticky projection was committed.
func (store *jointDPBiomedicalGaussianOneDrawDurableReleaseStore) loadReleasedForFormalGLMPhase21(
	admission formalGLMPhase16ProductiveAdmission,
) (jointDPBiomedicalGaussianOneDrawLocalRelease, error) {
	var zero jointDPBiomedicalGaussianOneDrawLocalRelease
	if store == nil {
		return zero, fmt.Errorf("formal-glm: missing one-draw recovery store")
	}
	authority, err := jointDPBiomedicalGaussianOneDrawAuthorityFromEnvelopes(
		[]jointDPBiomedicalGaussianSignedWorkerEnvelope{admission.Envelope},
		admission.Trust)
	if err != nil || !formalGLMPhase19Contains(authority.computePeers, store.peer) {
		return zero, fmt.Errorf("formal-glm: invalid one-draw recovery authority")
	}
	path, err := store.recordPath(authority.preimage.ReleaseInstanceID, false)
	if err != nil {
		return zero, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	encoded, err := jointDPBiomedicalGaussianFullReadDurableRecord(path)
	if err != nil {
		return zero, err
	}
	record, err := jointDPBiomedicalGaussianOneDrawDecodeRecord(store.key, encoded)
	if err != nil || record.State != "released" {
		return zero, fmt.Errorf("formal-glm: local one-draw release is not durable")
	}
	var receipt jointDPBiomedicalGaussianOneDrawLocalReleaseReceipt
	if err := json.Unmarshal([]byte(record.ReleaseReceiptJSON), &receipt); err != nil {
		return zero, err
	}
	if err := jointDPBiomedicalGaussianValidateOneDrawLocalRelease(
		authority, receipt); err != nil {
		return zero, err
	}
	return jointDPBiomedicalGaussianOneDrawLocalRelease{
		Receipt: receipt, Replayed: true,
	}, nil
}

func (store *jointDPBiomedicalGaussianFullDurableReleaseStore) loadReleasedForFormalGLMPhase21(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
) (jointDPBiomedicalGaussianFullLocalRelease, error) {
	var zero jointDPBiomedicalGaussianFullLocalRelease
	if store == nil {
		return zero, fmt.Errorf("formal-glm: missing full recovery store")
	}
	if err := jointDPBiomedicalGaussianValidateFullAdmissionCached(
		admission, pins); err != nil {
		return zero, err
	}
	contract := admission.selection.Contract
	if !formalGLMPhase19Contains(contract.DesignatedComputePeers, store.peer) {
		return zero, fmt.Errorf("formal-glm: invalid full recovery authority")
	}
	path, err := store.recordPath(contract.ReleaseInstanceID, false)
	if err != nil {
		return zero, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	encoded, err := jointDPBiomedicalGaussianFullReadDurableRecord(path)
	if err != nil {
		return zero, err
	}
	record, err := jointDPBiomedicalGaussianFullDecodeRecord(store.key, encoded)
	if err != nil || record.State != "released" {
		return zero, fmt.Errorf("formal-glm: local full release is not durable")
	}
	var receipt jointDPBiomedicalGaussianFullLocalReleaseReceipt
	if err := json.Unmarshal([]byte(record.ReleaseReceiptJSON), &receipt); err != nil {
		return zero, err
	}
	if err := jointDPBiomedicalGaussianValidateFullLocalRelease(
		admission, pins, receipt); err != nil {
		return zero, err
	}
	return jointDPBiomedicalGaussianFullLocalRelease{
		Receipt: receipt, Replayed: true,
	}, nil
}

func (store *formalGLMPhase16FullDurableReleaseStore) loadReleasedForFormalGLMPhase21(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
) (jointDPBiomedicalGaussianFullLocalRelease, error) {
	var zero jointDPBiomedicalGaussianFullLocalRelease
	if store == nil || store.inner == nil || admission.formalSelection == nil {
		return zero, fmt.Errorf("formal-glm: missing range-gated full recovery store")
	}
	contract := admission.selection.Contract
	selectionSHA256, err := formalGLMPhase16BackendSelectionSHA256(
		*admission.formalSelection)
	if err != nil {
		return zero, err
	}
	path := filepath.Join(store.dir, contract.ReleaseInstanceID[:2],
		contract.ReleaseInstanceID[2:4],
		"guard-"+contract.ReleaseInstanceID+".json")
	store.mu.Lock()
	encoded, err := jointDPBiomedicalGaussianFullReadDurableRecord(path)
	if err != nil {
		store.mu.Unlock()
		return zero, err
	}
	guard, err := formalGLMPhase16FullDecodeGuardRecord(store.key, encoded)
	store.mu.Unlock()
	if err != nil || guard.State != "valid_source" ||
		guard.PeerName != store.peer ||
		guard.ReleaseInstanceID != contract.ReleaseInstanceID ||
		guard.ReleaseContractSHA256 != contract.ReleaseContractSHA256 ||
		guard.BackendSelectionSHA256 != selectionSHA256 ||
		!guard.ValidityChecked || !guard.AllChunksValid {
		return zero, fmt.Errorf("formal-glm: local full range gate is not durable")
	}
	return store.inner.loadReleasedForFormalGLMPhase21(admission, pins)
}
