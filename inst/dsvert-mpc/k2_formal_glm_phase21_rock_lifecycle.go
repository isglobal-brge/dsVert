package main

// Rock-local, restartable adapter for the productive formal GLM one-draw
// lifecycle. Each action is confined to one authority root. Cross-authority
// inputs are exact signed records; private local shares remain in AEAD spools.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

const (
	formalGLMPhase21RockPurpose       = "formal_glm_rock_local_one_draw_lifecycle_v1"
	formalGLMPhase21RockRecordVersion = "dsvert-formal-glm-rock-lifecycle-record-v1"
	formalGLMPhase21RockSecretVersion = "dsvert-formal-glm-rock-lifecycle-secret-v1"
	formalGLMPhase21RockPinsetVersion = "dsvert-formal-glm-rock-lifecycle-pinset-v1"

	formalGLMPhase21RockPreflightPurpose        = "formal_glm_local_artifact_preflight_v1"
	formalGLMPhase21RockStagePurpose            = "formal_glm_local_one_draw_stage_v1"
	formalGLMPhase21RockTicketPurpose           = "formal_glm_finalizer_ticket_v1"
	formalGLMPhase21RockSealPurpose             = "formal_glm_local_envelope_seal_v1"
	formalGLMPhase21RockCandidatePurpose        = "formal_glm_finalizer_candidate_v1"
	formalGLMPhase21RockLocalReleasePurpose     = "formal_glm_nonblind_local_release_v1"
	formalGLMPhase21RockBaseCertificatePurpose  = "formal_glm_base_certificate_v1"
	formalGLMPhase21RockAuthorizationPurpose    = "formal_glm_ordered_certificate_authorization_v1"
	formalGLMPhase21RockPublicationReadyPurpose = "formal_glm_publication_ready_v1"
	formalGLMPhase21RockCommitPurpose           = "formal_glm_local_publication_commit_v1"
	formalGLMPhase21RockAckPurpose              = "formal_glm_finalizer_ack_v1"
	formalGLMPhase21RockCleanupPurpose          = "formal_glm_local_cleanup_v1"

	formalGLMPhase21RockStateAbsent            = "absent"
	formalGLMPhase21RockStateRepairPending     = "repair_pending"
	formalGLMPhase21RockStatePublished         = "published"
	formalGLMPhase21RockStateStaged            = "staged"
	formalGLMPhase21RockStateTicketReady       = "ticket_ready"
	formalGLMPhase21RockStateSealed            = "sealed"
	formalGLMPhase21RockStateCandidateReady    = "candidate_ready"
	formalGLMPhase21RockStateCandidateVerified = "candidate_verified"
	formalGLMPhase21RockStateCertificateReady  = "certificate_ready"
	formalGLMPhase21RockStateAuthorized        = "authorized"
	formalGLMPhase21RockStatePublicationReady  = "publication_ready"
	formalGLMPhase21RockStatePublicationCommit = "publication_committed"
	formalGLMPhase21RockStateAckReady          = "ack_ready"
	formalGLMPhase21RockStateCleaned           = "cleaned"

	formalGLMPhase21RockMaxSecret = 32 << 10
	formalGLMPhase21RockMaxRecord = 8 << 20
)

type formalGLMPhase21RockLifecycleResponse struct {
	Version           string                                     `json:"version"`
	Family            string                                     `json:"family"`
	Action            string                                     `json:"action"`
	State             string                                     `json:"state"`
	ArtifactID        string                                     `json:"artifact_id"`
	RecordSHA256      string                                     `json:"record_sha256,omitempty"`
	CertificateSHA256 string                                     `json:"certificate_sha256,omitempty"`
	Preflight         *formalGLMPhase21RockPreflightRecord       `json:"preflight,omitempty"`
	Stage             *formalGLMPhase21RockStageRecord           `json:"stage,omitempty"`
	Ticket            *formalGLMPhase21RockTicketRecord          `json:"ticket,omitempty"`
	Seal              *formalGLMPhase21RockSealRecord            `json:"seal,omitempty"`
	Candidate         *formalGLMPhase21RockCandidateRecord       `json:"candidate,omitempty"`
	LocalRelease      *formalGLMPhase21RockLocalReleaseRecord    `json:"local_release,omitempty"`
	BaseCertificate   *formalGLMPhase21RockBaseCertificateRecord `json:"base_certificate,omitempty"`
	Authorization     *formalGLMPhase21RockAuthorizationRecord   `json:"authorization,omitempty"`
	Publication       *formalGLMPhase21PublicCertificateV2       `json:"publication,omitempty"`
	Commit            *formalGLMPhase21RockCommitRecord          `json:"commit,omitempty"`
	Ack               *formalGLMPhase21RockAckRecord             `json:"ack,omitempty"`
	Cleanup           *formalGLMPhase21RockCleanupRecord         `json:"cleanup,omitempty"`
	Replayed          bool                                       `json:"replayed"`
	ProductionReady   bool                                       `json:"-"`
}

type formalGLMPhase21RockPinset struct {
	Version         string            `json:"version"`
	Family          string            `json:"family"`
	Purpose         string            `json:"purpose"`
	PinnedPublicKey map[string]string `json:"pinned_public_keys"`
}

type formalGLMPhase21RockPreflightReceipt struct {
	Version           string `json:"version"`
	Purpose           string `json:"purpose"`
	ArtifactID        string `json:"artifact_id"`
	PinsetSHA256      string `json:"pinset_sha256"`
	PeerName          string `json:"peer_name"`
	PeerID            string `json:"peer_id"`
	Role              string `json:"role"`
	State             string `json:"state"`
	CertificateSHA256 string `json:"certificate_sha256,omitempty"`
	ProductionReady   bool   `json:"-"`
	Signature         []byte `json:"signature"`
}

type formalGLMPhase21RockPreflightRecord struct {
	Version         string                               `json:"version"`
	Family          string                               `json:"family"`
	Purpose         string                               `json:"purpose"`
	Receipt         formalGLMPhase21RockPreflightReceipt `json:"receipt"`
	Publication     *formalGLMPhase21PublicCertificateV2 `json:"publication,omitempty"`
	ProductionReady bool                                 `json:"-"`
}

type formalGLMPhase21RockPreflightOperation struct {
	ArtifactContractPath   string `json:"artifact_contract_path"`
	PinsetPath             string `json:"pinset_path"`
	RegistryResolutionPath string `json:"registry_resolution_path,omitempty"`
	PeerName               string `json:"peer_name"`
	SecretBundlePath       string `json:"secret_bundle_path"`
}

type formalGLMPhase21RockStageReceipt struct {
	Version             string                                       `json:"version"`
	Purpose             string                                       `json:"purpose"`
	ArtifactID          string                                       `json:"artifact_id"`
	ContractSHA256      string                                       `json:"contract_sha256"`
	PeerName            string                                       `json:"peer_name"`
	PeerID              string                                       `json:"peer_id"`
	Role                string                                       `json:"role"`
	FinalPairRootSHA256 string                                       `json:"final_pair_root_sha256"`
	PlanSHA256          string                                       `json:"plan_sha256"`
	SourceReceiptSHA256 string                                       `json:"source_receipt_sha256"`
	SourceReceipt       jointDPBiomedicalGaussianOneDrawChunkReceipt `json:"source_receipt"`
	ProductionReady     bool                                         `json:"-"`
	Signature           []byte                                       `json:"signature"`
}

type formalGLMPhase21RockStageRecord struct {
	Version         string                           `json:"version"`
	Family          string                           `json:"family"`
	Purpose         string                           `json:"purpose"`
	ArtifactID      string                           `json:"artifact_id"`
	Binding         formalFinalizerHandoffBinding    `json:"binding"`
	Receipt         formalGLMPhase21RockStageReceipt `json:"receipt"`
	ProductionReady bool                             `json:"-"`
}

type formalGLMPhase21RockTicketRecord struct {
	Version         string                        `json:"version"`
	Family          string                        `json:"family"`
	Purpose         string                        `json:"purpose"`
	ArtifactID      string                        `json:"artifact_id"`
	Binding         formalFinalizerHandoffBinding `json:"binding"`
	Ticket          formalFinalizerHandoffTicket  `json:"ticket"`
	ProductionReady bool                          `json:"-"`
}

type formalGLMPhase21RockSealReceipt struct {
	Version             string `json:"version"`
	Purpose             string `json:"purpose"`
	ArtifactID          string `json:"artifact_id"`
	FinalPairRootSHA256 string `json:"final_pair_root_sha256"`
	PlanSHA256          string `json:"plan_sha256"`
	PinsetSHA256        string `json:"pinset_sha256"`
	TicketSHA256        string `json:"ticket_sha256"`
	PeerName            string `json:"peer_name"`
	PeerID              string `json:"peer_id"`
	Role                string `json:"role"`
	PayloadKind         string `json:"payload_kind"`
	PayloadSHA256       string `json:"payload_sha256"`
	CiphertextSHA256    string `json:"ciphertext_sha256"`
	EnvelopeSHA256      string `json:"envelope_sha256"`
	ProductionReady     bool   `json:"-"`
	Signature           []byte `json:"signature"`
}

type formalGLMPhase21RockSealRecord struct {
	Version         string                          `json:"version"`
	Family          string                          `json:"family"`
	Purpose         string                          `json:"purpose"`
	ArtifactID      string                          `json:"artifact_id"`
	Receipt         formalGLMPhase21RockSealReceipt `json:"receipt"`
	ProductionReady bool                            `json:"-"`
}

type formalGLMPhase21RockCandidateReceipt struct {
	Version             string `json:"version"`
	Purpose             string `json:"purpose"`
	ArtifactID          string `json:"artifact_id"`
	FinalPairRootSHA256 string `json:"final_pair_root_sha256"`
	PlanSHA256          string `json:"plan_sha256"`
	PinsetSHA256        string `json:"pinset_sha256"`
	TicketSHA256        string `json:"ticket_sha256"`
	CandidateSHA256     string `json:"candidate_sha256"`
	FinalizerPeerName   string `json:"finalizer_peer_name"`
	FinalizerPeerID     string `json:"finalizer_peer_id"`
	FinalizerRole       string `json:"finalizer_role"`
	ProductionReady     bool   `json:"-"`
	Signature           []byte `json:"signature"`
}

type formalGLMPhase21RockCandidateRecord struct {
	Version         string                                        `json:"version"`
	Family          string                                        `json:"family"`
	Purpose         string                                        `json:"purpose"`
	ArtifactID      string                                        `json:"artifact_id"`
	Candidate       jointDPBiomedicalGaussianOneDrawCommonRelease `json:"candidate"`
	Receipt         formalGLMPhase21RockCandidateReceipt          `json:"receipt"`
	ProductionReady bool                                          `json:"-"`
}

type formalGLMPhase21RockLocalReleaseBinding struct {
	Version             string `json:"version"`
	Purpose             string `json:"purpose"`
	ArtifactID          string `json:"artifact_id"`
	FinalPairRootSHA256 string `json:"final_pair_root_sha256"`
	PlanSHA256          string `json:"plan_sha256"`
	PinsetSHA256        string `json:"pinset_sha256"`
	TicketSHA256        string `json:"ticket_sha256"`
	CandidateSHA256     string `json:"candidate_sha256"`
	LocalReleaseSHA256  string `json:"local_release_sha256"`
	PeerName            string `json:"peer_name"`
	PeerID              string `json:"peer_id"`
	Role                string `json:"role"`
	ProductionReady     bool   `json:"-"`
	Signature           []byte `json:"signature"`
}

type formalGLMPhase21RockLocalReleaseRecord struct {
	Version         string                                       `json:"version"`
	Family          string                                       `json:"family"`
	Purpose         string                                       `json:"purpose"`
	ArtifactID      string                                       `json:"artifact_id"`
	LocalRelease    jointDPBiomedicalGaussianOneDrawLocalRelease `json:"local_release"`
	Binding         formalGLMPhase21RockLocalReleaseBinding      `json:"binding"`
	ProductionReady bool                                         `json:"-"`
}

type formalGLMPhase21RockBaseCertificateReceipt struct {
	Version                string `json:"version"`
	Purpose                string `json:"purpose"`
	ArtifactID             string `json:"artifact_id"`
	FinalPairRootSHA256    string `json:"final_pair_root_sha256"`
	PlanSHA256             string `json:"plan_sha256"`
	PinsetSHA256           string `json:"pinset_sha256"`
	TicketSHA256           string `json:"ticket_sha256"`
	CandidateSHA256        string `json:"candidate_sha256"`
	CertifiedReleaseSHA256 string `json:"certified_release_sha256"`
	BaseCertificateSHA256  string `json:"base_certificate_sha256"`
	FinalizerPeerName      string `json:"finalizer_peer_name"`
	FinalizerPeerID        string `json:"finalizer_peer_id"`
	FinalizerRole          string `json:"finalizer_role"`
	ProductionReady        bool   `json:"-"`
	Signature              []byte `json:"signature"`
}

type formalGLMPhase21RockBaseCertificateRecord struct {
	Version          string                                     `json:"version"`
	Family           string                                     `json:"family"`
	Purpose          string                                     `json:"purpose"`
	ArtifactID       string                                     `json:"artifact_id"`
	CertifiedRelease formalGLMPhase16CertifiedRelease           `json:"certified_release"`
	BaseCertificate  formalGLMPhase21StickyCertificate          `json:"base_certificate"`
	Receipt          formalGLMPhase21RockBaseCertificateReceipt `json:"receipt"`
	ProductionReady  bool                                       `json:"-"`
}

type formalGLMPhase21RockAuthorizationRecord struct {
	Version                string                                    `json:"version"`
	Family                 string                                    `json:"family"`
	Purpose                string                                    `json:"purpose"`
	ArtifactID             string                                    `json:"artifact_id"`
	Role                   string                                    `json:"role"`
	IntentSHA256           string                                    `json:"intent_sha256"`
	TransportAuthorization formalFinalizerHandoffIntentAuthorization `json:"transport_authorization"`
	StickyAuthorization    jointDPBiomedicalGaussianSignature        `json:"sticky_authorization"`
	PublicV2Authorization  jointDPBiomedicalGaussianSignature        `json:"public_v2_authorization"`
	ProductionReady        bool                                      `json:"-"`
}

type formalGLMPhase21RockPublicationReadyReceipt struct {
	Version                   string `json:"version"`
	Purpose                   string `json:"purpose"`
	ArtifactID                string `json:"artifact_id"`
	FinalPairRootSHA256       string `json:"final_pair_root_sha256"`
	PlanSHA256                string `json:"plan_sha256"`
	PinsetSHA256              string `json:"pinset_sha256"`
	TicketSHA256              string `json:"ticket_sha256"`
	InternalCertificateSHA256 string `json:"internal_certificate_sha256"`
	PublicCertificateSHA256   string `json:"public_certificate_sha256"`
	FinalizerPeerName         string `json:"finalizer_peer_name"`
	FinalizerPeerID           string `json:"finalizer_peer_id"`
	FinalizerRole             string `json:"finalizer_role"`
	ProductionReady           bool   `json:"-"`
	Signature                 []byte `json:"signature"`
}

type formalGLMPhase21RockPublicationReadyRecord struct {
	Version             string                                      `json:"version"`
	Family              string                                      `json:"family"`
	Purpose             string                                      `json:"purpose"`
	ArtifactID          string                                      `json:"artifact_id"`
	InternalCertificate formalGLMPhase21StickyCertificate           `json:"internal_certificate"`
	PublicCertificate   formalGLMPhase21PublicCertificateV2         `json:"public_certificate"`
	Receipt             formalGLMPhase21RockPublicationReadyReceipt `json:"receipt"`
	ProductionReady     bool                                        `json:"-"`
}

type formalGLMPhase21RockCommitReceipt struct {
	Version           string `json:"version"`
	Purpose           string `json:"purpose"`
	ArtifactID        string `json:"artifact_id"`
	CertificateSHA256 string `json:"certificate_sha256"`
	PeerName          string `json:"peer_name"`
	PeerID            string `json:"peer_id"`
	Role              string `json:"role"`
	ProductionReady   bool   `json:"-"`
	Signature         []byte `json:"signature"`
}

type formalGLMPhase21RockCommitRecord struct {
	Version         string                              `json:"version"`
	Family          string                              `json:"family"`
	Purpose         string                              `json:"purpose"`
	Receipt         formalGLMPhase21RockCommitReceipt   `json:"receipt"`
	Publication     formalGLMPhase21PublicCertificateV2 `json:"publication"`
	ProductionReady bool                                `json:"-"`
}

type formalGLMPhase21RockAckRecord struct {
	Version         string                            `json:"version"`
	Family          string                            `json:"family"`
	Purpose         string                            `json:"purpose"`
	ArtifactID      string                            `json:"artifact_id"`
	Proof           formalFinalizerHandoffCommitProof `json:"proof"`
	ProductionReady bool                              `json:"-"`
}

type formalGLMPhase21RockCleanupReceipt struct {
	Version           string `json:"version"`
	Purpose           string `json:"purpose"`
	ArtifactID        string `json:"artifact_id"`
	CertificateSHA256 string `json:"certificate_sha256"`
	PeerName          string `json:"peer_name"`
	PeerID            string `json:"peer_id"`
	Role              string `json:"role"`
	SourceCleaned     bool   `json:"source_cleaned"`
	LocalSpoolCleaned bool   `json:"local_spool_cleaned"`
	TransportCleaned  bool   `json:"transport_cleaned"`
	ProductionReady   bool   `json:"-"`
	Signature         []byte `json:"signature"`
}

type formalGLMPhase21RockCleanupRecord struct {
	Version         string                              `json:"version"`
	Family          string                              `json:"family"`
	Purpose         string                              `json:"purpose"`
	Receipt         formalGLMPhase21RockCleanupReceipt  `json:"receipt"`
	Publication     formalGLMPhase21PublicCertificateV2 `json:"publication"`
	ProductionReady bool                                `json:"-"`
}

type formalGLMPhase21RockStageOperation struct {
	ArtifactContractPath      string    `json:"artifact_contract_path"`
	PinsetPath                string    `json:"pinset_path"`
	RegistryResolutionPath    string    `json:"registry_resolution_path,omitempty"`
	PreflightRecordPaths      [2]string `json:"preflight_record_paths"`
	PeerName                  string    `json:"peer_name"`
	Phase20SemanticRootSHA256 string    `json:"phase20_semantic_root_sha256"`
	CapsulePath               string    `json:"capsule_path"`
	RequestPath               string    `json:"request_path"`
	BackendSignaturesPath     string    `json:"backend_signatures_path"`
	WorkerSignaturesPath      string    `json:"worker_signatures_path"`
	SamplerAuthorizationsPath string    `json:"sampler_authorizations_path"`
	SpoolDir                  string    `json:"spool_dir"`
	MaxSpoolBytes             int64     `json:"max_spool_bytes"`
	TTLSeconds                int       `json:"ttl_seconds"`
	SecretBundlePath          string    `json:"secret_bundle_path"`
}

type formalGLMPhase21RockTicketOperation struct {
	ArtifactContractPath string    `json:"artifact_contract_path"`
	PinsetPath           string    `json:"pinset_path"`
	PreflightRecordPaths [2]string `json:"preflight_record_paths"`
	StageRecordPaths     [2]string `json:"stage_record_paths"`
	PeerName             string    `json:"peer_name"`
	SecretBundlePath     string    `json:"secret_bundle_path"`
}

type formalGLMPhase21RockSealOperation struct {
	ArtifactContractPath      string    `json:"artifact_contract_path"`
	PinsetPath                string    `json:"pinset_path"`
	RegistryResolutionPath    string    `json:"registry_resolution_path,omitempty"`
	PreflightRecordPaths      [2]string `json:"preflight_record_paths"`
	StageRecordPaths          [2]string `json:"stage_record_paths"`
	TicketRecordPath          string    `json:"ticket_record_path"`
	PeerName                  string    `json:"peer_name"`
	Phase20SemanticRootSHA256 string    `json:"phase20_semantic_root_sha256"`
	CapsulePath               string    `json:"capsule_path"`
	RequestPath               string    `json:"request_path"`
	BackendSignaturesPath     string    `json:"backend_signatures_path"`
	WorkerSignaturesPath      string    `json:"worker_signatures_path"`
	SecretBundlePath          string    `json:"secret_bundle_path"`
}

type formalGLMPhase21RockPrepareCandidateOperation struct {
	ArtifactContractPath      string    `json:"artifact_contract_path"`
	PinsetPath                string    `json:"pinset_path"`
	RegistryResolutionPath    string    `json:"registry_resolution_path,omitempty"`
	PreflightRecordPaths      [2]string `json:"preflight_record_paths"`
	StageRecordPaths          [2]string `json:"stage_record_paths"`
	TicketRecordPath          string    `json:"ticket_record_path"`
	SealRecordPaths           [2]string `json:"seal_record_paths"`
	PeerName                  string    `json:"peer_name"`
	Phase20SemanticRootSHA256 string    `json:"phase20_semantic_root_sha256"`
	CapsulePath               string    `json:"capsule_path"`
	RequestPath               string    `json:"request_path"`
	BackendSignaturesPath     string    `json:"backend_signatures_path"`
	WorkerSignaturesPath      string    `json:"worker_signatures_path"`
	SecretBundlePath          string    `json:"secret_bundle_path"`
}

type formalGLMPhase21RockVerifyCandidateOperation struct {
	ArtifactContractPath      string    `json:"artifact_contract_path"`
	PinsetPath                string    `json:"pinset_path"`
	RegistryResolutionPath    string    `json:"registry_resolution_path,omitempty"`
	PreflightRecordPaths      [2]string `json:"preflight_record_paths"`
	StageRecordPaths          [2]string `json:"stage_record_paths"`
	TicketRecordPath          string    `json:"ticket_record_path"`
	CandidateRecordPath       string    `json:"candidate_record_path"`
	PeerName                  string    `json:"peer_name"`
	Phase20SemanticRootSHA256 string    `json:"phase20_semantic_root_sha256"`
	CapsulePath               string    `json:"capsule_path"`
	RequestPath               string    `json:"request_path"`
	BackendSignaturesPath     string    `json:"backend_signatures_path"`
	WorkerSignaturesPath      string    `json:"worker_signatures_path"`
	SecretBundlePath          string    `json:"secret_bundle_path"`
}

type formalGLMPhase21RockPrepareCertificateOperation struct {
	ArtifactContractPath      string    `json:"artifact_contract_path"`
	PinsetPath                string    `json:"pinset_path"`
	RegistryResolutionPath    string    `json:"registry_resolution_path,omitempty"`
	PreflightRecordPaths      [2]string `json:"preflight_record_paths"`
	StageRecordPaths          [2]string `json:"stage_record_paths"`
	TicketRecordPath          string    `json:"ticket_record_path"`
	CandidateRecordPath       string    `json:"candidate_record_path"`
	LocalReleaseRecordPaths   [2]string `json:"local_release_record_paths"`
	PeerName                  string    `json:"peer_name"`
	Phase20SemanticRootSHA256 string    `json:"phase20_semantic_root_sha256"`
	CapsulePath               string    `json:"capsule_path"`
	RequestPath               string    `json:"request_path"`
	BackendSignaturesPath     string    `json:"backend_signatures_path"`
	WorkerSignaturesPath      string    `json:"worker_signatures_path"`
	SecretBundlePath          string    `json:"secret_bundle_path"`
}

type formalGLMPhase21RockSignCertificateOperation struct {
	ArtifactContractPath         string    `json:"artifact_contract_path"`
	PinsetPath                   string    `json:"pinset_path"`
	RegistryResolutionPath       string    `json:"registry_resolution_path,omitempty"`
	PreflightRecordPaths         [2]string `json:"preflight_record_paths"`
	StageRecordPaths             [2]string `json:"stage_record_paths"`
	TicketRecordPath             string    `json:"ticket_record_path"`
	CandidateRecordPath          string    `json:"candidate_record_path"`
	LocalReleaseRecordPaths      [2]string `json:"local_release_record_paths"`
	BaseCertificateRecordPath    string    `json:"base_certificate_record_path"`
	PredecessorAuthorizationPath *string   `json:"predecessor_authorization_path,omitempty"`
	PeerName                     string    `json:"peer_name"`
	Phase20SemanticRootSHA256    string    `json:"phase20_semantic_root_sha256"`
	CapsulePath                  string    `json:"capsule_path"`
	RequestPath                  string    `json:"request_path"`
	BackendSignaturesPath        string    `json:"backend_signatures_path"`
	WorkerSignaturesPath         string    `json:"worker_signatures_path"`
	SecretBundlePath             string    `json:"secret_bundle_path"`
}

type formalGLMPhase21RockPreparePublicationOperation struct {
	ArtifactContractPath      string    `json:"artifact_contract_path"`
	PinsetPath                string    `json:"pinset_path"`
	RegistryResolutionPath    string    `json:"registry_resolution_path,omitempty"`
	PreflightRecordPaths      [2]string `json:"preflight_record_paths"`
	StageRecordPaths          [2]string `json:"stage_record_paths"`
	TicketRecordPath          string    `json:"ticket_record_path"`
	CandidateRecordPath       string    `json:"candidate_record_path"`
	BaseCertificateRecordPath string    `json:"base_certificate_record_path"`
	AuthorizationRecordPaths  [2]string `json:"authorization_record_paths"`
	PeerName                  string    `json:"peer_name"`
	SecretBundlePath          string    `json:"secret_bundle_path"`
}

type formalGLMPhase21RockCommitPublicationOperation struct {
	ArtifactContractPath string                              `json:"artifact_contract_path"`
	PinsetPath           string                              `json:"pinset_path"`
	PeerName             string                              `json:"peer_name"`
	Publication          formalGLMPhase21PublicCertificateV2 `json:"publication"`
	SecretBundlePath     string                              `json:"secret_bundle_path"`
}

type formalGLMPhase21RockFinalizeAckOperation struct {
	ArtifactContractPath       string    `json:"artifact_contract_path"`
	PinsetPath                 string    `json:"pinset_path"`
	StageRecordPaths           [2]string `json:"stage_record_paths"`
	TicketRecordPath           string    `json:"ticket_record_path"`
	PublicationReadyRecordPath string    `json:"publication_ready_record_path"`
	CommitRecordPaths          [2]string `json:"commit_record_paths"`
	PeerName                   string    `json:"peer_name"`
	SecretBundlePath           string    `json:"secret_bundle_path"`
}

type formalGLMPhase21RockAckOperation struct {
	ArtifactContractPath      string                              `json:"artifact_contract_path"`
	PinsetPath                string                              `json:"pinset_path"`
	RegistryResolutionPath    string                              `json:"registry_resolution_path,omitempty"`
	StageRecordPaths          [2]string                           `json:"stage_record_paths"`
	TicketRecordPath          string                              `json:"ticket_record_path"`
	CommitRecordPath          string                              `json:"commit_record_path"`
	AckRecordPath             string                              `json:"ack_record_path"`
	PeerName                  string                              `json:"peer_name"`
	Publication               formalGLMPhase21PublicCertificateV2 `json:"publication"`
	Phase20SemanticRootSHA256 string                              `json:"phase20_semantic_root_sha256"`
	CapsulePath               string                              `json:"capsule_path"`
	RequestPath               string                              `json:"request_path"`
	BackendSignaturesPath     string                              `json:"backend_signatures_path"`
	WorkerSignaturesPath      string                              `json:"worker_signatures_path"`
	SecretBundlePath          string                              `json:"secret_bundle_path"`
}

type formalGLMPhase21RockPreflightSecret struct {
	Version           string `json:"version"`
	Family            string `json:"family"`
	Purpose           string `json:"purpose"`
	Action            string `json:"action"`
	StickyStorageRoot string `json:"sticky_storage_root"`
	SigningPrivateKey string `json:"signing_private_key"`
}

type formalGLMPhase21RockStageSecret struct {
	Version              string `json:"version"`
	Family               string `json:"family"`
	Purpose              string `json:"purpose"`
	Action               string `json:"action"`
	StickyStorageRoot    string `json:"sticky_storage_root"`
	Phase20StorageRoot   string `json:"phase20_storage_root"`
	BackendKey           string `json:"backend_key"`
	AuthorityRoot        string `json:"authority_root"`
	TransportStorageRoot string `json:"transport_storage_root"`
	SigningPrivateKey    string `json:"signing_private_key"`
}

type formalGLMPhase21RockTicketSecret struct {
	Version              string `json:"version"`
	Family               string `json:"family"`
	Purpose              string `json:"purpose"`
	Action               string `json:"action"`
	TransportStorageRoot string `json:"transport_storage_root"`
	SigningPrivateKey    string `json:"signing_private_key"`
}

type formalGLMPhase21RockSealSecret struct {
	Version              string `json:"version"`
	Family               string `json:"family"`
	Purpose              string `json:"purpose"`
	Action               string `json:"action"`
	Phase20StorageRoot   string `json:"phase20_storage_root"`
	BackendKey           string `json:"backend_key"`
	TransportStorageRoot string `json:"transport_storage_root"`
	SigningPrivateKey    string `json:"signing_private_key"`
}

type formalGLMPhase21RockCandidateSecret struct {
	Version              string `json:"version"`
	Family               string `json:"family"`
	Purpose              string `json:"purpose"`
	Action               string `json:"action"`
	Phase20StorageRoot   string `json:"phase20_storage_root"`
	BackendKey           string `json:"backend_key"`
	TransportStorageRoot string `json:"transport_storage_root"`
	SigningPrivateKey    string `json:"signing_private_key"`
}

type formalGLMPhase21RockVerifyCandidateSecret struct {
	Version              string `json:"version"`
	Family               string `json:"family"`
	Purpose              string `json:"purpose"`
	Action               string `json:"action"`
	Phase20StorageRoot   string `json:"phase20_storage_root"`
	BackendKey           string `json:"backend_key"`
	TransportStorageRoot string `json:"transport_storage_root"`
	SigningPrivateKey    string `json:"signing_private_key"`
}

type formalGLMPhase21RockPrepareCertificateSecret struct {
	Version              string `json:"version"`
	Family               string `json:"family"`
	Purpose              string `json:"purpose"`
	Action               string `json:"action"`
	Phase20StorageRoot   string `json:"phase20_storage_root"`
	BackendKey           string `json:"backend_key"`
	TransportStorageRoot string `json:"transport_storage_root"`
	SigningPrivateKey    string `json:"signing_private_key"`
}

type formalGLMPhase21RockSignCertificateSecret struct {
	Version              string `json:"version"`
	Family               string `json:"family"`
	Purpose              string `json:"purpose"`
	Action               string `json:"action"`
	StickyStorageRoot    string `json:"sticky_storage_root"`
	Phase20StorageRoot   string `json:"phase20_storage_root"`
	BackendKey           string `json:"backend_key"`
	TransportStorageRoot string `json:"transport_storage_root"`
	SigningPrivateKey    string `json:"signing_private_key"`
}

type formalGLMPhase21RockPreparePublicationSecret struct {
	Version              string `json:"version"`
	Family               string `json:"family"`
	Purpose              string `json:"purpose"`
	Action               string `json:"action"`
	TransportStorageRoot string `json:"transport_storage_root"`
	SigningPrivateKey    string `json:"signing_private_key"`
}

type formalGLMPhase21RockCommitPublicationSecret struct {
	Version           string `json:"version"`
	Family            string `json:"family"`
	Purpose           string `json:"purpose"`
	Action            string `json:"action"`
	StickyStorageRoot string `json:"sticky_storage_root"`
	SigningPrivateKey string `json:"signing_private_key"`
}

type formalGLMPhase21RockFinalizeAckSecret struct {
	Version              string `json:"version"`
	Family               string `json:"family"`
	Purpose              string `json:"purpose"`
	Action               string `json:"action"`
	StickyStorageRoot    string `json:"sticky_storage_root"`
	TransportStorageRoot string `json:"transport_storage_root"`
	SigningPrivateKey    string `json:"signing_private_key"`
}

type formalGLMPhase21RockAckSecret struct {
	Version              string `json:"version"`
	Family               string `json:"family"`
	Purpose              string `json:"purpose"`
	Action               string `json:"action"`
	StickyStorageRoot    string `json:"sticky_storage_root"`
	Phase20StorageRoot   string `json:"phase20_storage_root"`
	BackendKey           string `json:"backend_key"`
	TransportStorageRoot string `json:"transport_storage_root"`
	SigningPrivateKey    string `json:"signing_private_key"`
}

type formalGLMPhase21RockContext struct {
	contract   formalGLMPhase21SamplerV2Contract
	pins       map[string]ed25519.PublicKey
	artifactID string
}

type formalGLMPhase21RockPhaseHook func(string) error

func formalGLMPhase21RockStrictDecode(encoded []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("formal-glm lifecycle: invalid typed record")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("formal-glm lifecycle: trailing typed record")
	}
	canonical, err := json.Marshal(output)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return fmt.Errorf("formal-glm lifecycle: non-canonical typed record")
	}
	return nil
}

func formalGLMPhase21RockRelative(root, path string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		!filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("formal-glm lifecycle: invalid Rock path")
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || relative == "" ||
		filepath.IsAbs(relative) || relative == ".." ||
		len(relative) > 4096 ||
		len(relative) >= 3 && relative[:3] == ".."+string(filepath.Separator) {
		return "", fmt.Errorf("formal-glm lifecycle: path left authority root")
	}
	return relative, nil
}

func formalGLMPhase21RockOpenRoot(root string) (*os.Root, error) {
	if err := formalFinalizerHandoffEnsurePrivateDir(root); err != nil {
		return nil, fmt.Errorf("formal-glm lifecycle: unsafe authority root")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || filepath.Clean(resolved) != root {
		return nil, fmt.Errorf("formal-glm lifecycle: redirected authority root")
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("formal-glm lifecycle: authority root unavailable")
	}
	return opened, nil
}

func formalGLMPhase21RockRead(root, path string, maximum int64) ([]byte, error) {
	relative, err := formalGLMPhase21RockRelative(root, path)
	if err != nil {
		return nil, err
	}
	opened, err := formalGLMPhase21RockOpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer opened.Close()
	encoded, err := formalGLMPhase21RootReadRecord(opened, relative, maximum)
	if err != nil {
		return nil, fmt.Errorf("formal-glm lifecycle: unreadable private record")
	}
	return encoded, nil
}

func formalGLMPhase21RockReadJSON(root, path string, maximum int64,
	output any,
) error {
	encoded, err := formalGLMPhase21RockRead(root, path, maximum)
	if err != nil {
		return err
	}
	defer clear(encoded)
	return formalGLMPhase21RockStrictDecode(encoded, output)
}

func formalGLMPhase21RockTryReadJSON(root, path string, maximum int64,
	output any,
) (bool, error) {
	relative, err := formalGLMPhase21RockRelative(root, path)
	if err != nil {
		return false, err
	}
	opened, err := formalGLMPhase21RockOpenRoot(root)
	if err != nil {
		return false, err
	}
	defer opened.Close()
	encoded, err := formalGLMPhase21RootReadRecord(opened, relative, maximum)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("formal-glm lifecycle: unreadable private record")
	}
	defer clear(encoded)
	if err := formalGLMPhase21RockStrictDecode(encoded, output); err != nil {
		return false, err
	}
	return true, nil
}

func formalGLMPhase21RockEnsureParent(root *os.Root, relative string) error {
	parent := filepath.Dir(relative)
	if parent == "." {
		return fmt.Errorf("formal-glm lifecycle: record lacks private parent")
	}
	return formalGLMPhase21EnsureRootPrivateDir(root, parent)
}

func formalGLMPhase21RockWriteJSON(root, path string, value any) (
	string, bool, error,
) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) < 64 ||
		len(encoded) > formalGLMPhase21RockMaxRecord {
		return "", false, fmt.Errorf("formal-glm lifecycle: invalid durable output")
	}
	relative, err := formalGLMPhase21RockRelative(root, path)
	if err != nil {
		return "", false, err
	}
	opened, err := formalGLMPhase21RockOpenRoot(root)
	if err != nil {
		return "", false, err
	}
	defer opened.Close()
	if err := formalGLMPhase21RockEnsureParent(opened, relative); err != nil {
		return "", false, err
	}
	created, err := formalGLMPhase21RootCreateRecord(opened, relative, encoded)
	if err != nil {
		return "", false, fmt.Errorf("formal-glm lifecycle: durable output failed")
	}
	existing, err := formalGLMPhase21RootReadRecord(
		opened, relative, formalGLMPhase21RockMaxRecord)
	if err != nil || !bytes.Equal(existing, encoded) {
		clear(existing)
		return "", false, fmt.Errorf("formal-glm lifecycle: conflicting durable output")
	}
	clear(existing)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), !created, nil
}

func formalGLMPhase21RockRemoveSecret(root, path string) error {
	relative, err := formalGLMPhase21RockRelative(root, path)
	if err != nil {
		return err
	}
	opened, err := formalGLMPhase21RockOpenRoot(root)
	if err != nil {
		return err
	}
	defer opened.Close()
	info, err := opened.Lstat(relative)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
		!exactGCPrivateOwnedRegular(info) || info.Size() < 64 ||
		info.Size() > formalGLMPhase21RockMaxSecret {
		return fmt.Errorf("formal-glm lifecycle: secret cleanup refused")
	}
	if err := opened.Remove(relative); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("formal-glm lifecycle: secret cleanup failed")
	}
	if err := formalGLMPhase21RootSyncDir(opened, relative); err != nil {
		return fmt.Errorf("formal-glm lifecycle: secret cleanup sync failed")
	}
	return nil
}

func formalGLMPhase21RockDecodeBase64(value string, size int) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != size ||
		base64.StdEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, fmt.Errorf("formal-glm lifecycle: invalid secret bundle")
	}
	var zero byte
	for _, item := range decoded {
		zero |= item
	}
	if zero == 0 {
		clear(decoded)
		return nil, fmt.Errorf("formal-glm lifecycle: invalid secret bundle")
	}
	return decoded, nil
}

func formalGLMPhase21RockDecodeRoot(value string) ([32]byte, error) {
	var result [32]byte
	decoded, err := formalGLMPhase21RockDecodeBase64(value, len(result))
	if err != nil {
		return result, err
	}
	copy(result[:], decoded)
	clear(decoded)
	return result, nil
}

func formalGLMPhase21RockDecodePrivateKey(value string) (
	ed25519.PrivateKey, error,
) {
	decoded, err := formalGLMPhase21RockDecodeBase64(
		value, ed25519.PrivateKeySize)
	if err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(decoded), nil
}

func formalGLMPhase21RockLoadPins(root, path string) (
	map[string]ed25519.PublicKey, error,
) {
	var record formalGLMPhase21RockPinset
	if err := formalGLMPhase21RockReadJSON(
		root, path, formalGLMPhase21RockMaxRecord, &record); err != nil {
		return nil, err
	}
	if record.Version != formalGLMPhase21RockPinsetVersion ||
		record.Family != formalFinalizerHandoffFamilyGLM ||
		record.Purpose != formalGLMPhase21RockPurpose ||
		len(record.PinnedPublicKey) < 2 {
		return nil, fmt.Errorf("formal-glm lifecycle: invalid pinset")
	}
	pins := make(map[string]ed25519.PublicKey, len(record.PinnedPublicKey))
	for peer, encoded := range record.PinnedPublicKey {
		decoded, err := formalGLMPhase21RockDecodeBase64(
			encoded, ed25519.PublicKeySize)
		if err != nil || !jointDPBiomedicalGaussianValidPeerName(peer) {
			clear(decoded)
			return nil, fmt.Errorf("formal-glm lifecycle: invalid pinset")
		}
		pins[peer] = ed25519.PublicKey(decoded)
	}
	return pins, nil
}

func formalGLMPhase21RockLoadContext(root, contractPath, pinsetPath string) (
	formalGLMPhase21RockContext, error,
) {
	var result formalGLMPhase21RockContext
	pins, err := formalGLMPhase21RockLoadPins(root, pinsetPath)
	if err != nil {
		return result, err
	}
	var contract formalGLMPhase21SamplerV2Contract
	if err := formalGLMPhase21RockReadJSON(
		root, contractPath, formalGLMPhase21RockMaxRecord,
		&contract); err != nil {
		return result, err
	}
	if err := formalGLMPhase21RequireProductiveOneDraw(
		contract.SamplerMode); err != nil ||
		formalGLMPhase21ValidateSamplerV2Contract(contract, pins) != nil {
		return result, fmt.Errorf(
			"formal-glm lifecycle: invalid signed artifact contract")
	}
	return formalGLMPhase21RockContext{
		contract: contract, pins: pins, artifactID: contract.ArtifactID,
	}, nil
}

func formalGLMPhase21RockLoadRegistryResolution(
	root, path string, context formalGLMPhase21RockContext,
) (*formalGLMArtifactRegistryResolutionV1, error) {
	registered := context.contract.Artifact.DescriptorCoreSHA256 != ""
	if !registered {
		if path != "" {
			return nil, fmt.Errorf(
				"formal-glm lifecycle: broad artifact cannot select a registry entry")
		}
		return nil, nil
	}
	if path == "" {
		return nil, fmt.Errorf(
			"formal-glm lifecycle: registered artifact resolution is required")
	}
	var resolution formalGLMArtifactRegistryResolutionV1
	if err := formalGLMPhase21RockReadJSON(
		root, path, formalGLMPhase21RockMaxRecord, &resolution); err != nil {
		return nil, err
	}
	if resolution.ArtifactID != context.artifactID ||
		resolution.Descriptor.ArtifactID != context.artifactID ||
		formalGLMValidateSignedPublicDescriptorV1(
			resolution.Descriptor, context.pins) != nil ||
		formalGLMValidatePublicDescriptorAgainstArtifactV1(
			resolution.Descriptor, context.contract.Artifact) != nil {
		return nil, fmt.Errorf(
			"formal-glm lifecycle: registry resolution differs from artifact contract")
	}
	return &resolution, nil
}

func formalGLMPhase21RockBuildResolvedPublicCertificate(
	internal formalGLMPhase21StickyCertificate,
	resolution *formalGLMArtifactRegistryResolutionV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase21PublicCertificateV2, error) {
	if resolution != nil {
		return formalGLMPhase21BuildRegisteredPublicCertificateV2(
			internal, *resolution, pins)
	}
	if internal.Artifact.DescriptorCoreSHA256 != "" {
		return formalGLMPhase21PublicCertificateV2{}, fmt.Errorf(
			"formal-glm lifecycle: registered publication lacks resolution")
	}
	return formalGLMPhase21BuildPublicCertificateV2(internal, pins)
}

func formalGLMPhase21RockValidateResolvedPublication(
	publication formalGLMPhase21PublicCertificateV2,
	resolution *formalGLMArtifactRegistryResolutionV1,
	pins map[string]ed25519.PublicKey,
) error {
	if formalGLMPhase21ValidatePublicCertificateV2(publication, pins) != nil {
		return fmt.Errorf("formal-glm lifecycle: invalid resolved publication")
	}
	if resolution == nil {
		if publication.PublicDescriptor != nil ||
			publication.Artifact.DescriptorCoreSHA256 != "" {
			return fmt.Errorf(
				"formal-glm lifecycle: unexpected registered publication")
		}
		return nil
	}
	if publication.PublicDescriptor == nil ||
		publication.ArtifactID != resolution.ArtifactID ||
		!reflect.DeepEqual(*publication.PublicDescriptor,
			resolution.Descriptor) {
		return fmt.Errorf(
			"formal-glm lifecycle: publication differs from registry resolution")
	}
	return nil
}

func formalGLMPhase21RockAuthority(artifact formalGLMPhase21StickyArtifact,
	peer string,
) (formalFinalizerHandoffAuthority, error) {
	for _, authority := range artifact.NoiseAuthorities {
		if authority.PeerName == peer {
			return formalFinalizerHandoffAuthority{
				PeerName: authority.PeerName, PeerID: authority.PeerID,
				Role: authority.Role,
			}, nil
		}
	}
	return formalFinalizerHandoffAuthority{},
		fmt.Errorf("formal-glm lifecycle: peer is not a noise authority")
}

func formalGLMPhase21RockPreflightMessage(
	receipt formalGLMPhase21RockPreflightReceipt,
) ([]byte, error) {
	receipt.Signature = nil
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMPhase21PublicV2Domain+"/rock-preflight|"),
		encoded...), nil
}

func formalGLMPhase21RockValidatePreflightReceipt(
	receipt formalGLMPhase21RockPreflightReceipt,
	contract formalGLMPhase21SamplerV2Contract,
	pins map[string]ed25519.PublicKey,
) error {
	position := -1
	for index, authority := range contract.Artifact.NoiseAuthorities {
		if authority.PeerName == receipt.PeerName {
			position = index
		}
	}
	message, err := formalGLMPhase21RockPreflightMessage(receipt)
	if err != nil || position < 0 ||
		receipt.Version != formalGLMPhase21RockRecordVersion ||
		receipt.Purpose != formalGLMPhase21RockPreflightPurpose ||
		receipt.ArtifactID != contract.ArtifactID ||
		receipt.PinsetSHA256 != contract.PinsetSHA256 ||
		receipt.PeerID != contract.Artifact.NoiseAuthorities[position].PeerID ||
		receipt.Role != contract.Artifact.NoiseAuthorities[position].Role ||
		receipt.ProductionReady ||
		(receipt.State != formalGLMPhase21RockStateAbsent &&
			receipt.State != formalGLMPhase21RockStatePublished) ||
		receipt.State == formalGLMPhase21RockStateAbsent &&
			receipt.CertificateSHA256 != "" ||
		receipt.State == formalGLMPhase21RockStatePublished &&
			!formalGLMIsSHA256(receipt.CertificateSHA256) ||
		len(receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pins[receipt.PeerName], message, receipt.Signature) {
		return fmt.Errorf("formal-glm lifecycle: invalid preflight receipt")
	}
	return nil
}

func formalGLMPhase21RockValidatePreflightRecord(
	record formalGLMPhase21RockPreflightRecord,
	contract formalGLMPhase21SamplerV2Contract,
	pins map[string]ed25519.PublicKey,
) error {
	if record.Version != formalGLMPhase21RockRecordVersion ||
		record.Family != formalFinalizerHandoffFamilyGLM ||
		record.Purpose != formalGLMPhase21RockPreflightPurpose ||
		record.ProductionReady ||
		formalGLMPhase21RockValidatePreflightReceipt(
			record.Receipt, contract, pins) != nil {
		return fmt.Errorf("formal-glm lifecycle: invalid preflight record")
	}
	if record.Receipt.State == formalGLMPhase21RockStateAbsent {
		if record.Publication != nil {
			return fmt.Errorf("formal-glm lifecycle: absent preflight carried release")
		}
		return nil
	}
	if record.Publication == nil ||
		record.Publication.ArtifactID != contract.ArtifactID ||
		formalGLMPhase21ValidatePublicCertificateV2(
			*record.Publication, pins) != nil ||
		contract.Artifact.DescriptorCoreSHA256 != "" &&
			record.Publication.PublicDescriptor == nil ||
		contract.Artifact.DescriptorCoreSHA256 == "" &&
			record.Publication.PublicDescriptor != nil {
		return fmt.Errorf("formal-glm lifecycle: invalid preflight publication")
	}
	encoded, err := json.Marshal(record.Publication)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMPhase21PublicV2Domain+"/sealed-certificate|"),
		encoded...))
	if hex.EncodeToString(digest[:]) != record.Receipt.CertificateSHA256 {
		return fmt.Errorf("formal-glm lifecycle: preflight publication changed")
	}
	return nil
}

func formalGLMPhase21RockPreflightPair(
	records [2]formalGLMPhase21RockPreflightRecord,
	contract formalGLMPhase21SamplerV2Contract,
	pins map[string]ed25519.PublicKey,
) (string, *formalGLMPhase21PublicCertificateV2, error) {
	for index := range records {
		if formalGLMPhase21RockValidatePreflightRecord(
			records[index], contract, pins) != nil {
			return "", nil, fmt.Errorf(
				"formal-glm lifecycle: invalid preflight pair")
		}
		authority := contract.Artifact.NoiseAuthorities[index]
		if records[index].Receipt.PeerName != authority.PeerName ||
			records[index].Receipt.PeerID != authority.PeerID ||
			records[index].Receipt.Role != authority.Role {
			return "", nil, fmt.Errorf(
				"formal-glm lifecycle: reordered preflight pair")
		}
	}
	left, right := records[0], records[1]
	if left.Receipt.State != right.Receipt.State {
		published := left
		if right.Receipt.State == formalGLMPhase21RockStatePublished {
			published = right
		}
		if published.Publication == nil {
			return "", nil, fmt.Errorf(
				"formal-glm lifecycle: repair publication missing")
		}
		copy := *published.Publication
		return formalGLMPhase21RockStateRepairPending, &copy, nil
	}
	if left.Receipt.State == formalGLMPhase21RockStateAbsent {
		return formalGLMPhase21RockStateAbsent, nil, nil
	}
	leftBytes, leftErr := json.Marshal(left.Publication)
	rightBytes, rightErr := json.Marshal(right.Publication)
	if leftErr != nil || rightErr != nil ||
		left.Receipt.CertificateSHA256 != right.Receipt.CertificateSHA256 ||
		!bytes.Equal(leftBytes, rightBytes) {
		return "", nil, fmt.Errorf(
			"formal-glm lifecycle: split-brain public preflight")
	}
	copy := *left.Publication
	return formalGLMPhase21RockStatePublished, &copy, nil
}

func formalGLMPhase21RockPreflightRecordPath(root, artifactID, state,
	certificateSHA256 string,
) (string, error) {
	if !formalGLMIsSHA256(artifactID) ||
		(state != formalGLMPhase21RockStateAbsent &&
			state != formalGLMPhase21RockStatePublished) ||
		state == formalGLMPhase21RockStateAbsent && certificateSHA256 != "" ||
		state == formalGLMPhase21RockStatePublished &&
			!formalGLMIsSHA256(certificateSHA256) {
		return "", fmt.Errorf("formal-glm lifecycle: invalid preflight slot")
	}
	suffix := state
	if certificateSHA256 != "" {
		suffix += "-" + certificateSHA256
	}
	return filepath.Join(root, "formal-glm-lifecycle-v1", "preflight-v1",
		artifactID[:2], artifactID[2:4], suffix+"-"+artifactID+".json"), nil
}

func formalGLMPhase21RockLoadPreflightPair(root string, paths [2]string,
	context formalGLMPhase21RockContext,
) ([2]formalGLMPhase21RockPreflightRecord, string,
	*formalGLMPhase21PublicCertificateV2, error,
) {
	var records [2]formalGLMPhase21RockPreflightRecord
	for index := range records {
		if err := formalGLMPhase21RockReadJSON(
			root, paths[index], formalGLMPhase21RockMaxRecord,
			&records[index]); err != nil {
			return records, "", nil, err
		}
	}
	state, publication, err := formalGLMPhase21RockPreflightPair(
		records, context.contract, context.pins)
	return records, state, publication, err
}

func formalGLMPhase21RockStageMessage(
	receipt formalGLMPhase21RockStageReceipt,
) ([]byte, error) {
	receipt.Signature = nil
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMPhase21PublicV2Domain+"/rock-stage|"),
		encoded...), nil
}

func formalGLMPhase21RockValidateStageRecord(
	record formalGLMPhase21RockStageRecord,
	contract formalGLMPhase21SamplerV2Contract,
	pins map[string]ed25519.PublicKey,
) error {
	if record.Version != formalGLMPhase21RockRecordVersion ||
		record.Family != formalFinalizerHandoffFamilyGLM ||
		record.Purpose != formalGLMPhase21RockStagePurpose ||
		record.ArtifactID != contract.ArtifactID || record.ProductionReady ||
		formalFinalizerHandoffValidateBinding(record.Binding, pins) != nil ||
		record.Binding.Family != formalFinalizerHandoffFamilyGLM ||
		record.Binding.Purpose != formalFinalizerHandoffGLMPurpose ||
		record.Binding.ArtifactID != contract.ArtifactID ||
		record.Binding.PinsetSHA256 != contract.PinsetSHA256 ||
		!reflect.DeepEqual(record.Binding.Authorities,
			[]formalFinalizerHandoffAuthority{
				{PeerName: contract.Artifact.NoiseAuthorities[0].PeerName,
					PeerID: contract.Artifact.NoiseAuthorities[0].PeerID,
					Role:   contract.Artifact.NoiseAuthorities[0].Role},
				{PeerName: contract.Artifact.NoiseAuthorities[1].PeerName,
					PeerID: contract.Artifact.NoiseAuthorities[1].PeerID,
					Role:   contract.Artifact.NoiseAuthorities[1].Role},
			}) ||
		!formalFinalizerHandoffAuthorityEqual(
			record.Binding.Finalizer, record.Binding.Authorities[0]) {
		return fmt.Errorf("formal-glm lifecycle: invalid stage binding")
	}
	receipt := record.Receipt
	contractSHA256, contractErr := formalGLMPhase21SamplerV2ContractSHA256(
		contract)
	receiptSHA256, receiptErr := formalGLMPhase21LocalSpoolReceiptSHA256(
		receipt.SourceReceipt)
	authority, authorityErr := formalFinalizerHandoffPeer(
		record.Binding, receipt.Role)
	chunkMessage, chunkErr :=
		jointDPBiomedicalGaussianOneDrawChunkReceiptMessage(
			receipt.SourceReceipt)
	stageMessage, stageErr := formalGLMPhase21RockStageMessage(receipt)
	if contractErr != nil || receiptErr != nil || authorityErr != nil ||
		chunkErr != nil || stageErr != nil ||
		receipt.Version != formalGLMPhase21RockRecordVersion ||
		receipt.Purpose != formalGLMPhase21RockStagePurpose ||
		receipt.ArtifactID != contract.ArtifactID ||
		receipt.ContractSHA256 != contractSHA256 ||
		receipt.PeerName != authority.PeerName ||
		receipt.PeerID != authority.PeerID ||
		receipt.FinalPairRootSHA256 != record.Binding.FinalPairRootSHA256 ||
		receipt.PlanSHA256 != record.Binding.PlanSHA256 ||
		receipt.SourceReceiptSHA256 != receiptSHA256 ||
		receipt.ProductionReady ||
		receipt.SourceReceipt.PeerName != authority.PeerName ||
		receipt.SourceReceipt.PeerID != authority.PeerID ||
		receipt.SourceReceipt.Role != authority.Role ||
		receipt.SourceReceipt.PlanSHA256 != record.Binding.PlanSHA256 ||
		receipt.SourceReceipt.ChunkStart != 0 ||
		receipt.SourceReceipt.CoordinateCount !=
			receipt.SourceReceipt.TotalCoordinateCount ||
		len(receipt.SourceReceipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pins[authority.PeerName], chunkMessage,
			receipt.SourceReceipt.Signature) ||
		len(receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pins[authority.PeerName], stageMessage,
			receipt.Signature) {
		return fmt.Errorf("formal-glm lifecycle: invalid signed stage record")
	}
	return nil
}

func formalGLMPhase21RockStagePair(
	records [2]formalGLMPhase21RockStageRecord,
	contract formalGLMPhase21SamplerV2Contract,
	pins map[string]ed25519.PublicKey,
) (formalFinalizerHandoffBinding, error) {
	for index := range records {
		if formalGLMPhase21RockValidateStageRecord(
			records[index], contract, pins) != nil {
			return formalFinalizerHandoffBinding{},
				fmt.Errorf("formal-glm lifecycle: invalid stage pair")
		}
		authority := contract.Artifact.NoiseAuthorities[index]
		if records[index].Receipt.PeerName != authority.PeerName ||
			records[index].Receipt.Role != authority.Role {
			return formalFinalizerHandoffBinding{},
				fmt.Errorf("formal-glm lifecycle: reordered stage pair")
		}
	}
	if !reflect.DeepEqual(records[0].Binding, records[1].Binding) {
		return formalFinalizerHandoffBinding{},
			fmt.Errorf("formal-glm lifecycle: stage pair root changed")
	}
	return records[0].Binding, nil
}

func formalGLMPhase21RockLoadStagePair(root string, paths [2]string,
	context formalGLMPhase21RockContext,
) ([2]formalGLMPhase21RockStageRecord,
	formalFinalizerHandoffBinding, error,
) {
	var records [2]formalGLMPhase21RockStageRecord
	for index := range records {
		if err := formalGLMPhase21RockReadJSON(
			root, paths[index], formalGLMPhase21RockMaxRecord,
			&records[index]); err != nil {
			return records, formalFinalizerHandoffBinding{}, err
		}
	}
	binding, err := formalGLMPhase21RockStagePair(
		records, context.contract, context.pins)
	return records, binding, err
}

func formalGLMPhase21RockStageRecordPath(root, artifactID, role string) (
	string, error,
) {
	if !formalGLMIsSHA256(artifactID) ||
		(role != "garbler" && role != "evaluator") {
		return "", fmt.Errorf("formal-glm lifecycle: invalid stage slot")
	}
	return filepath.Join(root, "formal-glm-lifecycle-v1", "stage-v1",
		artifactID[:2], artifactID[2:4], role+"-"+artifactID+".json"), nil
}

func formalGLMPhase21RockTicketRecordPath(root, artifactID string) (
	string, error,
) {
	if !formalGLMIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-glm lifecycle: invalid ticket slot")
	}
	return filepath.Join(root, "formal-glm-lifecycle-v1", "ticket-v1",
		artifactID[:2], artifactID[2:4], "ticket-"+artifactID+".json"), nil
}

func formalGLMPhase21RockValidateTicketRecord(
	record formalGLMPhase21RockTicketRecord,
	context formalGLMPhase21RockContext,
) error {
	if record.Version != formalGLMPhase21RockRecordVersion ||
		record.Family != formalFinalizerHandoffFamilyGLM ||
		record.Purpose != formalGLMPhase21RockTicketPurpose ||
		record.ArtifactID != context.artifactID || record.ProductionReady ||
		formalFinalizerHandoffValidateBinding(record.Binding, context.pins) != nil ||
		record.Binding.ArtifactID != context.artifactID ||
		record.Binding.PinsetSHA256 != context.contract.PinsetSHA256 ||
		formalFinalizerHandoffValidateTicket(
			record.Ticket, record.Binding, context.pins) != nil {
		return fmt.Errorf("formal-glm lifecycle: invalid ticket record")
	}
	return nil
}

func formalGLMPhase21RockSealMessage(
	receipt formalGLMPhase21RockSealReceipt,
) ([]byte, error) {
	receipt.Signature = nil
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalFinalizerHandoffDomain+"/glm-rock-seal|"),
		encoded...), nil
}

func formalGLMPhase21RockSealRecordPath(root, artifactID, role string) (
	string, error,
) {
	if !formalGLMIsSHA256(artifactID) ||
		(role != "garbler" && role != "evaluator") {
		return "", fmt.Errorf("formal-glm lifecycle: invalid seal slot")
	}
	return filepath.Join(root, "formal-glm-lifecycle-v1", "seal-v1",
		artifactID[:2], artifactID[2:4], role+"-"+artifactID+".json"), nil
}

func formalGLMPhase21RockValidateSealRecord(
	record formalGLMPhase21RockSealRecord,
	context formalGLMPhase21RockContext,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
) error {
	receipt := record.Receipt
	authority, authorityErr := formalFinalizerHandoffPeer(
		binding, receipt.Role)
	ticketSHA, ticketErr := formalFinalizerHandoffTicketSHA256(ticket)
	message, messageErr := formalGLMPhase21RockSealMessage(receipt)
	if authorityErr != nil || ticketErr != nil || messageErr != nil ||
		record.Version != formalGLMPhase21RockRecordVersion ||
		record.Family != formalFinalizerHandoffFamilyGLM ||
		record.Purpose != formalGLMPhase21RockSealPurpose ||
		record.ArtifactID != context.artifactID || record.ProductionReady ||
		receipt.Version != formalGLMPhase21RockRecordVersion ||
		receipt.Purpose != formalGLMPhase21RockSealPurpose ||
		receipt.ArtifactID != context.artifactID ||
		receipt.FinalPairRootSHA256 != binding.FinalPairRootSHA256 ||
		receipt.PlanSHA256 != binding.PlanSHA256 ||
		receipt.PinsetSHA256 != binding.PinsetSHA256 ||
		receipt.TicketSHA256 != ticketSHA ||
		receipt.PeerName != authority.PeerName ||
		receipt.PeerID != authority.PeerID ||
		receipt.PayloadKind != formalFinalizerHandoffGLMOneDrawKind ||
		!formalGLMIsSHA256(receipt.PayloadSHA256) ||
		!formalGLMIsSHA256(receipt.CiphertextSHA256) ||
		!formalGLMIsSHA256(receipt.EnvelopeSHA256) ||
		receipt.ProductionReady ||
		len(receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(context.pins[authority.PeerName],
			message, receipt.Signature) {
		return fmt.Errorf("formal-glm lifecycle: invalid seal record")
	}
	return nil
}

func formalGLMPhase21RockBuildSealRecord(
	context formalGLMPhase21RockContext,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	envelope formalFinalizerHandoffEnvelope,
	privateKey ed25519.PrivateKey,
) (formalGLMPhase21RockSealRecord, error) {
	var zero formalGLMPhase21RockSealRecord
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil {
		return zero, err
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return zero, err
	}
	digest := sha256.Sum256(encoded)
	receipt := formalGLMPhase21RockSealReceipt{
		Version:             formalGLMPhase21RockRecordVersion,
		Purpose:             formalGLMPhase21RockSealPurpose,
		ArtifactID:          context.artifactID,
		FinalPairRootSHA256: binding.FinalPairRootSHA256,
		PlanSHA256:          binding.PlanSHA256, PinsetSHA256: binding.PinsetSHA256,
		TicketSHA256: ticketSHA,
		PeerName:     envelope.SenderPeerName, PeerID: envelope.SenderPeerID,
		Role: envelope.SenderRole, PayloadKind: envelope.PayloadKind,
		PayloadSHA256:    envelope.PayloadSHA256,
		CiphertextSHA256: envelope.CiphertextSHA256,
		EnvelopeSHA256:   hex.EncodeToString(digest[:]),
		ProductionReady:  false,
	}
	message, err := formalGLMPhase21RockSealMessage(receipt)
	if err != nil {
		return zero, err
	}
	receipt.Signature = ed25519.Sign(privateKey, message)
	record := formalGLMPhase21RockSealRecord{
		Version:    formalGLMPhase21RockRecordVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Purpose:    formalGLMPhase21RockSealPurpose,
		ArtifactID: context.artifactID, Receipt: receipt,
		ProductionReady: false,
	}
	if err := formalGLMPhase21RockValidateSealRecord(
		record, context, binding, ticket); err != nil {
		return zero, err
	}
	return record, nil
}

func formalGLMPhase21RockLoadSealPair(root string, paths [2]string,
	context formalGLMPhase21RockContext,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
) ([2]formalGLMPhase21RockSealRecord, error) {
	var records [2]formalGLMPhase21RockSealRecord
	for index := range records {
		if err := formalGLMPhase21RockReadJSON(
			root, paths[index], formalGLMPhase21RockMaxRecord,
			&records[index]); err != nil ||
			formalGLMPhase21RockValidateSealRecord(
				records[index], context, binding, ticket) != nil {
			return records, fmt.Errorf(
				"formal-glm lifecycle: invalid seal pair")
		}
		authority := binding.Authorities[index]
		if records[index].Receipt.PeerName != authority.PeerName ||
			records[index].Receipt.PeerID != authority.PeerID ||
			records[index].Receipt.Role != authority.Role {
			return records, fmt.Errorf(
				"formal-glm lifecycle: reordered seal pair")
		}
	}
	return records, nil
}

func formalGLMPhase21RockCandidateSHA256(
	candidate jointDPBiomedicalGaussianOneDrawCommonRelease,
) (string, error) {
	if len(candidate.Signatures) != 0 {
		return "", fmt.Errorf("formal-glm lifecycle: candidate is already signed")
	}
	message, err := jointDPBiomedicalGaussianOneDrawCommonReleaseMessage(
		candidate)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalFinalizerHandoffDomain+"/glm-candidate|"), message...))
	clear(message)
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPhase21RockCandidateMessage(
	receipt formalGLMPhase21RockCandidateReceipt,
) ([]byte, error) {
	receipt.Signature = nil
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalFinalizerHandoffDomain+"/glm-rock-candidate|"),
		encoded...), nil
}

func formalGLMPhase21RockCandidateRecordPath(root, artifactID string) (
	string, error,
) {
	if !formalGLMIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-glm lifecycle: invalid candidate slot")
	}
	return filepath.Join(root, "formal-glm-lifecycle-v1", "candidate-v1",
		artifactID[:2], artifactID[2:4], "candidate-"+artifactID+".json"), nil
}

func formalGLMPhase21RockValidateCandidateRecord(
	record formalGLMPhase21RockCandidateRecord,
	context formalGLMPhase21RockContext,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
) error {
	receipt := record.Receipt
	candidateSHA, candidateErr := formalGLMPhase21RockCandidateSHA256(
		record.Candidate)
	ticketSHA, ticketErr := formalFinalizerHandoffTicketSHA256(ticket)
	message, messageErr := formalGLMPhase21RockCandidateMessage(receipt)
	if candidateErr != nil || ticketErr != nil || messageErr != nil ||
		record.Version != formalGLMPhase21RockRecordVersion ||
		record.Family != formalFinalizerHandoffFamilyGLM ||
		record.Purpose != formalGLMPhase21RockCandidatePurpose ||
		record.ArtifactID != context.artifactID || record.ProductionReady ||
		receipt.Version != formalGLMPhase21RockRecordVersion ||
		receipt.Purpose != formalGLMPhase21RockCandidatePurpose ||
		receipt.ArtifactID != context.artifactID ||
		receipt.FinalPairRootSHA256 != binding.FinalPairRootSHA256 ||
		receipt.PlanSHA256 != binding.PlanSHA256 ||
		receipt.PinsetSHA256 != binding.PinsetSHA256 ||
		receipt.TicketSHA256 != ticketSHA ||
		receipt.CandidateSHA256 != candidateSHA ||
		receipt.FinalizerPeerName != binding.Finalizer.PeerName ||
		receipt.FinalizerPeerID != binding.Finalizer.PeerID ||
		receipt.FinalizerRole != binding.Finalizer.Role ||
		receipt.ProductionReady ||
		len(receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(context.pins[binding.Finalizer.PeerName],
			message, receipt.Signature) {
		return fmt.Errorf("formal-glm lifecycle: invalid candidate record")
	}
	return nil
}

func formalGLMPhase21RockBuildCandidateRecord(
	context formalGLMPhase21RockContext,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	candidate jointDPBiomedicalGaussianOneDrawCommonRelease,
	privateKey ed25519.PrivateKey,
) (formalGLMPhase21RockCandidateRecord, error) {
	var zero formalGLMPhase21RockCandidateRecord
	candidateSHA, err := formalGLMPhase21RockCandidateSHA256(candidate)
	if err != nil {
		return zero, err
	}
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil {
		return zero, err
	}
	receipt := formalGLMPhase21RockCandidateReceipt{
		Version:             formalGLMPhase21RockRecordVersion,
		Purpose:             formalGLMPhase21RockCandidatePurpose,
		ArtifactID:          context.artifactID,
		FinalPairRootSHA256: binding.FinalPairRootSHA256,
		PlanSHA256:          binding.PlanSHA256, PinsetSHA256: binding.PinsetSHA256,
		TicketSHA256: ticketSHA, CandidateSHA256: candidateSHA,
		FinalizerPeerName: binding.Finalizer.PeerName,
		FinalizerPeerID:   binding.Finalizer.PeerID,
		FinalizerRole:     binding.Finalizer.Role, ProductionReady: false,
	}
	message, err := formalGLMPhase21RockCandidateMessage(receipt)
	if err != nil {
		return zero, err
	}
	receipt.Signature = ed25519.Sign(privateKey, message)
	record := formalGLMPhase21RockCandidateRecord{
		Version:    formalGLMPhase21RockRecordVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Purpose:    formalGLMPhase21RockCandidatePurpose,
		ArtifactID: context.artifactID, Candidate: candidate,
		Receipt: receipt, ProductionReady: false,
	}
	if err := formalGLMPhase21RockValidateCandidateRecord(
		record, context, binding, ticket); err != nil {
		return zero, err
	}
	return record, nil
}

func formalGLMPhase21RockLocalReleaseSHA256(
	release jointDPBiomedicalGaussianOneDrawLocalRelease,
) (string, error) {
	encoded, err := json.Marshal(release)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalFinalizerHandoffDomain+"/glm-local-release|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPhase21RockLocalReleaseMessage(
	binding formalGLMPhase21RockLocalReleaseBinding,
) ([]byte, error) {
	binding.Signature = nil
	encoded, err := json.Marshal(binding)
	if err != nil {
		return nil, err
	}
	return append([]byte(
		formalFinalizerHandoffDomain+"/glm-rock-local-release|"), encoded...), nil
}

func formalGLMPhase21RockLocalReleaseRecordPath(
	root, artifactID, role string,
) (string, error) {
	if !formalGLMIsSHA256(artifactID) ||
		(role != "garbler" && role != "evaluator") {
		return "", fmt.Errorf("formal-glm lifecycle: invalid local release slot")
	}
	return filepath.Join(root, "formal-glm-lifecycle-v1", "local-release-v1",
		artifactID[:2], artifactID[2:4], role+"-"+artifactID+".json"), nil
}

func formalGLMPhase21RockValidateLocalReleaseRecord(
	record formalGLMPhase21RockLocalReleaseRecord,
	context formalGLMPhase21RockContext,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	candidate formalGLMPhase21RockCandidateRecord,
) error {
	localBinding := record.Binding
	authority, authorityErr := formalFinalizerHandoffPeer(
		binding, localBinding.Role)
	ticketSHA, ticketErr := formalFinalizerHandoffTicketSHA256(ticket)
	candidateSHA, candidateErr := formalGLMPhase21RockCandidateSHA256(
		candidate.Candidate)
	releaseSHA, releaseErr := formalGLMPhase21RockLocalReleaseSHA256(
		record.LocalRelease)
	bindingMessage, bindingErr := formalGLMPhase21RockLocalReleaseMessage(
		localBinding)
	commonMessage, commonErr :=
		jointDPBiomedicalGaussianOneDrawCommonReleaseMessage(candidate.Candidate)
	releaseMessage, localErr := jointDPBiomedicalGaussianOneDrawLocalReleaseMessage(
		record.LocalRelease.Receipt)
	if authorityErr != nil || ticketErr != nil || candidateErr != nil ||
		releaseErr != nil || bindingErr != nil || commonErr != nil || localErr != nil ||
		record.Version != formalGLMPhase21RockRecordVersion ||
		record.Family != formalFinalizerHandoffFamilyGLM ||
		record.Purpose != formalGLMPhase21RockLocalReleasePurpose ||
		record.ArtifactID != context.artifactID || record.ProductionReady ||
		localBinding.Version != formalGLMPhase21RockRecordVersion ||
		localBinding.Purpose != formalGLMPhase21RockLocalReleasePurpose ||
		localBinding.ArtifactID != context.artifactID ||
		localBinding.FinalPairRootSHA256 != binding.FinalPairRootSHA256 ||
		localBinding.PlanSHA256 != binding.PlanSHA256 ||
		localBinding.PinsetSHA256 != binding.PinsetSHA256 ||
		localBinding.TicketSHA256 != ticketSHA ||
		localBinding.CandidateSHA256 != candidateSHA ||
		localBinding.LocalReleaseSHA256 != releaseSHA ||
		localBinding.PeerName != authority.PeerName ||
		localBinding.PeerID != authority.PeerID ||
		localBinding.ProductionReady ||
		record.LocalRelease.Receipt.PeerName != authority.PeerName ||
		len(record.LocalRelease.Receipt.CommonReleaseSignature) !=
			ed25519.SignatureSize ||
		!ed25519.Verify(context.pins[authority.PeerName], commonMessage,
			record.LocalRelease.Receipt.CommonReleaseSignature) ||
		len(record.LocalRelease.Receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(context.pins[authority.PeerName], releaseMessage,
			record.LocalRelease.Receipt.Signature) ||
		len(localBinding.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(context.pins[authority.PeerName], bindingMessage,
			localBinding.Signature) {
		return fmt.Errorf("formal-glm lifecycle: invalid local release record")
	}
	return nil
}

func formalGLMPhase21RockBuildLocalReleaseRecord(
	context formalGLMPhase21RockContext,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	candidate formalGLMPhase21RockCandidateRecord,
	role string,
	release jointDPBiomedicalGaussianOneDrawLocalRelease,
	privateKey ed25519.PrivateKey,
) (formalGLMPhase21RockLocalReleaseRecord, error) {
	var zero formalGLMPhase21RockLocalReleaseRecord
	authority, err := formalFinalizerHandoffPeer(binding, role)
	if err != nil {
		return zero, err
	}
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil {
		return zero, err
	}
	candidateSHA, err := formalGLMPhase21RockCandidateSHA256(candidate.Candidate)
	if err != nil {
		return zero, err
	}
	releaseSHA, err := formalGLMPhase21RockLocalReleaseSHA256(release)
	if err != nil {
		return zero, err
	}
	localBinding := formalGLMPhase21RockLocalReleaseBinding{
		Version:             formalGLMPhase21RockRecordVersion,
		Purpose:             formalGLMPhase21RockLocalReleasePurpose,
		ArtifactID:          context.artifactID,
		FinalPairRootSHA256: binding.FinalPairRootSHA256,
		PlanSHA256:          binding.PlanSHA256, PinsetSHA256: binding.PinsetSHA256,
		TicketSHA256: ticketSHA, CandidateSHA256: candidateSHA,
		LocalReleaseSHA256: releaseSHA,
		PeerName:           authority.PeerName, PeerID: authority.PeerID,
		Role: authority.Role, ProductionReady: false,
	}
	message, err := formalGLMPhase21RockLocalReleaseMessage(localBinding)
	if err != nil {
		return zero, err
	}
	localBinding.Signature = ed25519.Sign(privateKey, message)
	record := formalGLMPhase21RockLocalReleaseRecord{
		Version:    formalGLMPhase21RockRecordVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Purpose:    formalGLMPhase21RockLocalReleasePurpose,
		ArtifactID: context.artifactID, LocalRelease: release,
		Binding: localBinding, ProductionReady: false,
	}
	if err := formalGLMPhase21RockValidateLocalReleaseRecord(
		record, context, binding, ticket, candidate); err != nil {
		return zero, err
	}
	return record, nil
}

func formalGLMPhase21RockLoadLocalReleasePair(root string, paths [2]string,
	context formalGLMPhase21RockContext,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	candidate formalGLMPhase21RockCandidateRecord,
) ([2]formalGLMPhase21RockLocalReleaseRecord, error) {
	var records [2]formalGLMPhase21RockLocalReleaseRecord
	for index := range records {
		if err := formalGLMPhase21RockReadJSON(
			root, paths[index], formalGLMPhase21RockMaxRecord,
			&records[index]); err != nil ||
			formalGLMPhase21RockValidateLocalReleaseRecord(
				records[index], context, binding, ticket, candidate) != nil {
			return records, fmt.Errorf(
				"formal-glm lifecycle: invalid local release pair")
		}
		authority := binding.Authorities[index]
		if records[index].Binding.PeerName != authority.PeerName ||
			records[index].Binding.PeerID != authority.PeerID ||
			records[index].Binding.Role != authority.Role {
			return records, fmt.Errorf(
				"formal-glm lifecycle: reordered local release pair")
		}
	}
	return records, nil
}

func formalGLMPhase21RockCertifiedReleaseSHA256(
	release formalGLMPhase16CertifiedRelease,
) (string, error) {
	encoded, err := json.Marshal(release)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalFinalizerHandoffDomain+"/glm-certified-release|"),
		encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPhase21RockBaseCertificateMessage(
	receipt formalGLMPhase21RockBaseCertificateReceipt,
) ([]byte, error) {
	receipt.Signature = nil
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append([]byte(
		formalFinalizerHandoffDomain+"/glm-rock-base-certificate|"),
		encoded...), nil
}

func formalGLMPhase21RockBaseCertificateRecordPath(
	root, artifactID string,
) (string, error) {
	if !formalGLMIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-glm lifecycle: invalid certificate slot")
	}
	return filepath.Join(root, "formal-glm-lifecycle-v1", "base-certificate-v1",
		artifactID[:2], artifactID[2:4],
		"base-certificate-"+artifactID+".json"), nil
}

func formalGLMPhase21RockValidateBaseCertificateRecord(
	record formalGLMPhase21RockBaseCertificateRecord,
	context formalGLMPhase21RockContext,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	candidate formalGLMPhase21RockCandidateRecord,
) error {
	receipt := record.Receipt
	ticketSHA, ticketErr := formalFinalizerHandoffTicketSHA256(ticket)
	candidateSHA, candidateErr := formalGLMPhase21RockCandidateSHA256(
		candidate.Candidate)
	releaseSHA, releaseErr := formalGLMPhase21RockCertifiedReleaseSHA256(
		record.CertifiedRelease)
	certificateSHA, certificateErr := formalGLMPhase21DistributedIntentSHA256(
		record.BaseCertificate)
	message, messageErr := formalGLMPhase21RockBaseCertificateMessage(receipt)
	releasedCandidate := jointDPBiomedicalGaussianOneDrawCommonRelease{}
	if record.CertifiedRelease.OneDraw != nil {
		releasedCandidate = *record.CertifiedRelease.OneDraw
		releasedCandidate.Signatures = nil
	}
	if ticketErr != nil || candidateErr != nil || releaseErr != nil ||
		certificateErr != nil || messageErr != nil ||
		record.Version != formalGLMPhase21RockRecordVersion ||
		record.Family != formalFinalizerHandoffFamilyGLM ||
		record.Purpose != formalGLMPhase21RockBaseCertificatePurpose ||
		record.ArtifactID != context.artifactID || record.ProductionReady ||
		record.CertifiedRelease.OneDraw == nil ||
		!reflect.DeepEqual(releasedCandidate, candidate.Candidate) ||
		len(record.CertifiedRelease.OneDraw.Signatures) != 2 ||
		formalGLMPhase21ValidateStickyCertificateCore(
			record.BaseCertificate, context.pins) != nil ||
		record.BaseCertificate.ArtifactID != context.artifactID ||
		len(record.BaseCertificate.AuthorityReceipts) != 0 ||
		receipt.Version != formalGLMPhase21RockRecordVersion ||
		receipt.Purpose != formalGLMPhase21RockBaseCertificatePurpose ||
		receipt.ArtifactID != context.artifactID ||
		receipt.FinalPairRootSHA256 != binding.FinalPairRootSHA256 ||
		receipt.PlanSHA256 != binding.PlanSHA256 ||
		receipt.PinsetSHA256 != binding.PinsetSHA256 ||
		receipt.TicketSHA256 != ticketSHA ||
		receipt.CandidateSHA256 != candidateSHA ||
		receipt.CertifiedReleaseSHA256 != releaseSHA ||
		receipt.BaseCertificateSHA256 != certificateSHA ||
		receipt.FinalizerPeerName != binding.Finalizer.PeerName ||
		receipt.FinalizerPeerID != binding.Finalizer.PeerID ||
		receipt.FinalizerRole != binding.Finalizer.Role ||
		receipt.ProductionReady ||
		len(receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(context.pins[binding.Finalizer.PeerName],
			message, receipt.Signature) {
		return fmt.Errorf("formal-glm lifecycle: invalid base certificate record")
	}
	return nil
}

func formalGLMPhase21RockBuildBaseCertificateRecord(
	context formalGLMPhase21RockContext,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	candidate formalGLMPhase21RockCandidateRecord,
	release formalGLMPhase16CertifiedRelease,
	certificate formalGLMPhase21StickyCertificate,
	privateKey ed25519.PrivateKey,
) (formalGLMPhase21RockBaseCertificateRecord, error) {
	var zero formalGLMPhase21RockBaseCertificateRecord
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil {
		return zero, err
	}
	candidateSHA, err := formalGLMPhase21RockCandidateSHA256(candidate.Candidate)
	if err != nil {
		return zero, err
	}
	releaseSHA, err := formalGLMPhase21RockCertifiedReleaseSHA256(release)
	if err != nil {
		return zero, err
	}
	certificateSHA, err := formalGLMPhase21DistributedIntentSHA256(certificate)
	if err != nil {
		return zero, err
	}
	receipt := formalGLMPhase21RockBaseCertificateReceipt{
		Version:             formalGLMPhase21RockRecordVersion,
		Purpose:             formalGLMPhase21RockBaseCertificatePurpose,
		ArtifactID:          context.artifactID,
		FinalPairRootSHA256: binding.FinalPairRootSHA256,
		PlanSHA256:          binding.PlanSHA256, PinsetSHA256: binding.PinsetSHA256,
		TicketSHA256: ticketSHA, CandidateSHA256: candidateSHA,
		CertifiedReleaseSHA256: releaseSHA,
		BaseCertificateSHA256:  certificateSHA,
		FinalizerPeerName:      binding.Finalizer.PeerName,
		FinalizerPeerID:        binding.Finalizer.PeerID,
		FinalizerRole:          binding.Finalizer.Role, ProductionReady: false,
	}
	message, err := formalGLMPhase21RockBaseCertificateMessage(receipt)
	if err != nil {
		return zero, err
	}
	receipt.Signature = ed25519.Sign(privateKey, message)
	record := formalGLMPhase21RockBaseCertificateRecord{
		Version:    formalGLMPhase21RockRecordVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Purpose:    formalGLMPhase21RockBaseCertificatePurpose,
		ArtifactID: context.artifactID, CertifiedRelease: release,
		BaseCertificate: certificate, Receipt: receipt,
		ProductionReady: false,
	}
	if err := formalGLMPhase21RockValidateBaseCertificateRecord(
		record, context, binding, ticket, candidate); err != nil {
		return zero, err
	}
	return record, nil
}

func formalGLMPhase21RockAuthorizationRecordPath(
	root, artifactID, role string,
) (string, error) {
	if !formalGLMIsSHA256(artifactID) ||
		(role != "garbler" && role != "evaluator") {
		return "", fmt.Errorf("formal-glm lifecycle: invalid authorization slot")
	}
	return filepath.Join(root, "formal-glm-lifecycle-v1", "authorization-v1",
		artifactID[:2], artifactID[2:4], role+"-"+artifactID+".json"), nil
}

func formalGLMPhase21RockDistributedAuthorization(
	record formalGLMPhase21RockAuthorizationRecord,
) formalGLMPhase21DistributedAuthorization {
	return formalGLMPhase21DistributedAuthorization{
		Version:    formalGLMPhase21DistributedAuthorizationVersion,
		Purpose:    formalGLMPhase21DistributedAuthorizationPurpose,
		ArtifactID: record.ArtifactID, IntentSHA256: record.IntentSHA256,
		TransportAuthorization: record.TransportAuthorization,
		StickyAuthorization:    record.StickyAuthorization,
		ProductionReady:        false,
	}
}

func formalGLMPhase21RockValidateAuthorizationRecord(
	record formalGLMPhase21RockAuthorizationRecord,
	context formalGLMPhase21RockContext,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	base formalGLMPhase21RockBaseCertificateRecord,
	registryResolution *formalGLMArtifactRegistryResolutionV1,
	predecessor *formalGLMPhase21RockAuthorizationRecord,
) error {
	promoted, promoteErr := formalGLMPhase21PromoteDurableV2(
		base.BaseCertificate, context.pins)
	intentSHA, intentErr := formalGLMPhase21DistributedIntentSHA256(promoted)
	ticketSHA, ticketErr := formalFinalizerHandoffTicketSHA256(ticket)
	authority, authorityErr := formalFinalizerHandoffPeer(binding, record.Role)
	stickyMessage, stickyErr := formalGLMPhase21StickyCertificateMessage(promoted)
	publicCertificate, publicErr := formalGLMPhase21RockBuildResolvedPublicCertificate(
		promoted, registryResolution, context.pins)
	publicMessage, publicMessageErr :=
		formalGLMPhase21PublicCertificateV2Message(publicCertificate)
	transportErr := formalFinalizerHandoffValidateIntentAuthorization(
		record.TransportAuthorization, binding, ticketSHA, context.pins)
	if promoteErr != nil || intentErr != nil || ticketErr != nil ||
		authorityErr != nil || stickyErr != nil || publicErr != nil ||
		publicMessageErr != nil || transportErr != nil ||
		record.Version != formalGLMPhase21RockRecordVersion ||
		record.Family != formalFinalizerHandoffFamilyGLM ||
		record.Purpose != formalGLMPhase21RockAuthorizationPurpose ||
		record.ArtifactID != context.artifactID || record.ProductionReady ||
		record.IntentSHA256 != intentSHA ||
		record.TransportAuthorization.SignerRole != record.Role ||
		record.TransportAuthorization.SignerPeerName != authority.PeerName ||
		record.TransportAuthorization.IntentSHA256 != intentSHA ||
		record.StickyAuthorization.Signer != authority.PeerName ||
		len(record.StickyAuthorization.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(context.pins[authority.PeerName], stickyMessage,
			record.StickyAuthorization.Signature) ||
		record.PublicV2Authorization.Signer != authority.PeerName ||
		len(record.PublicV2Authorization.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(context.pins[authority.PeerName], publicMessage,
			record.PublicV2Authorization.Signature) {
		return fmt.Errorf("formal-glm lifecycle: invalid certificate authorization")
	}
	if record.Role == "garbler" {
		if predecessor != nil ||
			record.TransportAuthorization.PredecessorReceiptSHA256 != "" {
			return fmt.Errorf("formal-glm lifecycle: garbler authorization has predecessor")
		}
		return nil
	}
	if record.Role != "evaluator" || predecessor == nil ||
		formalGLMPhase21RockValidateAuthorizationRecord(
			*predecessor, context, binding, ticket, base,
			registryResolution, nil) != nil ||
		predecessor.Role != "garbler" {
		return fmt.Errorf("formal-glm lifecycle: evaluator authorization lacks predecessor")
	}
	predecessorSHA, err := formalFinalizerHandoffIntentSHA256(
		predecessor.TransportAuthorization)
	if err != nil || record.TransportAuthorization.PredecessorReceiptSHA256 !=
		predecessorSHA {
		return fmt.Errorf("formal-glm lifecycle: evaluator predecessor changed")
	}
	return nil
}

func formalGLMPhase21RockPublicCertificateDigest(
	certificate formalGLMPhase21PublicCertificateV2,
) (string, error) {
	encoded, err := json.Marshal(certificate)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMPhase21PublicV2Domain+"/sealed-certificate|"),
		encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPhase21RockPublicationReadyMessage(
	receipt formalGLMPhase21RockPublicationReadyReceipt,
) ([]byte, error) {
	receipt.Signature = nil
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append([]byte(
		formalFinalizerHandoffDomain+"/glm-rock-publication-ready|"),
		encoded...), nil
}

func formalGLMPhase21RockPublicationReadyRecordPath(
	root, artifactID string,
) (string, error) {
	if !formalGLMIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-glm lifecycle: invalid publication-ready slot")
	}
	return filepath.Join(root, "formal-glm-lifecycle-v1", "publication-ready-v1",
		artifactID[:2], artifactID[2:4],
		"publication-ready-"+artifactID+".json"), nil
}

func formalGLMPhase21RockValidatePublicationReadyRecord(
	record formalGLMPhase21RockPublicationReadyRecord,
	context formalGLMPhase21RockContext,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
) error {
	receipt := record.Receipt
	ticketSHA, ticketErr := formalFinalizerHandoffTicketSHA256(ticket)
	internalSHA, internalErr := formalGLMPhase21StickyHash(
		formalGLMPhase21StickyDomain+"/sealed-internal-certificate",
		record.InternalCertificate)
	publicSHA, publicErr := formalGLMPhase21RockPublicCertificateDigest(
		record.PublicCertificate)
	message, messageErr := formalGLMPhase21RockPublicationReadyMessage(receipt)
	if ticketErr != nil || internalErr != nil || publicErr != nil ||
		messageErr != nil ||
		record.Version != formalGLMPhase21RockRecordVersion ||
		record.Family != formalFinalizerHandoffFamilyGLM ||
		record.Purpose != formalGLMPhase21RockPublicationReadyPurpose ||
		record.ArtifactID != context.artifactID || record.ProductionReady ||
		formalGLMPhase21ValidateStickyCertificate(
			record.InternalCertificate, context.pins) != nil ||
		record.InternalCertificate.ArtifactID != context.artifactID ||
		formalGLMPhase21ValidatePublicCertificateV2(
			record.PublicCertificate, context.pins) != nil ||
		record.PublicCertificate.ArtifactID != context.artifactID ||
		record.PublicCertificate.VectorSHA256 !=
			record.InternalCertificate.VectorSHA256 ||
		!reflect.DeepEqual(record.PublicCertificate.ClampedScaledValues,
			record.InternalCertificate.ClampedScaledValues) ||
		receipt.Version != formalGLMPhase21RockRecordVersion ||
		receipt.Purpose != formalGLMPhase21RockPublicationReadyPurpose ||
		receipt.ArtifactID != context.artifactID ||
		receipt.FinalPairRootSHA256 != binding.FinalPairRootSHA256 ||
		receipt.PlanSHA256 != binding.PlanSHA256 ||
		receipt.PinsetSHA256 != binding.PinsetSHA256 ||
		receipt.TicketSHA256 != ticketSHA ||
		receipt.InternalCertificateSHA256 != internalSHA ||
		receipt.PublicCertificateSHA256 != publicSHA ||
		receipt.FinalizerPeerName != binding.Finalizer.PeerName ||
		receipt.FinalizerPeerID != binding.Finalizer.PeerID ||
		receipt.FinalizerRole != binding.Finalizer.Role ||
		receipt.ProductionReady ||
		len(receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(context.pins[binding.Finalizer.PeerName],
			message, receipt.Signature) {
		return fmt.Errorf("formal-glm lifecycle: invalid publication-ready record")
	}
	return nil
}

func formalGLMPhase21RockBuildPublicationReadyRecord(
	context formalGLMPhase21RockContext,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	internal formalGLMPhase21StickyCertificate,
	public formalGLMPhase21PublicCertificateV2,
	privateKey ed25519.PrivateKey,
) (formalGLMPhase21RockPublicationReadyRecord, error) {
	var zero formalGLMPhase21RockPublicationReadyRecord
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil {
		return zero, err
	}
	internalSHA, err := formalGLMPhase21StickyHash(
		formalGLMPhase21StickyDomain+"/sealed-internal-certificate", internal)
	if err != nil {
		return zero, err
	}
	publicSHA, err := formalGLMPhase21RockPublicCertificateDigest(public)
	if err != nil {
		return zero, err
	}
	receipt := formalGLMPhase21RockPublicationReadyReceipt{
		Version:             formalGLMPhase21RockRecordVersion,
		Purpose:             formalGLMPhase21RockPublicationReadyPurpose,
		ArtifactID:          context.artifactID,
		FinalPairRootSHA256: binding.FinalPairRootSHA256,
		PlanSHA256:          binding.PlanSHA256, PinsetSHA256: binding.PinsetSHA256,
		TicketSHA256:              ticketSHA,
		InternalCertificateSHA256: internalSHA,
		PublicCertificateSHA256:   publicSHA,
		FinalizerPeerName:         binding.Finalizer.PeerName,
		FinalizerPeerID:           binding.Finalizer.PeerID,
		FinalizerRole:             binding.Finalizer.Role, ProductionReady: false,
	}
	message, err := formalGLMPhase21RockPublicationReadyMessage(receipt)
	if err != nil {
		return zero, err
	}
	receipt.Signature = ed25519.Sign(privateKey, message)
	record := formalGLMPhase21RockPublicationReadyRecord{
		Version:             formalGLMPhase21RockRecordVersion,
		Family:              formalFinalizerHandoffFamilyGLM,
		Purpose:             formalGLMPhase21RockPublicationReadyPurpose,
		ArtifactID:          context.artifactID,
		InternalCertificate: internal, PublicCertificate: public,
		Receipt: receipt, ProductionReady: false,
	}
	if err := formalGLMPhase21RockValidatePublicationReadyRecord(
		record, context, binding, ticket); err != nil {
		return zero, err
	}
	return record, nil
}

type formalGLMPhase21RockPublicPublicationGuard struct {
	store *formalGLMPhase21StickyReleaseStore
}

func formalGLMPhase21RockVerifyPublicRecordWithoutKey(root, peer string,
	publication formalGLMPhase21PublicCertificateV2,
) error {
	if !formalFinalizerHandoffPathSafePeerName(peer) {
		return fmt.Errorf("formal-glm lifecycle: invalid public publication peer")
	}
	if !formalGLMIsSHA256(publication.ArtifactID) {
		return fmt.Errorf("formal-glm lifecycle: invalid public publication slot")
	}
	path := filepath.Join(root, "formal-glm-sticky-v2", "public-v2",
		publication.ArtifactID[:2], publication.ArtifactID[2:4],
		"release-"+publication.ArtifactID+".json")
	encoded, err := formalGLMPhase21RockRead(
		root, path, formalGLMPhase21StickyMaxBytes)
	if err != nil {
		return fmt.Errorf("formal-glm lifecycle: public publication disappeared")
	}
	defer clear(encoded)
	var record formalGLMPhase21PublicV2Record
	if err := formalGLMPhase21RockStrictDecode(encoded, &record); err != nil {
		return fmt.Errorf("formal-glm lifecycle: public publication is corrupt")
	}
	canonicalRecord, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonicalRecord, encoded) {
		return fmt.Errorf("formal-glm lifecycle: public publication is non-canonical")
	}
	certificateJSON, err := json.Marshal(publication)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMPhase21PublicV2Domain+"/sealed-certificate|"),
		certificateJSON...))
	if record.Version != formalGLMPhase21PublicV2RecordVersion ||
		record.Purpose != formalGLMPhase21PublicV2Purpose ||
		record.Peer != peer || record.ArtifactID != publication.ArtifactID ||
		record.CertificateSHA256 != hex.EncodeToString(digest[:]) ||
		record.CertificateJSON != string(certificateJSON) ||
		!formalGLMIsSHA256(record.RecordMAC) {
		return fmt.Errorf("formal-glm lifecycle: public publication differs")
	}
	return nil
}

func (guard formalGLMPhase21RockPublicPublicationGuard) formalFinalizerHandoffVerifyPublication(
	artifactID, certificateSHA256 string,
) error {
	if guard.store == nil {
		return fmt.Errorf("formal-glm lifecycle: missing public publication store")
	}
	publication, err := guard.store.ReplayPublicV2(artifactID)
	if err != nil || publication.CertificateSHA256 != certificateSHA256 {
		return fmt.Errorf("formal-glm lifecycle: exact public publication is absent")
	}
	return nil
}

func formalGLMPhase21RockCommitRecordPath(root, artifactID, role string) (
	string, error,
) {
	if !formalGLMIsSHA256(artifactID) ||
		(role != "garbler" && role != "evaluator") {
		return "", fmt.Errorf("formal-glm lifecycle: invalid commit slot")
	}
	return filepath.Join(root, "formal-glm-lifecycle-v1", "commit-v1",
		artifactID[:2], artifactID[2:4], role+"-"+artifactID+".json"), nil
}

func formalGLMPhase21RockAckRecordPath(root, artifactID string) (string, error) {
	if !formalGLMIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-glm lifecycle: invalid ACK slot")
	}
	return filepath.Join(root, "formal-glm-lifecycle-v1", "ack-v1",
		artifactID[:2], artifactID[2:4], "ack-"+artifactID+".json"), nil
}

func formalGLMPhase21RockCleanupRecordPath(root, artifactID, role string) (
	string, error,
) {
	if !formalGLMIsSHA256(artifactID) ||
		(role != "garbler" && role != "evaluator") {
		return "", fmt.Errorf("formal-glm lifecycle: invalid cleanup slot")
	}
	return filepath.Join(root, "formal-glm-lifecycle-v1", "cleanup-v1",
		artifactID[:2], artifactID[2:4], role+"-"+artifactID+".json"), nil
}

func formalGLMPhase21RockCommitMessage(
	receipt formalGLMPhase21RockCommitReceipt,
) ([]byte, error) {
	receipt.Signature = nil
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append([]byte(
		formalGLMPhase21PublicV2Domain+"/rock-publication-commit|"),
		encoded...), nil
}

func formalGLMPhase21RockValidateCommitRecord(
	record formalGLMPhase21RockCommitRecord,
	context formalGLMPhase21RockContext,
	local formalFinalizerHandoffAuthority,
) error {
	receipt := record.Receipt
	certificateSHA, certificateErr := formalGLMPhase21RockPublicCertificateDigest(
		record.Publication)
	message, messageErr := formalGLMPhase21RockCommitMessage(receipt)
	if certificateErr != nil || messageErr != nil ||
		record.Version != formalGLMPhase21RockRecordVersion ||
		record.Family != formalFinalizerHandoffFamilyGLM ||
		record.Purpose != formalGLMPhase21RockCommitPurpose ||
		record.ProductionReady ||
		formalGLMPhase21ValidatePublicCertificateV2(
			record.Publication, context.pins) != nil ||
		record.Publication.ArtifactID != context.artifactID ||
		receipt.Version != formalGLMPhase21RockRecordVersion ||
		receipt.Purpose != formalGLMPhase21RockCommitPurpose ||
		receipt.ArtifactID != context.artifactID ||
		receipt.CertificateSHA256 != certificateSHA || receipt.ProductionReady ||
		receipt.PeerName != local.PeerName || receipt.PeerID != local.PeerID ||
		receipt.Role != local.Role || len(receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(context.pins[local.PeerName], message, receipt.Signature) {
		return fmt.Errorf("formal-glm lifecycle: invalid local commit record")
	}
	return nil
}

func formalGLMPhase21RockLoadCommitPair(root string, paths [2]string,
	context formalGLMPhase21RockContext,
	certificateSHA string,
) ([2]formalGLMPhase21RockCommitRecord, error) {
	var records [2]formalGLMPhase21RockCommitRecord
	for index := range records {
		authority := context.contract.Artifact.NoiseAuthorities[index]
		local := formalFinalizerHandoffAuthority{
			PeerName: authority.PeerName, PeerID: authority.PeerID,
			Role: authority.Role,
		}
		if err := formalGLMPhase21RockReadJSON(
			root, paths[index], formalGLMPhase21RockMaxRecord,
			&records[index]); err != nil ||
			formalGLMPhase21RockValidateCommitRecord(
				records[index], context, local) != nil ||
			records[index].Receipt.CertificateSHA256 != certificateSHA {
			return records,
				fmt.Errorf("formal-glm lifecycle: invalid ordered commit records")
		}
	}
	return records, nil
}

func formalGLMPhase21RockValidateAckRecord(
	record formalGLMPhase21RockAckRecord,
	context formalGLMPhase21RockContext,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	certificateSHA string,
) error {
	ticketSHA, ticketErr := formalFinalizerHandoffTicketSHA256(ticket)
	if ticketErr != nil || record.Version != formalGLMPhase21RockRecordVersion ||
		record.Family != formalFinalizerHandoffFamilyGLM ||
		record.Purpose != formalGLMPhase21RockAckPurpose ||
		record.ArtifactID != context.artifactID || record.ProductionReady ||
		record.Proof.CertificateSHA256 != certificateSHA ||
		formalFinalizerHandoffValidateCommitProof(
			record.Proof, binding, ticketSHA, context.pins) != nil {
		return fmt.Errorf("formal-glm lifecycle: invalid ACK record")
	}
	return nil
}

func formalGLMPhase21RockCleanupMessage(
	receipt formalGLMPhase21RockCleanupReceipt,
) ([]byte, error) {
	receipt.Signature = nil
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append([]byte(
		formalGLMPhase21PublicV2Domain+"/rock-local-cleanup|"), encoded...), nil
}

func formalGLMPhase21RockValidateCleanupRecord(
	record formalGLMPhase21RockCleanupRecord,
	context formalGLMPhase21RockContext,
	local formalFinalizerHandoffAuthority,
) error {
	receipt := record.Receipt
	certificateSHA, certificateErr := formalGLMPhase21RockPublicCertificateDigest(
		record.Publication)
	message, messageErr := formalGLMPhase21RockCleanupMessage(receipt)
	if certificateErr != nil || messageErr != nil ||
		record.Version != formalGLMPhase21RockRecordVersion ||
		record.Family != formalFinalizerHandoffFamilyGLM ||
		record.Purpose != formalGLMPhase21RockCleanupPurpose ||
		record.ProductionReady ||
		formalGLMPhase21ValidatePublicCertificateV2(
			record.Publication, context.pins) != nil ||
		record.Publication.ArtifactID != context.artifactID ||
		receipt.Version != formalGLMPhase21RockRecordVersion ||
		receipt.Purpose != formalGLMPhase21RockCleanupPurpose ||
		receipt.ArtifactID != context.artifactID ||
		receipt.CertificateSHA256 != certificateSHA ||
		receipt.PeerName != local.PeerName || receipt.PeerID != local.PeerID ||
		receipt.Role != local.Role || !receipt.SourceCleaned ||
		!receipt.LocalSpoolCleaned || !receipt.TransportCleaned ||
		receipt.ProductionReady || len(receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(context.pins[local.PeerName], message, receipt.Signature) {
		return fmt.Errorf("formal-glm lifecycle: invalid cleanup record")
	}
	return nil
}

func formalGLMPhase21RockCleanupSourceAfterPublicAck(
	store *formalGLMPhase20HandoffStore,
	publication formalGLMPhase21PublicCertificateV2,
	capsule formalGLMPhase16CapsuleBinding,
	request formalGLMPhase16ProductiveRequest,
	backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature,
	registryResolution *formalGLMArtifactRegistryResolutionV1,
) (int64, error) {
	if store == nil || formalGLMPhase21ValidatePublicCertificateV2(
		publication, store.pins) != nil {
		return 0, fmt.Errorf("formal-glm lifecycle: invalid source cleanup")
	}
	if _, err := os.Lstat(store.recordPath); os.IsNotExist(err) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	runtime, commit, err := formalGLMPhase21LoadAndAdmit(
		store, capsule, request, backendSignatures, workerSignatures)
	if err != nil {
		return 0, err
	}
	defer runtime.clear()
	artifact, artifactID, err := formalGLMPhase21BuildCanonicalArtifact(
		runtime.Admission.Productive.Compiled.Binding,
		runtime.Source.Plan, store.pins)
	if err == nil && registryResolution != nil {
		artifact, artifactID, err = formalGLMPhase21ProjectRegisteredArtifactV1(
			artifact, publication.Artifact, *registryResolution, store.pins)
	} else if err == nil && publication.Artifact.DescriptorCoreSHA256 != "" {
		return 0, fmt.Errorf(
			"formal-glm lifecycle: registered cleanup lacks registry resolution")
	}
	if err != nil || artifactID != publication.ArtifactID ||
		!reflect.DeepEqual(artifact, publication.Artifact) {
		return 0, fmt.Errorf("formal-glm lifecycle: publication targets another source")
	}
	return store.Consume(commit.SHA256)
}

func formalGLMPhase21RockBuildStageRecord(
	context formalGLMPhase21RockContext,
	binding formalFinalizerHandoffBinding,
	local formalFinalizerHandoffAuthority,
	sourceReceipt jointDPBiomedicalGaussianOneDrawChunkReceipt,
	privateKey ed25519.PrivateKey,
) (formalGLMPhase21RockStageRecord, error) {
	var zero formalGLMPhase21RockStageRecord
	contractSHA256, err := formalGLMPhase21SamplerV2ContractSHA256(
		context.contract)
	if err != nil {
		return zero, err
	}
	receiptSHA256, err := formalGLMPhase21LocalSpoolReceiptSHA256(sourceReceipt)
	if err != nil {
		return zero, err
	}
	receipt := formalGLMPhase21RockStageReceipt{
		Version:    formalGLMPhase21RockRecordVersion,
		Purpose:    formalGLMPhase21RockStagePurpose,
		ArtifactID: context.artifactID, ContractSHA256: contractSHA256,
		PeerName: local.PeerName, PeerID: local.PeerID, Role: local.Role,
		FinalPairRootSHA256: binding.FinalPairRootSHA256,
		PlanSHA256:          binding.PlanSHA256,
		SourceReceiptSHA256: receiptSHA256, SourceReceipt: sourceReceipt,
		ProductionReady: false,
	}
	message, err := formalGLMPhase21RockStageMessage(receipt)
	if err != nil {
		return zero, err
	}
	receipt.Signature = ed25519.Sign(privateKey, message)
	record := formalGLMPhase21RockStageRecord{
		Version:    formalGLMPhase21RockRecordVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Purpose:    formalGLMPhase21RockStagePurpose,
		ArtifactID: context.artifactID, Binding: binding, Receipt: receipt,
		ProductionReady: false,
	}
	if err := formalGLMPhase21RockValidateStageRecord(
		record, context.contract, context.pins); err != nil {
		return zero, err
	}
	return record, nil
}

func formalGLMPhase21RockLocalSpoolPath(root, artifactID, role string) (
	string, error,
) {
	if !formalGLMIsSHA256(artifactID) ||
		(role != "garbler" && role != "evaluator") {
		return "", fmt.Errorf("formal-glm lifecycle: invalid local spool slot")
	}
	return filepath.Join(root, "formal-glm-local-v1", artifactID[:2],
		artifactID[2:4], "one-draw-"+role+"-"+artifactID+".bin"), nil
}

func formalGLMPhase21RockRecoverStageFromLocalSpool(
	root string, guard *formalFinalizerHandoffAuthorityGuard,
	context formalGLMPhase21RockContext,
	local formalFinalizerHandoffAuthority,
	transportRoot [32]byte, privateKey ed25519.PrivateKey,
) (formalGLMPhase21RockStageRecord, *formalFinalizerHandoffStore,
	bool, error,
) {
	var zero formalGLMPhase21RockStageRecord
	spoolPath, err := formalGLMPhase21RockLocalSpoolPath(
		root, context.artifactID, local.Role)
	if err != nil {
		return zero, nil, false, err
	}
	var header formalGLMPhase21LocalSpoolRecord
	found, err := formalGLMPhase21RockTryReadJSON(
		root, spoolPath, formalGLMPhase21LocalSpoolMaxBytes, &header)
	if err != nil || !found {
		return zero, nil, found, err
	}
	contractSHA256, err := formalGLMPhase21SamplerV2ContractSHA256(
		context.contract)
	if err != nil || header.Version != formalGLMPhase21LocalSpoolVersion ||
		header.Purpose != formalGLMPhase21LocalSpoolPurpose ||
		header.ArtifactID != context.artifactID ||
		header.PinsetSHA256 != context.contract.PinsetSHA256 ||
		header.SamplerContractSHA256 != contractSHA256 ||
		header.PeerName != local.PeerName || header.PeerID != local.PeerID ||
		header.Role != local.Role || header.ProductionReady ||
		!formalGLMIsSHA256(header.FinalPairRootSHA256) ||
		!formalGLMIsSHA256(header.PlanSHA256) {
		return zero, nil, true,
			fmt.Errorf("formal-glm lifecycle: invalid recoverable local spool")
	}
	authorities := make([]formalFinalizerHandoffAuthority, 2)
	for index, authority := range context.contract.Artifact.NoiseAuthorities {
		authorities[index] = formalFinalizerHandoffAuthority{
			PeerName: authority.PeerName, PeerID: authority.PeerID,
			Role: authority.Role,
		}
	}
	binding := formalFinalizerHandoffBinding{
		Family:              formalFinalizerHandoffFamilyGLM,
		Purpose:             formalFinalizerHandoffGLMPurpose,
		ArtifactID:          context.artifactID,
		FinalPairRootSHA256: header.FinalPairRootSHA256,
		PlanSHA256:          header.PlanSHA256,
		PinsetSHA256:        context.contract.PinsetSHA256,
		Authorities:         authorities, Finalizer: authorities[0],
	}
	store, err := openFormalFinalizerHandoffAuthorityStoreWithGuard(
		guard, binding, transportRoot, context.pins)
	if err != nil {
		return zero, nil, true, err
	}
	encoded, err := formalGLMPhase21RockRead(
		root, spoolPath, formalGLMPhase21LocalSpoolMaxBytes)
	if err != nil {
		store.Close()
		return zero, nil, true, err
	}
	payload, err := formalGLMPhase21DecodeLocalSpool(
		store, context.contract, encoded)
	clear(encoded)
	if err != nil {
		store.Close()
		return zero, nil, true, err
	}
	defer formalGLMPhase21ClearLocalSpoolPayload(&payload)
	record, err := formalGLMPhase21RockBuildStageRecord(
		context, binding, local, payload.OneDraw.Receipt, privateKey)
	if err != nil {
		store.Close()
		return zero, nil, true, err
	}
	return record, store, true, nil
}

func formalGLMPhase21RockDecodeStageSecrets(
	secret formalGLMPhase21RockStageSecret,
) ([32]byte, [32]byte, [32]byte, [32]byte, [32]byte,
	ed25519.PrivateKey, error,
) {
	var zero [32]byte
	if secret.Version != formalGLMPhase21RockSecretVersion ||
		secret.Family != formalFinalizerHandoffFamilyGLM ||
		secret.Purpose != formalGLMPhase21RockPurpose ||
		secret.Action != formalGLMPhase21RockActionStage {
		return zero, zero, zero, zero, zero, nil,
			fmt.Errorf("formal-glm lifecycle: invalid stage secret")
	}
	sticky, err := formalGLMPhase21RockDecodeRoot(secret.StickyStorageRoot)
	if err != nil {
		return zero, zero, zero, zero, zero, nil, err
	}
	phase20, err := formalGLMPhase21RockDecodeRoot(secret.Phase20StorageRoot)
	if err != nil {
		clear(sticky[:])
		return zero, zero, zero, zero, zero, nil, err
	}
	backend, err := formalGLMPhase21RockDecodeRoot(secret.BackendKey)
	if err != nil {
		clear(sticky[:])
		clear(phase20[:])
		return zero, zero, zero, zero, zero, nil, err
	}
	authorityRoot, err := formalGLMPhase21RockDecodeRoot(secret.AuthorityRoot)
	if err != nil {
		clear(sticky[:])
		clear(phase20[:])
		clear(backend[:])
		return zero, zero, zero, zero, zero, nil, err
	}
	transport, err := formalGLMPhase21RockDecodeRoot(
		secret.TransportStorageRoot)
	if err != nil {
		clear(sticky[:])
		clear(phase20[:])
		clear(backend[:])
		clear(authorityRoot[:])
		return zero, zero, zero, zero, zero, nil, err
	}
	privateKey, err := formalGLMPhase21RockDecodePrivateKey(
		secret.SigningPrivateKey)
	if err != nil {
		clear(sticky[:])
		clear(phase20[:])
		clear(backend[:])
		clear(authorityRoot[:])
		clear(transport[:])
		return zero, zero, zero, zero, zero, nil, err
	}
	return sticky, phase20, backend, authorityRoot, transport, privateKey, nil
}

func formalGLMPhase21RockRunStage(root string, production bool,
	operation formalGLMPhase21RockStageOperation,
	hook formalGLMPhase21RockPhaseHook,
) (formalGLMPhase21RockLifecycleResponse, error) {
	context, err := formalGLMPhase21RockLoadContext(
		root, operation.ArtifactContractPath, operation.PinsetPath)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	registryResolution, err := formalGLMPhase21RockLoadRegistryResolution(
		root, operation.RegistryResolutionPath, context)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	local, err := formalGLMPhase21RockAuthority(
		context.contract.Artifact, operation.PeerName)
	if err != nil || formalTypedFinalizerLifecycleRequireLocalAuthority(
		root, filepath.Dir(root), operation.PeerName) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: local authority mismatch")
	}
	guard, err := newFormalFinalizerHandoffAuthorityGuard(
		root, context.artifactID, local, production)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer guard.Close()
	_, preflightState, preflightPublication, err :=
		formalGLMPhase21RockLoadPreflightPair(
			root, operation.PreflightRecordPaths, context)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if preflightState != formalGLMPhase21RockStateAbsent {
		response := formalGLMPhase21RockLifecycleResponse{
			Version: formalTypedFinalizerLifecycleVersion,
			Family:  formalFinalizerHandoffFamilyGLM,
			Action:  formalGLMPhase21RockActionStage,
			State:   preflightState, ArtifactID: context.artifactID,
			Publication: preflightPublication, Replayed: true,
		}
		if preflightPublication != nil {
			encoded, _ := json.Marshal(preflightPublication)
			digest := sha256.Sum256(append(
				[]byte(formalGLMPhase21PublicV2Domain+"/sealed-certificate|"),
				encoded...))
			response.CertificateSHA256 = hex.EncodeToString(digest[:])
		}
		return response, nil
	}
	if operation.SpoolDir != filepath.Join(root, "formal-glm-exact-gc-v2",
		context.artifactID) || operation.MaxSpoolBytes < 1<<20 ||
		operation.MaxSpoolBytes > 64<<30 || operation.TTLSeconds < 10 ||
		operation.TTLSeconds > 86400 ||
		!formalGLMIsSHA256(operation.Phase20SemanticRootSHA256) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid stage policy")
	}
	stagePath, err := formalGLMPhase21RockStageRecordPath(
		root, context.artifactID, local.Role)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	var existing formalGLMPhase21RockStageRecord
	found, err := formalGLMPhase21RockTryReadJSON(
		root, stagePath, formalGLMPhase21RockMaxRecord, &existing)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if found {
		if formalGLMPhase21RockValidateStageRecord(
			existing, context.contract, context.pins) != nil ||
			existing.Receipt.PeerName != local.PeerName ||
			existing.Receipt.Role != local.Role {
			return formalGLMPhase21RockLifecycleResponse{},
				fmt.Errorf("formal-glm lifecycle: conflicting stage replay")
		}
		if err := formalGLMPhase21RockRemoveSecret(
			root, operation.SecretBundlePath); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		encoded, _ := json.Marshal(existing)
		digest := sha256.Sum256(encoded)
		return formalGLMPhase21RockLifecycleResponse{
			Version:      formalTypedFinalizerLifecycleVersion,
			Family:       formalFinalizerHandoffFamilyGLM,
			Action:       formalGLMPhase21RockActionStage,
			State:        formalGLMPhase21RockStateStaged,
			ArtifactID:   context.artifactID,
			RecordSHA256: hex.EncodeToString(digest[:]),
			Stage:        &existing, Replayed: true,
		}, nil
	}
	var secret formalGLMPhase21RockStageSecret
	if err := formalGLMPhase21RockReadJSON(
		root, operation.SecretBundlePath,
		formalGLMPhase21RockMaxSecret, &secret); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	stickyRoot, phase20Root, backendKey, authorityRoot, transportRoot,
		privateKey, err := formalGLMPhase21RockDecodeStageSecrets(secret)
	secret.StickyStorageRoot, secret.Phase20StorageRoot = "", ""
	secret.BackendKey, secret.AuthorityRoot = "", ""
	secret.TransportStorageRoot, secret.SigningPrivateKey = "", ""
	defer clear(stickyRoot[:])
	defer clear(phase20Root[:])
	defer clear(backendKey[:])
	defer clear(authorityRoot[:])
	defer clear(transportRoot[:])
	defer clear(privateKey)
	if err != nil || !hmac.Equal(
		privateKey.Public().(ed25519.PublicKey), context.pins[local.PeerName]) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid stage signer")
	}
	sticky, err := newFormalGLMPhase21StickyReleaseStore(
		filepath.Join(root, "formal-glm-sticky-v2"), local.PeerName,
		stickyRoot, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if publication, replayErr := sticky.ReplayPublicV2(
		context.artifactID); replayErr == nil {
		sticky.close()
		certificate, decodeErr := formalGLMPhase21DecodePublicV2Publication(
			publication, context.pins)
		if decodeErr != nil {
			return formalGLMPhase21RockLifecycleResponse{}, decodeErr
		}
		if err := formalGLMPhase21RockValidateResolvedPublication(
			certificate, registryResolution, context.pins); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		if err := formalGLMPhase21RockRemoveSecret(
			root, operation.SecretBundlePath); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		return formalGLMPhase21RockLifecycleResponse{
			Version:           formalTypedFinalizerLifecycleVersion,
			Family:            formalFinalizerHandoffFamilyGLM,
			Action:            formalGLMPhase21RockActionStage,
			State:             formalGLMPhase21RockStatePublished,
			ArtifactID:        context.artifactID,
			CertificateSHA256: publication.CertificateSHA256,
			Publication:       &certificate, Replayed: true,
		}, nil
	} else if !os.IsNotExist(replayErr) {
		sticky.close()
		return formalGLMPhase21RockLifecycleResponse{}, replayErr
	}
	sticky.close()
	recovered, recoveredStore, recoveredFound, err :=
		formalGLMPhase21RockRecoverStageFromLocalSpool(
			root, guard, context, local, transportRoot, privateKey)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if recoveredFound {
		defer recoveredStore.Close()
		digest, _, err := formalGLMPhase21RockWriteJSON(
			root, stagePath, recovered)
		if err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		if hook != nil {
			if err := hook(
				"after_recovered_stage_record_before_secret_cleanup"); err != nil {
				return formalGLMPhase21RockLifecycleResponse{}, err
			}
		}
		if err := formalGLMPhase21RockRemoveSecret(
			root, operation.SecretBundlePath); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		return formalGLMPhase21RockLifecycleResponse{
			Version:    formalTypedFinalizerLifecycleVersion,
			Family:     formalFinalizerHandoffFamilyGLM,
			Action:     formalGLMPhase21RockActionStage,
			State:      formalGLMPhase21RockStateStaged,
			ArtifactID: context.artifactID, RecordSHA256: digest,
			Stage: &recovered, Replayed: true, ProductionReady: false,
		}, nil
	}
	var capsule formalGLMPhase16CapsuleBinding
	var request formalGLMPhase16ProductiveRequest
	var backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature
	var samplerAuthorizations []formalGLMPhase21SamplerV2Authorization
	for path, target := range map[string]any{
		operation.CapsulePath:               &capsule,
		operation.RequestPath:               &request,
		operation.BackendSignaturesPath:     &backendSignatures,
		operation.WorkerSignaturesPath:      &workerSignatures,
		operation.SamplerAuthorizationsPath: &samplerAuthorizations,
	} {
		if err := formalGLMPhase21RockReadJSON(
			root, path, formalGLMPhase21RockMaxRecord, target); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	if formalGLMPhase21ValidateSamplerV2Authorizations(
		context.contract, samplerAuthorizations, context.pins) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid sampler authorizations")
	}
	source, err := newFormalGLMPhase20HandoffStore(
		filepath.Join(root, "formal-glm-phase20-handoff"),
		operation.Phase20SemanticRootSHA256, local.PeerName,
		phase20Root, backendKey, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer source.close()
	if err := exactGCPrepareWorkerSpool(operation.SpoolDir); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	spool, err := newExactGCSpoolRW(operation.SpoolDir,
		operation.MaxSpoolBytes,
		time.Duration(operation.TTLSeconds)*time.Second)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	output, runErr := formalGLMPhase21RunOneDrawLocalV2(
		spool, source, capsule, request, backendSignatures, workerSignatures,
		authorityRoot, privateKey, context.contract, samplerAuthorizations,
		registryResolution)
	closeErr := spool.Close()
	if runErr != nil {
		return formalGLMPhase21RockLifecycleResponse{}, runErr
	}
	if closeErr != nil {
		output.clear()
		return formalGLMPhase21RockLifecycleResponse{}, closeErr
	}
	defer output.clear()
	if hook != nil {
		if err := hook("after_sampler_before_local_spool"); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	var binding formalFinalizerHandoffBinding
	if registryResolution == nil {
		binding, err = formalGLMPhase21OneDrawFinalizerBinding(source, output)
	} else {
		binding, err = formalGLMPhase21RegisteredOneDrawFinalizerBinding(
			source, output, context.contract, *registryResolution)
	}
	if err != nil || binding.ArtifactID != context.artifactID ||
		!formalFinalizerHandoffBindingHasAuthority(binding, local) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: stage binding mismatch")
	}
	transport, err := openFormalFinalizerHandoffAuthorityStoreWithGuard(
		guard, binding, transportRoot, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer transport.Close()
	spoolReplayed, err := formalGLMPhase21PersistLocalOneDrawSpoolWithResolution(
		source, transport, context.contract, output, registryResolution)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_local_spool_before_stage_record"); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	record, err := formalGLMPhase21RockBuildStageRecord(
		context, binding, local, output.Receipt, privateKey)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	digest, recordReplayed, err := formalGLMPhase21RockWriteJSON(
		root, stagePath, record)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_stage_record_before_secret_cleanup"); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	if err := formalGLMPhase21RockRemoveSecret(
		root, operation.SecretBundlePath); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	return formalGLMPhase21RockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Action:     formalGLMPhase21RockActionStage,
		State:      formalGLMPhase21RockStateStaged,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		Stage: &record, Replayed: spoolReplayed && recordReplayed,
		ProductionReady: false,
	}, nil
}

func formalGLMPhase21RockRunTicket(root string, production bool,
	operation formalGLMPhase21RockTicketOperation,
	hook formalGLMPhase21RockPhaseHook,
) (formalGLMPhase21RockLifecycleResponse, error) {
	context, err := formalGLMPhase21RockLoadContext(
		root, operation.ArtifactContractPath, operation.PinsetPath)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	local, err := formalGLMPhase21RockAuthority(
		context.contract.Artifact, operation.PeerName)
	if err != nil || formalTypedFinalizerLifecycleRequireLocalAuthority(
		root, filepath.Dir(root), operation.PeerName) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: local authority mismatch")
	}
	guard, err := newFormalFinalizerHandoffAuthorityGuard(
		root, context.artifactID, local, production)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer guard.Close()
	_, preflightState, publication, err :=
		formalGLMPhase21RockLoadPreflightPair(
			root, operation.PreflightRecordPaths, context)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if preflightState != formalGLMPhase21RockStateAbsent {
		return formalGLMPhase21RockLifecycleResponse{
			Version: formalTypedFinalizerLifecycleVersion,
			Family:  formalFinalizerHandoffFamilyGLM,
			Action:  formalGLMPhase21RockActionTicket,
			State:   preflightState, ArtifactID: context.artifactID,
			Publication: publication, Replayed: true,
		}, nil
	}
	_, binding, err := formalGLMPhase21RockLoadStagePair(
		root, operation.StageRecordPaths, context)
	if err != nil || !formalFinalizerHandoffAuthorityEqual(
		local, binding.Finalizer) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: ticket requires fixed finalizer")
	}
	recordPath, err := formalGLMPhase21RockTicketRecordPath(
		root, context.artifactID)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	var existing formalGLMPhase21RockTicketRecord
	if found, readErr := formalGLMPhase21RockTryReadJSON(
		root, recordPath, formalGLMPhase21RockMaxRecord, &existing); readErr != nil {
		return formalGLMPhase21RockLifecycleResponse{}, readErr
	} else if found {
		if formalGLMPhase21RockValidateTicketRecord(existing, context) != nil ||
			!reflect.DeepEqual(existing.Binding, binding) {
			return formalGLMPhase21RockLifecycleResponse{},
				fmt.Errorf("formal-glm lifecycle: conflicting ticket replay")
		}
		if err := formalGLMPhase21RockRemoveSecret(
			root, operation.SecretBundlePath); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		encoded, _ := json.Marshal(existing)
		digest := sha256.Sum256(encoded)
		return formalGLMPhase21RockLifecycleResponse{
			Version:      formalTypedFinalizerLifecycleVersion,
			Family:       formalFinalizerHandoffFamilyGLM,
			Action:       formalGLMPhase21RockActionTicket,
			State:        formalGLMPhase21RockStateTicketReady,
			ArtifactID:   context.artifactID,
			RecordSHA256: hex.EncodeToString(digest[:]),
			Ticket:       &existing, Replayed: true,
		}, nil
	}
	var secret formalGLMPhase21RockTicketSecret
	if err := formalGLMPhase21RockReadJSON(
		root, operation.SecretBundlePath,
		formalGLMPhase21RockMaxSecret, &secret); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if secret.Version != formalGLMPhase21RockSecretVersion ||
		secret.Family != formalFinalizerHandoffFamilyGLM ||
		secret.Purpose != formalGLMPhase21RockPurpose ||
		secret.Action != formalGLMPhase21RockActionTicket {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid ticket secret")
	}
	transportRoot, err := formalGLMPhase21RockDecodeRoot(
		secret.TransportStorageRoot)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	privateKey, err := formalGLMPhase21RockDecodePrivateKey(
		secret.SigningPrivateKey)
	secret.TransportStorageRoot, secret.SigningPrivateKey = "", ""
	defer clear(transportRoot[:])
	defer clear(privateKey)
	if err != nil || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		context.pins[local.PeerName]) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid ticket signer")
	}
	store, err := openFormalFinalizerHandoffAuthorityStoreWithGuard(
		guard, binding, transportRoot, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer store.Close()
	ticket, secretKey, ticketReplayed, err := store.IssueTicketOnce(privateKey)
	clear(secretKey)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	record := formalGLMPhase21RockTicketRecord{
		Version:    formalGLMPhase21RockRecordVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Purpose:    formalGLMPhase21RockTicketPurpose,
		ArtifactID: context.artifactID,
		Binding:    binding, Ticket: ticket, ProductionReady: false,
	}
	if err := formalGLMPhase21RockValidateTicketRecord(
		record, context); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_ticket_before_record"); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	digest, recordReplayed, err := formalGLMPhase21RockWriteJSON(
		root, recordPath, record)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_ticket_record_before_secret_cleanup"); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	if err := formalGLMPhase21RockRemoveSecret(
		root, operation.SecretBundlePath); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	return formalGLMPhase21RockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Action:     formalGLMPhase21RockActionTicket,
		State:      formalGLMPhase21RockStateTicketReady,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		Ticket: &record, Replayed: ticketReplayed && recordReplayed,
		ProductionReady: false,
	}, nil
}

func formalGLMPhase21RockRunSeal(root string, production bool,
	operation formalGLMPhase21RockSealOperation,
	hook formalGLMPhase21RockPhaseHook,
) (formalGLMPhase21RockLifecycleResponse, error) {
	context, err := formalGLMPhase21RockLoadContext(
		root, operation.ArtifactContractPath, operation.PinsetPath)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	registryResolution, err := formalGLMPhase21RockLoadRegistryResolution(
		root, operation.RegistryResolutionPath, context)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	local, err := formalGLMPhase21RockAuthority(
		context.contract.Artifact, operation.PeerName)
	if err != nil || formalTypedFinalizerLifecycleRequireLocalAuthority(
		root, filepath.Dir(root), operation.PeerName) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: local authority mismatch")
	}
	guard, err := newFormalFinalizerHandoffAuthorityGuard(
		root, context.artifactID, local, production)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer guard.Close()
	_, preflightState, publication, err :=
		formalGLMPhase21RockLoadPreflightPair(
			root, operation.PreflightRecordPaths, context)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if preflightState != formalGLMPhase21RockStateAbsent {
		return formalGLMPhase21RockLifecycleResponse{
			Version: formalTypedFinalizerLifecycleVersion,
			Family:  formalFinalizerHandoffFamilyGLM,
			Action:  formalGLMPhase21RockActionSeal,
			State:   preflightState, ArtifactID: context.artifactID,
			Publication: publication, Replayed: true,
		}, nil
	}
	_, binding, err := formalGLMPhase21RockLoadStagePair(
		root, operation.StageRecordPaths, context)
	if err != nil || !formalFinalizerHandoffBindingHasAuthority(
		binding, local) ||
		!formalGLMIsSHA256(operation.Phase20SemanticRootSHA256) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid seal binding")
	}
	var ticketRecord formalGLMPhase21RockTicketRecord
	if err := formalGLMPhase21RockReadJSON(
		root, operation.TicketRecordPath,
		formalGLMPhase21RockMaxRecord, &ticketRecord); err != nil ||
		formalGLMPhase21RockValidateTicketRecord(ticketRecord, context) != nil ||
		!reflect.DeepEqual(ticketRecord.Binding, binding) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid seal ticket")
	}
	recordPath, err := formalGLMPhase21RockSealRecordPath(
		root, context.artifactID, local.Role)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	var existing formalGLMPhase21RockSealRecord
	if found, readErr := formalGLMPhase21RockTryReadJSON(
		root, recordPath, formalGLMPhase21RockMaxRecord, &existing); readErr != nil {
		return formalGLMPhase21RockLifecycleResponse{}, readErr
	} else if found {
		if formalGLMPhase21RockValidateSealRecord(
			existing, context, binding, ticketRecord.Ticket) != nil ||
			existing.Receipt.PeerName != local.PeerName ||
			existing.Receipt.Role != local.Role {
			return formalGLMPhase21RockLifecycleResponse{},
				fmt.Errorf("formal-glm lifecycle: conflicting seal replay")
		}
		if err := formalGLMPhase21RockRemoveSecret(
			root, operation.SecretBundlePath); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		encoded, _ := json.Marshal(existing)
		digest := sha256.Sum256(encoded)
		return formalGLMPhase21RockLifecycleResponse{
			Version:      formalTypedFinalizerLifecycleVersion,
			Family:       formalFinalizerHandoffFamilyGLM,
			Action:       formalGLMPhase21RockActionSeal,
			State:        formalGLMPhase21RockStateSealed,
			ArtifactID:   context.artifactID,
			RecordSHA256: hex.EncodeToString(digest[:]),
			Seal:         &existing, Replayed: true,
		}, nil
	}
	var secret formalGLMPhase21RockSealSecret
	if err := formalGLMPhase21RockReadJSON(
		root, operation.SecretBundlePath,
		formalGLMPhase21RockMaxSecret, &secret); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if secret.Version != formalGLMPhase21RockSecretVersion ||
		secret.Family != formalFinalizerHandoffFamilyGLM ||
		secret.Purpose != formalGLMPhase21RockPurpose ||
		secret.Action != formalGLMPhase21RockActionSeal {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid seal secret")
	}
	phase20Root, err := formalGLMPhase21RockDecodeRoot(
		secret.Phase20StorageRoot)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	backendKey, err := formalGLMPhase21RockDecodeRoot(secret.BackendKey)
	if err != nil {
		clear(phase20Root[:])
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	transportRoot, err := formalGLMPhase21RockDecodeRoot(
		secret.TransportStorageRoot)
	if err != nil {
		clear(phase20Root[:])
		clear(backendKey[:])
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	privateKey, err := formalGLMPhase21RockDecodePrivateKey(
		secret.SigningPrivateKey)
	secret.Phase20StorageRoot, secret.BackendKey = "", ""
	secret.TransportStorageRoot, secret.SigningPrivateKey = "", ""
	defer clear(phase20Root[:])
	defer clear(backendKey[:])
	defer clear(transportRoot[:])
	defer clear(privateKey)
	if err != nil || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		context.pins[local.PeerName]) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid seal signer")
	}
	store, err := openFormalFinalizerHandoffAuthorityStoreWithGuard(
		guard, binding, transportRoot, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer store.Close()
	source, err := newFormalGLMPhase20HandoffStore(
		filepath.Join(root, "formal-glm-phase20-handoff"),
		operation.Phase20SemanticRootSHA256, local.PeerName,
		phase20Root, backendKey, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer source.close()
	var capsule formalGLMPhase16CapsuleBinding
	var request formalGLMPhase16ProductiveRequest
	var backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature
	for path, target := range map[string]any{
		operation.CapsulePath:           &capsule,
		operation.RequestPath:           &request,
		operation.BackendSignaturesPath: &backendSignatures,
		operation.WorkerSignaturesPath:  &workerSignatures,
	} {
		if err := formalGLMPhase21RockReadJSON(
			root, path, formalGLMPhase21RockMaxRecord, target); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	output, err := formalGLMPhase21LoadLocalOneDrawSpoolWithResolution(
		source, store, context.contract, ticketRecord.Ticket,
		capsule, request, backendSignatures, workerSignatures,
		registryResolution)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer output.clear()
	envelope, envelopeReplayed, err := formalGLMPhase21SealLocalOneDrawWithResolution(
		source, store, context.contract, ticketRecord.Ticket, output,
		privateKey, nil, registryResolution)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	record, err := formalGLMPhase21RockBuildSealRecord(
		context, binding, ticketRecord.Ticket, envelope, privateKey)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_outbox_before_seal_record"); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	digest, recordReplayed, err := formalGLMPhase21RockWriteJSON(
		root, recordPath, record)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_seal_record_before_secret_cleanup"); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	if err := formalGLMPhase21RockRemoveSecret(
		root, operation.SecretBundlePath); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	return formalGLMPhase21RockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Action:     formalGLMPhase21RockActionSeal,
		State:      formalGLMPhase21RockStateSealed,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		Seal: &record, Replayed: envelopeReplayed && recordReplayed,
		ProductionReady: false,
	}, nil
}

func formalGLMPhase21RockRunPrepareCandidate(root string, production bool,
	operation formalGLMPhase21RockPrepareCandidateOperation,
	hook formalGLMPhase21RockPhaseHook,
) (formalGLMPhase21RockLifecycleResponse, error) {
	context, err := formalGLMPhase21RockLoadContext(
		root, operation.ArtifactContractPath, operation.PinsetPath)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	registryResolution, err := formalGLMPhase21RockLoadRegistryResolution(
		root, operation.RegistryResolutionPath, context)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	local, err := formalGLMPhase21RockAuthority(
		context.contract.Artifact, operation.PeerName)
	if err != nil || formalTypedFinalizerLifecycleRequireLocalAuthority(
		root, filepath.Dir(root), operation.PeerName) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: local authority mismatch")
	}
	guard, err := newFormalFinalizerHandoffAuthorityGuard(
		root, context.artifactID, local, production)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer guard.Close()
	_, preflightState, publication, err :=
		formalGLMPhase21RockLoadPreflightPair(
			root, operation.PreflightRecordPaths, context)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if preflightState != formalGLMPhase21RockStateAbsent {
		return formalGLMPhase21RockLifecycleResponse{
			Version: formalTypedFinalizerLifecycleVersion,
			Family:  formalFinalizerHandoffFamilyGLM,
			Action:  formalGLMPhase21RockActionPrepareCandidate,
			State:   preflightState, ArtifactID: context.artifactID,
			Publication: publication, Replayed: true,
		}, nil
	}
	_, binding, err := formalGLMPhase21RockLoadStagePair(
		root, operation.StageRecordPaths, context)
	if err != nil || !formalFinalizerHandoffAuthorityEqual(
		local, binding.Finalizer) ||
		!formalGLMIsSHA256(operation.Phase20SemanticRootSHA256) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid candidate binding")
	}
	var ticketRecord formalGLMPhase21RockTicketRecord
	if err := formalGLMPhase21RockReadJSON(
		root, operation.TicketRecordPath,
		formalGLMPhase21RockMaxRecord, &ticketRecord); err != nil ||
		formalGLMPhase21RockValidateTicketRecord(ticketRecord, context) != nil ||
		!reflect.DeepEqual(ticketRecord.Binding, binding) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid candidate ticket")
	}
	sealRecords, err := formalGLMPhase21RockLoadSealPair(
		root, operation.SealRecordPaths, context, binding, ticketRecord.Ticket)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	recordPath, err := formalGLMPhase21RockCandidateRecordPath(
		root, context.artifactID)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	var existing formalGLMPhase21RockCandidateRecord
	if found, readErr := formalGLMPhase21RockTryReadJSON(
		root, recordPath, formalGLMPhase21RockMaxRecord, &existing); readErr != nil {
		return formalGLMPhase21RockLifecycleResponse{}, readErr
	} else if found {
		if formalGLMPhase21RockValidateCandidateRecord(
			existing, context, binding, ticketRecord.Ticket) != nil {
			return formalGLMPhase21RockLifecycleResponse{},
				fmt.Errorf("formal-glm lifecycle: conflicting candidate replay")
		}
		if err := formalGLMPhase21RockRemoveSecret(
			root, operation.SecretBundlePath); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		encoded, _ := json.Marshal(existing)
		digest := sha256.Sum256(encoded)
		return formalGLMPhase21RockLifecycleResponse{
			Version:      formalTypedFinalizerLifecycleVersion,
			Family:       formalFinalizerHandoffFamilyGLM,
			Action:       formalGLMPhase21RockActionPrepareCandidate,
			State:        formalGLMPhase21RockStateCandidateReady,
			ArtifactID:   context.artifactID,
			RecordSHA256: hex.EncodeToString(digest[:]),
			Candidate:    &existing, Replayed: true,
		}, nil
	}
	var secret formalGLMPhase21RockCandidateSecret
	if err := formalGLMPhase21RockReadJSON(
		root, operation.SecretBundlePath,
		formalGLMPhase21RockMaxSecret, &secret); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if secret.Version != formalGLMPhase21RockSecretVersion ||
		secret.Family != formalFinalizerHandoffFamilyGLM ||
		secret.Purpose != formalGLMPhase21RockPurpose ||
		secret.Action != formalGLMPhase21RockActionPrepareCandidate {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid candidate secret")
	}
	phase20Root, err := formalGLMPhase21RockDecodeRoot(
		secret.Phase20StorageRoot)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	backendKey, err := formalGLMPhase21RockDecodeRoot(secret.BackendKey)
	if err != nil {
		clear(phase20Root[:])
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	transportRoot, err := formalGLMPhase21RockDecodeRoot(
		secret.TransportStorageRoot)
	if err != nil {
		clear(phase20Root[:])
		clear(backendKey[:])
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	privateKey, err := formalGLMPhase21RockDecodePrivateKey(
		secret.SigningPrivateKey)
	secret.Phase20StorageRoot, secret.BackendKey = "", ""
	secret.TransportStorageRoot, secret.SigningPrivateKey = "", ""
	defer clear(phase20Root[:])
	defer clear(backendKey[:])
	defer clear(transportRoot[:])
	defer clear(privateKey)
	if err != nil || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		context.pins[local.PeerName]) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid candidate signer")
	}
	store, err := openFormalFinalizerHandoffAuthorityStoreWithGuard(
		guard, binding, transportRoot, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer store.Close()
	source, err := newFormalGLMPhase20HandoffStore(
		filepath.Join(root, "formal-glm-phase20-handoff"),
		operation.Phase20SemanticRootSHA256, local.PeerName,
		phase20Root, backendKey, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer source.close()
	var capsule formalGLMPhase16CapsuleBinding
	var request formalGLMPhase16ProductiveRequest
	var backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature
	for path, target := range map[string]any{
		operation.CapsulePath:           &capsule,
		operation.RequestPath:           &request,
		operation.BackendSignaturesPath: &backendSignatures,
		operation.WorkerSignaturesPath:  &workerSignatures,
	} {
		if err := formalGLMPhase21RockReadJSON(
			root, path, formalGLMPhase21RockMaxRecord, target); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	var imported [2]formalGLMPhase21OneDrawLocalOutput
	defer imported[0].clear()
	defer imported[1].clear()
	for index, role := range []string{"garbler", "evaluator"} {
		envelope, loadErr := store.loadEnvelope("ingress-v1", role)
		if loadErr != nil {
			return formalGLMPhase21RockLifecycleResponse{},
				fmt.Errorf("formal-glm lifecycle: incomplete candidate ingress")
		}
		envelopeJSON, marshalErr := json.Marshal(envelope)
		envelopeDigest := sha256.Sum256(envelopeJSON)
		clear(envelopeJSON)
		if marshalErr != nil || hex.EncodeToString(envelopeDigest[:]) !=
			sealRecords[index].Receipt.EnvelopeSHA256 {
			return formalGLMPhase21RockLifecycleResponse{},
				fmt.Errorf("formal-glm lifecycle: ingress differs from seal receipt")
		}
		payload, openErr := formalGLMPhase21OpenDurableOneDrawTransit(
			store, ticketRecord.Ticket, role)
		if openErr != nil {
			return formalGLMPhase21RockLifecycleResponse{}, openErr
		}
		imported[index], err = formalGLMPhase21ImportOneDrawTransitWithResolution(
			source, capsule, request, backendSignatures, workerSignatures,
			binding, ticketRecord.Ticket, payload, &context.contract,
			registryResolution)
		formalGLMPhase21ClearOneDrawTransit(&payload)
		if err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		if hook != nil {
			if err := hook("after_candidate_import_" + role); err != nil {
				return formalGLMPhase21RockLifecycleResponse{}, err
			}
		}
	}
	finalizerRelease, err :=
		newJointDPBiomedicalGaussianOneDrawDurableReleaseStore(
			filepath.Join(root, "formal-glm-finalizer-release-v1"),
			local.PeerName, backendKey, privateKey)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer clear(finalizerRelease.key[:])
	defer clear(finalizerRelease.signer)
	localRelease, err := formalGLMPhase21FinalizeOneDrawLocal(
		source, finalizerRelease, imported[0], imported[1], nil)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	authority, err := jointDPBiomedicalGaussianOneDrawAuthorityFromEnvelopes(
		[]jointDPBiomedicalGaussianSignedWorkerEnvelope{
			imported[0].Admission.Envelope,
		}, imported[0].Admission.Trust)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	candidate := jointDPBiomedicalGaussianOneDrawCommonFromLocal(
		authority, localRelease.Receipt)
	if _, err := formalGLMPhase21OneDrawUnsignedCandidateValid(
		imported[0], candidate); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	record, err := formalGLMPhase21RockBuildCandidateRecord(
		context, binding, ticketRecord.Ticket, candidate, privateKey)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_candidate_before_record"); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	digest, recordReplayed, err := formalGLMPhase21RockWriteJSON(
		root, recordPath, record)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if err := formalGLMPhase21RockRemoveSecret(
		root, operation.SecretBundlePath); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	return formalGLMPhase21RockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Action:     formalGLMPhase21RockActionPrepareCandidate,
		State:      formalGLMPhase21RockStateCandidateReady,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		Candidate: &record, Replayed: recordReplayed,
		ProductionReady: false,
	}, nil
}

func formalGLMPhase21RockRunVerifyCandidate(root string, production bool,
	operation formalGLMPhase21RockVerifyCandidateOperation,
	hook formalGLMPhase21RockPhaseHook,
) (formalGLMPhase21RockLifecycleResponse, error) {
	context, err := formalGLMPhase21RockLoadContext(
		root, operation.ArtifactContractPath, operation.PinsetPath)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	registryResolution, err := formalGLMPhase21RockLoadRegistryResolution(
		root, operation.RegistryResolutionPath, context)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	local, err := formalGLMPhase21RockAuthority(
		context.contract.Artifact, operation.PeerName)
	if err != nil || formalTypedFinalizerLifecycleRequireLocalAuthority(
		root, filepath.Dir(root), operation.PeerName) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: local authority mismatch")
	}
	guard, err := newFormalFinalizerHandoffAuthorityGuard(
		root, context.artifactID, local, production)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer guard.Close()
	_, preflightState, publication, err :=
		formalGLMPhase21RockLoadPreflightPair(
			root, operation.PreflightRecordPaths, context)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if preflightState != formalGLMPhase21RockStateAbsent {
		return formalGLMPhase21RockLifecycleResponse{
			Version: formalTypedFinalizerLifecycleVersion,
			Family:  formalFinalizerHandoffFamilyGLM,
			Action:  formalGLMPhase21RockActionVerifyCandidate,
			State:   preflightState, ArtifactID: context.artifactID,
			Publication: publication, Replayed: true,
		}, nil
	}
	stageRecords, binding, err := formalGLMPhase21RockLoadStagePair(
		root, operation.StageRecordPaths, context)
	if err != nil || !formalFinalizerHandoffBindingHasAuthority(
		binding, local) || !formalGLMIsSHA256(
		operation.Phase20SemanticRootSHA256) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid candidate verifier binding")
	}
	var ticketRecord formalGLMPhase21RockTicketRecord
	if err := formalGLMPhase21RockReadJSON(
		root, operation.TicketRecordPath,
		formalGLMPhase21RockMaxRecord, &ticketRecord); err != nil ||
		formalGLMPhase21RockValidateTicketRecord(ticketRecord, context) != nil ||
		!reflect.DeepEqual(ticketRecord.Binding, binding) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid candidate verifier ticket")
	}
	var candidate formalGLMPhase21RockCandidateRecord
	if err := formalGLMPhase21RockReadJSON(
		root, operation.CandidateRecordPath,
		formalGLMPhase21RockMaxRecord, &candidate); err != nil ||
		formalGLMPhase21RockValidateCandidateRecord(
			candidate, context, binding, ticketRecord.Ticket) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid signed candidate")
	}
	recordPath, err := formalGLMPhase21RockLocalReleaseRecordPath(
		root, context.artifactID, local.Role)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	var existing formalGLMPhase21RockLocalReleaseRecord
	if found, readErr := formalGLMPhase21RockTryReadJSON(
		root, recordPath, formalGLMPhase21RockMaxRecord, &existing); readErr != nil {
		return formalGLMPhase21RockLifecycleResponse{}, readErr
	} else if found {
		if formalGLMPhase21RockValidateLocalReleaseRecord(
			existing, context, binding, ticketRecord.Ticket, candidate) != nil ||
			existing.Binding.PeerName != local.PeerName ||
			existing.Binding.Role != local.Role {
			return formalGLMPhase21RockLifecycleResponse{},
				fmt.Errorf("formal-glm lifecycle: conflicting local release replay")
		}
		if err := formalGLMPhase21RockRemoveSecret(
			root, operation.SecretBundlePath); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		encoded, _ := json.Marshal(existing)
		digest := sha256.Sum256(encoded)
		return formalGLMPhase21RockLifecycleResponse{
			Version:      formalTypedFinalizerLifecycleVersion,
			Family:       formalFinalizerHandoffFamilyGLM,
			Action:       formalGLMPhase21RockActionVerifyCandidate,
			State:        formalGLMPhase21RockStateCandidateVerified,
			ArtifactID:   context.artifactID,
			RecordSHA256: hex.EncodeToString(digest[:]),
			LocalRelease: &existing, Replayed: true,
		}, nil
	}
	var secret formalGLMPhase21RockVerifyCandidateSecret
	if err := formalGLMPhase21RockReadJSON(
		root, operation.SecretBundlePath,
		formalGLMPhase21RockMaxSecret, &secret); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if secret.Version != formalGLMPhase21RockSecretVersion ||
		secret.Family != formalFinalizerHandoffFamilyGLM ||
		secret.Purpose != formalGLMPhase21RockPurpose ||
		secret.Action != formalGLMPhase21RockActionVerifyCandidate {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid candidate verifier secret")
	}
	phase20Root, err := formalGLMPhase21RockDecodeRoot(
		secret.Phase20StorageRoot)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	backendKey, err := formalGLMPhase21RockDecodeRoot(secret.BackendKey)
	if err != nil {
		clear(phase20Root[:])
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	transportRoot, err := formalGLMPhase21RockDecodeRoot(
		secret.TransportStorageRoot)
	if err != nil {
		clear(phase20Root[:])
		clear(backendKey[:])
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	privateKey, err := formalGLMPhase21RockDecodePrivateKey(
		secret.SigningPrivateKey)
	secret.Phase20StorageRoot, secret.BackendKey = "", ""
	secret.TransportStorageRoot, secret.SigningPrivateKey = "", ""
	defer clear(phase20Root[:])
	defer clear(backendKey[:])
	defer clear(transportRoot[:])
	defer clear(privateKey)
	if err != nil || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		context.pins[local.PeerName]) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid candidate verifier signer")
	}
	store, err := openFormalFinalizerHandoffAuthorityStoreWithGuard(
		guard, binding, transportRoot, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer store.Close()
	source, err := newFormalGLMPhase20HandoffStore(
		filepath.Join(root, "formal-glm-phase20-handoff"),
		operation.Phase20SemanticRootSHA256, local.PeerName,
		phase20Root, backendKey, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer source.close()
	var capsule formalGLMPhase16CapsuleBinding
	var request formalGLMPhase16ProductiveRequest
	var backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature
	for path, target := range map[string]any{
		operation.CapsulePath:           &capsule,
		operation.RequestPath:           &request,
		operation.BackendSignaturesPath: &backendSignatures,
		operation.WorkerSignaturesPath:  &workerSignatures,
	} {
		if err := formalGLMPhase21RockReadJSON(
			root, path, formalGLMPhase21RockMaxRecord, target); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	output, err := formalGLMPhase21LoadLocalOneDrawSpoolWithResolution(
		source, store, context.contract, ticketRecord.Ticket,
		capsule, request, backendSignatures, workerSignatures,
		registryResolution)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer output.clear()
	position := -1
	for index, authority := range binding.Authorities {
		if formalFinalizerHandoffAuthorityEqual(authority, local) {
			position = index
		}
	}
	if position < 0 {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: candidate verifier role absent")
	}
	opposite := stageRecords[1-position].Receipt.SourceReceipt
	release, err := formalGLMPhase21BuildVerifiedOneDrawLocalRelease(
		source, output, opposite, candidate.Candidate, privateKey)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	record, err := formalGLMPhase21RockBuildLocalReleaseRecord(
		context, binding, ticketRecord.Ticket, candidate,
		local.Role, release, privateKey)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_nonblind_verification_before_record"); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	digest, recordReplayed, err := formalGLMPhase21RockWriteJSON(
		root, recordPath, record)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if err := formalGLMPhase21RockRemoveSecret(
		root, operation.SecretBundlePath); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	return formalGLMPhase21RockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Action:     formalGLMPhase21RockActionVerifyCandidate,
		State:      formalGLMPhase21RockStateCandidateVerified,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		LocalRelease: &record, Replayed: recordReplayed,
		ProductionReady: false,
	}, nil
}

func formalGLMPhase21RockRunPrepareCertificate(root string, production bool,
	operation formalGLMPhase21RockPrepareCertificateOperation,
	hook formalGLMPhase21RockPhaseHook,
) (formalGLMPhase21RockLifecycleResponse, error) {
	context, err := formalGLMPhase21RockLoadContext(
		root, operation.ArtifactContractPath, operation.PinsetPath)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	registryResolution, err := formalGLMPhase21RockLoadRegistryResolution(
		root, operation.RegistryResolutionPath, context)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	local, err := formalGLMPhase21RockAuthority(
		context.contract.Artifact, operation.PeerName)
	if err != nil || formalTypedFinalizerLifecycleRequireLocalAuthority(
		root, filepath.Dir(root), operation.PeerName) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: local authority mismatch")
	}
	guard, err := newFormalFinalizerHandoffAuthorityGuard(
		root, context.artifactID, local, production)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer guard.Close()
	_, preflightState, publication, err :=
		formalGLMPhase21RockLoadPreflightPair(
			root, operation.PreflightRecordPaths, context)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if preflightState != formalGLMPhase21RockStateAbsent {
		return formalGLMPhase21RockLifecycleResponse{
			Version: formalTypedFinalizerLifecycleVersion,
			Family:  formalFinalizerHandoffFamilyGLM,
			Action:  formalGLMPhase21RockActionPrepareCertificate,
			State:   preflightState, ArtifactID: context.artifactID,
			Publication: publication, Replayed: true,
		}, nil
	}
	_, binding, err := formalGLMPhase21RockLoadStagePair(
		root, operation.StageRecordPaths, context)
	if err != nil || !formalFinalizerHandoffAuthorityEqual(
		local, binding.Finalizer) ||
		!formalGLMIsSHA256(operation.Phase20SemanticRootSHA256) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid certificate binding")
	}
	var ticketRecord formalGLMPhase21RockTicketRecord
	if err := formalGLMPhase21RockReadJSON(
		root, operation.TicketRecordPath,
		formalGLMPhase21RockMaxRecord, &ticketRecord); err != nil ||
		formalGLMPhase21RockValidateTicketRecord(ticketRecord, context) != nil ||
		!reflect.DeepEqual(ticketRecord.Binding, binding) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid certificate ticket")
	}
	var candidate formalGLMPhase21RockCandidateRecord
	if err := formalGLMPhase21RockReadJSON(
		root, operation.CandidateRecordPath,
		formalGLMPhase21RockMaxRecord, &candidate); err != nil ||
		formalGLMPhase21RockValidateCandidateRecord(
			candidate, context, binding, ticketRecord.Ticket) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid certificate candidate")
	}
	localReleases, err := formalGLMPhase21RockLoadLocalReleasePair(
		root, operation.LocalReleaseRecordPaths, context, binding,
		ticketRecord.Ticket, candidate)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	recordPath, err := formalGLMPhase21RockBaseCertificateRecordPath(
		root, context.artifactID)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	var existing formalGLMPhase21RockBaseCertificateRecord
	if found, readErr := formalGLMPhase21RockTryReadJSON(
		root, recordPath, formalGLMPhase21RockMaxRecord, &existing); readErr != nil {
		return formalGLMPhase21RockLifecycleResponse{}, readErr
	} else if found {
		if formalGLMPhase21RockValidateBaseCertificateRecord(
			existing, context, binding, ticketRecord.Ticket, candidate) != nil {
			return formalGLMPhase21RockLifecycleResponse{},
				fmt.Errorf("formal-glm lifecycle: conflicting certificate replay")
		}
		if err := formalGLMPhase21RockRemoveSecret(
			root, operation.SecretBundlePath); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		encoded, _ := json.Marshal(existing)
		digest := sha256.Sum256(encoded)
		return formalGLMPhase21RockLifecycleResponse{
			Version:         formalTypedFinalizerLifecycleVersion,
			Family:          formalFinalizerHandoffFamilyGLM,
			Action:          formalGLMPhase21RockActionPrepareCertificate,
			State:           formalGLMPhase21RockStateCertificateReady,
			ArtifactID:      context.artifactID,
			RecordSHA256:    hex.EncodeToString(digest[:]),
			BaseCertificate: &existing, Replayed: true,
		}, nil
	}
	var secret formalGLMPhase21RockPrepareCertificateSecret
	if err := formalGLMPhase21RockReadJSON(
		root, operation.SecretBundlePath,
		formalGLMPhase21RockMaxSecret, &secret); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if secret.Version != formalGLMPhase21RockSecretVersion ||
		secret.Family != formalFinalizerHandoffFamilyGLM ||
		secret.Purpose != formalGLMPhase21RockPurpose ||
		secret.Action != formalGLMPhase21RockActionPrepareCertificate {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid certificate secret")
	}
	phase20Root, err := formalGLMPhase21RockDecodeRoot(
		secret.Phase20StorageRoot)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	backendKey, err := formalGLMPhase21RockDecodeRoot(secret.BackendKey)
	if err != nil {
		clear(phase20Root[:])
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	transportRoot, err := formalGLMPhase21RockDecodeRoot(
		secret.TransportStorageRoot)
	if err != nil {
		clear(phase20Root[:])
		clear(backendKey[:])
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	privateKey, err := formalGLMPhase21RockDecodePrivateKey(
		secret.SigningPrivateKey)
	secret.Phase20StorageRoot, secret.BackendKey = "", ""
	secret.TransportStorageRoot, secret.SigningPrivateKey = "", ""
	defer clear(phase20Root[:])
	defer clear(backendKey[:])
	defer clear(transportRoot[:])
	defer clear(privateKey)
	if err != nil || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		context.pins[local.PeerName]) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid certificate signer")
	}
	store, err := openFormalFinalizerHandoffAuthorityStoreWithGuard(
		guard, binding, transportRoot, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer store.Close()
	source, err := newFormalGLMPhase20HandoffStore(
		filepath.Join(root, "formal-glm-phase20-handoff"),
		operation.Phase20SemanticRootSHA256, local.PeerName,
		phase20Root, backendKey, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer source.close()
	var capsule formalGLMPhase16CapsuleBinding
	var request formalGLMPhase16ProductiveRequest
	var backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature
	for path, target := range map[string]any{
		operation.CapsulePath:           &capsule,
		operation.RequestPath:           &request,
		operation.BackendSignaturesPath: &backendSignatures,
		operation.WorkerSignaturesPath:  &workerSignatures,
	} {
		if err := formalGLMPhase21RockReadJSON(
			root, path, formalGLMPhase21RockMaxRecord, target); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	output, err := formalGLMPhase21LoadLocalOneDrawSpoolWithResolution(
		source, store, context.contract, ticketRecord.Ticket,
		capsule, request, backendSignatures, workerSignatures,
		registryResolution)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer output.clear()
	releases := [2]jointDPBiomedicalGaussianOneDrawLocalRelease{
		localReleases[0].LocalRelease, localReleases[1].LocalRelease,
	}
	certified, baseCertificate, err :=
		formalGLMPhase21BuildDistributedOneDrawCertificateWithResolution(
			source, output, candidate.Candidate, releases, context.contract,
			registryResolution)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	record, err := formalGLMPhase21RockBuildBaseCertificateRecord(
		context, binding, ticketRecord.Ticket, candidate,
		certified, baseCertificate, privateKey)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_base_certificate_before_record"); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	digest, recordReplayed, err := formalGLMPhase21RockWriteJSON(
		root, recordPath, record)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if err := formalGLMPhase21RockRemoveSecret(
		root, operation.SecretBundlePath); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	return formalGLMPhase21RockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Action:     formalGLMPhase21RockActionPrepareCertificate,
		State:      formalGLMPhase21RockStateCertificateReady,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		BaseCertificate: &record, Replayed: recordReplayed,
		ProductionReady: false,
	}, nil
}

func formalGLMPhase21RockRunSignCertificate(root string, production bool,
	operation formalGLMPhase21RockSignCertificateOperation,
	hook formalGLMPhase21RockPhaseHook,
) (formalGLMPhase21RockLifecycleResponse, error) {
	context, err := formalGLMPhase21RockLoadContext(
		root, operation.ArtifactContractPath, operation.PinsetPath)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	registryResolution, err := formalGLMPhase21RockLoadRegistryResolution(
		root, operation.RegistryResolutionPath, context)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	local, err := formalGLMPhase21RockAuthority(
		context.contract.Artifact, operation.PeerName)
	if err != nil || formalTypedFinalizerLifecycleRequireLocalAuthority(
		root, filepath.Dir(root), operation.PeerName) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: local authority mismatch")
	}
	guard, err := newFormalFinalizerHandoffAuthorityGuard(
		root, context.artifactID, local, production)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer guard.Close()
	_, preflightState, publication, err :=
		formalGLMPhase21RockLoadPreflightPair(
			root, operation.PreflightRecordPaths, context)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if preflightState != formalGLMPhase21RockStateAbsent {
		return formalGLMPhase21RockLifecycleResponse{
			Version: formalTypedFinalizerLifecycleVersion,
			Family:  formalFinalizerHandoffFamilyGLM,
			Action:  formalGLMPhase21RockActionSignCertificate,
			State:   preflightState, ArtifactID: context.artifactID,
			Publication: publication, Replayed: true,
		}, nil
	}
	stageRecords, binding, err := formalGLMPhase21RockLoadStagePair(
		root, operation.StageRecordPaths, context)
	if err != nil || !formalFinalizerHandoffBindingHasAuthority(
		binding, local) || !formalGLMIsSHA256(
		operation.Phase20SemanticRootSHA256) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid authorization binding")
	}
	var ticketRecord formalGLMPhase21RockTicketRecord
	if err := formalGLMPhase21RockReadJSON(
		root, operation.TicketRecordPath,
		formalGLMPhase21RockMaxRecord, &ticketRecord); err != nil ||
		formalGLMPhase21RockValidateTicketRecord(ticketRecord, context) != nil ||
		!reflect.DeepEqual(ticketRecord.Binding, binding) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid authorization ticket")
	}
	var candidate formalGLMPhase21RockCandidateRecord
	if err := formalGLMPhase21RockReadJSON(
		root, operation.CandidateRecordPath,
		formalGLMPhase21RockMaxRecord, &candidate); err != nil ||
		formalGLMPhase21RockValidateCandidateRecord(
			candidate, context, binding, ticketRecord.Ticket) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid authorization candidate")
	}
	if _, err := formalGLMPhase21RockLoadLocalReleasePair(
		root, operation.LocalReleaseRecordPaths, context, binding,
		ticketRecord.Ticket, candidate); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	var base formalGLMPhase21RockBaseCertificateRecord
	if err := formalGLMPhase21RockReadJSON(
		root, operation.BaseCertificateRecordPath,
		formalGLMPhase21RockMaxRecord, &base); err != nil ||
		formalGLMPhase21RockValidateBaseCertificateRecord(
			base, context, binding, ticketRecord.Ticket, candidate) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid base certificate")
	}
	var predecessor *formalGLMPhase21RockAuthorizationRecord
	if operation.PredecessorAuthorizationPath != nil {
		var value formalGLMPhase21RockAuthorizationRecord
		if err := formalGLMPhase21RockReadJSON(
			root, *operation.PredecessorAuthorizationPath,
			formalGLMPhase21RockMaxRecord, &value); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		predecessor = &value
	}
	if local.Role == "garbler" && predecessor != nil ||
		local.Role == "evaluator" && predecessor == nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid authorization order")
	}
	if predecessor != nil && formalGLMPhase21RockValidateAuthorizationRecord(
		*predecessor, context, binding, ticketRecord.Ticket, base,
		registryResolution, nil) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid authorization predecessor")
	}
	recordPath, err := formalGLMPhase21RockAuthorizationRecordPath(
		root, context.artifactID, local.Role)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	var existing formalGLMPhase21RockAuthorizationRecord
	if found, readErr := formalGLMPhase21RockTryReadJSON(
		root, recordPath, formalGLMPhase21RockMaxRecord, &existing); readErr != nil {
		return formalGLMPhase21RockLifecycleResponse{}, readErr
	} else if found {
		if formalGLMPhase21RockValidateAuthorizationRecord(
			existing, context, binding, ticketRecord.Ticket,
			base, registryResolution, predecessor) != nil ||
			existing.Role != local.Role {
			return formalGLMPhase21RockLifecycleResponse{},
				fmt.Errorf("formal-glm lifecycle: conflicting authorization replay")
		}
		if err := formalGLMPhase21RockRemoveSecret(
			root, operation.SecretBundlePath); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		encoded, _ := json.Marshal(existing)
		digest := sha256.Sum256(encoded)
		return formalGLMPhase21RockLifecycleResponse{
			Version:       formalTypedFinalizerLifecycleVersion,
			Family:        formalFinalizerHandoffFamilyGLM,
			Action:        formalGLMPhase21RockActionSignCertificate,
			State:         formalGLMPhase21RockStateAuthorized,
			ArtifactID:    context.artifactID,
			RecordSHA256:  hex.EncodeToString(digest[:]),
			Authorization: &existing, Replayed: true,
		}, nil
	}
	var secret formalGLMPhase21RockSignCertificateSecret
	if err := formalGLMPhase21RockReadJSON(
		root, operation.SecretBundlePath,
		formalGLMPhase21RockMaxSecret, &secret); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if secret.Version != formalGLMPhase21RockSecretVersion ||
		secret.Family != formalFinalizerHandoffFamilyGLM ||
		secret.Purpose != formalGLMPhase21RockPurpose ||
		secret.Action != formalGLMPhase21RockActionSignCertificate {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid authorization secret")
	}
	stickyRoot, err := formalGLMPhase21RockDecodeRoot(secret.StickyStorageRoot)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	phase20Root, err := formalGLMPhase21RockDecodeRoot(secret.Phase20StorageRoot)
	if err != nil {
		clear(stickyRoot[:])
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	backendKey, err := formalGLMPhase21RockDecodeRoot(secret.BackendKey)
	if err != nil {
		clear(stickyRoot[:])
		clear(phase20Root[:])
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	transportRoot, err := formalGLMPhase21RockDecodeRoot(
		secret.TransportStorageRoot)
	if err != nil {
		clear(stickyRoot[:])
		clear(phase20Root[:])
		clear(backendKey[:])
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	privateKey, err := formalGLMPhase21RockDecodePrivateKey(
		secret.SigningPrivateKey)
	secret.StickyStorageRoot, secret.Phase20StorageRoot = "", ""
	secret.BackendKey, secret.TransportStorageRoot = "", ""
	secret.SigningPrivateKey = ""
	defer clear(stickyRoot[:])
	defer clear(phase20Root[:])
	defer clear(backendKey[:])
	defer clear(transportRoot[:])
	defer clear(privateKey)
	if err != nil || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		context.pins[local.PeerName]) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid authorization signer")
	}
	store, err := openFormalFinalizerHandoffAuthorityStoreWithGuard(
		guard, binding, transportRoot, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer store.Close()
	source, err := newFormalGLMPhase20HandoffStore(
		filepath.Join(root, "formal-glm-phase20-handoff"),
		operation.Phase20SemanticRootSHA256, local.PeerName,
		phase20Root, backendKey, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer source.close()
	sticky, err := newFormalGLMPhase21StickyReleaseStore(
		filepath.Join(root, "formal-glm-sticky-v2"), local.PeerName,
		stickyRoot, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer sticky.close()
	var capsule formalGLMPhase16CapsuleBinding
	var request formalGLMPhase16ProductiveRequest
	var backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature
	for path, target := range map[string]any{
		operation.CapsulePath:           &capsule,
		operation.RequestPath:           &request,
		operation.BackendSignaturesPath: &backendSignatures,
		operation.WorkerSignaturesPath:  &workerSignatures,
	} {
		if err := formalGLMPhase21RockReadJSON(
			root, path, formalGLMPhase21RockMaxRecord, target); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	output, err := formalGLMPhase21LoadLocalOneDrawSpoolWithResolution(
		source, store, context.contract, ticketRecord.Ticket,
		capsule, request, backendSignatures, workerSignatures,
		registryResolution)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer output.clear()
	position := 0
	if local.Role == "evaluator" {
		position = 1
	}
	opposite := stageRecords[1-position].Receipt.SourceReceipt
	var transportPredecessors []formalFinalizerHandoffIntentAuthorization
	var stickyPredecessors []jointDPBiomedicalGaussianSignature
	if predecessor != nil {
		transportPredecessors = []formalFinalizerHandoffIntentAuthorization{
			predecessor.TransportAuthorization,
		}
		stickyPredecessors = []jointDPBiomedicalGaussianSignature{
			predecessor.StickyAuthorization,
		}
	}
	authorization, authorizationReplayed, err :=
		formalGLMPhase21DistributedSignOnceWithResolution(
			source, store, sticky, ticketRecord.Ticket, context.contract,
			output, opposite, candidate.Candidate, base.CertifiedRelease,
			base.BaseCertificate, privateKey,
			transportPredecessors, stickyPredecessors, registryResolution)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	promoted, err := formalGLMPhase21PromoteDurableV2(
		base.BaseCertificate, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	publicCertificate, err := formalGLMPhase21RockBuildResolvedPublicCertificate(
		promoted, registryResolution, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	publicAuthorization, err := formalGLMPhase21SignPublicCertificateV2(
		publicCertificate, local.PeerName, privateKey, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	record := formalGLMPhase21RockAuthorizationRecord{
		Version:    formalGLMPhase21RockRecordVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Purpose:    formalGLMPhase21RockAuthorizationPurpose,
		ArtifactID: context.artifactID, Role: local.Role,
		IntentSHA256:           authorization.IntentSHA256,
		TransportAuthorization: authorization.TransportAuthorization,
		StickyAuthorization:    authorization.StickyAuthorization,
		PublicV2Authorization:  publicAuthorization,
		ProductionReady:        false,
	}
	if err := formalGLMPhase21RockValidateAuthorizationRecord(
		record, context, binding, ticketRecord.Ticket,
		base, registryResolution, predecessor); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_sign_once_before_authorization_record"); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	digest, recordReplayed, err := formalGLMPhase21RockWriteJSON(
		root, recordPath, record)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if err := formalGLMPhase21RockRemoveSecret(
		root, operation.SecretBundlePath); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	return formalGLMPhase21RockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Action:     formalGLMPhase21RockActionSignCertificate,
		State:      formalGLMPhase21RockStateAuthorized,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		Authorization:   &record,
		Replayed:        authorizationReplayed && recordReplayed,
		ProductionReady: false,
	}, nil
}

func formalGLMPhase21RockRunPreparePublication(root string, production bool,
	operation formalGLMPhase21RockPreparePublicationOperation,
	hook formalGLMPhase21RockPhaseHook,
) (formalGLMPhase21RockLifecycleResponse, error) {
	context, err := formalGLMPhase21RockLoadContext(
		root, operation.ArtifactContractPath, operation.PinsetPath)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	registryResolution, err := formalGLMPhase21RockLoadRegistryResolution(
		root, operation.RegistryResolutionPath, context)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	local, err := formalGLMPhase21RockAuthority(
		context.contract.Artifact, operation.PeerName)
	if err != nil || formalTypedFinalizerLifecycleRequireLocalAuthority(
		root, filepath.Dir(root), operation.PeerName) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: local authority mismatch")
	}
	guard, err := newFormalFinalizerHandoffAuthorityGuard(
		root, context.artifactID, local, production)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer guard.Close()
	_, preflightState, publication, err :=
		formalGLMPhase21RockLoadPreflightPair(
			root, operation.PreflightRecordPaths, context)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if preflightState != formalGLMPhase21RockStateAbsent {
		return formalGLMPhase21RockLifecycleResponse{
			Version: formalTypedFinalizerLifecycleVersion,
			Family:  formalFinalizerHandoffFamilyGLM,
			Action:  formalGLMPhase21RockActionPreparePublication,
			State:   preflightState, ArtifactID: context.artifactID,
			Publication: publication, Replayed: true,
		}, nil
	}
	_, binding, err := formalGLMPhase21RockLoadStagePair(
		root, operation.StageRecordPaths, context)
	if err != nil || !formalFinalizerHandoffAuthorityEqual(
		local, binding.Finalizer) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: publication requires fixed finalizer")
	}
	var ticketRecord formalGLMPhase21RockTicketRecord
	if err := formalGLMPhase21RockReadJSON(
		root, operation.TicketRecordPath,
		formalGLMPhase21RockMaxRecord, &ticketRecord); err != nil ||
		formalGLMPhase21RockValidateTicketRecord(ticketRecord, context) != nil ||
		!reflect.DeepEqual(ticketRecord.Binding, binding) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid publication ticket")
	}
	var candidate formalGLMPhase21RockCandidateRecord
	if err := formalGLMPhase21RockReadJSON(
		root, operation.CandidateRecordPath,
		formalGLMPhase21RockMaxRecord, &candidate); err != nil ||
		formalGLMPhase21RockValidateCandidateRecord(
			candidate, context, binding, ticketRecord.Ticket) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid publication candidate")
	}
	var base formalGLMPhase21RockBaseCertificateRecord
	if err := formalGLMPhase21RockReadJSON(
		root, operation.BaseCertificateRecordPath,
		formalGLMPhase21RockMaxRecord, &base); err != nil ||
		formalGLMPhase21RockValidateBaseCertificateRecord(
			base, context, binding, ticketRecord.Ticket, candidate) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid publication base certificate")
	}
	var authorizations [2]formalGLMPhase21RockAuthorizationRecord
	for index := range authorizations {
		if err := formalGLMPhase21RockReadJSON(
			root, operation.AuthorizationRecordPaths[index],
			formalGLMPhase21RockMaxRecord, &authorizations[index]); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		var predecessor *formalGLMPhase21RockAuthorizationRecord
		if index == 1 {
			predecessor = &authorizations[0]
		}
		if formalGLMPhase21RockValidateAuthorizationRecord(
			authorizations[index], context, binding, ticketRecord.Ticket,
			base, registryResolution, predecessor) != nil ||
			authorizations[index].Role != binding.Authorities[index].Role {
			return formalGLMPhase21RockLifecycleResponse{},
				fmt.Errorf("formal-glm lifecycle: invalid ordered authorizations")
		}
	}
	recordPath, err := formalGLMPhase21RockPublicationReadyRecordPath(
		root, context.artifactID)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	var existing formalGLMPhase21RockPublicationReadyRecord
	if found, readErr := formalGLMPhase21RockTryReadJSON(
		root, recordPath, formalGLMPhase21RockMaxRecord, &existing); readErr != nil {
		return formalGLMPhase21RockLifecycleResponse{}, readErr
	} else if found {
		if formalGLMPhase21RockValidatePublicationReadyRecord(
			existing, context, binding, ticketRecord.Ticket) != nil {
			return formalGLMPhase21RockLifecycleResponse{},
				fmt.Errorf("formal-glm lifecycle: conflicting publication replay")
		}
		if err := formalGLMPhase21RockRemoveSecret(
			root, operation.SecretBundlePath); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		encoded, _ := json.Marshal(existing)
		digest := sha256.Sum256(encoded)
		certificateSHA, _ := formalGLMPhase21RockPublicCertificateDigest(
			existing.PublicCertificate)
		publicCopy := existing.PublicCertificate
		return formalGLMPhase21RockLifecycleResponse{
			Version:           formalTypedFinalizerLifecycleVersion,
			Family:            formalFinalizerHandoffFamilyGLM,
			Action:            formalGLMPhase21RockActionPreparePublication,
			State:             formalGLMPhase21RockStatePublicationReady,
			ArtifactID:        context.artifactID,
			RecordSHA256:      hex.EncodeToString(digest[:]),
			CertificateSHA256: certificateSHA,
			Publication:       &publicCopy, Replayed: true,
		}, nil
	}
	var secret formalGLMPhase21RockPreparePublicationSecret
	if err := formalGLMPhase21RockReadJSON(
		root, operation.SecretBundlePath,
		formalGLMPhase21RockMaxSecret, &secret); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if secret.Version != formalGLMPhase21RockSecretVersion ||
		secret.Family != formalFinalizerHandoffFamilyGLM ||
		secret.Purpose != formalGLMPhase21RockPurpose ||
		secret.Action != formalGLMPhase21RockActionPreparePublication {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid publication secret")
	}
	transportRoot, err := formalGLMPhase21RockDecodeRoot(
		secret.TransportStorageRoot)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	privateKey, err := formalGLMPhase21RockDecodePrivateKey(
		secret.SigningPrivateKey)
	secret.TransportStorageRoot, secret.SigningPrivateKey = "", ""
	defer clear(transportRoot[:])
	defer clear(privateKey)
	if err != nil || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		context.pins[local.PeerName]) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid publication signer")
	}
	store, err := openFormalFinalizerHandoffAuthorityStoreWithGuard(
		guard, binding, transportRoot, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer store.Close()
	promoted, err := formalGLMPhase21PromoteDurableV2(
		base.BaseCertificate, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	distributed := [2]formalGLMPhase21DistributedAuthorization{
		formalGLMPhase21RockDistributedAuthorization(authorizations[0]),
		formalGLMPhase21RockDistributedAuthorization(authorizations[1]),
	}
	if err := formalGLMPhase21ValidateDistributedAuthorization(
		store, ticketRecord.Ticket, promoted, "garbler", distributed[0],
		nil, nil); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if err := formalGLMPhase21ValidateDistributedAuthorization(
		store, ticketRecord.Ticket, promoted, "evaluator", distributed[1],
		[]formalFinalizerHandoffIntentAuthorization{
			distributed[0].TransportAuthorization,
		}, []jointDPBiomedicalGaussianSignature{
			distributed[0].StickyAuthorization,
		}); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	internal, err := formalGLMPhase21SealStickyCertificate(
		promoted, []jointDPBiomedicalGaussianSignature{
			distributed[0].StickyAuthorization,
			distributed[1].StickyAuthorization,
		}, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	publicCertificate, err := formalGLMPhase21RockBuildResolvedPublicCertificate(
		promoted, registryResolution, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	publicCertificate, err = formalGLMPhase21SealPublicCertificateV2(
		publicCertificate, []jointDPBiomedicalGaussianSignature{
			authorizations[0].PublicV2Authorization,
			authorizations[1].PublicV2Authorization,
		}, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	record, err := formalGLMPhase21RockBuildPublicationReadyRecord(
		context, binding, ticketRecord.Ticket,
		internal, publicCertificate, privateKey)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_publication_ready_before_record"); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	digest, recordReplayed, err := formalGLMPhase21RockWriteJSON(
		root, recordPath, record)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if err := formalGLMPhase21RockRemoveSecret(
		root, operation.SecretBundlePath); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	certificateSHA, _ := formalGLMPhase21RockPublicCertificateDigest(
		publicCertificate)
	return formalGLMPhase21RockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Action:     formalGLMPhase21RockActionPreparePublication,
		State:      formalGLMPhase21RockStatePublicationReady,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		CertificateSHA256: certificateSHA,
		Publication:       &publicCertificate, Replayed: recordReplayed,
		ProductionReady: false,
	}, nil
}

func formalGLMPhase21RockRunCommitPublication(root string, production bool,
	operation formalGLMPhase21RockCommitPublicationOperation,
	hook formalGLMPhase21RockPhaseHook,
) (formalGLMPhase21RockLifecycleResponse, error) {
	context, err := formalGLMPhase21RockLoadContext(
		root, operation.ArtifactContractPath, operation.PinsetPath)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	local, err := formalGLMPhase21RockAuthority(
		context.contract.Artifact, operation.PeerName)
	if err != nil || formalTypedFinalizerLifecycleRequireLocalAuthority(
		root, filepath.Dir(root), operation.PeerName) != nil ||
		formalGLMPhase21ValidatePublicCertificateV2(
			operation.Publication, context.pins) != nil ||
		operation.Publication.ArtifactID != context.artifactID {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid local publication")
	}
	guard, err := newFormalFinalizerHandoffAuthorityGuard(
		root, context.artifactID, local, production)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer guard.Close()
	recordPath, err := formalGLMPhase21RockCommitRecordPath(
		root, context.artifactID, local.Role)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	var existing formalGLMPhase21RockCommitRecord
	if found, readErr := formalGLMPhase21RockTryReadJSON(
		root, recordPath, formalGLMPhase21RockMaxRecord, &existing); readErr != nil {
		return formalGLMPhase21RockLifecycleResponse{}, readErr
	} else if found {
		if formalGLMPhase21RockValidateCommitRecord(
			existing, context, local) != nil ||
			!reflect.DeepEqual(existing.Publication, operation.Publication) ||
			formalGLMPhase21RockVerifyPublicRecordWithoutKey(
				root, local.PeerName, existing.Publication) != nil {
			return formalGLMPhase21RockLifecycleResponse{},
				fmt.Errorf("formal-glm lifecycle: conflicting publication replay")
		}
		if err := formalGLMPhase21RockRemoveSecret(
			root, operation.SecretBundlePath); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		encoded, _ := json.Marshal(existing)
		digest := sha256.Sum256(encoded)
		publicCopy := existing.Publication
		return formalGLMPhase21RockLifecycleResponse{
			Version:    formalTypedFinalizerLifecycleVersion,
			Family:     formalFinalizerHandoffFamilyGLM,
			Action:     formalGLMPhase21RockActionCommitPublication,
			State:      formalGLMPhase21RockStatePublicationCommit,
			ArtifactID: context.artifactID, RecordSHA256: hex.EncodeToString(digest[:]),
			CertificateSHA256: existing.Receipt.CertificateSHA256,
			Publication:       &publicCopy, Commit: &existing, Replayed: true,
			ProductionReady: false,
		}, nil
	}
	var secret formalGLMPhase21RockCommitPublicationSecret
	if err := formalGLMPhase21RockReadJSON(
		root, operation.SecretBundlePath,
		formalGLMPhase21RockMaxSecret, &secret); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if secret.Version != formalGLMPhase21RockSecretVersion ||
		secret.Family != formalFinalizerHandoffFamilyGLM ||
		secret.Purpose != formalGLMPhase21RockPurpose ||
		secret.Action != formalGLMPhase21RockActionCommitPublication {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid publication commit secret")
	}
	stickyRoot, err := formalGLMPhase21RockDecodeRoot(secret.StickyStorageRoot)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	privateKey, err := formalGLMPhase21RockDecodePrivateKey(
		secret.SigningPrivateKey)
	secret.StickyStorageRoot, secret.SigningPrivateKey = "", ""
	defer clear(stickyRoot[:])
	defer clear(privateKey)
	if err != nil || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		context.pins[local.PeerName]) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid publication commit signer")
	}
	sticky, err := newFormalGLMPhase21StickyReleaseStore(
		filepath.Join(root, "formal-glm-sticky-v2"), local.PeerName,
		stickyRoot, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer sticky.close()
	publication, err := sticky.CommitPublicV2(operation.Publication)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_publication_commit_before_receipt"); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	receipt := formalGLMPhase21RockCommitReceipt{
		Version:           formalGLMPhase21RockRecordVersion,
		Purpose:           formalGLMPhase21RockCommitPurpose,
		ArtifactID:        context.artifactID,
		CertificateSHA256: publication.CertificateSHA256,
		PeerName:          local.PeerName, PeerID: local.PeerID, Role: local.Role,
		ProductionReady: false,
	}
	message, err := formalGLMPhase21RockCommitMessage(receipt)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	receipt.Signature = ed25519.Sign(privateKey, message)
	record := formalGLMPhase21RockCommitRecord{
		Version: formalGLMPhase21RockRecordVersion,
		Family:  formalFinalizerHandoffFamilyGLM,
		Purpose: formalGLMPhase21RockCommitPurpose,
		Receipt: receipt, Publication: operation.Publication,
		ProductionReady: false,
	}
	if err := formalGLMPhase21RockValidateCommitRecord(
		record, context, local); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	digest, recordReplayed, err := formalGLMPhase21RockWriteJSON(
		root, recordPath, record)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if err := formalGLMPhase21RockRemoveSecret(
		root, operation.SecretBundlePath); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	publicCopy := operation.Publication
	return formalGLMPhase21RockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Action:     formalGLMPhase21RockActionCommitPublication,
		State:      formalGLMPhase21RockStatePublicationCommit,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		CertificateSHA256: publication.CertificateSHA256,
		Publication:       &publicCopy, Commit: &record,
		Replayed:        publication.Replayed || recordReplayed,
		ProductionReady: false,
	}, nil
}

func formalGLMPhase21RockRunFinalizeAck(root string, production bool,
	operation formalGLMPhase21RockFinalizeAckOperation,
	hook formalGLMPhase21RockPhaseHook,
) (formalGLMPhase21RockLifecycleResponse, error) {
	context, err := formalGLMPhase21RockLoadContext(
		root, operation.ArtifactContractPath, operation.PinsetPath)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	local, err := formalGLMPhase21RockAuthority(
		context.contract.Artifact, operation.PeerName)
	if err != nil || formalTypedFinalizerLifecycleRequireLocalAuthority(
		root, filepath.Dir(root), operation.PeerName) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid ACK finalizer")
	}
	guard, err := newFormalFinalizerHandoffAuthorityGuard(
		root, context.artifactID, local, production)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer guard.Close()
	_, binding, err := formalGLMPhase21RockLoadStagePair(
		root, operation.StageRecordPaths, context)
	if err != nil || !formalFinalizerHandoffAuthorityEqual(
		local, binding.Finalizer) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: ACK finalizer binding mismatch")
	}
	var ticketRecord formalGLMPhase21RockTicketRecord
	if err := formalGLMPhase21RockReadJSON(
		root, operation.TicketRecordPath,
		formalGLMPhase21RockMaxRecord, &ticketRecord); err != nil ||
		formalGLMPhase21RockValidateTicketRecord(ticketRecord, context) != nil ||
		!reflect.DeepEqual(ticketRecord.Binding, binding) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid ACK ticket")
	}
	var ready formalGLMPhase21RockPublicationReadyRecord
	if err := formalGLMPhase21RockReadJSON(
		root, operation.PublicationReadyRecordPath,
		formalGLMPhase21RockMaxRecord, &ready); err != nil ||
		formalGLMPhase21RockValidatePublicationReadyRecord(
			ready, context, binding, ticketRecord.Ticket) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid ACK publication")
	}
	certificateSHA, err := formalGLMPhase21RockPublicCertificateDigest(
		ready.PublicCertificate)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	recordPath, err := formalGLMPhase21RockAckRecordPath(root, context.artifactID)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	var existing formalGLMPhase21RockAckRecord
	if found, readErr := formalGLMPhase21RockTryReadJSON(
		root, recordPath, formalGLMPhase21RockMaxRecord, &existing); readErr != nil {
		return formalGLMPhase21RockLifecycleResponse{}, readErr
	} else if found {
		if formalGLMPhase21RockValidateAckRecord(
			existing, context, binding, ticketRecord.Ticket,
			certificateSHA) != nil ||
			formalGLMPhase21RockVerifyPublicRecordWithoutKey(
				root, local.PeerName, ready.PublicCertificate) != nil {
			return formalGLMPhase21RockLifecycleResponse{},
				fmt.Errorf("formal-glm lifecycle: conflicting ACK replay")
		}
		if err := formalGLMPhase21RockRemoveSecret(
			root, operation.SecretBundlePath); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		encoded, _ := json.Marshal(existing)
		digest := sha256.Sum256(encoded)
		publicCopy := ready.PublicCertificate
		return formalGLMPhase21RockLifecycleResponse{
			Version:    formalTypedFinalizerLifecycleVersion,
			Family:     formalFinalizerHandoffFamilyGLM,
			Action:     formalGLMPhase21RockActionFinalizeAck,
			State:      formalGLMPhase21RockStateAckReady,
			ArtifactID: context.artifactID, RecordSHA256: hex.EncodeToString(digest[:]),
			CertificateSHA256: certificateSHA, Publication: &publicCopy,
			Ack: &existing, Replayed: true, ProductionReady: false,
		}, nil
	}
	if _, err := formalGLMPhase21RockLoadCommitPair(
		root, operation.CommitRecordPaths, context, certificateSHA); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	var secret formalGLMPhase21RockFinalizeAckSecret
	if err := formalGLMPhase21RockReadJSON(
		root, operation.SecretBundlePath,
		formalGLMPhase21RockMaxSecret, &secret); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if secret.Version != formalGLMPhase21RockSecretVersion ||
		secret.Family != formalFinalizerHandoffFamilyGLM ||
		secret.Purpose != formalGLMPhase21RockPurpose ||
		secret.Action != formalGLMPhase21RockActionFinalizeAck {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid ACK secret")
	}
	stickyRoot, err := formalGLMPhase21RockDecodeRoot(secret.StickyStorageRoot)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	transportRoot, err := formalGLMPhase21RockDecodeRoot(
		secret.TransportStorageRoot)
	if err != nil {
		clear(stickyRoot[:])
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	privateKey, err := formalGLMPhase21RockDecodePrivateKey(
		secret.SigningPrivateKey)
	secret.StickyStorageRoot, secret.TransportStorageRoot = "", ""
	secret.SigningPrivateKey = ""
	defer clear(stickyRoot[:])
	defer clear(transportRoot[:])
	defer clear(privateKey)
	if err != nil || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		context.pins[local.PeerName]) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid ACK signer")
	}
	sticky, err := newFormalGLMPhase21StickyReleaseStore(
		filepath.Join(root, "formal-glm-sticky-v2"), local.PeerName,
		stickyRoot, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer sticky.close()
	publicGuard := formalGLMPhase21RockPublicPublicationGuard{store: sticky}
	if err := publicGuard.formalFinalizerHandoffVerifyPublication(
		context.artifactID, certificateSHA); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	transport, err := openFormalFinalizerHandoffAuthorityStoreWithGuard(
		guard, binding, transportRoot, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer transport.Close()
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticketRecord.Ticket)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	proof, err := formalFinalizerHandoffBuildCommitProof(
		binding, ticketSHA, certificateSHA, privateKey, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	stored, ackReplayed, err := transport.AckAfterCommit(proof, publicGuard)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_finalizer_ack_before_record"); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	record := formalGLMPhase21RockAckRecord{
		Version:    formalGLMPhase21RockRecordVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Purpose:    formalGLMPhase21RockAckPurpose,
		ArtifactID: context.artifactID, Proof: stored, ProductionReady: false,
	}
	if err := formalGLMPhase21RockValidateAckRecord(
		record, context, binding, ticketRecord.Ticket, certificateSHA); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	digest, recordReplayed, err := formalGLMPhase21RockWriteJSON(
		root, recordPath, record)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if err := formalGLMPhase21RockRemoveSecret(
		root, operation.SecretBundlePath); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	publicCopy := ready.PublicCertificate
	return formalGLMPhase21RockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Action:     formalGLMPhase21RockActionFinalizeAck,
		State:      formalGLMPhase21RockStateAckReady,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		CertificateSHA256: certificateSHA, Publication: &publicCopy,
		Ack: &record, Replayed: ackReplayed || recordReplayed,
		ProductionReady: false,
	}, nil
}

func formalGLMPhase21RockRunAck(root string, production bool,
	operation formalGLMPhase21RockAckOperation,
	hook formalGLMPhase21RockPhaseHook,
) (formalGLMPhase21RockLifecycleResponse, error) {
	context, err := formalGLMPhase21RockLoadContext(
		root, operation.ArtifactContractPath, operation.PinsetPath)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	registryResolution, err := formalGLMPhase21RockLoadRegistryResolution(
		root, operation.RegistryResolutionPath, context)
	if err != nil || formalGLMPhase21RockValidateResolvedPublication(
		operation.Publication, registryResolution, context.pins) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid cleanup registry resolution")
	}
	local, err := formalGLMPhase21RockAuthority(
		context.contract.Artifact, operation.PeerName)
	if err != nil || formalTypedFinalizerLifecycleRequireLocalAuthority(
		root, filepath.Dir(root), operation.PeerName) != nil ||
		formalGLMPhase21ValidatePublicCertificateV2(
			operation.Publication, context.pins) != nil ||
		operation.Publication.ArtifactID != context.artifactID {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid local cleanup")
	}
	guard, err := newFormalFinalizerHandoffAuthorityGuard(
		root, context.artifactID, local, production)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer guard.Close()
	cleanupPath, err := formalGLMPhase21RockCleanupRecordPath(
		root, context.artifactID, local.Role)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	var existing formalGLMPhase21RockCleanupRecord
	if found, readErr := formalGLMPhase21RockTryReadJSON(
		root, cleanupPath, formalGLMPhase21RockMaxRecord, &existing); readErr != nil {
		return formalGLMPhase21RockLifecycleResponse{}, readErr
	} else if found {
		if formalGLMPhase21RockValidateCleanupRecord(
			existing, context, local) != nil ||
			!reflect.DeepEqual(existing.Publication, operation.Publication) ||
			formalGLMPhase21RockVerifyPublicRecordWithoutKey(
				root, local.PeerName, existing.Publication) != nil {
			return formalGLMPhase21RockLifecycleResponse{},
				fmt.Errorf("formal-glm lifecycle: conflicting cleanup replay")
		}
		if err := formalGLMPhase21RockRemoveSecret(
			root, operation.SecretBundlePath); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		encoded, _ := json.Marshal(existing)
		digest := sha256.Sum256(encoded)
		publicCopy := existing.Publication
		return formalGLMPhase21RockLifecycleResponse{
			Version:    formalTypedFinalizerLifecycleVersion,
			Family:     formalFinalizerHandoffFamilyGLM,
			Action:     formalGLMPhase21RockActionAck,
			State:      formalGLMPhase21RockStateCleaned,
			ArtifactID: context.artifactID, RecordSHA256: hex.EncodeToString(digest[:]),
			CertificateSHA256: existing.Receipt.CertificateSHA256,
			Publication:       &publicCopy, Cleanup: &existing,
			Replayed: true, ProductionReady: false,
		}, nil
	}
	_, binding, err := formalGLMPhase21RockLoadStagePair(
		root, operation.StageRecordPaths, context)
	if err != nil || !formalFinalizerHandoffBindingHasAuthority(binding, local) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: cleanup binding mismatch")
	}
	var ticketRecord formalGLMPhase21RockTicketRecord
	if err := formalGLMPhase21RockReadJSON(
		root, operation.TicketRecordPath,
		formalGLMPhase21RockMaxRecord, &ticketRecord); err != nil ||
		formalGLMPhase21RockValidateTicketRecord(ticketRecord, context) != nil ||
		!reflect.DeepEqual(ticketRecord.Binding, binding) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid cleanup ticket")
	}
	var commit formalGLMPhase21RockCommitRecord
	if err := formalGLMPhase21RockReadJSON(
		root, operation.CommitRecordPath,
		formalGLMPhase21RockMaxRecord, &commit); err != nil ||
		formalGLMPhase21RockValidateCommitRecord(commit, context, local) != nil ||
		!reflect.DeepEqual(commit.Publication, operation.Publication) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid cleanup publication receipt")
	}
	certificateSHA := commit.Receipt.CertificateSHA256
	var ack formalGLMPhase21RockAckRecord
	if err := formalGLMPhase21RockReadJSON(
		root, operation.AckRecordPath,
		formalGLMPhase21RockMaxRecord, &ack); err != nil ||
		formalGLMPhase21RockValidateAckRecord(
			ack, context, binding, ticketRecord.Ticket, certificateSHA) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid cleanup ACK")
	}
	var secret formalGLMPhase21RockAckSecret
	if err := formalGLMPhase21RockReadJSON(
		root, operation.SecretBundlePath,
		formalGLMPhase21RockMaxSecret, &secret); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if secret.Version != formalGLMPhase21RockSecretVersion ||
		secret.Family != formalFinalizerHandoffFamilyGLM ||
		secret.Purpose != formalGLMPhase21RockPurpose ||
		secret.Action != formalGLMPhase21RockActionAck {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid cleanup secret")
	}
	stickyRoot, err := formalGLMPhase21RockDecodeRoot(secret.StickyStorageRoot)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	phase20Root, err := formalGLMPhase21RockDecodeRoot(secret.Phase20StorageRoot)
	if err != nil {
		clear(stickyRoot[:])
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	backendKey, err := formalGLMPhase21RockDecodeRoot(secret.BackendKey)
	if err != nil {
		clear(stickyRoot[:])
		clear(phase20Root[:])
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	transportRoot, err := formalGLMPhase21RockDecodeRoot(
		secret.TransportStorageRoot)
	if err != nil {
		clear(stickyRoot[:])
		clear(phase20Root[:])
		clear(backendKey[:])
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	privateKey, err := formalGLMPhase21RockDecodePrivateKey(
		secret.SigningPrivateKey)
	secret.StickyStorageRoot, secret.Phase20StorageRoot = "", ""
	secret.BackendKey, secret.TransportStorageRoot = "", ""
	secret.SigningPrivateKey = ""
	defer clear(stickyRoot[:])
	defer clear(phase20Root[:])
	defer clear(backendKey[:])
	defer clear(transportRoot[:])
	defer clear(privateKey)
	if err != nil || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		context.pins[local.PeerName]) ||
		!formalGLMIsSHA256(operation.Phase20SemanticRootSHA256) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid cleanup authority")
	}
	sticky, err := newFormalGLMPhase21StickyReleaseStore(
		filepath.Join(root, "formal-glm-sticky-v2"), local.PeerName,
		stickyRoot, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer sticky.close()
	publicGuard := formalGLMPhase21RockPublicPublicationGuard{store: sticky}
	if err := publicGuard.formalFinalizerHandoffVerifyPublication(
		context.artifactID, certificateSHA); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	transport, err := openFormalFinalizerHandoffAuthorityStoreWithGuard(
		guard, binding, transportRoot, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer transport.Close()
	if _, _, err := transport.AckAfterCommit(ack.Proof, publicGuard); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_local_ack_before_cleanup"); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	var capsule formalGLMPhase16CapsuleBinding
	var request formalGLMPhase16ProductiveRequest
	var backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature
	for path, target := range map[string]any{
		operation.CapsulePath:           &capsule,
		operation.RequestPath:           &request,
		operation.BackendSignaturesPath: &backendSignatures,
		operation.WorkerSignaturesPath:  &workerSignatures,
	} {
		if err := formalGLMPhase21RockReadJSON(
			root, path, formalGLMPhase21RockMaxRecord, target); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	source, err := newFormalGLMPhase20HandoffStore(
		filepath.Join(root, "formal-glm-phase20-handoff"),
		operation.Phase20SemanticRootSHA256, local.PeerName,
		phase20Root, backendKey, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer source.close()
	if _, err := formalGLMPhase21RockCleanupSourceAfterPublicAck(
		source, operation.Publication, capsule, request,
		backendSignatures, workerSignatures, registryResolution); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_source_cleanup"); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	spoolsRemoved, err := formalGLMPhase21CleanupLocalOneDrawSpoolAfterAck(
		transport, context.contract, ack.Proof)
	if err != nil || (spoolsRemoved != 0 && spoolsRemoved != 1) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: incomplete local spool cleanup")
	}
	if hook != nil {
		if err := hook("after_local_spool_cleanup"); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	transportRemoved, err := transport.CleanupTransportAfterAck(ack.Proof)
	expectedTransport := 1
	if formalFinalizerHandoffAuthorityEqual(local, binding.Finalizer) {
		expectedTransport = 4
	}
	if err != nil || (transportRemoved != 0 && transportRemoved != expectedTransport) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: incomplete transport cleanup")
	}
	if _, err := formalGLMPhase21CleanupLocalOneDrawSpoolAfterAck(
		transport, context.contract, ack.Proof); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if removed, err := transport.CleanupTransportAfterAck(
		ack.Proof); err != nil || removed != 0 {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: transport cleanup did not stabilize")
	}
	if _, err := os.Lstat(source.recordPath); !os.IsNotExist(err) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: source cleanup did not stabilize")
	}
	if hook != nil {
		if err := hook("after_transport_cleanup_before_record"); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
	}
	receipt := formalGLMPhase21RockCleanupReceipt{
		Version:    formalGLMPhase21RockRecordVersion,
		Purpose:    formalGLMPhase21RockCleanupPurpose,
		ArtifactID: context.artifactID, CertificateSHA256: certificateSHA,
		PeerName: local.PeerName, PeerID: local.PeerID, Role: local.Role,
		SourceCleaned: true, LocalSpoolCleaned: true, TransportCleaned: true,
		ProductionReady: false,
	}
	message, err := formalGLMPhase21RockCleanupMessage(receipt)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	receipt.Signature = ed25519.Sign(privateKey, message)
	record := formalGLMPhase21RockCleanupRecord{
		Version: formalGLMPhase21RockRecordVersion,
		Family:  formalFinalizerHandoffFamilyGLM,
		Purpose: formalGLMPhase21RockCleanupPurpose,
		Receipt: receipt, Publication: operation.Publication,
		ProductionReady: false,
	}
	if err := formalGLMPhase21RockValidateCleanupRecord(
		record, context, local); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	digest, recordReplayed, err := formalGLMPhase21RockWriteJSON(
		root, cleanupPath, record)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if err := formalGLMPhase21RockRemoveSecret(
		root, operation.SecretBundlePath); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	publicCopy := operation.Publication
	return formalGLMPhase21RockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Action:     formalGLMPhase21RockActionAck,
		State:      formalGLMPhase21RockStateCleaned,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		CertificateSHA256: certificateSHA, Publication: &publicCopy,
		Cleanup:         &record,
		Replayed:        recordReplayed || spoolsRemoved == 0 || transportRemoved == 0,
		ProductionReady: false,
	}, nil
}

func formalGLMPhase21RockRunPreflight(root string, production bool,
	operation formalGLMPhase21RockPreflightOperation,
) (formalGLMPhase21RockLifecycleResponse, error) {
	context, err := formalGLMPhase21RockLoadContext(
		root, operation.ArtifactContractPath, operation.PinsetPath)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	registryResolution, err := formalGLMPhase21RockLoadRegistryResolution(
		root, operation.RegistryResolutionPath, context)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	local, err := formalGLMPhase21RockAuthority(
		context.contract.Artifact, operation.PeerName)
	if err != nil || formalTypedFinalizerLifecycleRequireLocalAuthority(
		root, filepath.Dir(root), operation.PeerName) != nil {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: local authority mismatch")
	}
	guard, err := newFormalFinalizerHandoffAuthorityGuard(
		root, context.artifactID, local, production)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer guard.Close()
	var secret formalGLMPhase21RockPreflightSecret
	if err := formalGLMPhase21RockReadJSON(
		root, operation.SecretBundlePath,
		formalGLMPhase21RockMaxSecret, &secret); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if secret.Version != formalGLMPhase21RockSecretVersion ||
		secret.Family != formalFinalizerHandoffFamilyGLM ||
		secret.Purpose != formalGLMPhase21RockPurpose ||
		secret.Action != formalGLMPhase21RockActionPreflight {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid preflight secret")
	}
	storageRoot, err := formalGLMPhase21RockDecodeRoot(secret.StickyStorageRoot)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	privateKey, err := formalGLMPhase21RockDecodePrivateKey(
		secret.SigningPrivateKey)
	secret.StickyStorageRoot, secret.SigningPrivateKey = "", ""
	defer clear(storageRoot[:])
	defer clear(privateKey)
	if err != nil || !hmac.Equal(
		privateKey.Public().(ed25519.PublicKey), context.pins[local.PeerName]) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: invalid preflight signer")
	}
	sticky, err := newFormalGLMPhase21StickyReleaseStore(
		filepath.Join(root, "formal-glm-sticky-v2"), local.PeerName,
		storageRoot, context.pins)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	defer sticky.close()
	state := formalGLMPhase21RockStateAbsent
	certificateSHA256 := ""
	var publication *formalGLMPhase21PublicCertificateV2
	stored, replayErr := sticky.ReplayPublicV2(context.artifactID)
	if replayErr == nil {
		certificate, decodeErr := formalGLMPhase21DecodePublicV2Publication(
			stored, context.pins)
		if decodeErr != nil {
			return formalGLMPhase21RockLifecycleResponse{}, decodeErr
		}
		if err := formalGLMPhase21RockValidateResolvedPublication(
			certificate, registryResolution, context.pins); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		state, certificateSHA256 = formalGLMPhase21RockStatePublished,
			stored.CertificateSHA256
		publication = &certificate
	} else if !os.IsNotExist(replayErr) {
		return formalGLMPhase21RockLifecycleResponse{}, replayErr
	}
	receipt := formalGLMPhase21RockPreflightReceipt{
		Version:      formalGLMPhase21RockRecordVersion,
		Purpose:      formalGLMPhase21RockPreflightPurpose,
		ArtifactID:   context.artifactID,
		PinsetSHA256: context.contract.PinsetSHA256,
		PeerName:     local.PeerName, PeerID: local.PeerID, Role: local.Role,
		State: state, CertificateSHA256: certificateSHA256,
		ProductionReady: false,
	}
	message, err := formalGLMPhase21RockPreflightMessage(receipt)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	receipt.Signature = ed25519.Sign(privateKey, message)
	record := formalGLMPhase21RockPreflightRecord{
		Version: formalGLMPhase21RockRecordVersion,
		Family:  formalFinalizerHandoffFamilyGLM,
		Purpose: formalGLMPhase21RockPreflightPurpose,
		Receipt: receipt, Publication: publication, ProductionReady: false,
	}
	if err := formalGLMPhase21RockValidatePreflightRecord(
		record, context.contract, context.pins); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	recordPath, err := formalGLMPhase21RockPreflightRecordPath(
		root, context.artifactID, state, certificateSHA256)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	digest, replayed, err := formalGLMPhase21RockWriteJSON(
		root, recordPath, record)
	if err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	if err := formalGLMPhase21RockRemoveSecret(
		root, operation.SecretBundlePath); err != nil {
		return formalGLMPhase21RockLifecycleResponse{}, err
	}
	return formalGLMPhase21RockLifecycleResponse{
		Version: formalTypedFinalizerLifecycleVersion,
		Family:  formalFinalizerHandoffFamilyGLM,
		Action:  formalGLMPhase21RockActionPreflight,
		State:   state, ArtifactID: context.artifactID,
		RecordSHA256: digest, CertificateSHA256: certificateSHA256,
		Preflight: &record, Replayed: replayed, ProductionReady: false,
	}, nil
}

func formalGLMPhase21RockRun(root string, production bool, action string,
	operation json.RawMessage,
) (formalGLMPhase21RockLifecycleResponse, error) {
	return formalGLMPhase21RockRunWithHook(
		root, production, action, operation, nil)
}

func formalGLMPhase21RockRunWithHook(root string, production bool,
	action string, operation json.RawMessage,
	hook formalGLMPhase21RockPhaseHook,
) (formalGLMPhase21RockLifecycleResponse, error) {
	if !formalTypedFinalizerLifecycleActionAllowed(
		formalFinalizerHandoffFamilyGLM, action) {
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: unsupported action")
	}
	switch action {
	case formalGLMPhase21RockActionPreflight:
		var decoded formalGLMPhase21RockPreflightOperation
		if err := formalGLMPhase21RockStrictDecode(operation, &decoded); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		return formalGLMPhase21RockRunPreflight(root, production, decoded)
	case formalGLMPhase21RockActionStage:
		var decoded formalGLMPhase21RockStageOperation
		if err := formalGLMPhase21RockStrictDecode(operation, &decoded); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		return formalGLMPhase21RockRunStage(root, production, decoded, hook)
	case formalGLMPhase21RockActionTicket:
		var decoded formalGLMPhase21RockTicketOperation
		if err := formalGLMPhase21RockStrictDecode(operation, &decoded); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		return formalGLMPhase21RockRunTicket(root, production, decoded, hook)
	case formalGLMPhase21RockActionSeal:
		var decoded formalGLMPhase21RockSealOperation
		if err := formalGLMPhase21RockStrictDecode(operation, &decoded); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		return formalGLMPhase21RockRunSeal(root, production, decoded, hook)
	case formalGLMPhase21RockActionPrepareCandidate:
		var decoded formalGLMPhase21RockPrepareCandidateOperation
		if err := formalGLMPhase21RockStrictDecode(operation, &decoded); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		return formalGLMPhase21RockRunPrepareCandidate(
			root, production, decoded, hook)
	case formalGLMPhase21RockActionVerifyCandidate:
		var decoded formalGLMPhase21RockVerifyCandidateOperation
		if err := formalGLMPhase21RockStrictDecode(operation, &decoded); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		return formalGLMPhase21RockRunVerifyCandidate(
			root, production, decoded, hook)
	case formalGLMPhase21RockActionPrepareCertificate:
		var decoded formalGLMPhase21RockPrepareCertificateOperation
		if err := formalGLMPhase21RockStrictDecode(operation, &decoded); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		return formalGLMPhase21RockRunPrepareCertificate(
			root, production, decoded, hook)
	case formalGLMPhase21RockActionSignCertificate:
		var decoded formalGLMPhase21RockSignCertificateOperation
		if err := formalGLMPhase21RockStrictDecode(operation, &decoded); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		return formalGLMPhase21RockRunSignCertificate(
			root, production, decoded, hook)
	case formalGLMPhase21RockActionPreparePublication:
		var decoded formalGLMPhase21RockPreparePublicationOperation
		if err := formalGLMPhase21RockStrictDecode(operation, &decoded); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		return formalGLMPhase21RockRunPreparePublication(
			root, production, decoded, hook)
	case formalGLMPhase21RockActionCommitPublication:
		var decoded formalGLMPhase21RockCommitPublicationOperation
		if err := formalGLMPhase21RockStrictDecode(operation, &decoded); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		return formalGLMPhase21RockRunCommitPublication(
			root, production, decoded, hook)
	case formalGLMPhase21RockActionFinalizeAck:
		var decoded formalGLMPhase21RockFinalizeAckOperation
		if err := formalGLMPhase21RockStrictDecode(operation, &decoded); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		return formalGLMPhase21RockRunFinalizeAck(
			root, production, decoded, hook)
	case formalGLMPhase21RockActionAck:
		var decoded formalGLMPhase21RockAckOperation
		if err := formalGLMPhase21RockStrictDecode(operation, &decoded); err != nil {
			return formalGLMPhase21RockLifecycleResponse{}, err
		}
		return formalGLMPhase21RockRunAck(
			root, production, decoded, hook)
	default:
		return formalGLMPhase21RockLifecycleResponse{},
			fmt.Errorf("formal-glm lifecycle: action is not wired")
	}
}

func handleFormalGLMPhase21RockLifecycle(root, action string,
	operation json.RawMessage,
) error {
	response, err := formalGLMPhase21RockRun(root, true, action, operation)
	if err != nil {
		return fmt.Errorf("formal-glm lifecycle action failed")
	}
	output(response)
	return nil
}
