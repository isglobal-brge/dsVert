package main

// Rock-local command adapter for the formal Cox opening lifecycle. Each
// invocation is confined to one owner-only Rock root. Cross-node exchange is
// limited to the signed typed records defined here; no store handle, secret,
// share, or ciphertext is returned by the command.

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
	"strings"

	"golang.org/x/crypto/hkdf"
)

const (
	formalCoxBlockwiseRockPurpose       = "formal_cox_rock_local_opening_lifecycle_v1"
	formalCoxBlockwiseRockRecordVersion = "dsvert-formal-cox-rock-lifecycle-record-v1"
	formalCoxBlockwiseRockSecretVersion = "dsvert-formal-cox-rock-lifecycle-secret-v1"
	formalCoxBlockwiseRockPinsetVersion = "dsvert-formal-cox-rock-lifecycle-pinset-v1"

	formalCoxBlockwiseRockActionPreflight          = "preflight-local"
	formalCoxBlockwiseRockActionStage              = "stage-local"
	formalCoxBlockwiseRockActionTicket             = "issue-ticket"
	formalCoxBlockwiseRockActionSeal               = "seal-local"
	formalCoxBlockwiseRockActionPrepare            = "prepare-finalizer"
	formalCoxBlockwiseRockActionSign               = "sign-local"
	formalCoxBlockwiseRockActionPreparePublication = "prepare-publication-finalizer"
	formalCoxBlockwiseRockActionCommitPublication  = "commit-publication-local"
	formalCoxBlockwiseRockActionFinalizeAck        = "finalize-ack"
	formalCoxBlockwiseRockActionAck                = "ack-local"

	formalCoxBlockwiseRockPreflightPurpose = "formal_cox_local_artifact_preflight_v1"
	formalCoxBlockwiseRockCommitPurpose    = "formal_cox_local_publication_commit_v1"
	formalCoxBlockwiseRockCleanupPurpose   = "formal_cox_local_transport_cleanup_v1"

	formalCoxBlockwiseRockStateAbsent               = "absent"
	formalCoxBlockwiseRockStateRepairPending        = "repair_pending"
	formalCoxBlockwiseRockStatePublished            = "published"
	formalCoxBlockwiseRockStateStaged               = "staged"
	formalCoxBlockwiseRockStateTicketReady          = "ticket_ready"
	formalCoxBlockwiseRockStateSealed               = "sealed"
	formalCoxBlockwiseRockStateCandidateReady       = "candidate_ready"
	formalCoxBlockwiseRockStateAuthorized           = "authorized"
	formalCoxBlockwiseRockStatePublicationReady     = "publication_ready"
	formalCoxBlockwiseRockStatePublicationCommitted = "publication_committed"
	formalCoxBlockwiseRockStateAckReady             = "ack_ready"
	formalCoxBlockwiseRockStateCleaned              = "cleaned"

	formalCoxBlockwiseRockMaxSecret = 32 << 10
	formalCoxBlockwiseRockMaxRecord = 8 << 20
)

type formalCoxBlockwiseRockLifecycleResponse struct {
	Version           string                             `json:"version"`
	Family            string                             `json:"family"`
	Action            string                             `json:"action"`
	State             string                             `json:"state"`
	ArtifactID        string                             `json:"artifact_id"`
	RecordSHA256      string                             `json:"record_sha256,omitempty"`
	CertificateSHA256 string                             `json:"certificate_sha256,omitempty"`
	Publication       *formalCoxBlockwiseRockPublication `json:"publication,omitempty"`
	Replayed          bool                               `json:"replayed"`
	ProductionReady   bool                               `json:"-"`
}

type formalCoxBlockwiseRockPinset struct {
	Version         string            `json:"version"`
	Family          string            `json:"family"`
	Purpose         string            `json:"purpose"`
	PinnedPublicKey map[string]string `json:"pinned_public_keys"`
}

type formalCoxBlockwiseRockPreflightReceipt struct {
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

type formalCoxBlockwiseRockPublication struct {
	ArtifactID        string `json:"artifact_id"`
	CertificateSHA256 string `json:"certificate_sha256"`
	Certificate       []byte `json:"certificate"`
}

type formalCoxBlockwiseRockPreflightRecord struct {
	Version         string                                 `json:"version"`
	Family          string                                 `json:"family"`
	Purpose         string                                 `json:"purpose"`
	Receipt         formalCoxBlockwiseRockPreflightReceipt `json:"receipt"`
	Publication     *formalCoxBlockwiseRockPublication     `json:"publication,omitempty"`
	ProductionReady bool                                   `json:"-"`
}

type formalCoxBlockwiseRockHeaderRecord struct {
	Version         string                                 `json:"version"`
	Family          string                                 `json:"family"`
	Purpose         string                                 `json:"purpose"`
	ArtifactID      string                                 `json:"artifact_id"`
	Header          formalCoxBlockwiseOpeningHandoffHeader `json:"header"`
	ProductionReady bool                                   `json:"-"`
}

type formalCoxBlockwiseRockTicketRecord struct {
	Version         string                       `json:"version"`
	Family          string                       `json:"family"`
	Purpose         string                       `json:"purpose"`
	ArtifactID      string                       `json:"artifact_id"`
	Ticket          formalFinalizerHandoffTicket `json:"ticket"`
	ProductionReady bool                         `json:"-"`
}

type formalCoxBlockwiseRockEnvelopeRecord struct {
	Version         string                         `json:"version"`
	Family          string                         `json:"family"`
	Purpose         string                         `json:"purpose"`
	ArtifactID      string                         `json:"artifact_id"`
	Role            string                         `json:"role"`
	Envelope        formalFinalizerHandoffEnvelope `json:"envelope"`
	ProductionReady bool                           `json:"-"`
}

type formalCoxBlockwiseRockCandidateRecord struct {
	Version         string                             `json:"version"`
	Family          string                             `json:"family"`
	Purpose         string                             `json:"purpose"`
	ArtifactID      string                             `json:"artifact_id"`
	Candidate       formalCoxBlockwiseOpeningCandidate `json:"candidate"`
	Intent          formalCoxBlockwiseOpeningIntent    `json:"intent"`
	ProductionReady bool                               `json:"-"`
}

type formalCoxBlockwiseRockAuthorizationRecord struct {
	Version         string                                       `json:"version"`
	Family          string                                       `json:"family"`
	Purpose         string                                       `json:"purpose"`
	ArtifactID      string                                       `json:"artifact_id"`
	Role            string                                       `json:"role"`
	Authorization   formalCoxBlockwiseRemoteOpeningAuthorization `json:"authorization"`
	ProductionReady bool                                         `json:"-"`
}

type formalCoxBlockwiseRockPublicationRecord struct {
	Version         string                            `json:"version"`
	Family          string                            `json:"family"`
	Purpose         string                            `json:"purpose"`
	ArtifactID      string                            `json:"artifact_id"`
	Publication     formalCoxBlockwiseRockPublication `json:"publication"`
	ProductionReady bool                              `json:"-"`
}

type formalCoxBlockwiseRockCommitReceipt struct {
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

type formalCoxBlockwiseRockCommitRecord struct {
	Version         string                              `json:"version"`
	Family          string                              `json:"family"`
	Purpose         string                              `json:"purpose"`
	Receipt         formalCoxBlockwiseRockCommitReceipt `json:"receipt"`
	ProductionReady bool                                `json:"-"`
}

type formalCoxBlockwiseRockAckRecord struct {
	Version         string                            `json:"version"`
	Family          string                            `json:"family"`
	Purpose         string                            `json:"purpose"`
	ArtifactID      string                            `json:"artifact_id"`
	Proof           formalFinalizerHandoffCommitProof `json:"proof"`
	ProductionReady bool                              `json:"-"`
}

type formalCoxBlockwiseRockCleanupReceipt struct {
	Version           string `json:"version"`
	Purpose           string `json:"purpose"`
	ArtifactID        string `json:"artifact_id"`
	CertificateSHA256 string `json:"certificate_sha256"`
	PeerName          string `json:"peer_name"`
	PeerID            string `json:"peer_id"`
	Role              string `json:"role"`
	RemovedRecords    int    `json:"removed_records"`
	ProductionReady   bool   `json:"-"`
	Signature         []byte `json:"signature"`
}

type formalCoxBlockwiseRockCleanupRecord struct {
	Version         string                               `json:"version"`
	Family          string                               `json:"family"`
	Purpose         string                               `json:"purpose"`
	Receipt         formalCoxBlockwiseRockCleanupReceipt `json:"receipt"`
	ProductionReady bool                                 `json:"-"`
}

type formalCoxBlockwiseRockPreflightOperation struct {
	ArtifactContractPath  string `json:"artifact_contract_path"`
	PinsetPath            string `json:"pinset_path"`
	OpeningDir            string `json:"opening_dir"`
	PeerName              string `json:"peer_name"`
	SecretBundlePath      string `json:"secret_bundle_path"`
	RecordPath            string `json:"record_path"`
	PublicationRecordPath string `json:"publication_record_path"`
}

type formalCoxBlockwiseRockStageOperation struct {
	ArtifactContractPath string    `json:"artifact_contract_path"`
	PinsetPath           string    `json:"pinset_path"`
	PreflightRecordPaths [2]string `json:"preflight_record_paths"`
	PlanPath             string    `json:"plan_path"`
	PreflightOpeningDir  string    `json:"preflight_opening_dir"`
	CheckpointDir        string    `json:"checkpoint_dir"`
	OpeningDir           string    `json:"opening_dir"`
	PeerName             string    `json:"peer_name"`
	SecretBundlePath     string    `json:"secret_bundle_path"`
	HeaderRecordPath     string    `json:"header_record_path"`
}

type formalCoxBlockwiseRockTicketOperation struct {
	ArtifactContractPath string    `json:"artifact_contract_path"`
	PinsetPath           string    `json:"pinset_path"`
	PreflightRecordPaths [2]string `json:"preflight_record_paths"`
	PlanPath             string    `json:"plan_path"`
	OpeningDir           string    `json:"opening_dir"`
	TransportDir         string    `json:"transport_dir"`
	HeaderRecordPaths    [2]string `json:"header_record_paths"`
	SecretBundlePath     string    `json:"secret_bundle_path"`
	TicketRecordPath     string    `json:"ticket_record_path"`
}

type formalCoxBlockwiseRockSealOperation struct {
	PinsetPath         string    `json:"pinset_path"`
	PlanPath           string    `json:"plan_path"`
	OpeningDir         string    `json:"opening_dir"`
	TransportDir       string    `json:"transport_dir"`
	PeerName           string    `json:"peer_name"`
	HeaderRecordPaths  [2]string `json:"header_record_paths"`
	TicketRecordPath   string    `json:"ticket_record_path"`
	SecretBundlePath   string    `json:"secret_bundle_path"`
	EnvelopeRecordPath string    `json:"envelope_record_path"`
}

type formalCoxBlockwiseRockPrepareOperation struct {
	PinsetPath          string    `json:"pinset_path"`
	PlanPath            string    `json:"plan_path"`
	OpeningDir          string    `json:"opening_dir"`
	TransportDir        string    `json:"transport_dir"`
	HeaderRecordPaths   [2]string `json:"header_record_paths"`
	TicketRecordPath    string    `json:"ticket_record_path"`
	EnvelopeRecordPaths [2]string `json:"envelope_record_paths"`
	SecretBundlePath    string    `json:"secret_bundle_path"`
	CandidateRecordPath string    `json:"candidate_record_path"`
}

type formalCoxBlockwiseRockSignOperation struct {
	PinsetPath                    string    `json:"pinset_path"`
	PlanPath                      string    `json:"plan_path"`
	OpeningDir                    string    `json:"opening_dir"`
	TransportDir                  string    `json:"transport_dir"`
	PeerName                      string    `json:"peer_name"`
	Role                          string    `json:"role"`
	HeaderRecordPaths             [2]string `json:"header_record_paths"`
	TicketRecordPath              string    `json:"ticket_record_path"`
	CandidateRecordPath           string    `json:"candidate_record_path"`
	PredecessorAuthorizationPaths []string  `json:"predecessor_authorization_paths"`
	SecretBundlePath              string    `json:"secret_bundle_path"`
	AuthorizationRecordPath       string    `json:"authorization_record_path"`
}

type formalCoxBlockwiseRockPreparePublicationOperation struct {
	PinsetPath               string    `json:"pinset_path"`
	PlanPath                 string    `json:"plan_path"`
	OpeningDir               string    `json:"opening_dir"`
	TransportDir             string    `json:"transport_dir"`
	HeaderRecordPaths        [2]string `json:"header_record_paths"`
	TicketRecordPath         string    `json:"ticket_record_path"`
	CandidateRecordPath      string    `json:"candidate_record_path"`
	AuthorizationRecordPaths [2]string `json:"authorization_record_paths"`
	SecretBundlePath         string    `json:"secret_bundle_path"`
	PublicationRecordPath    string    `json:"publication_record_path"`
}

type formalCoxBlockwiseRockCommitPublicationOperation struct {
	PinsetPath            string                            `json:"pinset_path"`
	PlanPath              string                            `json:"plan_path"`
	OpeningDir            string                            `json:"opening_dir"`
	PeerName              string                            `json:"peer_name"`
	Role                  string                            `json:"role"`
	Publication           formalCoxBlockwiseRockPublication `json:"publication"`
	PublicationRecordPath string                            `json:"publication_record_path"`
	SecretBundlePath      string                            `json:"secret_bundle_path"`
	CommitRecordPath      string                            `json:"commit_record_path"`
}

type formalCoxBlockwiseRockFinalizeAckOperation struct {
	PinsetPath            string    `json:"pinset_path"`
	PlanPath              string    `json:"plan_path"`
	OpeningDir            string    `json:"opening_dir"`
	TransportDir          string    `json:"transport_dir"`
	HeaderRecordPaths     [2]string `json:"header_record_paths"`
	TicketRecordPath      string    `json:"ticket_record_path"`
	PublicationRecordPath string    `json:"publication_record_path"`
	CommitRecordPaths     [2]string `json:"commit_record_paths"`
	SecretBundlePath      string    `json:"secret_bundle_path"`
	AckRecordPath         string    `json:"ack_record_path"`
}

type formalCoxBlockwiseRockAckOperation struct {
	PinsetPath            string    `json:"pinset_path"`
	PlanPath              string    `json:"plan_path"`
	OpeningDir            string    `json:"opening_dir"`
	TransportDir          string    `json:"transport_dir"`
	PeerName              string    `json:"peer_name"`
	Role                  string    `json:"role"`
	HeaderRecordPaths     [2]string `json:"header_record_paths"`
	TicketRecordPath      string    `json:"ticket_record_path"`
	PublicationRecordPath string    `json:"publication_record_path"`
	AckRecordPath         string    `json:"ack_record_path"`
	SecretBundlePath      string    `json:"secret_bundle_path"`
	CleanupRecordPath     string    `json:"cleanup_record_path"`
}

type formalCoxBlockwiseRockPreflightSecret struct {
	Version            string `json:"version"`
	Family             string `json:"family"`
	Purpose            string `json:"purpose"`
	Action             string `json:"action"`
	OpeningStorageRoot string `json:"opening_storage_root"`
	SigningPrivateKey  string `json:"signing_private_key"`
}

type formalCoxBlockwiseRockStageSecret struct {
	Version                     string `json:"version"`
	Family                      string `json:"family"`
	Purpose                     string `json:"purpose"`
	Action                      string `json:"action"`
	PreflightOpeningStorageRoot string `json:"preflight_opening_storage_root"`
	CheckpointKey               string `json:"checkpoint_key"`
	OpeningStorageRoot          string `json:"opening_storage_root"`
	SigningPrivateKey           string `json:"signing_private_key"`
}

type formalCoxBlockwiseRockTransportSecret struct {
	Version              string `json:"version"`
	Family               string `json:"family"`
	Purpose              string `json:"purpose"`
	Action               string `json:"action"`
	OpeningStorageRoot   string `json:"opening_storage_root"`
	TransportStorageRoot string `json:"transport_storage_root"`
	SigningPrivateKey    string `json:"signing_private_key"`
}

type formalCoxBlockwiseRockContext struct {
	plan       formalCoxBlockwisePlan
	pins       map[string]ed25519.PublicKey
	artifact   formalCoxBlockwiseStickyArtifact
	artifactID string
}

type formalCoxBlockwiseRockPhaseHook func(string) error

func formalCoxBlockwiseRockStrictDecode(encoded []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("formal-cox lifecycle: invalid typed record")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("formal-cox lifecycle: invalid typed record")
	}
	return nil
}

func formalCoxBlockwiseRockOpenRoot(root string) (*os.Root, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
		return nil, fmt.Errorf("formal-cox lifecycle: unsafe Rock root")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || !formalFinalizerHandoffPrivateOwnedDirectory(info) {
		return nil, fmt.Errorf("formal-cox lifecycle: unsafe Rock root")
	}
	return os.OpenRoot(root)
}

func formalCoxBlockwiseRockRelative(root, path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("formal-cox lifecycle: unsafe private path")
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || relative == "" || relative == ".." ||
		len(relative) >= 3 && relative[:3] == ".."+string(filepath.Separator) ||
		filepath.IsAbs(relative) || filepath.Clean(relative) != relative {
		return "", fmt.Errorf("formal-cox lifecycle: private path escaped Rock root")
	}
	return relative, nil
}

func formalCoxBlockwiseRockEnsureDir(root, path string) error {
	relative, err := formalCoxBlockwiseRockRelative(root, path)
	if err != nil {
		return err
	}
	opened, err := formalCoxBlockwiseRockOpenRoot(root)
	if err != nil {
		return err
	}
	defer opened.Close()
	if err := formalCoxBlockwiseGuardEnsureRootDir(opened, relative); err != nil {
		return fmt.Errorf("formal-cox lifecycle: unsafe private directory")
	}
	current := ""
	for _, part := range strings.Split(filepath.ToSlash(relative), "/") {
		if part == "" {
			return fmt.Errorf("formal-cox lifecycle: unsafe private directory")
		}
		current = filepath.Join(current, part)
		info, statErr := opened.Lstat(current)
		if statErr != nil || !formalFinalizerHandoffPrivateOwnedDirectory(info) {
			return fmt.Errorf("formal-cox lifecycle: unsafe private directory")
		}
	}
	return nil
}

func formalCoxBlockwiseRockRead(root, path string, maximum int64) ([]byte, error) {
	relative, err := formalCoxBlockwiseRockRelative(root, path)
	if err != nil {
		return nil, err
	}
	opened, err := formalCoxBlockwiseRockOpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer opened.Close()
	encoded, err := formalCoxBlockwiseGuardRootReadRecord(opened, relative, maximum)
	if err != nil {
		return nil, fmt.Errorf("formal-cox lifecycle: unsafe or missing private record")
	}
	return encoded, nil
}

func formalCoxBlockwiseRockReadJSON(root, path string, maximum int64, value any) error {
	encoded, err := formalCoxBlockwiseRockRead(root, path, maximum)
	if err != nil {
		return err
	}
	defer clear(encoded)
	return formalCoxBlockwiseRockStrictDecode(encoded, value)
}

func formalCoxBlockwiseRockWriteJSON(root, path string, value any) (string, bool, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) < 64 || len(encoded) > formalCoxBlockwiseRockMaxRecord {
		clear(encoded)
		return "", false, fmt.Errorf("formal-cox lifecycle: invalid typed output")
	}
	defer clear(encoded)
	relative, err := formalCoxBlockwiseRockRelative(root, path)
	if err != nil {
		return "", false, err
	}
	opened, err := formalCoxBlockwiseRockOpenRoot(root)
	if err != nil {
		return "", false, err
	}
	defer opened.Close()
	parent := filepath.Dir(relative)
	if parent == "." || formalCoxBlockwiseGuardEnsureRootDir(opened, parent) != nil {
		return "", false, fmt.Errorf("formal-cox lifecycle: unsafe output directory")
	}
	created, err := formalCoxBlockwiseGuardRootCreateRecord(opened, relative, encoded)
	if err != nil {
		return "", false, fmt.Errorf("formal-cox lifecycle: durable output failed")
	}
	existing, err := formalCoxBlockwiseGuardRootReadRecord(
		opened, relative, formalCoxBlockwiseRockMaxRecord)
	if err != nil || !bytes.Equal(existing, encoded) {
		clear(existing)
		return "", false, fmt.Errorf("formal-cox lifecycle: conflicting durable output")
	}
	clear(existing)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), !created, nil
}

func formalCoxBlockwiseRockExists(root, path string) (bool, error) {
	relative, err := formalCoxBlockwiseRockRelative(root, path)
	if err != nil {
		return false, err
	}
	opened, err := formalCoxBlockwiseRockOpenRoot(root)
	if err != nil {
		return false, err
	}
	defer opened.Close()
	info, err := opened.Lstat(relative)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || !exactGCPrivateOwnedRegular(info) {
		return false, fmt.Errorf("formal-cox lifecycle: unsafe private record")
	}
	return true, nil
}

func formalCoxBlockwiseRockRemoveSecret(root, path string) error {
	encoded, err := formalCoxBlockwiseRockRead(
		root, path, formalCoxBlockwiseRockMaxSecret)
	if err != nil {
		if exists, existsErr := formalCoxBlockwiseRockExists(root, path); existsErr == nil && !exists {
			return nil
		}
		return fmt.Errorf("formal-cox lifecycle: secret cleanup refused")
	}
	clear(encoded)
	relative, err := formalCoxBlockwiseRockRelative(root, path)
	if err != nil {
		return err
	}
	opened, err := formalCoxBlockwiseRockOpenRoot(root)
	if err != nil {
		return err
	}
	defer opened.Close()
	if err := opened.Remove(relative); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("formal-cox lifecycle: secret cleanup failed")
	}
	if err := formalCoxBlockwiseGuardRootSyncDir(opened, relative); err != nil {
		return fmt.Errorf("formal-cox lifecycle: secret cleanup sync failed")
	}
	return nil
}

func formalCoxBlockwiseRockDecodeBase64(value string, size int) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != size || base64.StdEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, fmt.Errorf("formal-cox lifecycle: invalid secret bundle")
	}
	zero := true
	for _, item := range decoded {
		zero = zero && item == 0
	}
	if zero {
		clear(decoded)
		return nil, fmt.Errorf("formal-cox lifecycle: invalid secret bundle")
	}
	return decoded, nil
}

func formalCoxBlockwiseRockDecodeRoot(value string) ([32]byte, error) {
	var result [32]byte
	decoded, err := formalCoxBlockwiseRockDecodeBase64(value, len(result))
	if err != nil {
		return result, err
	}
	copy(result[:], decoded)
	clear(decoded)
	return result, nil
}

func formalCoxBlockwiseRockDecodePrivateKey(value string) (ed25519.PrivateKey, error) {
	decoded, err := formalCoxBlockwiseRockDecodeBase64(value, ed25519.PrivateKeySize)
	if err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(decoded), nil
}

func formalCoxBlockwiseRockValidateSecretHeader(version, family, purpose, action,
	wantAction string,
) error {
	if version != formalCoxBlockwiseRockSecretVersion ||
		family != formalFinalizerHandoffFamilyCox ||
		purpose != formalCoxBlockwiseRockPurpose || action != wantAction {
		return fmt.Errorf("formal-cox lifecycle: invalid secret bundle")
	}
	return nil
}

func formalCoxBlockwiseRockLoadPins(root, path string) (map[string]ed25519.PublicKey, error) {
	var record formalCoxBlockwiseRockPinset
	if err := formalCoxBlockwiseRockReadJSON(root, path,
		formalCoxBlockwiseRockMaxRecord, &record); err != nil {
		return nil, err
	}
	if record.Version != formalCoxBlockwiseRockPinsetVersion ||
		record.Family != formalFinalizerHandoffFamilyCox ||
		record.Purpose != formalCoxBlockwiseRockPurpose || len(record.PinnedPublicKey) < 2 {
		return nil, fmt.Errorf("formal-cox lifecycle: invalid pinset")
	}
	pins := make(map[string]ed25519.PublicKey, len(record.PinnedPublicKey))
	for peer, encoded := range record.PinnedPublicKey {
		decoded, err := formalCoxBlockwiseRockDecodeBase64(encoded, ed25519.PublicKeySize)
		if err != nil || peer == "" {
			clear(decoded)
			return nil, fmt.Errorf("formal-cox lifecycle: invalid pinset")
		}
		pins[peer] = ed25519.PublicKey(decoded)
	}
	return pins, nil
}

func formalCoxBlockwiseRockLoadContract(root, path string,
	pins map[string]ed25519.PublicKey,
) (formalCoxBlockwiseSamplerContract, error) {
	var contract formalCoxBlockwiseSamplerContract
	if err := formalCoxBlockwiseRockReadJSON(root, path,
		formalCoxBlockwiseRockMaxRecord, &contract); err != nil {
		return contract, err
	}
	if err := formalCoxBlockwiseValidateSamplerContract(contract, pins); err != nil {
		return contract, fmt.Errorf("formal-cox lifecycle: invalid signed artifact contract")
	}
	return contract, nil
}

func formalCoxBlockwiseRockLoadContext(root, planPath, pinsetPath string) (
	formalCoxBlockwiseRockContext, error,
) {
	var result formalCoxBlockwiseRockContext
	pins, err := formalCoxBlockwiseRockLoadPins(root, pinsetPath)
	if err != nil {
		return result, err
	}
	var plan formalCoxBlockwisePlan
	if err := formalCoxBlockwiseRockReadJSON(root, planPath,
		formalCoxBlockwiseRockMaxRecord, &plan); err != nil {
		return result, err
	}
	artifact, artifactID, err := formalCoxBlockwiseBuildStickyArtifact(plan, pins)
	if err != nil {
		return result, fmt.Errorf("formal-cox lifecycle: invalid scientific plan")
	}
	return formalCoxBlockwiseRockContext{
		plan: plan, pins: pins, artifact: artifact, artifactID: artifactID,
	}, nil
}

func formalCoxBlockwiseRockPublicationFromOpening(
	publication formalCoxBlockwiseOpeningPublication,
) formalCoxBlockwiseRockPublication {
	return formalCoxBlockwiseRockPublication{
		ArtifactID: publication.ArtifactID, CertificateSHA256: publication.CertificateSHA256,
		Certificate: append([]byte(nil), publication.Certificate...),
	}
}

func formalCoxBlockwiseRockPublicationToOpening(
	publication formalCoxBlockwiseRockPublication,
) formalCoxBlockwiseOpeningPublication {
	return formalCoxBlockwiseOpeningPublication{
		ArtifactID: publication.ArtifactID, CertificateSHA256: publication.CertificateSHA256,
		Certificate: append([]byte(nil), publication.Certificate...), Replayed: true,
	}
}

func newFormalCoxBlockwiseOpeningReplayStore(dir string, storageRoot [32]byte,
	artifact formalCoxBlockwiseStickyArtifact, artifactID string,
	pins map[string]ed25519.PublicKey,
) (*formalCoxBlockwiseOpeningStore, error) {
	var zero [32]byte
	wantID, err := formalCoxBlockwiseStickyArtifactID(artifact)
	if err != nil || wantID != artifactID ||
		formalCoxBlockwiseValidateStickyArtifact(artifact, pins) != nil ||
		hmac.Equal(storageRoot[:], zero[:]) {
		return nil, fmt.Errorf("formal-cox lifecycle: invalid replay store")
	}
	if err := formalCoxBlockwiseSourceEnsurePrivateDir(dir); err != nil {
		return nil, fmt.Errorf("formal-cox lifecycle: invalid replay store")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	if err := formalCoxBlockwiseGuardEnsureRootDir(root, "public-v1"); err != nil {
		_ = root.Close()
		return nil, err
	}
	artifactBytes, err := hex.DecodeString(artifactID)
	if err != nil || len(artifactBytes) != sha256.Size {
		clear(artifactBytes)
		_ = root.Close()
		return nil, fmt.Errorf("formal-cox lifecycle: invalid replay store")
	}
	reader := hkdf.New(sha256.New, storageRoot[:], artifactBytes,
		[]byte(formalCoxBlockwiseOpeningDomain+"/owner-store-key"))
	clear(artifactBytes)
	var key [32]byte
	if _, err := io.ReadFull(reader, key[:]); err != nil || hmac.Equal(key[:], zero[:]) {
		clear(key[:])
		_ = root.Close()
		return nil, fmt.Errorf("formal-cox lifecycle: invalid replay store")
	}
	copyPins := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		copyPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	return &formalCoxBlockwiseOpeningStore{
		root: root, key: key, pins: copyPins, artifact: artifact, artifactID: artifactID,
	}, nil
}

func formalCoxBlockwiseRockPreflightMessage(
	receipt formalCoxBlockwiseRockPreflightReceipt,
) ([]byte, error) {
	receipt.Signature = nil
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalCoxBlockwiseOpeningDomain+"/rock-preflight|"), encoded...), nil
}

func formalCoxBlockwiseRockValidatePreflightReceipt(
	receipt formalCoxBlockwiseRockPreflightReceipt,
	contract formalCoxBlockwiseSamplerContract, pins map[string]ed25519.PublicKey,
) error {
	position := -1
	for index, authority := range contract.Artifact.NoiseAuthorities {
		if authority.PeerName == receipt.PeerName {
			position = index
		}
	}
	message, err := formalCoxBlockwiseRockPreflightMessage(receipt)
	if err != nil || position < 0 || receipt.Version != formalCoxBlockwiseRockRecordVersion ||
		receipt.Purpose != formalCoxBlockwiseRockPreflightPurpose ||
		receipt.ArtifactID != contract.ArtifactID ||
		receipt.PinsetSHA256 != contract.PinsetSHA256 || receipt.ProductionReady ||
		receipt.PeerID != contract.Artifact.NoiseAuthorities[position].PeerID ||
		receipt.Role != contract.Artifact.NoiseAuthorities[position].Role ||
		(receipt.State != formalCoxBlockwiseRockStateAbsent &&
			receipt.State != formalCoxBlockwiseRockStatePublished) ||
		receipt.State == formalCoxBlockwiseRockStateAbsent && receipt.CertificateSHA256 != "" ||
		receipt.State == formalCoxBlockwiseRockStatePublished &&
			!formalCoxIsSHA256(receipt.CertificateSHA256) ||
		len(receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pins[receipt.PeerName], message, receipt.Signature) {
		return fmt.Errorf("formal-cox lifecycle: invalid preflight receipt")
	}
	return nil
}

func formalCoxBlockwiseRockLoadPreflightRecord(root, path string,
	contract formalCoxBlockwiseSamplerContract, pins map[string]ed25519.PublicKey,
) (formalCoxBlockwiseRockPreflightRecord, error) {
	var record formalCoxBlockwiseRockPreflightRecord
	if err := formalCoxBlockwiseRockReadJSON(root, path,
		formalCoxBlockwiseRockMaxRecord, &record); err != nil {
		return record, err
	}
	if record.Version != formalCoxBlockwiseRockRecordVersion ||
		record.Family != formalFinalizerHandoffFamilyCox ||
		record.Purpose != formalCoxBlockwiseRockPreflightPurpose ||
		record.ProductionReady ||
		formalCoxBlockwiseRockValidatePreflightReceipt(record.Receipt, contract, pins) != nil {
		return record, fmt.Errorf("formal-cox lifecycle: invalid preflight record")
	}
	if record.Receipt.State == formalCoxBlockwiseRockStateAbsent {
		if record.Publication != nil {
			return record, fmt.Errorf("formal-cox lifecycle: absent receipt carried publication")
		}
		return record, nil
	}
	if record.Publication == nil || record.Publication.ArtifactID != contract.ArtifactID ||
		record.Publication.CertificateSHA256 != record.Receipt.CertificateSHA256 {
		return record, fmt.Errorf("formal-cox lifecycle: published receipt lacks certificate")
	}
	publication := formalCoxBlockwiseRockPublicationToOpening(*record.Publication)
	if _, err := formalCoxBlockwiseDecodeOpeningPublication(publication, pins); err != nil {
		return record, fmt.Errorf("formal-cox lifecycle: invalid preflight publication")
	}
	return record, nil
}

func formalCoxBlockwiseRockLoadPreflightPair(root string, paths [2]string,
	contract formalCoxBlockwiseSamplerContract, pins map[string]ed25519.PublicKey,
) ([2]formalCoxBlockwiseRockPreflightRecord, string, error) {
	var records [2]formalCoxBlockwiseRockPreflightRecord
	for index := range records {
		record, err := formalCoxBlockwiseRockLoadPreflightRecord(
			root, paths[index], contract, pins)
		if err != nil {
			return records, "", err
		}
		authority := contract.Artifact.NoiseAuthorities[index]
		if record.Receipt.PeerName != authority.PeerName || record.Receipt.Role != authority.Role {
			return records, "", fmt.Errorf("formal-cox lifecycle: reordered preflight receipts")
		}
		records[index] = record
	}
	if records[0].Receipt.State != records[1].Receipt.State {
		published := 0
		if records[1].Receipt.State == formalCoxBlockwiseRockStatePublished {
			published = 1
		}
		if records[published].Publication == nil {
			return records, "", fmt.Errorf("formal-cox lifecycle: invalid repair publication")
		}
		return records, formalCoxBlockwiseRockStateRepairPending, nil
	}
	if records[0].Receipt.State == formalCoxBlockwiseRockStatePublished {
		left, right := records[0].Publication, records[1].Publication
		if left == nil || right == nil || left.CertificateSHA256 != right.CertificateSHA256 ||
			!bytes.Equal(left.Certificate, right.Certificate) {
			return records, "", fmt.Errorf("formal-cox lifecycle: conflicting publication preflight")
		}
		return records, formalCoxBlockwiseRockStatePublished, nil
	}
	return records, formalCoxBlockwiseRockStateAbsent, nil
}

func formalCoxBlockwiseRockRunPreflight(root string, production bool,
	operation formalCoxBlockwiseRockPreflightOperation, hook formalCoxBlockwiseRockPhaseHook,
) (formalCoxBlockwiseRockLifecycleResponse, error) {
	pins, err := formalCoxBlockwiseRockLoadPins(root, operation.PinsetPath)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	contract, err := formalCoxBlockwiseRockLoadContract(root, operation.ArtifactContractPath, pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	localAuthority, err := formalCoxBlockwiseRockAuthority(
		contract.Artifact, operation.PeerName)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	guard, err := formalCoxBlockwiseRockAcquireGuard(
		root, contract.ArtifactID, localAuthority, production)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer guard.Close()
	var secret formalCoxBlockwiseRockPreflightSecret
	if err := formalCoxBlockwiseRockReadJSON(root, operation.SecretBundlePath,
		formalCoxBlockwiseRockMaxSecret, &secret); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if err := formalCoxBlockwiseRockValidateSecretHeader(secret.Version, secret.Family,
		secret.Purpose, secret.Action, formalCoxBlockwiseRockActionPreflight); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	storageRoot, err := formalCoxBlockwiseRockDecodeRoot(secret.OpeningStorageRoot)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	privateKey, err := formalCoxBlockwiseRockDecodePrivateKey(secret.SigningPrivateKey)
	secret.OpeningStorageRoot, secret.SigningPrivateKey = "", ""
	defer clear(storageRoot[:])
	defer clear(privateKey)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	authorityIndex := -1
	for index, authority := range contract.Artifact.NoiseAuthorities {
		if authority.PeerName == operation.PeerName {
			authorityIndex = index
		}
	}
	if authorityIndex < 0 || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		pins[operation.PeerName]) {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: invalid local preflight authority")
	}
	if err := formalCoxBlockwiseRockEnsureDir(root, operation.OpeningDir); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	store, err := newFormalCoxBlockwiseOpeningReplayStore(operation.OpeningDir,
		storageRoot, contract.Artifact, contract.ArtifactID, pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer store.Close()
	state := formalCoxBlockwiseRockStateAbsent
	certificateSHA := ""
	var publication *formalCoxBlockwiseRockPublication
	if existing, replayErr := store.Replay(contract.ArtifactID); replayErr == nil {
		state, certificateSHA = formalCoxBlockwiseRockStatePublished, existing.CertificateSHA256
		converted := formalCoxBlockwiseRockPublicationFromOpening(existing)
		publication = &converted
	} else if !os.IsNotExist(replayErr) {
		return formalCoxBlockwiseRockLifecycleResponse{}, replayErr
	}
	authority := contract.Artifact.NoiseAuthorities[authorityIndex]
	receipt := formalCoxBlockwiseRockPreflightReceipt{
		Version:    formalCoxBlockwiseRockRecordVersion,
		Purpose:    formalCoxBlockwiseRockPreflightPurpose,
		ArtifactID: contract.ArtifactID, PinsetSHA256: contract.PinsetSHA256,
		PeerName: authority.PeerName, PeerID: authority.PeerID, Role: authority.Role,
		State: state, CertificateSHA256: certificateSHA, ProductionReady: false,
	}
	message, err := formalCoxBlockwiseRockPreflightMessage(receipt)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	receipt.Signature = ed25519.Sign(privateKey, message)
	record := formalCoxBlockwiseRockPreflightRecord{
		Version: formalCoxBlockwiseRockRecordVersion,
		Family:  formalFinalizerHandoffFamilyCox,
		Purpose: formalCoxBlockwiseRockPreflightPurpose,
		Receipt: receipt, Publication: publication, ProductionReady: false,
	}
	if hook != nil {
		if err := hook("after_preflight_before_record"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	digest, replayed, err := formalCoxBlockwiseRockWriteJSON(root, operation.RecordPath, record)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if publication != nil {
		publicationRecord := formalCoxBlockwiseRockPublicationRecord{
			Version:    formalCoxBlockwiseRockRecordVersion,
			Family:     formalFinalizerHandoffFamilyCox,
			Purpose:    formalCoxBlockwiseRockPurpose,
			ArtifactID: contract.ArtifactID, Publication: *publication,
			ProductionReady: false,
		}
		_, publicationReplayed, err := formalCoxBlockwiseRockWriteJSON(
			root, operation.PublicationRecordPath, publicationRecord)
		if err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		replayed = replayed || publicationReplayed
	}
	if err := formalCoxBlockwiseRockRemoveSecret(root, operation.SecretBundlePath); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	return formalCoxBlockwiseRockLifecycleResponse{
		Version: formalTypedFinalizerLifecycleVersion,
		Family:  formalFinalizerHandoffFamilyCox,
		Action:  formalCoxBlockwiseRockActionPreflight,
		State:   state, ArtifactID: contract.ArtifactID, RecordSHA256: digest,
		CertificateSHA256: certificateSHA, Publication: publication,
		Replayed: replayed, ProductionReady: false,
	}, nil
}

func formalCoxBlockwiseRockPairSHA256(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	clear(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxBlockwiseRockRunStage(root string, production bool,
	operation formalCoxBlockwiseRockStageOperation, hook formalCoxBlockwiseRockPhaseHook,
) (formalCoxBlockwiseRockLifecycleResponse, error) {
	pins, err := formalCoxBlockwiseRockLoadPins(root, operation.PinsetPath)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	contract, err := formalCoxBlockwiseRockLoadContract(
		root, operation.ArtifactContractPath, pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	localAuthority, err := formalCoxBlockwiseRockAuthority(
		contract.Artifact, operation.PeerName)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	guard, err := formalCoxBlockwiseRockAcquireGuard(
		root, contract.ArtifactID, localAuthority, production)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer guard.Close()
	preflight, state, err := formalCoxBlockwiseRockLoadPreflightPair(
		root, operation.PreflightRecordPaths, contract, pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	pairSHA, err := formalCoxBlockwiseRockPairSHA256(preflight)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if state != formalCoxBlockwiseRockStateAbsent {
		published := 0
		if preflight[0].Receipt.State != formalCoxBlockwiseRockStatePublished {
			published = 1
		}
		if err := formalCoxBlockwiseRockRemoveSecret(root,
			operation.SecretBundlePath); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		return formalCoxBlockwiseRockLifecycleResponse{
			Version:    formalTypedFinalizerLifecycleVersion,
			Family:     formalFinalizerHandoffFamilyCox,
			Action:     formalCoxBlockwiseRockActionStage,
			State:      state,
			ArtifactID: contract.ArtifactID, RecordSHA256: pairSHA,
			CertificateSHA256: preflight[published].Receipt.CertificateSHA256,
			Publication:       preflight[published].Publication,
			Replayed:          true, ProductionReady: false,
		}, nil
	}
	var secret formalCoxBlockwiseRockStageSecret
	if err := formalCoxBlockwiseRockReadJSON(root, operation.SecretBundlePath,
		formalCoxBlockwiseRockMaxSecret, &secret); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if err := formalCoxBlockwiseRockValidateSecretHeader(secret.Version, secret.Family,
		secret.Purpose, secret.Action, formalCoxBlockwiseRockActionStage); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	preflightRoot, err := formalCoxBlockwiseRockDecodeRoot(
		secret.PreflightOpeningStorageRoot)
	secret.PreflightOpeningStorageRoot = ""
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer clear(preflightRoot[:])
	if err := formalCoxBlockwiseRockEnsureDir(root,
		operation.PreflightOpeningDir); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	replayStore, err := newFormalCoxBlockwiseOpeningReplayStore(
		operation.PreflightOpeningDir, preflightRoot,
		contract.Artifact, contract.ArtifactID, pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	publication, replayErr := replayStore.Replay(contract.ArtifactID)
	closeErr := replayStore.Close()
	if replayErr == nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, fmt.Errorf(
			"formal-cox lifecycle: stale absence preflight after publication")
	}
	if !os.IsNotExist(replayErr) {
		return formalCoxBlockwiseRockLifecycleResponse{}, replayErr
	}
	if closeErr != nil || publication.CertificateSHA256 != "" {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: local publication preflight failed")
	}
	// Only now, after both signed absence receipts and a fresh local replay
	// lookup, may an attempt-specific plan or checkpoint be inspected.
	if hook != nil {
		if err := hook("before_run_plan"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	context, err := formalCoxBlockwiseRockLoadContext(
		root, operation.PlanPath, operation.PinsetPath)
	if err != nil || context.artifactID != contract.ArtifactID ||
		!formalCoxBlockwiseOpeningEqual(context.artifact, contract.Artifact) {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: run plan changed canonical artifact")
	}
	checkpointKey, err := formalCoxBlockwiseRockDecodeRoot(secret.CheckpointKey)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	openingRoot, err := formalCoxBlockwiseRockDecodeRoot(secret.OpeningStorageRoot)
	if err != nil {
		clear(checkpointKey[:])
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	privateKey, err := formalCoxBlockwiseRockDecodePrivateKey(secret.SigningPrivateKey)
	secret.CheckpointKey, secret.OpeningStorageRoot, secret.SigningPrivateKey = "", "", ""
	defer clear(checkpointKey[:])
	defer clear(openingRoot[:])
	defer clear(privateKey)
	if err != nil || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		context.pins[operation.PeerName]) {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: invalid stage authority")
	}
	if err := formalCoxBlockwiseRockEnsureDir(root, operation.CheckpointDir); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if err := formalCoxBlockwiseRockEnsureDir(root, operation.OpeningDir); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("before_checkpoint_open"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	checkpoint, err := newFormalCoxBlockwiseCheckpointStore(
		operation.CheckpointDir, checkpointKey, context.plan, operation.PeerName)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	opening, err := newFormalCoxBlockwiseOpeningStore(
		operation.OpeningDir, openingRoot, context.plan, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer opening.Close()
	if hook != nil {
		if err := hook("before_stage_submit"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	header, replayed, err := opening.SubmitLocal(checkpoint, privateKey)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	record := formalCoxBlockwiseRockHeaderRecord{
		Version:    formalCoxBlockwiseRockRecordVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Purpose:    formalCoxBlockwiseRockPurpose,
		ArtifactID: context.artifactID, Header: header, ProductionReady: false,
	}
	if hook != nil {
		if err := hook("after_stage_durable"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	digest, recordReplayed, err := formalCoxBlockwiseRockWriteJSON(
		root, operation.HeaderRecordPath, record)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if err := formalCoxBlockwiseRockRemoveSecret(root,
		operation.SecretBundlePath); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	return formalCoxBlockwiseRockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Action:     formalCoxBlockwiseRockActionStage,
		State:      formalCoxBlockwiseRockStateStaged,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		Replayed: replayed || recordReplayed, ProductionReady: false,
	}, nil
}

func formalCoxBlockwiseRockLoadHeaders(root string, paths [2]string,
	context formalCoxBlockwiseRockContext,
) ([2]formalCoxBlockwiseOpeningHandoffHeader, error) {
	var headers [2]formalCoxBlockwiseOpeningHandoffHeader
	for index, path := range paths {
		var record formalCoxBlockwiseRockHeaderRecord
		if err := formalCoxBlockwiseRockReadJSON(root, path,
			formalCoxBlockwiseRockMaxRecord, &record); err != nil {
			return headers, err
		}
		authority := context.artifact.NoiseAuthorities[index]
		if record.Version != formalCoxBlockwiseRockRecordVersion ||
			record.Family != formalFinalizerHandoffFamilyCox ||
			record.Purpose != formalCoxBlockwiseRockPurpose || record.ProductionReady ||
			record.ArtifactID != context.artifactID ||
			record.Header.ArtifactID != context.artifactID ||
			record.Header.PeerName != authority.PeerName ||
			record.Header.PeerID != authority.PeerID || record.Header.Role != authority.Role {
			return headers, fmt.Errorf("formal-cox lifecycle: invalid ordered header record")
		}
		headers[index] = record.Header
	}
	return headers, nil
}

func formalCoxBlockwiseRockLoadTicket(root, path string,
	binding formalFinalizerHandoffBinding, pins map[string]ed25519.PublicKey,
) (formalFinalizerHandoffTicket, error) {
	var record formalCoxBlockwiseRockTicketRecord
	if err := formalCoxBlockwiseRockReadJSON(root, path,
		formalCoxBlockwiseRockMaxRecord, &record); err != nil {
		return record.Ticket, err
	}
	if record.Version != formalCoxBlockwiseRockRecordVersion ||
		record.Family != formalFinalizerHandoffFamilyCox ||
		record.Purpose != formalCoxBlockwiseRockPurpose || record.ProductionReady ||
		record.ArtifactID != binding.ArtifactID ||
		formalFinalizerHandoffValidateTicket(record.Ticket, binding, pins) != nil {
		return record.Ticket, fmt.Errorf("formal-cox lifecycle: invalid ticket record")
	}
	return record.Ticket, nil
}

func formalCoxBlockwiseRockAuthority(
	artifact formalCoxBlockwiseStickyArtifact, peer string,
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
		fmt.Errorf("formal-cox lifecycle: unknown local authority")
}

func formalCoxBlockwiseRockAcquireGuard(root, artifactID string,
	local formalFinalizerHandoffAuthority, production bool,
) (*formalFinalizerHandoffAuthorityGuard, error) {
	return newFormalFinalizerHandoffAuthorityGuard(
		root, artifactID, local, production)
}

func formalCoxBlockwiseRockOpenTransportStore(
	guard *formalFinalizerHandoffAuthorityGuard,
	binding formalFinalizerHandoffBinding, storageRoot [32]byte,
	pins map[string]ed25519.PublicKey,
) (*formalFinalizerHandoffStore, error) {
	return openFormalFinalizerHandoffAuthorityStoreWithGuard(
		guard, binding, storageRoot, pins)
}

func formalCoxBlockwiseRockLoadTransportSecret(root, path, action string) (
	[32]byte, [32]byte, ed25519.PrivateKey, error,
) {
	var zero [32]byte
	var secret formalCoxBlockwiseRockTransportSecret
	if err := formalCoxBlockwiseRockReadJSON(root, path,
		formalCoxBlockwiseRockMaxSecret, &secret); err != nil {
		return zero, zero, nil, err
	}
	if err := formalCoxBlockwiseRockValidateSecretHeader(secret.Version, secret.Family,
		secret.Purpose, secret.Action, action); err != nil {
		return zero, zero, nil, err
	}
	openingRoot, err := formalCoxBlockwiseRockDecodeRoot(secret.OpeningStorageRoot)
	if err != nil {
		return zero, zero, nil, err
	}
	transportRoot, err := formalCoxBlockwiseRockDecodeRoot(secret.TransportStorageRoot)
	if err != nil {
		clear(openingRoot[:])
		return zero, zero, nil, err
	}
	privateKey, err := formalCoxBlockwiseRockDecodePrivateKey(secret.SigningPrivateKey)
	secret.OpeningStorageRoot, secret.TransportStorageRoot, secret.SigningPrivateKey = "", "", ""
	if err != nil {
		clear(openingRoot[:])
		clear(transportRoot[:])
		return zero, zero, nil, err
	}
	return openingRoot, transportRoot, privateKey, nil
}

func formalCoxBlockwiseRockLoadOpeningSecret(root, path, action string) (
	[32]byte, ed25519.PrivateKey, error,
) {
	var zero [32]byte
	var secret formalCoxBlockwiseRockPreflightSecret
	if err := formalCoxBlockwiseRockReadJSON(root, path,
		formalCoxBlockwiseRockMaxSecret, &secret); err != nil {
		return zero, nil, err
	}
	if err := formalCoxBlockwiseRockValidateSecretHeader(secret.Version, secret.Family,
		secret.Purpose, secret.Action, action); err != nil {
		return zero, nil, err
	}
	openingRoot, err := formalCoxBlockwiseRockDecodeRoot(secret.OpeningStorageRoot)
	if err != nil {
		return zero, nil, err
	}
	privateKey, err := formalCoxBlockwiseRockDecodePrivateKey(secret.SigningPrivateKey)
	secret.OpeningStorageRoot, secret.SigningPrivateKey = "", ""
	if err != nil {
		clear(openingRoot[:])
		return zero, nil, err
	}
	return openingRoot, privateKey, nil
}

func formalCoxBlockwiseRockRunTicket(root string, production bool,
	operation formalCoxBlockwiseRockTicketOperation, hook formalCoxBlockwiseRockPhaseHook,
) (formalCoxBlockwiseRockLifecycleResponse, error) {
	pins, err := formalCoxBlockwiseRockLoadPins(root, operation.PinsetPath)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	contract, err := formalCoxBlockwiseRockLoadContract(
		root, operation.ArtifactContractPath, pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	localAuthority, err := formalCoxBlockwiseRockAuthority(
		contract.Artifact, contract.Artifact.NoiseAuthorities[0].PeerName)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	guard, err := formalCoxBlockwiseRockAcquireGuard(
		root, contract.ArtifactID, localAuthority, production)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer guard.Close()
	_, state, err := formalCoxBlockwiseRockLoadPreflightPair(
		root, operation.PreflightRecordPaths, contract, pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if state != formalCoxBlockwiseRockStateAbsent {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: published artifact cannot issue ticket")
	}
	openingRoot, transportRoot, privateKey, err :=
		formalCoxBlockwiseRockLoadTransportSecret(
			root, operation.SecretBundlePath, formalCoxBlockwiseRockActionTicket)
	defer clear(openingRoot[:])
	defer clear(transportRoot[:])
	defer clear(privateKey)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if err := formalCoxBlockwiseRockEnsureDir(root, operation.OpeningDir); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	replayStore, err := newFormalCoxBlockwiseOpeningReplayStore(
		operation.OpeningDir, openingRoot, contract.Artifact, contract.ArtifactID, pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	_, replayErr := replayStore.Replay(contract.ArtifactID)
	closeErr := replayStore.Close()
	if replayErr == nil {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: canonical publication already exists")
	}
	if !os.IsNotExist(replayErr) || closeErr != nil {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: publication preflight failed")
	}
	if hook != nil {
		if err := hook("before_ticket_run_plan"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	context, err := formalCoxBlockwiseRockLoadContext(
		root, operation.PlanPath, operation.PinsetPath)
	if err != nil || context.artifactID != contract.ArtifactID ||
		!formalCoxBlockwiseOpeningEqual(context.artifact, contract.Artifact) {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: ticket plan changed canonical artifact")
	}
	finalizer, err := newFormalCoxBlockwiseOpeningStore(
		operation.OpeningDir, openingRoot, context.plan, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer finalizer.Close()
	headers, err := formalCoxBlockwiseRockLoadHeaders(
		root, operation.HeaderRecordPaths, context)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	binding, err := formalCoxBlockwiseOpeningFinalizerBinding(finalizer, headers)
	if err != nil || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		context.pins[binding.Finalizer.PeerName]) {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: invalid ticket issuer")
	}
	if operation.TransportDir != root {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: transport left local Rock")
	}
	transport, err := formalCoxBlockwiseRockOpenTransportStore(
		guard, binding, transportRoot, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer transport.Close()
	if hook != nil {
		if err := hook("before_ticket_issue"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	ticket, secret, replayed, err := transport.IssueTicketOnce(privateKey)
	clear(secret)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	record := formalCoxBlockwiseRockTicketRecord{
		Version:    formalCoxBlockwiseRockRecordVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Purpose:    formalCoxBlockwiseRockPurpose,
		ArtifactID: context.artifactID, Ticket: ticket, ProductionReady: false,
	}
	if hook != nil {
		if err := hook("after_ticket_durable"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	digest, recordReplayed, err := formalCoxBlockwiseRockWriteJSON(
		root, operation.TicketRecordPath, record)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if err := formalCoxBlockwiseRockRemoveSecret(root,
		operation.SecretBundlePath); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	return formalCoxBlockwiseRockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Action:     formalCoxBlockwiseRockActionTicket,
		State:      formalCoxBlockwiseRockStateTicketReady,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		Replayed: replayed || recordReplayed, ProductionReady: false,
	}, nil
}

func formalCoxBlockwiseRockLoadEnvelopes(root string, paths [2]string,
	binding formalFinalizerHandoffBinding, ticket formalFinalizerHandoffTicket,
	pins map[string]ed25519.PublicKey,
) ([2]formalFinalizerHandoffEnvelope, error) {
	var envelopes [2]formalFinalizerHandoffEnvelope
	for index, path := range paths {
		var record formalCoxBlockwiseRockEnvelopeRecord
		if err := formalCoxBlockwiseRockReadJSON(root, path,
			formalCoxBlockwiseRockMaxRecord, &record); err != nil {
			return envelopes, err
		}
		role := []string{"garbler", "evaluator"}[index]
		if record.Version != formalCoxBlockwiseRockRecordVersion ||
			record.Family != formalFinalizerHandoffFamilyCox ||
			record.Purpose != formalCoxBlockwiseRockPurpose || record.ProductionReady ||
			record.ArtifactID != binding.ArtifactID || record.Role != role ||
			record.Envelope.SenderRole != role ||
			formalFinalizerHandoffValidateEnvelope(
				binding, ticket, record.Envelope, pins) != nil {
			return envelopes, fmt.Errorf("formal-cox lifecycle: invalid ordered envelope record")
		}
		envelopes[index] = record.Envelope
	}
	return envelopes, nil
}

func formalCoxBlockwiseRockRunSeal(root string, production bool,
	operation formalCoxBlockwiseRockSealOperation, hook formalCoxBlockwiseRockPhaseHook,
) (formalCoxBlockwiseRockLifecycleResponse, error) {
	context, err := formalCoxBlockwiseRockLoadContext(
		root, operation.PlanPath, operation.PinsetPath)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	localAuthority, err := formalCoxBlockwiseRockAuthority(
		context.artifact, operation.PeerName)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	guard, err := formalCoxBlockwiseRockAcquireGuard(
		root, context.artifactID, localAuthority, production)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer guard.Close()
	openingRoot, transportRoot, privateKey, err :=
		formalCoxBlockwiseRockLoadTransportSecret(
			root, operation.SecretBundlePath, formalCoxBlockwiseRockActionSeal)
	defer clear(openingRoot[:])
	defer clear(transportRoot[:])
	defer clear(privateKey)
	if err != nil || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		context.pins[operation.PeerName]) {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: invalid sealing authority")
	}
	if err := formalCoxBlockwiseRockEnsureDir(root, operation.OpeningDir); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	local, err := newFormalCoxBlockwiseOpeningStore(
		operation.OpeningDir, openingRoot, context.plan, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer local.Close()
	headers, err := formalCoxBlockwiseRockLoadHeaders(
		root, operation.HeaderRecordPaths, context)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	binding, err := formalCoxBlockwiseOpeningFinalizerBinding(local, headers)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	ticket, err := formalCoxBlockwiseRockLoadTicket(
		root, operation.TicketRecordPath, binding, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	role, err := local.roleForPeer(operation.PeerName)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	boundAuthority, err := formalFinalizerHandoffPeer(binding, role)
	if err != nil || !formalFinalizerHandoffAuthorityEqual(
		boundAuthority, localAuthority) {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: local transport authority mismatch")
	}
	if operation.TransportDir != root {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: transport left local Rock")
	}
	outbox, err := formalCoxBlockwiseRockOpenTransportStore(
		guard, binding, transportRoot, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer outbox.Close()
	if hook != nil {
		if err := hook("before_seal_commit"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	envelope, replayed, err := formalCoxBlockwiseSealLocalOpening(
		local, outbox, ticket, headers, operation.PeerName, privateKey)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	record := formalCoxBlockwiseRockEnvelopeRecord{
		Version:    formalCoxBlockwiseRockRecordVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Purpose:    formalCoxBlockwiseRockPurpose,
		ArtifactID: context.artifactID, Role: role,
		Envelope: envelope, ProductionReady: false,
	}
	if hook != nil {
		if err := hook("after_seal_durable"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	digest, recordReplayed, err := formalCoxBlockwiseRockWriteJSON(
		root, operation.EnvelopeRecordPath, record)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if err := formalCoxBlockwiseRockRemoveSecret(root,
		operation.SecretBundlePath); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	return formalCoxBlockwiseRockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Action:     formalCoxBlockwiseRockActionSeal,
		State:      formalCoxBlockwiseRockStateSealed,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		Replayed: replayed || recordReplayed, ProductionReady: false,
	}, nil
}

func formalCoxBlockwiseRockRunPrepare(root string, production bool,
	operation formalCoxBlockwiseRockPrepareOperation, hook formalCoxBlockwiseRockPhaseHook,
) (formalCoxBlockwiseRockLifecycleResponse, error) {
	context, err := formalCoxBlockwiseRockLoadContext(
		root, operation.PlanPath, operation.PinsetPath)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	localAuthority, err := formalCoxBlockwiseRockAuthority(
		context.artifact, context.artifact.NoiseAuthorities[0].PeerName)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	guard, err := formalCoxBlockwiseRockAcquireGuard(
		root, context.artifactID, localAuthority, production)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer guard.Close()
	openingRoot, transportRoot, privateKey, err :=
		formalCoxBlockwiseRockLoadTransportSecret(
			root, operation.SecretBundlePath, formalCoxBlockwiseRockActionPrepare)
	defer clear(openingRoot[:])
	defer clear(transportRoot[:])
	defer clear(privateKey)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if err := formalCoxBlockwiseRockEnsureDir(root, operation.OpeningDir); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	finalizer, err := newFormalCoxBlockwiseOpeningStore(
		operation.OpeningDir, openingRoot, context.plan, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer finalizer.Close()
	// This ArtifactID lookup precedes every run header, pair root, ticket,
	// envelope, transport decrypt, and candidate opening.
	if publication, replayErr := finalizer.Replay(context.artifactID); replayErr == nil {
		if err := formalCoxBlockwiseRockRemoveSecret(root,
			operation.SecretBundlePath); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		return formalCoxBlockwiseRockLifecycleResponse{
			Version:           formalTypedFinalizerLifecycleVersion,
			Family:            formalFinalizerHandoffFamilyCox,
			Action:            formalCoxBlockwiseRockActionPrepare,
			State:             formalCoxBlockwiseRockStatePublished,
			ArtifactID:        context.artifactID,
			RecordSHA256:      publication.CertificateSHA256,
			CertificateSHA256: publication.CertificateSHA256,
			Replayed:          true, ProductionReady: false,
		}, nil
	} else if !os.IsNotExist(replayErr) {
		return formalCoxBlockwiseRockLifecycleResponse{}, replayErr
	}
	headers, err := formalCoxBlockwiseRockLoadHeaders(
		root, operation.HeaderRecordPaths, context)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	binding, err := formalCoxBlockwiseOpeningFinalizerBinding(finalizer, headers)
	if err != nil || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		context.pins[binding.Finalizer.PeerName]) ||
		!formalFinalizerHandoffAuthorityEqual(binding.Finalizer, localAuthority) {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: invalid finalizer authority")
	}
	ticket, err := formalCoxBlockwiseRockLoadTicket(
		root, operation.TicketRecordPath, binding, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	envelopes, err := formalCoxBlockwiseRockLoadEnvelopes(
		root, operation.EnvelopeRecordPaths, binding, ticket, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if operation.TransportDir != root {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: transport left local Rock")
	}
	ingress, err := formalCoxBlockwiseRockOpenTransportStore(
		guard, binding, transportRoot, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer ingress.Close()
	if _, found, err := formalCoxBlockwiseOpeningDistributedPreflight(
		finalizer, ingress, ticket, headers, envelopes); err != nil || found {
		if err == nil {
			err = fmt.Errorf("formal-cox lifecycle: publication appeared during prepare")
		}
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	phaseHook := func(phase string) error {
		if hook == nil {
			return nil
		}
		return hook("prepare_" + phase)
	}
	intent, publication, found, err :=
		formalCoxBlockwiseOpeningDistributedOpenAndPrepare(
			finalizer, ingress, ticket, headers, phaseHook)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if found {
		if err := formalCoxBlockwiseRockRemoveSecret(root,
			operation.SecretBundlePath); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		return formalCoxBlockwiseRockLifecycleResponse{
			Version:           formalTypedFinalizerLifecycleVersion,
			Family:            formalFinalizerHandoffFamilyCox,
			Action:            formalCoxBlockwiseRockActionPrepare,
			State:             formalCoxBlockwiseRockStatePublished,
			ArtifactID:        context.artifactID,
			RecordSHA256:      publication.CertificateSHA256,
			CertificateSHA256: publication.CertificateSHA256,
			Replayed:          true, ProductionReady: false,
		}, nil
	}
	candidate, err := finalizer.loadCandidate()
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	record := formalCoxBlockwiseRockCandidateRecord{
		Version:    formalCoxBlockwiseRockRecordVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Purpose:    formalCoxBlockwiseRockPurpose,
		ArtifactID: context.artifactID, Candidate: candidate,
		Intent: intent, ProductionReady: false,
	}
	if hook != nil {
		if err := hook("after_prepare_durable"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	digest, replayed, err := formalCoxBlockwiseRockWriteJSON(
		root, operation.CandidateRecordPath, record)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if err := formalCoxBlockwiseRockRemoveSecret(root,
		operation.SecretBundlePath); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	return formalCoxBlockwiseRockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Action:     formalCoxBlockwiseRockActionPrepare,
		State:      formalCoxBlockwiseRockStateCandidateReady,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		Replayed: replayed, ProductionReady: false,
	}, nil
}

func formalCoxBlockwiseRockLoadCandidate(root, path string,
	context formalCoxBlockwiseRockContext,
) (formalCoxBlockwiseRockCandidateRecord, error) {
	var record formalCoxBlockwiseRockCandidateRecord
	if err := formalCoxBlockwiseRockReadJSON(root, path,
		formalCoxBlockwiseRockMaxRecord, &record); err != nil {
		return record, err
	}
	wantIntent, intentErr := formalCoxBlockwiseOpeningIntentFor(record.Candidate)
	if record.Version != formalCoxBlockwiseRockRecordVersion ||
		record.Family != formalFinalizerHandoffFamilyCox ||
		record.Purpose != formalCoxBlockwiseRockPurpose || record.ProductionReady ||
		record.ArtifactID != context.artifactID ||
		record.Candidate.ArtifactID != context.artifactID ||
		formalCoxBlockwiseValidateOpeningCandidateCore(
			record.Candidate, context.pins) != nil || intentErr != nil ||
		!formalCoxBlockwiseOpeningEqual(record.Intent, wantIntent) {
		return record, fmt.Errorf("formal-cox lifecycle: invalid candidate record")
	}
	return record, nil
}

func formalCoxBlockwiseRockLoadAuthorization(root, path, role, artifactID string) (
	formalCoxBlockwiseRockAuthorizationRecord, error,
) {
	var record formalCoxBlockwiseRockAuthorizationRecord
	if err := formalCoxBlockwiseRockReadJSON(root, path,
		formalCoxBlockwiseRockMaxRecord, &record); err != nil {
		return record, err
	}
	if record.Version != formalCoxBlockwiseRockRecordVersion ||
		record.Family != formalFinalizerHandoffFamilyCox ||
		record.Purpose != formalCoxBlockwiseRockPurpose || record.ProductionReady ||
		record.ArtifactID != artifactID || record.Role != role ||
		record.Authorization.Version !=
			formalCoxBlockwiseRemoteOpeningAuthorizationVersion ||
		record.Authorization.Purpose !=
			formalCoxBlockwiseRemoteOpeningAuthorizationPurpose ||
		record.Authorization.ArtifactID != artifactID ||
		record.Authorization.TransportAuthorization.SignerRole != role ||
		record.Authorization.ProductionReady {
		return record, fmt.Errorf("formal-cox lifecycle: invalid authorization record")
	}
	return record, nil
}

func formalCoxBlockwiseRockValidatePublication(
	publication formalCoxBlockwiseRockPublication,
	context formalCoxBlockwiseRockContext,
) (formalCoxBlockwiseOpeningPublication, error) {
	opening := formalCoxBlockwiseRockPublicationToOpening(publication)
	certificate, err := formalCoxBlockwiseDecodeOpeningPublication(
		opening, context.pins)
	if err != nil || publication.ArtifactID != context.artifactID ||
		!formalCoxBlockwiseOpeningEqual(
			certificate.Candidate.Artifact, context.artifact) {
		return formalCoxBlockwiseOpeningPublication{},
			fmt.Errorf("formal-cox lifecycle: invalid public publication")
	}
	return opening, nil
}

func formalCoxBlockwiseRockLoadPublication(root, path string,
	context formalCoxBlockwiseRockContext,
) (formalCoxBlockwiseRockPublication, error) {
	var record formalCoxBlockwiseRockPublicationRecord
	if err := formalCoxBlockwiseRockReadJSON(root, path,
		formalCoxBlockwiseRockMaxRecord, &record); err != nil {
		return record.Publication, err
	}
	if record.Version != formalCoxBlockwiseRockRecordVersion ||
		record.Family != formalFinalizerHandoffFamilyCox ||
		record.Purpose != formalCoxBlockwiseRockPurpose || record.ProductionReady ||
		record.ArtifactID != context.artifactID {
		return record.Publication,
			fmt.Errorf("formal-cox lifecycle: invalid publication record")
	}
	if _, err := formalCoxBlockwiseRockValidatePublication(
		record.Publication, context); err != nil {
		return record.Publication, err
	}
	return record.Publication, nil
}

// ImportPublicPublication is deliberately family-local: it accepts only the
// fully validated public Cox certificate and persists only its authenticated
// ArtifactID-keyed replay record. It never imports a candidate or either
// authority's private opening state.
func (store *formalCoxBlockwiseOpeningStore) ImportPublicPublication(
	publication formalCoxBlockwiseOpeningPublication,
) (formalCoxBlockwiseOpeningPublication, bool, error) {
	var zero formalCoxBlockwiseOpeningPublication
	if store == nil || store.root == nil ||
		publication.ArtifactID != store.artifactID {
		return zero, false, fmt.Errorf("formal-cox: invalid publication import")
	}
	certificate, err := formalCoxBlockwiseDecodeOpeningPublication(
		publication, store.pins)
	if err != nil || !formalCoxBlockwiseOpeningEqual(
		certificate.Candidate.Artifact, store.artifact) {
		return zero, false, fmt.Errorf("formal-cox: rejected publication import")
	}
	record := formalCoxBlockwiseOpeningPublicRecord{
		Version:    formalCoxBlockwiseOpeningVersion,
		Purpose:    formalCoxBlockwiseOpeningPurpose,
		ArtifactID: store.artifactID, CertificateSHA256: publication.CertificateSHA256,
		CertificateJSON: string(publication.Certificate),
	}
	encoded, err := store.encodePublicRecord(record)
	if err != nil {
		return zero, false, err
	}
	defer clear(encoded)
	path, err := store.publicRelativePath(store.artifactID, true)
	if err != nil {
		return zero, false, err
	}
	store.mu.Lock()
	created, err := formalCoxBlockwiseGuardRootCreateRecord(store.root, path, encoded)
	if err == nil {
		encoded, err = formalCoxBlockwiseGuardRootReadRecord(
			store.root, path, formalCoxBlockwiseOpeningPublicMax)
	}
	store.mu.Unlock()
	if err != nil {
		return zero, false, err
	}
	existing, err := store.decodePublicRecord(encoded)
	if err != nil || existing.CertificateSHA256 != publication.CertificateSHA256 ||
		!bytes.Equal(existing.Certificate, publication.Certificate) {
		return zero, false, fmt.Errorf("formal-cox: conflicting publication import")
	}
	existing.Replayed = !created
	return existing, !created, nil
}

func formalCoxBlockwiseRockCommitMessage(
	receipt formalCoxBlockwiseRockCommitReceipt,
) ([]byte, error) {
	receipt.Signature = nil
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalCoxBlockwiseOpeningDomain+"/rock-publication-commit|"),
		encoded...), nil
}

func formalCoxBlockwiseRockValidateCommitReceipt(
	receipt formalCoxBlockwiseRockCommitReceipt,
	context formalCoxBlockwiseRockContext, position int,
) error {
	if position < 0 || position >= len(context.artifact.NoiseAuthorities) {
		return fmt.Errorf("formal-cox lifecycle: invalid commit receipt position")
	}
	authority := context.artifact.NoiseAuthorities[position]
	message, err := formalCoxBlockwiseRockCommitMessage(receipt)
	if err != nil || receipt.Version != formalCoxBlockwiseRockRecordVersion ||
		receipt.Purpose != formalCoxBlockwiseRockCommitPurpose ||
		receipt.ArtifactID != context.artifactID ||
		!formalCoxIsSHA256(receipt.CertificateSHA256) || receipt.ProductionReady ||
		receipt.PeerName != authority.PeerName || receipt.PeerID != authority.PeerID ||
		receipt.Role != authority.Role || len(receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(context.pins[authority.PeerName], message, receipt.Signature) {
		return fmt.Errorf("formal-cox lifecycle: invalid ordered commit receipt")
	}
	return nil
}

func formalCoxBlockwiseRockLoadCommitPair(root string, paths [2]string,
	context formalCoxBlockwiseRockContext, certificateSHA string,
) ([2]formalCoxBlockwiseRockCommitReceipt, error) {
	var receipts [2]formalCoxBlockwiseRockCommitReceipt
	for position, path := range paths {
		var record formalCoxBlockwiseRockCommitRecord
		if err := formalCoxBlockwiseRockReadJSON(root, path,
			formalCoxBlockwiseRockMaxRecord, &record); err != nil {
			return receipts, err
		}
		if record.Version != formalCoxBlockwiseRockRecordVersion ||
			record.Family != formalFinalizerHandoffFamilyCox ||
			record.Purpose != formalCoxBlockwiseRockCommitPurpose ||
			record.ProductionReady || record.Receipt.CertificateSHA256 != certificateSHA ||
			formalCoxBlockwiseRockValidateCommitReceipt(
				record.Receipt, context, position) != nil {
			return receipts, fmt.Errorf("formal-cox lifecycle: invalid commit record")
		}
		receipts[position] = record.Receipt
	}
	return receipts, nil
}

func formalCoxBlockwiseRockRunSign(root string, production bool,
	operation formalCoxBlockwiseRockSignOperation, hook formalCoxBlockwiseRockPhaseHook,
) (formalCoxBlockwiseRockLifecycleResponse, error) {
	context, err := formalCoxBlockwiseRockLoadContext(
		root, operation.PlanPath, operation.PinsetPath)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	localAuthority, err := formalCoxBlockwiseRockAuthority(
		context.artifact, operation.PeerName)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	guard, err := formalCoxBlockwiseRockAcquireGuard(
		root, context.artifactID, localAuthority, production)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer guard.Close()
	openingRoot, transportRoot, privateKey, err :=
		formalCoxBlockwiseRockLoadTransportSecret(
			root, operation.SecretBundlePath, formalCoxBlockwiseRockActionSign)
	defer clear(openingRoot[:])
	defer clear(transportRoot[:])
	defer clear(privateKey)
	if err != nil || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		context.pins[operation.PeerName]) {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: invalid signing authority")
	}
	if err := formalCoxBlockwiseRockEnsureDir(root, operation.OpeningDir); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	local, err := newFormalCoxBlockwiseOpeningStore(
		operation.OpeningDir, openingRoot, context.plan, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer local.Close()
	headers, err := formalCoxBlockwiseRockLoadHeaders(
		root, operation.HeaderRecordPaths, context)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	binding, err := formalCoxBlockwiseOpeningFinalizerBinding(local, headers)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	localRole, err := local.roleForPeer(operation.PeerName)
	if err != nil || operation.Role != localRole {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: signer role mismatch")
	}
	boundAuthority, err := formalFinalizerHandoffPeer(binding, localRole)
	if err != nil || !formalFinalizerHandoffAuthorityEqual(
		boundAuthority, localAuthority) {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: signer authority mismatch")
	}
	ticket, err := formalCoxBlockwiseRockLoadTicket(
		root, operation.TicketRecordPath, binding, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	candidateRecord, err := formalCoxBlockwiseRockLoadCandidate(
		root, operation.CandidateRecordPath, context)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	var transportPredecessors []formalFinalizerHandoffIntentAuthorization
	var openingPredecessors []jointDPBiomedicalGaussianSignature
	if localRole == "garbler" {
		if len(operation.PredecessorAuthorizationPaths) != 0 {
			return formalCoxBlockwiseRockLifecycleResponse{},
				fmt.Errorf("formal-cox lifecycle: garbler signer has predecessor")
		}
	} else {
		if len(operation.PredecessorAuthorizationPaths) != 1 {
			return formalCoxBlockwiseRockLifecycleResponse{},
				fmt.Errorf("formal-cox lifecycle: evaluator predecessor is missing")
		}
		predecessor, err := formalCoxBlockwiseRockLoadAuthorization(
			root, operation.PredecessorAuthorizationPaths[0], "garbler",
			context.artifactID)
		if err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		transportPredecessors = []formalFinalizerHandoffIntentAuthorization{
			predecessor.Authorization.TransportAuthorization}
		openingPredecessors = []jointDPBiomedicalGaussianSignature{
			predecessor.Authorization.OpeningReceipt}
	}
	if operation.TransportDir != root {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: transport left local Rock")
	}
	outbox, err := formalCoxBlockwiseRockOpenTransportStore(
		guard, binding, transportRoot, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer outbox.Close()
	if hook != nil {
		if err := hook("before_remote_sign_once"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	authorization, replayed, err := formalCoxBlockwiseRemoteOpeningSignOnce(
		local, outbox, ticket, headers, candidateRecord.Candidate,
		localRole, privateKey, transportPredecessors, openingPredecessors)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	record := formalCoxBlockwiseRockAuthorizationRecord{
		Version:    formalCoxBlockwiseRockRecordVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Purpose:    formalCoxBlockwiseRockPurpose,
		ArtifactID: context.artifactID, Role: localRole,
		Authorization: authorization, ProductionReady: false,
	}
	if hook != nil {
		if err := hook("after_sign_durable"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	digest, recordReplayed, err := formalCoxBlockwiseRockWriteJSON(
		root, operation.AuthorizationRecordPath, record)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if err := formalCoxBlockwiseRockRemoveSecret(root,
		operation.SecretBundlePath); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	return formalCoxBlockwiseRockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Action:     formalCoxBlockwiseRockActionSign,
		State:      formalCoxBlockwiseRockStateAuthorized,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		Replayed: replayed || recordReplayed, ProductionReady: false,
	}, nil
}

func formalCoxBlockwiseRockPersistPublication(root, path string,
	context formalCoxBlockwiseRockContext,
	publication formalCoxBlockwiseOpeningPublication,
) (string, bool, formalCoxBlockwiseRockPublication, error) {
	rock := formalCoxBlockwiseRockPublicationFromOpening(publication)
	if _, err := formalCoxBlockwiseRockValidatePublication(rock, context); err != nil {
		return "", false, rock, err
	}
	record := formalCoxBlockwiseRockPublicationRecord{
		Version:    formalCoxBlockwiseRockRecordVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Purpose:    formalCoxBlockwiseRockPurpose,
		ArtifactID: context.artifactID, Publication: rock, ProductionReady: false,
	}
	digest, replayed, err := formalCoxBlockwiseRockWriteJSON(root, path, record)
	return digest, replayed, rock, err
}

func formalCoxBlockwiseRockRunPreparePublication(root string, production bool,
	operation formalCoxBlockwiseRockPreparePublicationOperation,
	hook formalCoxBlockwiseRockPhaseHook,
) (formalCoxBlockwiseRockLifecycleResponse, error) {
	context, err := formalCoxBlockwiseRockLoadContext(
		root, operation.PlanPath, operation.PinsetPath)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	localAuthority, err := formalCoxBlockwiseRockAuthority(
		context.artifact, context.artifact.NoiseAuthorities[0].PeerName)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	guard, err := formalCoxBlockwiseRockAcquireGuard(
		root, context.artifactID, localAuthority, production)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer guard.Close()
	openingRoot, transportRoot, privateKey, err :=
		formalCoxBlockwiseRockLoadTransportSecret(
			root, operation.SecretBundlePath,
			formalCoxBlockwiseRockActionPreparePublication)
	defer clear(openingRoot[:])
	defer clear(transportRoot[:])
	defer clear(privateKey)
	if err != nil || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		context.pins[localAuthority.PeerName]) {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: invalid publication finalizer")
	}
	if err := formalCoxBlockwiseRockEnsureDir(root, operation.OpeningDir); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	finalizer, err := newFormalCoxBlockwiseOpeningStore(
		operation.OpeningDir, openingRoot, context.plan, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer finalizer.Close()
	// ArtifactID replay is checked before any attempt-specific header, pair
	// root, ticket, authorization, transport record, or candidate is opened.
	if publication, replayErr := finalizer.Replay(context.artifactID); replayErr == nil {
		digest, _, rock, err := formalCoxBlockwiseRockPersistPublication(
			root, operation.PublicationRecordPath, context, publication)
		if err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		if err := formalCoxBlockwiseRockRemoveSecret(
			root, operation.SecretBundlePath); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		return formalCoxBlockwiseRockLifecycleResponse{
			Version:    formalTypedFinalizerLifecycleVersion,
			Family:     formalFinalizerHandoffFamilyCox,
			Action:     formalCoxBlockwiseRockActionPreparePublication,
			State:      formalCoxBlockwiseRockStatePublicationReady,
			ArtifactID: context.artifactID, RecordSHA256: digest,
			CertificateSHA256: rock.CertificateSHA256, Publication: &rock,
			Replayed: true, ProductionReady: false,
		}, nil
	} else if !os.IsNotExist(replayErr) {
		return formalCoxBlockwiseRockLifecycleResponse{}, replayErr
	}
	headers, err := formalCoxBlockwiseRockLoadHeaders(
		root, operation.HeaderRecordPaths, context)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	binding, err := formalCoxBlockwiseOpeningFinalizerBinding(finalizer, headers)
	if err != nil || !formalFinalizerHandoffAuthorityEqual(
		binding.Finalizer, localAuthority) {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: publication finalizer mismatch")
	}
	ticket, err := formalCoxBlockwiseRockLoadTicket(
		root, operation.TicketRecordPath, binding, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if operation.TransportDir != root {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: transport left local Rock")
	}
	ingress, err := formalCoxBlockwiseRockOpenTransportStore(
		guard, binding, transportRoot, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer ingress.Close()
	if proof, found, err := ingress.PreflightAck(); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	} else if found {
		publication, replayErr := formalCoxBlockwiseTerminalOpeningReplay(finalizer, proof)
		if replayErr != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, replayErr
		}
		digest, _, rock, err := formalCoxBlockwiseRockPersistPublication(
			root, operation.PublicationRecordPath, context, publication)
		if err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		if err := formalCoxBlockwiseRockRemoveSecret(
			root, operation.SecretBundlePath); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		return formalCoxBlockwiseRockLifecycleResponse{
			Version:    formalTypedFinalizerLifecycleVersion,
			Family:     formalFinalizerHandoffFamilyCox,
			Action:     formalCoxBlockwiseRockActionPreparePublication,
			State:      formalCoxBlockwiseRockStatePublicationReady,
			ArtifactID: context.artifactID, RecordSHA256: digest,
			CertificateSHA256: rock.CertificateSHA256, Publication: &rock,
			Replayed: true, ProductionReady: false,
		}, nil
	}
	candidate, err := formalCoxBlockwiseRockLoadCandidate(
		root, operation.CandidateRecordPath, context)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	garbler, err := formalCoxBlockwiseRockLoadAuthorization(
		root, operation.AuthorizationRecordPaths[0], "garbler", context.artifactID)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	evaluator, err := formalCoxBlockwiseRockLoadAuthorization(
		root, operation.AuthorizationRecordPaths[1], "evaluator", context.artifactID)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("before_publication_accept"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	receipt0, replay0, err := formalCoxBlockwiseAcceptRemoteOpeningSignOnce(
		finalizer, ingress, ticket, candidate.Intent, "garbler",
		garbler.Authorization, nil, nil)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	receipt1, replay1, err := formalCoxBlockwiseAcceptRemoteOpeningSignOnce(
		finalizer, ingress, ticket, candidate.Intent, "evaluator",
		evaluator.Authorization,
		[]formalFinalizerHandoffIntentAuthorization{
			garbler.Authorization.TransportAuthorization},
		[]jointDPBiomedicalGaussianSignature{receipt0})
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	publication, err := finalizer.Publish(candidate.Intent,
		[]jointDPBiomedicalGaussianSignature{receipt0, receipt1}, func(phase string) error {
			if hook == nil {
				return nil
			}
			return hook("publication_" + phase)
		})
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_publication_durable"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	digest, recordReplayed, rock, err := formalCoxBlockwiseRockPersistPublication(
		root, operation.PublicationRecordPath, context, publication)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if err := formalCoxBlockwiseRockRemoveSecret(
		root, operation.SecretBundlePath); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	return formalCoxBlockwiseRockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Action:     formalCoxBlockwiseRockActionPreparePublication,
		State:      formalCoxBlockwiseRockStatePublicationReady,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		CertificateSHA256: rock.CertificateSHA256, Publication: &rock,
		Replayed:        replay0 || replay1 || publication.Replayed || recordReplayed,
		ProductionReady: false,
	}, nil
}

func formalCoxBlockwiseRockRunCommitPublication(root string, production bool,
	operation formalCoxBlockwiseRockCommitPublicationOperation,
	hook formalCoxBlockwiseRockPhaseHook,
) (formalCoxBlockwiseRockLifecycleResponse, error) {
	context, err := formalCoxBlockwiseRockLoadContext(
		root, operation.PlanPath, operation.PinsetPath)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	localAuthority, err := formalCoxBlockwiseRockAuthority(
		context.artifact, operation.PeerName)
	if err != nil || operation.Role != localAuthority.Role {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: invalid publication authority")
	}
	guard, err := formalCoxBlockwiseRockAcquireGuard(
		root, context.artifactID, localAuthority, production)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer guard.Close()
	openingRoot, privateKey, err := formalCoxBlockwiseRockLoadOpeningSecret(
		root, operation.SecretBundlePath,
		formalCoxBlockwiseRockActionCommitPublication)
	defer clear(openingRoot[:])
	defer clear(privateKey)
	if err != nil || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		context.pins[localAuthority.PeerName]) {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: invalid publication authority secret")
	}
	opening, err := formalCoxBlockwiseRockValidatePublication(
		operation.Publication, context)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if err := formalCoxBlockwiseRockEnsureDir(root, operation.OpeningDir); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	store, err := newFormalCoxBlockwiseOpeningStore(
		operation.OpeningDir, openingRoot, context.plan, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer store.Close()
	stored, importReplayed, err := store.ImportPublicPublication(opening)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_publication_import_durable"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	_, publicationReplayed, rock, err := formalCoxBlockwiseRockPersistPublication(
		root, operation.PublicationRecordPath, context, stored)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	receipt := formalCoxBlockwiseRockCommitReceipt{
		Version:    formalCoxBlockwiseRockRecordVersion,
		Purpose:    formalCoxBlockwiseRockCommitPurpose,
		ArtifactID: context.artifactID, CertificateSHA256: stored.CertificateSHA256,
		PeerName: localAuthority.PeerName, PeerID: localAuthority.PeerID,
		Role: localAuthority.Role, ProductionReady: false,
	}
	message, err := formalCoxBlockwiseRockCommitMessage(receipt)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	receipt.Signature = ed25519.Sign(privateKey, message)
	record := formalCoxBlockwiseRockCommitRecord{
		Version: formalCoxBlockwiseRockRecordVersion,
		Family:  formalFinalizerHandoffFamilyCox,
		Purpose: formalCoxBlockwiseRockCommitPurpose,
		Receipt: receipt, ProductionReady: false,
	}
	digest, recordReplayed, err := formalCoxBlockwiseRockWriteJSON(
		root, operation.CommitRecordPath, record)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_publication_commit_durable"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	if err := formalCoxBlockwiseRockRemoveSecret(
		root, operation.SecretBundlePath); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	return formalCoxBlockwiseRockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Action:     formalCoxBlockwiseRockActionCommitPublication,
		State:      formalCoxBlockwiseRockStatePublicationCommitted,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		CertificateSHA256: rock.CertificateSHA256, Publication: &rock,
		Replayed:        importReplayed || publicationReplayed || recordReplayed,
		ProductionReady: false,
	}, nil
}

func formalCoxBlockwiseRockPersistAck(root, path string,
	context formalCoxBlockwiseRockContext,
	proof formalFinalizerHandoffCommitProof,
) (string, bool, error) {
	record := formalCoxBlockwiseRockAckRecord{
		Version:    formalCoxBlockwiseRockRecordVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Purpose:    formalCoxBlockwiseRockPurpose,
		ArtifactID: context.artifactID, Proof: proof, ProductionReady: false,
	}
	return formalCoxBlockwiseRockWriteJSON(root, path, record)
}

func formalCoxBlockwiseRockLoadAck(root, path string,
	context formalCoxBlockwiseRockContext, binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
) (formalFinalizerHandoffCommitProof, error) {
	var record formalCoxBlockwiseRockAckRecord
	if err := formalCoxBlockwiseRockReadJSON(root, path,
		formalCoxBlockwiseRockMaxRecord, &record); err != nil {
		return record.Proof, err
	}
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil || record.Version != formalCoxBlockwiseRockRecordVersion ||
		record.Family != formalFinalizerHandoffFamilyCox ||
		record.Purpose != formalCoxBlockwiseRockPurpose || record.ProductionReady ||
		record.ArtifactID != context.artifactID ||
		formalFinalizerHandoffValidateCommitProof(
			record.Proof, binding, ticketSHA, context.pins) != nil {
		return record.Proof, fmt.Errorf("formal-cox lifecycle: invalid ACK record")
	}
	return record.Proof, nil
}

func formalCoxBlockwiseRockCleanupMessage(
	receipt formalCoxBlockwiseRockCleanupReceipt,
) ([]byte, error) {
	receipt.Signature = nil
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalCoxBlockwiseOpeningDomain+"/rock-transport-cleanup|"),
		encoded...), nil
}

func formalCoxBlockwiseRockLoadCleanup(root, path string,
	context formalCoxBlockwiseRockContext,
	localAuthority formalFinalizerHandoffAuthority,
) (formalCoxBlockwiseRockCleanupRecord, error) {
	var record formalCoxBlockwiseRockCleanupRecord
	if err := formalCoxBlockwiseRockReadJSON(root, path,
		formalCoxBlockwiseRockMaxRecord, &record); err != nil {
		return record, err
	}
	receipt := record.Receipt
	expected := 1
	if localAuthority.Role == "garbler" {
		expected = 4
	}
	message, err := formalCoxBlockwiseRockCleanupMessage(receipt)
	if err != nil || record.Version != formalCoxBlockwiseRockRecordVersion ||
		record.Family != formalFinalizerHandoffFamilyCox ||
		record.Purpose != formalCoxBlockwiseRockCleanupPurpose ||
		record.ProductionReady || receipt.Version != formalCoxBlockwiseRockRecordVersion ||
		receipt.Purpose != formalCoxBlockwiseRockCleanupPurpose ||
		receipt.ArtifactID != context.artifactID ||
		!formalCoxIsSHA256(receipt.CertificateSHA256) || receipt.ProductionReady ||
		receipt.PeerName != localAuthority.PeerName ||
		receipt.PeerID != localAuthority.PeerID || receipt.Role != localAuthority.Role ||
		receipt.RemovedRecords != expected ||
		len(receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(context.pins[localAuthority.PeerName],
			message, receipt.Signature) {
		return record, fmt.Errorf("formal-cox lifecycle: invalid cleanup replay")
	}
	return record, nil
}

func formalCoxBlockwiseRockRunFinalizeAck(root string, production bool,
	operation formalCoxBlockwiseRockFinalizeAckOperation,
	hook formalCoxBlockwiseRockPhaseHook,
) (formalCoxBlockwiseRockLifecycleResponse, error) {
	context, err := formalCoxBlockwiseRockLoadContext(
		root, operation.PlanPath, operation.PinsetPath)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	localAuthority, err := formalCoxBlockwiseRockAuthority(
		context.artifact, context.artifact.NoiseAuthorities[0].PeerName)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	guard, err := formalCoxBlockwiseRockAcquireGuard(
		root, context.artifactID, localAuthority, production)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer guard.Close()
	openingRoot, transportRoot, privateKey, err :=
		formalCoxBlockwiseRockLoadTransportSecret(
			root, operation.SecretBundlePath, formalCoxBlockwiseRockActionFinalizeAck)
	defer clear(openingRoot[:])
	defer clear(transportRoot[:])
	defer clear(privateKey)
	if err != nil || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		context.pins[localAuthority.PeerName]) {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: invalid ACK finalizer")
	}
	if err := formalCoxBlockwiseRockEnsureDir(root, operation.OpeningDir); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	finalizer, err := newFormalCoxBlockwiseOpeningStore(
		operation.OpeningDir, openingRoot, context.plan, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer finalizer.Close()
	publication, err := formalCoxBlockwiseRockLoadPublication(
		root, operation.PublicationRecordPath, context)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	durable, err := finalizer.Replay(context.artifactID)
	if err != nil || durable.CertificateSHA256 != publication.CertificateSHA256 ||
		!bytes.Equal(durable.Certificate, publication.Certificate) {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: ACK lacks exact local publication")
	}
	headers, err := formalCoxBlockwiseRockLoadHeaders(
		root, operation.HeaderRecordPaths, context)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	binding, err := formalCoxBlockwiseOpeningFinalizerBinding(finalizer, headers)
	if err != nil || !formalFinalizerHandoffAuthorityEqual(
		binding.Finalizer, localAuthority) {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: ACK finalizer mismatch")
	}
	ticket, err := formalCoxBlockwiseRockLoadTicket(
		root, operation.TicketRecordPath, binding, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if operation.TransportDir != root {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: transport left local Rock")
	}
	ingress, err := formalCoxBlockwiseRockOpenTransportStore(
		guard, binding, transportRoot, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer ingress.Close()
	if existing, found, err := ingress.PreflightAck(); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	} else if found {
		if existing.CertificateSHA256 != publication.CertificateSHA256 {
			return formalCoxBlockwiseRockLifecycleResponse{},
				fmt.Errorf("formal-cox lifecycle: conflicting durable ACK")
		}
		digest, _, err := formalCoxBlockwiseRockPersistAck(
			root, operation.AckRecordPath, context, existing)
		if err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		if err := formalCoxBlockwiseRockRemoveSecret(
			root, operation.SecretBundlePath); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		return formalCoxBlockwiseRockLifecycleResponse{
			Version:    formalTypedFinalizerLifecycleVersion,
			Family:     formalFinalizerHandoffFamilyCox,
			Action:     formalCoxBlockwiseRockActionFinalizeAck,
			State:      formalCoxBlockwiseRockStateAckReady,
			ArtifactID: context.artifactID, RecordSHA256: digest,
			CertificateSHA256: publication.CertificateSHA256,
			Replayed:          true, ProductionReady: false,
		}, nil
	}
	if _, err := formalCoxBlockwiseRockLoadCommitPair(
		root, operation.CommitRecordPaths, context,
		publication.CertificateSHA256); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("before_ack_commit"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	proof, err := formalFinalizerHandoffBuildCommitProof(
		binding, ticketSHA, publication.CertificateSHA256,
		privateKey, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	stored, ackReplayed, err := ingress.AckAfterCommit(proof, finalizer)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_ack_durable"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	digest, recordReplayed, err := formalCoxBlockwiseRockPersistAck(
		root, operation.AckRecordPath, context, stored)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if err := formalCoxBlockwiseRockRemoveSecret(
		root, operation.SecretBundlePath); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	return formalCoxBlockwiseRockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Action:     formalCoxBlockwiseRockActionFinalizeAck,
		State:      formalCoxBlockwiseRockStateAckReady,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		CertificateSHA256: publication.CertificateSHA256,
		Replayed:          ackReplayed || recordReplayed, ProductionReady: false,
	}, nil
}

func formalCoxBlockwiseRockRunAck(root string, production bool,
	operation formalCoxBlockwiseRockAckOperation, hook formalCoxBlockwiseRockPhaseHook,
) (formalCoxBlockwiseRockLifecycleResponse, error) {
	context, err := formalCoxBlockwiseRockLoadContext(
		root, operation.PlanPath, operation.PinsetPath)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	localAuthority, err := formalCoxBlockwiseRockAuthority(
		context.artifact, operation.PeerName)
	if err != nil || operation.Role != localAuthority.Role {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: invalid cleanup authority")
	}
	guard, err := formalCoxBlockwiseRockAcquireGuard(
		root, context.artifactID, localAuthority, production)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer guard.Close()
	if exists, err := formalCoxBlockwiseRockExists(
		root, operation.CleanupRecordPath); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	} else if exists {
		record, err := formalCoxBlockwiseRockLoadCleanup(
			root, operation.CleanupRecordPath, context, localAuthority)
		if err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		digest, err := formalCoxBlockwiseRockPairSHA256(record)
		if err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		if err := formalCoxBlockwiseRockRemoveSecret(
			root, operation.SecretBundlePath); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		return formalCoxBlockwiseRockLifecycleResponse{
			Version:    formalTypedFinalizerLifecycleVersion,
			Family:     formalFinalizerHandoffFamilyCox,
			Action:     formalCoxBlockwiseRockActionAck,
			State:      formalCoxBlockwiseRockStateCleaned,
			ArtifactID: context.artifactID, RecordSHA256: digest,
			CertificateSHA256: record.Receipt.CertificateSHA256,
			Replayed:          true, ProductionReady: false,
		}, nil
	}
	openingRoot, transportRoot, privateKey, err :=
		formalCoxBlockwiseRockLoadTransportSecret(
			root, operation.SecretBundlePath, formalCoxBlockwiseRockActionAck)
	defer clear(openingRoot[:])
	defer clear(transportRoot[:])
	defer clear(privateKey)
	if err != nil || !hmac.Equal(privateKey.Public().(ed25519.PublicKey),
		context.pins[localAuthority.PeerName]) {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: invalid cleanup authority secret")
	}
	if err := formalCoxBlockwiseRockEnsureDir(root, operation.OpeningDir); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	opening, err := newFormalCoxBlockwiseOpeningStore(
		operation.OpeningDir, openingRoot, context.plan, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer opening.Close()
	publication, err := formalCoxBlockwiseRockLoadPublication(
		root, operation.PublicationRecordPath, context)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	localPublication, err := opening.Replay(context.artifactID)
	if err != nil || localPublication.CertificateSHA256 != publication.CertificateSHA256 ||
		!bytes.Equal(localPublication.Certificate, publication.Certificate) {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: cleanup lacks local publication")
	}
	headers, err := formalCoxBlockwiseRockLoadHeaders(
		root, operation.HeaderRecordPaths, context)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	binding, err := formalCoxBlockwiseOpeningFinalizerBinding(opening, headers)
	if err != nil || !formalFinalizerHandoffBindingHasAuthority(
		binding, localAuthority) {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: cleanup binding mismatch")
	}
	ticket, err := formalCoxBlockwiseRockLoadTicket(
		root, operation.TicketRecordPath, binding, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	proof, err := formalCoxBlockwiseRockLoadAck(
		root, operation.AckRecordPath, context, binding, ticket)
	if err != nil || proof.CertificateSHA256 != publication.CertificateSHA256 {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: cleanup ACK mismatch")
	}
	if operation.TransportDir != root {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: transport left local Rock")
	}
	transport, err := formalCoxBlockwiseRockOpenTransportStore(
		guard, binding, transportRoot, context.pins)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	defer transport.Close()
	_, ackReplayed, err := transport.AckAfterCommit(proof, opening)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if hook != nil {
		if err := hook("after_local_ack_before_cleanup"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	removed, err := transport.CleanupTransportAfterAck(proof)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	expected := 1
	if formalFinalizerHandoffAuthorityEqual(localAuthority, binding.Finalizer) {
		expected = 4
	}
	if removed != expected && removed != 0 {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: incomplete transport cleanup")
	}
	if hook != nil {
		if err := hook("after_transport_cleanup"); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
	}
	receipt := formalCoxBlockwiseRockCleanupReceipt{
		Version:           formalCoxBlockwiseRockRecordVersion,
		Purpose:           formalCoxBlockwiseRockCleanupPurpose,
		ArtifactID:        context.artifactID,
		CertificateSHA256: publication.CertificateSHA256,
		PeerName:          localAuthority.PeerName, PeerID: localAuthority.PeerID,
		Role: localAuthority.Role, RemovedRecords: expected, ProductionReady: false,
	}
	message, err := formalCoxBlockwiseRockCleanupMessage(receipt)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	receipt.Signature = ed25519.Sign(privateKey, message)
	record := formalCoxBlockwiseRockCleanupRecord{
		Version: formalCoxBlockwiseRockRecordVersion,
		Family:  formalFinalizerHandoffFamilyCox,
		Purpose: formalCoxBlockwiseRockCleanupPurpose,
		Receipt: receipt, ProductionReady: false,
	}
	digest, recordReplayed, err := formalCoxBlockwiseRockWriteJSON(
		root, operation.CleanupRecordPath, record)
	if err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	if err := formalCoxBlockwiseRockRemoveSecret(
		root, operation.SecretBundlePath); err != nil {
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	return formalCoxBlockwiseRockLifecycleResponse{
		Version:    formalTypedFinalizerLifecycleVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Action:     formalCoxBlockwiseRockActionAck,
		State:      formalCoxBlockwiseRockStateCleaned,
		ArtifactID: context.artifactID, RecordSHA256: digest,
		CertificateSHA256: publication.CertificateSHA256,
		Replayed:          ackReplayed || removed == 0 || recordReplayed,
		ProductionReady:   false,
	}, nil
}

func formalCoxBlockwiseRockRun(root string, production bool, action string,
	operationJSON json.RawMessage,
	hook formalCoxBlockwiseRockPhaseHook,
) (formalCoxBlockwiseRockLifecycleResponse, error) {
	if !formalTypedFinalizerLifecycleActionAllowed(
		formalFinalizerHandoffFamilyCox, action) || len(operationJSON) < 2 {
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: invalid command request")
	}
	switch action {
	case formalCoxBlockwiseRockActionPreflight:
		var operation formalCoxBlockwiseRockPreflightOperation
		if err := formalCoxBlockwiseRockStrictDecode(operationJSON, &operation); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		return formalCoxBlockwiseRockRunPreflight(root, production, operation, hook)
	case formalCoxBlockwiseRockActionStage:
		var operation formalCoxBlockwiseRockStageOperation
		if err := formalCoxBlockwiseRockStrictDecode(operationJSON, &operation); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		return formalCoxBlockwiseRockRunStage(root, production, operation, hook)
	case formalCoxBlockwiseRockActionTicket:
		var operation formalCoxBlockwiseRockTicketOperation
		if err := formalCoxBlockwiseRockStrictDecode(operationJSON, &operation); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		return formalCoxBlockwiseRockRunTicket(root, production, operation, hook)
	case formalCoxBlockwiseRockActionSeal:
		var operation formalCoxBlockwiseRockSealOperation
		if err := formalCoxBlockwiseRockStrictDecode(operationJSON, &operation); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		return formalCoxBlockwiseRockRunSeal(root, production, operation, hook)
	case formalCoxBlockwiseRockActionPrepare:
		var operation formalCoxBlockwiseRockPrepareOperation
		if err := formalCoxBlockwiseRockStrictDecode(operationJSON, &operation); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		return formalCoxBlockwiseRockRunPrepare(root, production, operation, hook)
	case formalCoxBlockwiseRockActionSign:
		var operation formalCoxBlockwiseRockSignOperation
		if err := formalCoxBlockwiseRockStrictDecode(operationJSON, &operation); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		return formalCoxBlockwiseRockRunSign(root, production, operation, hook)
	case formalCoxBlockwiseRockActionPreparePublication:
		var operation formalCoxBlockwiseRockPreparePublicationOperation
		if err := formalCoxBlockwiseRockStrictDecode(operationJSON, &operation); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		return formalCoxBlockwiseRockRunPreparePublication(
			root, production, operation, hook)
	case formalCoxBlockwiseRockActionCommitPublication:
		var operation formalCoxBlockwiseRockCommitPublicationOperation
		if err := formalCoxBlockwiseRockStrictDecode(operationJSON, &operation); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		return formalCoxBlockwiseRockRunCommitPublication(
			root, production, operation, hook)
	case formalCoxBlockwiseRockActionFinalizeAck:
		var operation formalCoxBlockwiseRockFinalizeAckOperation
		if err := formalCoxBlockwiseRockStrictDecode(operationJSON, &operation); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		return formalCoxBlockwiseRockRunFinalizeAck(root, production, operation, hook)
	case formalCoxBlockwiseRockActionAck:
		var operation formalCoxBlockwiseRockAckOperation
		if err := formalCoxBlockwiseRockStrictDecode(operationJSON, &operation); err != nil {
			return formalCoxBlockwiseRockLifecycleResponse{}, err
		}
		return formalCoxBlockwiseRockRunAck(root, production, operation, hook)
	default:
		return formalCoxBlockwiseRockLifecycleResponse{},
			fmt.Errorf("formal-cox lifecycle: unsupported action")
	}
}

func handleFormalCoxBlockwiseRockLifecycle(root, action string,
	operation json.RawMessage,
) error {
	response, err := formalCoxBlockwiseRockRun(
		root, true, action, operation, nil)
	if err != nil {
		// Command errors are deliberately coarse: .callMpcTool may surface both
		// stdout and stderr to an R caller.
		return fmt.Errorf("formal-cox lifecycle action failed")
	}
	output(response)
	return nil
}
