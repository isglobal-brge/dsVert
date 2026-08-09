package main

// Durable, server-local finalization for the Phase-1.9-bound scalable
// Gaussian route.  The ledger row is committed and synced before the common
// DP vector is computed.  A retry, restart, or different transport chunking
// returns the same signed release and never re-enters source materialization.
// This file intentionally adds no CLI command or public opening endpoint.

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
	"runtime"
	"sort"
	"strings"
	"sync"
)

const (
	jointDPBiomedicalGaussianFullDurableRecordVersion = "dsvert-biomedical-gaussian-independent-full-durable-record-v1"
	jointDPBiomedicalGaussianFullDurableRecordDomain  = "dsVert/biomedical-gaussian/independent-full/durable-record/v1"
	jointDPBiomedicalGaussianFullLocalReleaseVersion  = "dsvert-biomedical-gaussian-independent-full-local-release-v1"
	jointDPBiomedicalGaussianFullLocalReleaseDomain   = "dsVert/biomedical-gaussian/independent-full/local-release/v1"
	jointDPBiomedicalGaussianFullCommonReleaseVersion = "dsvert-biomedical-gaussian-independent-full-common-release-v1"
	jointDPBiomedicalGaussianFullCommonReleaseDomain  = "dsVert/biomedical-gaussian/independent-full/common-release/v1"
	jointDPBiomedicalGaussianFullRouteRole            = "certified_independent_full_fallback_not_primary_v1"
	jointDPBiomedicalGaussianFullMaximumRecordBytes   = 64 * 1024 * 1024
)

var jointDPBiomedicalGaussianFullReleaseBlockers = []string{
	"independent_full_sqrt2_accuracy_fallback_not_primary_v1",
	"internal_release_not_exposed_on_the_R_DSI_surface_v1",
}

type jointDPBiomedicalGaussianFullLocalReleaseReceipt struct {
	Version                           string   `json:"version"`
	Backend                           string   `json:"backend"`
	Mechanism                         string   `json:"mechanism"`
	Sampler                           string   `json:"sampler"`
	PeerName                          string   `json:"peer_name"`
	PeerIdentitySHA256                string   `json:"peer_identity_sha256"`
	ReleaseInstanceID                 string   `json:"release_instance_id"`
	ReleaseContractSHA256             string   `json:"release_contract_sha256"`
	Phase19PostExecutionRootSHA256    string   `json:"phase19_post_execution_root_sha256"`
	Phase19ExecutionReceiptPairSHA256 string   `json:"phase19_execution_receipt_pair_sha256"`
	LedgerReservationSHA256           string   `json:"ledger_reservation_sha256"`
	FinalizerReservationSHA256        string   `json:"finalizer_reservation_sha256"`
	VectorSHA256                      string   `json:"vector_sha256"`
	ClampedScaledValues               []string `json:"clamped_scaled_values"`
	Epsilon                           string   `json:"epsilon"`
	Delta                             string   `json:"delta"`
	RouteRole                         string   `json:"route_role"`
	TargetVarianceOptimal             bool     `json:"target_variance_optimal"`
	NominalVarianceMultiplier         int      `json:"nominal_variance_multiplier"`
	NominalStandardDeviationFactor    string   `json:"nominal_standard_deviation_factor"`
	LedgerAppendBeforeRelease         bool     `json:"ledger_append_before_release"`
	ExactlyOnceRelease                bool     `json:"exactly_once_release"`
	SingleCommonDPVector              bool     `json:"single_common_dp_vector"`
	UnlimitedDeterministicReplay      bool     `json:"unlimited_deterministic_replay"`
	UnlimitedPostprocessing           bool     `json:"unlimited_postprocessing"`
	HistoryCanDenyOperation           bool     `json:"history_can_deny_operation"`
	OperationLimit                    bool     `json:"operation_limit"`
	RequestLimit                      bool     `json:"request_limit"`
	OpeningsPerformed                 int      `json:"openings_performed"`
	ProductionReady                   bool     `json:"production_ready"`
	Blockers                          []string `json:"blockers"`
	CommonReleaseSignature            []byte   `json:"common_release_signature"`
	Signature                         []byte   `json:"signature"`
}

type jointDPBiomedicalGaussianFullLocalRelease struct {
	Receipt  jointDPBiomedicalGaussianFullLocalReleaseReceipt
	Replayed bool
}

type jointDPBiomedicalGaussianFullCommonRelease struct {
	Version                           string                               `json:"version"`
	Backend                           string                               `json:"backend"`
	Mechanism                         string                               `json:"mechanism"`
	Sampler                           string                               `json:"sampler"`
	ReleaseInstanceID                 string                               `json:"release_instance_id"`
	ReleaseContractSHA256             string                               `json:"release_contract_sha256"`
	Phase19PostExecutionRootSHA256    string                               `json:"phase19_post_execution_root_sha256"`
	Phase19ExecutionReceiptPairSHA256 string                               `json:"phase19_execution_receipt_pair_sha256"`
	LedgerReservationSHA256           string                               `json:"ledger_reservation_sha256"`
	FinalizerReservationSHA256        string                               `json:"finalizer_reservation_sha256"`
	DesignatedComputePeers            []string                             `json:"designated_compute_peers"`
	VectorSHA256                      string                               `json:"vector_sha256"`
	ClampedScaledValues               []string                             `json:"clamped_scaled_values"`
	Epsilon                           string                               `json:"epsilon"`
	Delta                             string                               `json:"delta"`
	RouteRole                         string                               `json:"route_role"`
	TargetVarianceOptimal             bool                                 `json:"target_variance_optimal"`
	NominalVarianceMultiplier         int                                  `json:"nominal_variance_multiplier"`
	NominalStandardDeviationFactor    string                               `json:"nominal_standard_deviation_factor"`
	LedgerAppendBeforeRelease         bool                                 `json:"ledger_append_before_release"`
	ExactlyOnceRelease                bool                                 `json:"exactly_once_release"`
	SingleCommonDPVector              bool                                 `json:"single_common_dp_vector"`
	UnlimitedDeterministicReplay      bool                                 `json:"unlimited_deterministic_replay"`
	UnlimitedPostprocessing           bool                                 `json:"unlimited_postprocessing"`
	HistoryCanDenyOperation           bool                                 `json:"history_can_deny_operation"`
	OperationLimit                    bool                                 `json:"operation_limit"`
	RequestLimit                      bool                                 `json:"request_limit"`
	OpeningsPerformed                 int                                  `json:"openings_performed"`
	ProductionReady                   bool                                 `json:"production_ready"`
	Blockers                          []string                             `json:"blockers"`
	Signatures                        []jointDPBiomedicalGaussianSignature `json:"signatures"`
}

type jointDPBiomedicalGaussianFullDurableRecord struct {
	Version                           string `json:"version"`
	State                             string `json:"state"`
	PeerName                          string `json:"peer_name"`
	ReleaseInstanceID                 string `json:"release_instance_id"`
	ReleaseContractSHA256             string `json:"release_contract_sha256"`
	Phase19PostExecutionRootSHA256    string `json:"phase19_post_execution_root_sha256"`
	Phase19ExecutionReceiptPairSHA256 string `json:"phase19_execution_receipt_pair_sha256"`
	InputCommitmentSHA256             string `json:"input_commitment_sha256"`
	LedgerReservationSHA256           string `json:"ledger_reservation_sha256"`
	FinalizerReservationSHA256        string `json:"finalizer_reservation_sha256"`
	LedgerAppendBeforeRelease         bool   `json:"ledger_append_before_release"`
	HistoryCanDenyOperation           bool   `json:"history_can_deny_operation"`
	OperationLimit                    bool   `json:"operation_limit"`
	RequestLimit                      bool   `json:"request_limit"`
	ReleaseReceiptJSON                string `json:"release_receipt_json"`
	RecordMAC                         string `json:"record_mac"`
}

type jointDPBiomedicalGaussianFullDurableReleaseStore struct {
	mu      sync.Mutex
	dir     string
	records string
	peer    string
	key     [32]byte
	signer  ed25519.PrivateKey
}

func newJointDPBiomedicalGaussianFullDurableReleaseStore(
	dir, peer string, backendKey [32]byte, signer ed25519.PrivateKey,
) (*jointDPBiomedicalGaussianFullDurableReleaseStore, error) {
	if !jointDPBiomedicalGaussianValidPeerName(peer) ||
		backendKey == ([32]byte{}) || len(signer) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid durable release identity")
	}
	if err := formalGLMPhase18EnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	records := filepath.Join(dir, "records")
	if err := formalGLMPhase18EnsurePrivateDir(records); err != nil {
		return nil, err
	}
	copySigner := append(ed25519.PrivateKey(nil), signer...)
	return &jointDPBiomedicalGaussianFullDurableReleaseStore{
		dir: dir, records: records, peer: peer,
		key: backendKey, signer: copySigner,
	}, nil
}

func jointDPBiomedicalGaussianFullLocalReleaseMessage(
	receipt jointDPBiomedicalGaussianFullLocalReleaseReceipt,
) ([]byte, error) {
	if receipt.Version != jointDPBiomedicalGaussianFullLocalReleaseVersion ||
		receipt.Backend != jointDPGaussianBackend ||
		receipt.Mechanism != jointDPGaussianMechanism ||
		receipt.Sampler != jointDPGaussianSampler ||
		!jointDPBiomedicalGaussianValidPeerName(receipt.PeerName) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.PeerIdentitySHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.ReleaseInstanceID) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.ReleaseContractSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(
			receipt.Phase19PostExecutionRootSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(
			receipt.Phase19ExecutionReceiptPairSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.LedgerReservationSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.FinalizerReservationSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.VectorSHA256) ||
		len(receipt.ClampedScaledValues) < 1 ||
		receipt.RouteRole != jointDPBiomedicalGaussianFullRouteRole ||
		receipt.TargetVarianceOptimal ||
		receipt.NominalVarianceMultiplier != 2 ||
		receipt.NominalStandardDeviationFactor !=
			"sqrt(2)_relative_to_one_full_draw" ||
		!receipt.LedgerAppendBeforeRelease || !receipt.ExactlyOnceRelease ||
		receipt.SingleCommonDPVector || !receipt.UnlimitedDeterministicReplay ||
		!receipt.UnlimitedPostprocessing || receipt.HistoryCanDenyOperation ||
		receipt.OperationLimit || receipt.RequestLimit ||
		receipt.OpeningsPerformed != 1 || receipt.ProductionReady ||
		!reflectStringSlicesEqual(receipt.Blockers,
			jointDPBiomedicalGaussianFullReleaseBlockers) ||
		len(receipt.CommonReleaseSignature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid local durable release")
	}
	for _, value := range receipt.ClampedScaledValues {
		if _, err := jointDPBiomedicalGaussianParseCanonicalInt(
			value, "released Gaussian coordinate", false); err != nil {
			return nil, err
		}
	}
	unsigned := receipt
	unsigned.Signature = nil
	return jointDPBiomedicalGaussianDomainMessage(
		jointDPBiomedicalGaussianFullLocalReleaseDomain, unsigned)
}

func reflectStringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func jointDPBiomedicalGaussianFullCommonFromLocal(
	admission jointDPBiomedicalGaussianFullAdmission,
	receipt jointDPBiomedicalGaussianFullLocalReleaseReceipt,
) jointDPBiomedicalGaussianFullCommonRelease {
	return jointDPBiomedicalGaussianFullCommonRelease{
		Version:                           jointDPBiomedicalGaussianFullCommonReleaseVersion,
		Backend:                           receipt.Backend,
		Mechanism:                         receipt.Mechanism,
		Sampler:                           receipt.Sampler,
		ReleaseInstanceID:                 receipt.ReleaseInstanceID,
		ReleaseContractSHA256:             receipt.ReleaseContractSHA256,
		Phase19PostExecutionRootSHA256:    receipt.Phase19PostExecutionRootSHA256,
		Phase19ExecutionReceiptPairSHA256: receipt.Phase19ExecutionReceiptPairSHA256,
		LedgerReservationSHA256:           receipt.LedgerReservationSHA256,
		FinalizerReservationSHA256:        receipt.FinalizerReservationSHA256,
		DesignatedComputePeers: append([]string(nil),
			admission.selection.Contract.DesignatedComputePeers...),
		VectorSHA256: receipt.VectorSHA256,
		ClampedScaledValues: append([]string(nil),
			receipt.ClampedScaledValues...),
		Epsilon:                        receipt.Epsilon,
		Delta:                          receipt.Delta,
		RouteRole:                      receipt.RouteRole,
		TargetVarianceOptimal:          receipt.TargetVarianceOptimal,
		NominalVarianceMultiplier:      receipt.NominalVarianceMultiplier,
		NominalStandardDeviationFactor: receipt.NominalStandardDeviationFactor,
		LedgerAppendBeforeRelease:      true,
		ExactlyOnceRelease:             true,
		SingleCommonDPVector:           true,
		UnlimitedDeterministicReplay:   true,
		UnlimitedPostprocessing:        true,
		HistoryCanDenyOperation:        false,
		OperationLimit:                 false,
		RequestLimit:                   false,
		OpeningsPerformed:              1,
		ProductionReady:                false,
		Blockers: append([]string(nil),
			jointDPBiomedicalGaussianFullReleaseBlockers...),
	}
}

func jointDPBiomedicalGaussianFullCommonReleaseMessage(
	release jointDPBiomedicalGaussianFullCommonRelease,
) ([]byte, error) {
	if release.Version != jointDPBiomedicalGaussianFullCommonReleaseVersion ||
		release.Backend != jointDPGaussianBackend ||
		release.Mechanism != jointDPGaussianMechanism ||
		release.Sampler != jointDPGaussianSampler ||
		!jointDPBiomedicalGaussianIsSHA256(release.ReleaseInstanceID) ||
		!jointDPBiomedicalGaussianIsSHA256(release.ReleaseContractSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(
			release.Phase19PostExecutionRootSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(
			release.Phase19ExecutionReceiptPairSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(release.LedgerReservationSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(release.FinalizerReservationSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(release.VectorSHA256) ||
		len(release.DesignatedComputePeers) != 2 ||
		release.DesignatedComputePeers[0] == release.DesignatedComputePeers[1] ||
		!jointDPBiomedicalGaussianValidPeerName(release.DesignatedComputePeers[0]) ||
		!jointDPBiomedicalGaussianValidPeerName(release.DesignatedComputePeers[1]) ||
		len(release.ClampedScaledValues) < 1 ||
		release.RouteRole != jointDPBiomedicalGaussianFullRouteRole ||
		release.TargetVarianceOptimal ||
		release.NominalVarianceMultiplier != 2 ||
		release.NominalStandardDeviationFactor !=
			"sqrt(2)_relative_to_one_full_draw" ||
		!release.LedgerAppendBeforeRelease || !release.ExactlyOnceRelease ||
		!release.SingleCommonDPVector || !release.UnlimitedDeterministicReplay ||
		!release.UnlimitedPostprocessing || release.HistoryCanDenyOperation ||
		release.OperationLimit || release.RequestLimit ||
		release.OpeningsPerformed != 1 || release.ProductionReady ||
		!reflectStringSlicesEqual(release.Blockers,
			jointDPBiomedicalGaussianFullReleaseBlockers) {
		return nil, fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid common durable release")
	}
	for _, value := range release.ClampedScaledValues {
		if _, err := jointDPBiomedicalGaussianParseCanonicalInt(
			value, "common released Gaussian coordinate", false); err != nil {
			return nil, err
		}
	}
	unsigned := release
	unsigned.Signatures = nil
	return jointDPBiomedicalGaussianDomainMessage(
		jointDPBiomedicalGaussianFullCommonReleaseDomain, unsigned)
}

func jointDPBiomedicalGaussianValidateFullReleasedVector(
	admission jointDPBiomedicalGaussianFullAdmission,
	vectorSHA256 string, values []string,
) error {
	certificate := admission.certificate
	if len(values) != admission.selection.Contract.TotalCoordinateCount ||
		len(certificate.ShiftedUpperBounds) != len(values) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: released vector shape mismatch")
	}
	for index, value := range values {
		parsed, err := jointDPBiomedicalGaussianParseCanonicalInt(
			value, "released Gaussian coordinate", false)
		if err != nil {
			return err
		}
		upper, err := jointDPBiomedicalGaussianParseCanonicalInt(
			certificate.ShiftedUpperBounds[index],
			"released Gaussian coordinate upper bound", false)
		if err != nil || parsed.Cmp(upper) > 0 {
			return fmt.Errorf("joint-dp-biomedical-gaussian-full: released coordinate exceeds its certified bound")
		}
	}
	vectorDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullLocalReleaseDomain+"/vector", values)
	if err != nil || vectorSHA256 != hex.EncodeToString(vectorDigest[:]) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: released vector digest mismatch")
	}
	return nil
}

func jointDPBiomedicalGaussianValidateFullLocalRelease(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	receipt jointDPBiomedicalGaussianFullLocalReleaseReceipt,
) error {
	if err := jointDPBiomedicalGaussianValidateFullAdmissionCached(
		admission, pins); err != nil {
		return err
	}
	contract := admission.selection.Contract
	ledger, err := jointDPBiomedicalGaussianFullReceipt(
		contract.ReceiptReferences, jointDPBiomedicalGaussianReceiptPrivacyLedger)
	if err != nil {
		return err
	}
	finalizer, err := jointDPBiomedicalGaussianFullReceipt(
		contract.ReceiptReferences, jointDPBiomedicalGaussianReceiptFinalizer)
	if err != nil {
		return err
	}
	if !formalGLMPhase19Contains(contract.DesignatedComputePeers,
		receipt.PeerName) || receipt.ReleaseInstanceID != contract.ReleaseInstanceID ||
		receipt.ReleaseContractSHA256 != contract.ReleaseContractSHA256 ||
		receipt.LedgerReservationSHA256 != ledger.SHA256 ||
		receipt.FinalizerReservationSHA256 != finalizer.SHA256 ||
		receipt.Epsilon != contract.Epsilon || receipt.Delta != contract.Delta ||
		len(receipt.ClampedScaledValues) != contract.TotalCoordinateCount {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: local release binding mismatch")
	}
	if err := jointDPBiomedicalGaussianValidateFullReleasedVector(
		admission, receipt.VectorSHA256,
		receipt.ClampedScaledValues); err != nil {
		return err
	}
	pin := pins[receipt.PeerName]
	pinDigest := sha256.Sum256(pin)
	message, err := jointDPBiomedicalGaussianFullLocalReleaseMessage(receipt)
	if err != nil {
		return err
	}
	if receipt.PeerIdentitySHA256 != hex.EncodeToString(pinDigest[:]) ||
		len(receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pin, message, receipt.Signature) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: local release signature verification failed")
	}
	common := jointDPBiomedicalGaussianFullCommonFromLocal(admission, receipt)
	commonMessage, err := jointDPBiomedicalGaussianFullCommonReleaseMessage(common)
	if err != nil || len(receipt.CommonReleaseSignature) != ed25519.SignatureSize ||
		!ed25519.Verify(pin, commonMessage, receipt.CommonReleaseSignature) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: common release signature verification failed")
	}
	return nil
}

func jointDPBiomedicalGaussianValidateFullCommonRelease(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	release jointDPBiomedicalGaussianFullCommonRelease,
) error {
	if err := jointDPBiomedicalGaussianValidateFullAdmissionCached(
		admission, pins); err != nil {
		return err
	}
	contract := admission.selection.Contract
	ledger, err := jointDPBiomedicalGaussianFullReceipt(
		contract.ReceiptReferences, jointDPBiomedicalGaussianReceiptPrivacyLedger)
	if err != nil {
		return err
	}
	finalizer, err := jointDPBiomedicalGaussianFullReceipt(
		contract.ReceiptReferences, jointDPBiomedicalGaussianReceiptFinalizer)
	if err != nil {
		return err
	}
	if release.ReleaseInstanceID != contract.ReleaseInstanceID ||
		release.ReleaseContractSHA256 != contract.ReleaseContractSHA256 ||
		release.LedgerReservationSHA256 != ledger.SHA256 ||
		release.FinalizerReservationSHA256 != finalizer.SHA256 ||
		!reflect.DeepEqual(release.DesignatedComputePeers,
			contract.DesignatedComputePeers) ||
		release.Epsilon != contract.Epsilon || release.Delta != contract.Delta {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: common release binding mismatch")
	}
	if err := jointDPBiomedicalGaussianValidateFullReleasedVector(
		admission, release.VectorSHA256,
		release.ClampedScaledValues); err != nil {
		return err
	}
	message, err := jointDPBiomedicalGaussianFullCommonReleaseMessage(release)
	if err != nil {
		return err
	}
	peers := contract.DesignatedComputePeers
	if len(release.Signatures) != len(peers) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: common release lacks both designated signatures")
	}
	for index, peer := range peers {
		signature := release.Signatures[index]
		if signature.Signer != peer ||
			len(signature.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(pins[peer], message, signature.Signature) {
			return fmt.Errorf("joint-dp-biomedical-gaussian-full: common release signature verification failed")
		}
	}
	return nil
}

func (store *jointDPBiomedicalGaussianFullDurableReleaseStore) recordPath(
	releaseID string, create bool,
) (string, error) {
	if !jointDPBiomedicalGaussianIsSHA256(releaseID) {
		return "", fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid durable release id")
	}
	shard := filepath.Join(store.records, releaseID[:2], releaseID[2:4])
	if create {
		if err := formalGLMPhase18EnsurePrivateDir(shard); err != nil {
			return "", err
		}
	}
	return filepath.Join(shard, "release-"+releaseID+".json"), nil
}

func jointDPBiomedicalGaussianFullReadDurableRecord(path string) ([]byte, error) {
	for attempt := 0; attempt < 32; attempt++ {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o077 != 0 ||
			info.Size() < 64 || info.Size() > jointDPBiomedicalGaussianFullMaximumRecordBytes {
			return nil, fmt.Errorf("joint-dp-biomedical-gaussian-full: unsafe durable release record")
		}
		if !exactGCPrivateOwnedRegular(info) {
			reaped, reapErr := jointDPBiomedicalGaussianFullReapCommittedTemp(
				path, info)
			if reapErr != nil {
				return nil, reapErr
			}
			if reaped {
				continue
			}
			runtime.Gosched()
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		opened, statErr := file.Stat()
		if statErr != nil {
			_ = file.Close()
			return nil, statErr
		}
		if !os.SameFile(info, opened) {
			if err := file.Close(); err != nil {
				return nil, err
			}
			// Another process may have atomically committed the same release
			// between Lstat and Open. Retry that bounded stabilization race, but
			// reject a path substitution before retrying so a symlink or unsafe
			// replacement never becomes an accepted transient state.
			current, err := os.Lstat(path)
			if err != nil {
				return nil, err
			}
			if !current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 ||
				current.Mode().Perm()&0o077 != 0 ||
				current.Size() < 64 ||
				current.Size() > jointDPBiomedicalGaussianFullMaximumRecordBytes {
				return nil, fmt.Errorf("joint-dp-biomedical-gaussian-full: unsafe durable release record")
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
	return nil, fmt.Errorf("joint-dp-biomedical-gaussian-full: linked durable record did not stabilize")
}

// Hard-link CAS has a short, crash-recoverable interval where the committed
// record and its internal temporary name reference the same complete inode.
// Remove only that same-directory, same-inode temporary name. An unrelated
// hard link remains fail-closed.
func jointDPBiomedicalGaussianFullReapCommittedTemp(
	path string, targetInfo os.FileInfo,
) (bool, error) {
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".gaussian-release-") {
			continue
		}
		tempPath := filepath.Join(filepath.Dir(path), entry.Name())
		tempInfo, err := os.Lstat(tempPath)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false, err
		}
		if !os.SameFile(targetInfo, tempInfo) {
			continue
		}
		if !tempInfo.Mode().IsRegular() || tempInfo.Mode()&os.ModeSymlink != 0 ||
			tempInfo.Mode().Perm()&0o077 != 0 ||
			tempInfo.Size() != targetInfo.Size() {
			return false, fmt.Errorf("joint-dp-biomedical-gaussian-full: unsafe linked durable release temporary file")
		}
		if err := os.Remove(tempPath); err != nil && !os.IsNotExist(err) {
			return false, err
		}
		if err := exactGCSyncDir(filepath.Dir(path)); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func jointDPBiomedicalGaussianFullRecordMAC(key [32]byte,
	record jointDPBiomedicalGaussianFullDurableRecord,
) (string, error) {
	record.RecordMAC = ""
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(jointDPBiomedicalGaussianFullDurableRecordDomain))
	mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func jointDPBiomedicalGaussianFullEncodeRecord(key [32]byte,
	record jointDPBiomedicalGaussianFullDurableRecord,
) ([]byte, error) {
	mac, err := jointDPBiomedicalGaussianFullRecordMAC(key, record)
	if err != nil {
		return nil, err
	}
	record.RecordMAC = mac
	return json.Marshal(record)
}

func jointDPBiomedicalGaussianFullDecodeRecord(key [32]byte,
	encoded []byte,
) (jointDPBiomedicalGaussianFullDurableRecord, error) {
	var zero jointDPBiomedicalGaussianFullDurableRecord
	if len(encoded) < 64 || len(encoded) > jointDPBiomedicalGaussianFullMaximumRecordBytes {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid durable record size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record jointDPBiomedicalGaussianFullDurableRecord
	if err := decoder.Decode(&record); err != nil {
		return zero, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: trailing durable record data")
	}
	want, err := jointDPBiomedicalGaussianFullRecordMAC(key, record)
	if err != nil || !hmac.Equal([]byte(want), []byte(record.RecordMAC)) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: durable record authentication failed")
	}
	if record.Version != jointDPBiomedicalGaussianFullDurableRecordVersion ||
		(record.State != "ledger_committed" && record.State != "released") ||
		!jointDPBiomedicalGaussianValidPeerName(record.PeerName) ||
		!jointDPBiomedicalGaussianIsSHA256(record.ReleaseInstanceID) ||
		!jointDPBiomedicalGaussianIsSHA256(record.ReleaseContractSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(record.Phase19PostExecutionRootSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(record.Phase19ExecutionReceiptPairSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(record.InputCommitmentSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(record.LedgerReservationSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(record.FinalizerReservationSHA256) ||
		!record.LedgerAppendBeforeRelease || record.HistoryCanDenyOperation ||
		record.OperationLimit || record.RequestLimit ||
		(record.State == "ledger_committed" && record.ReleaseReceiptJSON != "") ||
		(record.State == "released" && record.ReleaseReceiptJSON == "") {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid durable record contract")
	}
	canonical, err := jointDPBiomedicalGaussianFullEncodeRecord(key, record)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: non-canonical durable record")
	}
	return record, nil
}

func jointDPBiomedicalGaussianFullCreateRecord(path string, encoded []byte) (
	bool, error,
) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".gaussian-release-")
	if err != nil {
		return false, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := exactGCWriteFull(tmp, encoded); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Link(tmpPath, path); err != nil {
		if !os.IsExist(err) {
			return false, err
		}
		return false, nil
	}
	if err := os.Remove(tmpPath); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := exactGCSyncDir(filepath.Dir(path)); err != nil {
		return false, err
	}
	return true, nil
}

type jointDPBiomedicalGaussianFullNormalizedInput struct {
	left, right                             []byte
	postRoot, executionPair, digest         string
	ledgerReservation, finalizerReservation string
}

func jointDPBiomedicalGaussianFullNormalizeHandoffs(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	handoffs []jointDPBiomedicalGaussianFullPhase19FinalizerHandoff,
	backendKey [32]byte,
) (jointDPBiomedicalGaussianFullNormalizedInput, error) {
	var zero jointDPBiomedicalGaussianFullNormalizedInput
	contract := admission.selection.Contract
	if len(handoffs) < 1 || len(handoffs) > contract.TotalCoordinateCount {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: incomplete finalizer handoff schedule")
	}
	ordered := append([]jointDPBiomedicalGaussianFullPhase19FinalizerHandoff(nil),
		handoffs...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].ChunkStart < ordered[j].ChunkStart
	})
	left := make([]byte, 0, contract.TotalCoordinateCount*16)
	right := make([]byte, 0, contract.TotalCoordinateCount*16)
	next := 0
	postRoot, executionPair := "", ""
	for _, handoff := range ordered {
		if err := jointDPBiomedicalGaussianValidateFullPhase19FinalizerHandoff(
			admission, pins, handoff, backendKey); err != nil {
			return zero, err
		}
		if handoff.ChunkStart != next ||
			handoff.CoordinateCount > contract.TotalCoordinateCount-next {
			return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: overlapping, missing, or reordered release chunk")
		}
		if postRoot == "" {
			postRoot = handoff.Phase19PostExecutionRootSHA256
			executionPair = handoff.Phase19ExecutionReceiptPairSHA256
		} else if postRoot != handoff.Phase19PostExecutionRootSHA256 ||
			executionPair != handoff.Phase19ExecutionReceiptPairSHA256 {
			return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: release chunks use different Phase-1.9 evidence")
		}
		leftChunk, err := base64.StdEncoding.Strict().DecodeString(
			handoff.handoff.finalizerInput.LeftNoisedShare)
		if err != nil || len(leftChunk) != handoff.CoordinateCount*16 {
			return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid left protected release chunk")
		}
		rightChunk, err := base64.StdEncoding.Strict().DecodeString(
			handoff.handoff.finalizerInput.RightNoisedShare)
		if err != nil || len(rightChunk) != handoff.CoordinateCount*16 {
			return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid right protected release chunk")
		}
		left = append(left, leftChunk...)
		right = append(right, rightChunk...)
		clear(leftChunk)
		clear(rightChunk)
		next += handoff.CoordinateCount
	}
	if next != contract.TotalCoordinateCount {
		clear(left)
		clear(right)
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: incomplete release coordinate coverage")
	}
	leftDigest, rightDigest := sha256.Sum256(left), sha256.Sum256(right)
	inputDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullDurableRecordDomain+"/input", struct {
			ReleaseInstanceID                 string `json:"release_instance_id"`
			ReleaseContractSHA256             string `json:"release_contract_sha256"`
			Phase19PostExecutionRootSHA256    string `json:"phase19_post_execution_root_sha256"`
			Phase19ExecutionReceiptPairSHA256 string `json:"phase19_execution_receipt_pair_sha256"`
			LeftSHA256                        string `json:"left_sha256"`
			RightSHA256                       string `json:"right_sha256"`
		}{
			contract.ReleaseInstanceID, contract.ReleaseContractSHA256,
			postRoot, executionPair, hex.EncodeToString(leftDigest[:]),
			hex.EncodeToString(rightDigest[:]),
		})
	if err != nil {
		clear(left)
		clear(right)
		return zero, err
	}
	ledger, err := jointDPBiomedicalGaussianFullReceipt(
		contract.ReceiptReferences, jointDPBiomedicalGaussianReceiptPrivacyLedger)
	if err != nil {
		clear(left)
		clear(right)
		return zero, err
	}
	finalizer, err := jointDPBiomedicalGaussianFullReceipt(
		contract.ReceiptReferences, jointDPBiomedicalGaussianReceiptFinalizer)
	if err != nil {
		clear(left)
		clear(right)
		return zero, err
	}
	return jointDPBiomedicalGaussianFullNormalizedInput{
		left: left, right: right, postRoot: postRoot,
		executionPair:        executionPair,
		digest:               hex.EncodeToString(inputDigest[:]),
		ledgerReservation:    ledger.SHA256,
		finalizerReservation: finalizer.SHA256,
	}, nil
}

func jointDPBiomedicalGaussianFullFinalizeNormalized(
	admission jointDPBiomedicalGaussianFullAdmission,
	normalized jointDPBiomedicalGaussianFullNormalizedInput,
) ([]string, error) {
	contract := admission.selection.Contract
	chunkSize := contract.MaximumChunkCoordinates
	if chunkSize < 1 {
		return nil, fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid canonical finalizer chunk size")
	}
	values := make([]string, 0, contract.TotalCoordinateCount)
	for start := 0; start < contract.TotalCoordinateCount; start += chunkSize {
		count := chunkSize
		if count > contract.TotalCoordinateCount-start {
			count = contract.TotalCoordinateCount - start
		}
		first, last := start*16, (start+count)*16
		input := jointDPGaussianFinalizerInput{
			Version:  jointDPGaussianFinalizerInputVersion,
			RingBits: 128, FracBits: 0,
			TotalCoordinateCount: contract.TotalCoordinateCount,
			ChunkStart:           start, CoordinateCount: count,
			OutputLatticeBits:  contract.OutputLatticeBits,
			Epsilon:            contract.Epsilon,
			AllocatedDelta:     contract.Delta,
			L2SensitivitySteps: admission.certificate.SelectedBoundSteps,
			ScaleShifts:        make([]int, count),
			RawUpperBounds: append([]string(nil),
				admission.certificate.ShiftedUpperBounds[start:start+count]...),
			ReleaseContractHash: contract.ReleaseContractSHA256,
			TranscriptHash:      contract.WorkerTranscriptSHA256,
			LeftNoisedShare: base64.StdEncoding.EncodeToString(
				normalized.left[first:last]),
			RightNoisedShare: base64.StdEncoding.EncodeToString(
				normalized.right[first:last]),
		}
		output, err := jointDPGaussianFinalize(input)
		input.LeftNoisedShare, input.RightNoisedShare = "", ""
		if err != nil {
			return nil, err
		}
		if output.Backend != jointDPGaussianBackend ||
			output.ReleaseContractHash != contract.ReleaseContractSHA256 ||
			output.TranscriptHash != contract.WorkerTranscriptSHA256 ||
			output.ChunkStart != start || output.CoordinateCount != count ||
			output.PreclampValuesReturned || !output.NoWrapHeadroomCertified ||
			len(output.ClampedScaledValues) != count {
			return nil, fmt.Errorf("joint-dp-biomedical-gaussian-full: finalizer certificate mismatch")
		}
		values = append(values, output.ClampedScaledValues...)
	}
	return values, nil
}

func (store *jointDPBiomedicalGaussianFullDurableReleaseStore) FinalizeVector(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	handoffs []jointDPBiomedicalGaussianFullPhase19FinalizerHandoff,
	phaseHook func(string),
) (jointDPBiomedicalGaussianFullLocalRelease, error) {
	return store.finalizeVector(admission, pins, handoffs, phaseHook, false)
}

// finalizeVector's final flag is process-local authority issued only by the
// formal-GLM durable range gate.  It is deliberately absent from every JSON
// contract and public method: a formal fallback cannot bypass the hidden
// Phase-1.9 validity/range predicate by calling the generic finalizer.
func (store *jointDPBiomedicalGaussianFullDurableReleaseStore) finalizeVector(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	handoffs []jointDPBiomedicalGaussianFullPhase19FinalizerHandoff,
	phaseHook func(string), formalRangeGateConsumed bool,
) (jointDPBiomedicalGaussianFullLocalRelease, error) {
	var zero jointDPBiomedicalGaussianFullLocalRelease
	if err := jointDPBiomedicalGaussianValidateFullAdmissionCached(
		admission, pins); err != nil {
		return zero, err
	}
	if admission.formalSelection != nil && !formalRangeGateConsumed {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: formal fallback requires the durable exact range gate")
	}
	contract := admission.selection.Contract
	if !formalGLMPhase19Contains(contract.DesignatedComputePeers, store.peer) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: durable finalizer peer is not designated")
	}
	publicKey, ok := store.signer.Public().(ed25519.PublicKey)
	if !ok || !hmac.Equal(publicKey, pins[store.peer]) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: durable finalizer signer is not pinned")
	}
	normalized, err := jointDPBiomedicalGaussianFullNormalizeHandoffs(
		admission, pins, handoffs, store.key)
	if err != nil {
		return zero, err
	}
	defer clear(normalized.left)
	defer clear(normalized.right)

	record := jointDPBiomedicalGaussianFullDurableRecord{
		Version:                           jointDPBiomedicalGaussianFullDurableRecordVersion,
		State:                             "ledger_committed",
		PeerName:                          store.peer,
		ReleaseInstanceID:                 contract.ReleaseInstanceID,
		ReleaseContractSHA256:             contract.ReleaseContractSHA256,
		Phase19PostExecutionRootSHA256:    normalized.postRoot,
		Phase19ExecutionReceiptPairSHA256: normalized.executionPair,
		InputCommitmentSHA256:             normalized.digest,
		LedgerReservationSHA256:           normalized.ledgerReservation,
		FinalizerReservationSHA256:        normalized.finalizerReservation,
		LedgerAppendBeforeRelease:         true,
		HistoryCanDenyOperation:           false,
		OperationLimit:                    false,
		RequestLimit:                      false,
		ReleaseReceiptJSON:                "",
	}
	path, err := store.recordPath(contract.ReleaseInstanceID, true)
	if err != nil {
		return zero, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	read := func() (jointDPBiomedicalGaussianFullDurableRecord, error) {
		encoded, readErr := jointDPBiomedicalGaussianFullReadDurableRecord(path)
		if readErr != nil {
			return jointDPBiomedicalGaussianFullDurableRecord{}, readErr
		}
		return jointDPBiomedicalGaussianFullDecodeRecord(store.key, encoded)
	}
	existing, readErr := read()
	created := false
	if os.IsNotExist(readErr) {
		encoded, encodeErr := jointDPBiomedicalGaussianFullEncodeRecord(
			store.key, record)
		if encodeErr != nil {
			return zero, encodeErr
		}
		created, err = jointDPBiomedicalGaussianFullCreateRecord(path, encoded)
		if err != nil {
			return zero, err
		}
		existing, err = read()
		if err != nil {
			return zero, err
		}
	} else if readErr != nil {
		return zero, readErr
	}
	for _, pair := range [][2]string{
		{existing.PeerName, record.PeerName},
		{existing.ReleaseInstanceID, record.ReleaseInstanceID},
		{existing.ReleaseContractSHA256, record.ReleaseContractSHA256},
		{existing.Phase19PostExecutionRootSHA256, record.Phase19PostExecutionRootSHA256},
		{existing.Phase19ExecutionReceiptPairSHA256, record.Phase19ExecutionReceiptPairSHA256},
		{existing.InputCommitmentSHA256, record.InputCommitmentSHA256},
		{existing.LedgerReservationSHA256, record.LedgerReservationSHA256},
		{existing.FinalizerReservationSHA256, record.FinalizerReservationSHA256},
	} {
		if pair[0] != pair[1] {
			return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: conflicting durable release replay")
		}
	}
	if existing.State == "released" {
		var receipt jointDPBiomedicalGaussianFullLocalReleaseReceipt
		if err := json.Unmarshal([]byte(existing.ReleaseReceiptJSON), &receipt); err != nil {
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
	if created && phaseHook != nil {
		phaseHook("after_ledger_append_before_release")
	}
	values, err := jointDPBiomedicalGaussianFullFinalizeNormalized(
		admission, normalized)
	if err != nil {
		return zero, err
	}
	vectorDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullLocalReleaseDomain+"/vector", values)
	if err != nil {
		return zero, err
	}
	pinDigest := sha256.Sum256(publicKey)
	receipt := jointDPBiomedicalGaussianFullLocalReleaseReceipt{
		Version:                           jointDPBiomedicalGaussianFullLocalReleaseVersion,
		Backend:                           jointDPGaussianBackend,
		Mechanism:                         jointDPGaussianMechanism,
		Sampler:                           jointDPGaussianSampler,
		PeerName:                          store.peer,
		PeerIdentitySHA256:                hex.EncodeToString(pinDigest[:]),
		ReleaseInstanceID:                 contract.ReleaseInstanceID,
		ReleaseContractSHA256:             contract.ReleaseContractSHA256,
		Phase19PostExecutionRootSHA256:    normalized.postRoot,
		Phase19ExecutionReceiptPairSHA256: normalized.executionPair,
		LedgerReservationSHA256:           normalized.ledgerReservation,
		FinalizerReservationSHA256:        normalized.finalizerReservation,
		VectorSHA256:                      hex.EncodeToString(vectorDigest[:]),
		ClampedScaledValues:               append([]string(nil), values...),
		Epsilon:                           contract.Epsilon,
		Delta:                             contract.Delta,
		RouteRole:                         jointDPBiomedicalGaussianFullRouteRole,
		TargetVarianceOptimal:             false,
		NominalVarianceMultiplier:         2,
		NominalStandardDeviationFactor:    "sqrt(2)_relative_to_one_full_draw",
		LedgerAppendBeforeRelease:         true,
		ExactlyOnceRelease:                true,
		SingleCommonDPVector:              false,
		UnlimitedDeterministicReplay:      true,
		UnlimitedPostprocessing:           true,
		HistoryCanDenyOperation:           false,
		OperationLimit:                    false,
		RequestLimit:                      false,
		OpeningsPerformed:                 1,
		ProductionReady:                   false,
		Blockers: append([]string(nil),
			jointDPBiomedicalGaussianFullReleaseBlockers...),
	}
	common := jointDPBiomedicalGaussianFullCommonFromLocal(admission, receipt)
	commonMessage, err := jointDPBiomedicalGaussianFullCommonReleaseMessage(common)
	if err != nil {
		return zero, err
	}
	receipt.CommonReleaseSignature = ed25519.Sign(store.signer, commonMessage)
	message, err := jointDPBiomedicalGaussianFullLocalReleaseMessage(receipt)
	if err != nil {
		return zero, err
	}
	receipt.Signature = ed25519.Sign(store.signer, message)
	if err := jointDPBiomedicalGaussianValidateFullLocalRelease(
		admission, pins, receipt); err != nil {
		return zero, err
	}
	receiptBytes, err := json.Marshal(receipt)
	if err != nil {
		return zero, err
	}
	existing.State = "released"
	existing.ReleaseReceiptJSON = string(receiptBytes)
	encoded, err := jointDPBiomedicalGaussianFullEncodeRecord(store.key, existing)
	if err != nil {
		return zero, err
	}
	if err := exactGCAtomicReplace(path, encoded); err != nil {
		return zero, err
	}
	committed, err := read()
	if err != nil || committed.State != "released" ||
		committed.ReleaseReceiptJSON != string(receiptBytes) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: durable DP release commit failed")
	}
	if phaseHook != nil {
		phaseHook("after_dp_vector_durable")
	}
	return jointDPBiomedicalGaussianFullLocalRelease{
		Receipt: receipt, Replayed: false,
	}, nil
}

func jointDPBiomedicalGaussianPairFullLocalReleases(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	first, second jointDPBiomedicalGaussianFullLocalReleaseReceipt,
) (jointDPBiomedicalGaussianFullCommonRelease, error) {
	var zero jointDPBiomedicalGaussianFullCommonRelease
	if err := jointDPBiomedicalGaussianValidateFullLocalRelease(
		admission, pins, first); err != nil {
		return zero, err
	}
	if err := jointDPBiomedicalGaussianValidateFullLocalRelease(
		admission, pins, second); err != nil {
		return zero, err
	}
	peers := admission.selection.Contract.DesignatedComputePeers
	byPeer := map[string]jointDPBiomedicalGaussianFullLocalReleaseReceipt{
		first.PeerName: first, second.PeerName: second,
	}
	left, leftOK := byPeer[peers[0]]
	right, rightOK := byPeer[peers[1]]
	if !leftOK || !rightOK || len(byPeer) != 2 {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: common release lacks both designated peers")
	}
	leftCore, rightCore := left, right
	leftCore.PeerName, rightCore.PeerName = "", ""
	leftCore.PeerIdentitySHA256, rightCore.PeerIdentitySHA256 = "", ""
	leftCore.CommonReleaseSignature, rightCore.CommonReleaseSignature = nil, nil
	leftCore.Signature, rightCore.Signature = nil, nil
	if !reflect.DeepEqual(leftCore, rightCore) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: designated peers released different DP vectors")
	}
	commonLeft := jointDPBiomedicalGaussianFullCommonFromLocal(admission, left)
	commonRight := jointDPBiomedicalGaussianFullCommonFromLocal(admission, right)
	if !reflect.DeepEqual(commonLeft, commonRight) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: designated peers signed different common releases")
	}
	commonLeft.Signatures = []jointDPBiomedicalGaussianSignature{
		{Signer: peers[0], Signature: append([]byte(nil),
			left.CommonReleaseSignature...)},
		{Signer: peers[1], Signature: append([]byte(nil),
			right.CommonReleaseSignature...)},
	}
	if err := jointDPBiomedicalGaussianValidateFullCommonRelease(
		admission, pins, commonLeft); err != nil {
		return zero, err
	}
	return commonLeft, nil
}
