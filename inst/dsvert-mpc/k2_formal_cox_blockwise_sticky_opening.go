package main

// Internal durable finalizer for the blockwise Cox kernel. Local handoffs and
// the pre-publication candidate stay encrypted in owner-only Rock storage.
// This file exposes no command, capability, API, DSI method, or transport
// route.

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
	"sync"

	"golang.org/x/crypto/hkdf"
)

const (
	formalCoxBlockwiseOpeningVersion = "dsvert-formal-cox-blockwise-sticky-opening-v1"
	formalCoxBlockwiseOpeningPurpose = "formal_cox_one_public_beta_validity_opening_v1"
	formalCoxBlockwiseOpeningDomain  = "dsVert/formal-cox/blockwise-sticky/opening/v1"
	formalCoxBlockwiseOpeningMode    = "dual_authority_additive_ring_and_xor_validity_v1"
	formalCoxBlockwiseExpOpeningMode = "certified_dyadic_interval_midpoint_v1"

	formalCoxBlockwiseOpeningPrivateMax = 4 << 20
	formalCoxBlockwiseOpeningPublicMax  = 4 << 20
	formalCoxBlockwiseOpeningSignerMax  = 64 << 10
)

type formalCoxBlockwiseOpeningHandoffHeader struct {
	Version           string                        `json:"version"`
	Purpose           string                        `json:"purpose"`
	ArtifactID        string                        `json:"artifact_id"`
	PlanSHA256        string                        `json:"plan_sha256"`
	RunID             string                        `json:"run_id"`
	PinsetSHA256      string                        `json:"pinset_sha256"`
	FinalCursor       formalCoxBlockwiseWorkerStep  `json:"final_cursor"`
	Completion        formalCoxBlockwiseCompletion  `json:"completion"`
	FinalReceipt      formalCoxBlockwiseStepReceipt `json:"final_receipt"`
	PeerName          string                        `json:"peer_name"`
	PeerID            string                        `json:"peer_id"`
	Role              string                        `json:"role"`
	CoefficientCount  int                           `json:"coefficient_count"`
	RingBits          int                           `json:"ring_bits"`
	FractionBits      int                           `json:"fraction_bits"`
	LocalOutputSHA256 string                        `json:"local_beta_validity_sha256"`
	ProductionReady   bool                          `json:"-"`
	Signature         []byte                        `json:"signature"`
}

type formalCoxBlockwiseOpeningPrivateHandoff struct {
	Header            formalCoxBlockwiseOpeningHandoffHeader `json:"header"`
	CoefficientShares []string                               `json:"coefficient_shares"`
	ValidityShare     bool                                   `json:"validity_share"`
}

type formalCoxBlockwiseOpeningEncryptedRecord struct {
	Version    string `json:"version"`
	Purpose    string `json:"purpose"`
	Kind       string `json:"kind"`
	ArtifactID string `json:"artifact_id"`
	Slot       string `json:"slot"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type formalCoxBlockwiseOpeningCoefficient struct {
	Index                       int    `json:"index"`
	BetaSteps                   string `json:"beta_steps"`
	BetaRational                string `json:"beta_rational"`
	HazardRatioLowerRational    string `json:"hazard_ratio_lower_rational"`
	HazardRatioUpperRational    string `json:"hazard_ratio_upper_rational"`
	HazardRatioMidpointRational string `json:"hazard_ratio_midpoint_rational"`
}

type formalCoxBlockwiseOpeningCandidate struct {
	Version               string                                 `json:"version"`
	Purpose               string                                 `json:"purpose"`
	ArtifactID            string                                 `json:"artifact_id"`
	Artifact              formalCoxBlockwiseStickyArtifact       `json:"artifact"`
	PlanSHA256            string                                 `json:"plan_sha256"`
	FinalPairRootSHA256   string                                 `json:"final_pair_root_sha256"`
	FinalTranscriptSHA256 string                                 `json:"final_transcript_sha256"`
	FinalCommitSHA256     string                                 `json:"final_commit_sha256"`
	FinalCursor           formalCoxBlockwiseWorkerStep           `json:"final_cursor"`
	CoefficientCount      int                                    `json:"coefficient_count"`
	RingBits              int                                    `json:"ring_bits"`
	FractionBits          int                                    `json:"fraction_bits"`
	ExpCertificateBits    int                                    `json:"exp_certificate_bits"`
	OpeningMode           string                                 `json:"opening_mode"`
	ExpPostprocessMode    string                                 `json:"exp_postprocess_mode"`
	Valid                 bool                                   `json:"valid"`
	Coefficients          []formalCoxBlockwiseOpeningCoefficient `json:"coefficients"`
	ProductionReady       bool                                   `json:"-"`
}

type formalCoxBlockwiseOpeningIntent struct {
	Version             string `json:"version"`
	Purpose             string `json:"purpose"`
	ArtifactID          string `json:"artifact_id"`
	CandidateSHA256     string `json:"candidate_sha256"`
	FinalPairRootSHA256 string `json:"final_pair_root_sha256"`
	OpeningMode         string `json:"opening_mode"`
	ExpPostprocessMode  string `json:"exp_postprocess_mode"`
	ProductionReady     bool   `json:"-"`
}

type formalCoxBlockwiseOpeningCertificate struct {
	Version           string                               `json:"version"`
	Purpose           string                               `json:"purpose"`
	Candidate         formalCoxBlockwiseOpeningCandidate   `json:"candidate"`
	Intent            formalCoxBlockwiseOpeningIntent      `json:"intent"`
	AuthorityReceipts []jointDPBiomedicalGaussianSignature `json:"authority_receipts"`
	ProductionReady   bool                                 `json:"-"`
}

type formalCoxBlockwiseOpeningPublication struct {
	ArtifactID        string
	CertificateSHA256 string
	Certificate       []byte
	Replayed          bool
}

type formalCoxBlockwiseOpeningSignerRecord struct {
	Version                  string                             `json:"version"`
	Purpose                  string                             `json:"purpose"`
	ArtifactID               string                             `json:"artifact_id"`
	CandidateSHA256          string                             `json:"candidate_sha256"`
	Signer                   string                             `json:"signer"`
	Role                     string                             `json:"role"`
	PredecessorReceiptSHA256 string                             `json:"predecessor_receipt_sha256,omitempty"`
	Receipt                  jointDPBiomedicalGaussianSignature `json:"receipt"`
	RecordMAC                string                             `json:"record_mac"`
}

type formalCoxBlockwiseOpeningPublicRecord struct {
	Version           string `json:"version"`
	Purpose           string `json:"purpose"`
	ArtifactID        string `json:"artifact_id"`
	CertificateSHA256 string `json:"certificate_sha256"`
	CertificateJSON   string `json:"certificate_json"`
	RecordMAC         string `json:"record_mac"`
}

type formalCoxBlockwiseOpeningStore struct {
	mu         sync.Mutex
	root       *os.Root
	key        [32]byte
	plan       formalCoxBlockwisePlan
	planSHA256 string
	pins       map[string]ed25519.PublicKey
	artifact   formalCoxBlockwiseStickyArtifact
	artifactID string
}

func formalCoxBlockwiseOpeningHash(label string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalCoxBlockwiseOpeningDomain+"/"+label+"|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxBlockwiseOpeningEqual(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func newFormalCoxBlockwiseOpeningStore(dir string, storageRoot [32]byte,
	plan formalCoxBlockwisePlan, pins map[string]ed25519.PublicKey,
) (*formalCoxBlockwiseOpeningStore, error) {
	var zero [32]byte
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir ||
		dir == string(filepath.Separator) || hmac.Equal(storageRoot[:], zero[:]) {
		return nil, fmt.Errorf("formal-cox: invalid sticky opening store")
	}
	artifact, artifactID, err := formalCoxBlockwiseBuildStickyArtifact(plan, pins)
	if err != nil {
		return nil, err
	}
	planSHA256, err := formalCoxBlockwisePlanSHA256(plan)
	if err != nil {
		return nil, err
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	var frozen formalCoxBlockwisePlan
	if err := formalCoxBlockwiseSourceDecodeCanonical(planJSON,
		formalCoxBlockwiseOpeningPrivateMax, "sticky opening plan", &frozen); err != nil {
		return nil, err
	}
	copyPins := make(map[string]ed25519.PublicKey, len(pins))
	for name, pin := range pins {
		if len(pin) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("formal-cox: invalid sticky opening pinset")
		}
		copyPins[name] = append(ed25519.PublicKey(nil), pin...)
	}
	if err := formalCoxBlockwiseSourceEnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*formalCoxBlockwiseOpeningStore, error) {
		_ = root.Close()
		return nil, err
	}
	for _, relative := range []string{"private-v1", "signers-v1", "public-v1"} {
		if err := formalCoxBlockwiseGuardEnsureRootDir(root, relative); err != nil {
			return fail(err)
		}
	}
	artifactBytes, err := hex.DecodeString(artifactID)
	if err != nil || len(artifactBytes) != sha256.Size {
		clear(artifactBytes)
		return fail(fmt.Errorf("formal-cox: invalid sticky opening artifact id"))
	}
	reader := hkdf.New(sha256.New, storageRoot[:], artifactBytes,
		[]byte(formalCoxBlockwiseOpeningDomain+"/owner-store-key"))
	clear(artifactBytes)
	var key [32]byte
	if _, err := io.ReadFull(reader, key[:]); err != nil || hmac.Equal(key[:], zero[:]) {
		clear(key[:])
		return fail(fmt.Errorf("formal-cox: sticky opening key derivation failed"))
	}
	return &formalCoxBlockwiseOpeningStore{
		root: root, key: key, plan: frozen, planSHA256: planSHA256,
		pins: copyPins, artifact: artifact, artifactID: artifactID,
	}, nil
}

func (store *formalCoxBlockwiseOpeningStore) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	clear(store.key[:])
	if store.root == nil {
		return nil
	}
	err := store.root.Close()
	store.root = nil
	return err
}

func (store *formalCoxBlockwiseOpeningStore) roleForPeer(peer string) (string, error) {
	if store == nil || len(store.plan.Policy.ComputePeers) != 2 {
		return "", fmt.Errorf("formal-cox: invalid sticky opening store")
	}
	if peer == store.plan.Policy.ComputePeers[0] {
		return "garbler", nil
	}
	if peer == store.plan.Policy.ComputePeers[1] {
		return "evaluator", nil
	}
	return "", fmt.Errorf("formal-cox: peer is not an opening authority")
}

func (store *formalCoxBlockwiseOpeningStore) privateRelativePath(
	artifactID, kind, peer string, create bool,
) (string, error) {
	if store == nil || store.root == nil || artifactID != store.artifactID ||
		!formalCoxIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-cox: invalid private opening artifact")
	}
	slot := "candidate"
	switch kind {
	case "handoff":
		role, err := store.roleForPeer(peer)
		if err != nil {
			return "", err
		}
		slot = role
	case "candidate":
		if peer != "" {
			return "", fmt.Errorf("formal-cox: invalid private candidate slot")
		}
	default:
		return "", fmt.Errorf("formal-cox: invalid private opening kind")
	}
	shard := filepath.Join("private-v1", artifactID[:2], artifactID[2:4])
	if create {
		if err := formalCoxBlockwiseGuardEnsureRootDir(store.root, shard); err != nil {
			return "", err
		}
	}
	return filepath.Join(shard, kind+"-"+slot+"-"+artifactID+".bin"), nil
}

func (store *formalCoxBlockwiseOpeningStore) signerRelativePath(
	artifactID, peer string, create bool,
) (string, error) {
	role, err := store.roleForPeer(peer)
	if err != nil || artifactID != store.artifactID || !formalCoxIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-cox: invalid sticky opening signer")
	}
	shard := filepath.Join("signers-v1", artifactID[:2], artifactID[2:4])
	if create {
		if err := formalCoxBlockwiseGuardEnsureRootDir(store.root, shard); err != nil {
			return "", err
		}
	}
	return filepath.Join(shard, "signer-"+role+"-"+artifactID+".json"), nil
}

func (store *formalCoxBlockwiseOpeningStore) publicRelativePath(
	artifactID string, create bool,
) (string, error) {
	if store == nil || store.root == nil || artifactID != store.artifactID ||
		!formalCoxIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-cox: invalid public opening artifact")
	}
	shard := filepath.Join("public-v1", artifactID[:2], artifactID[2:4])
	if create {
		if err := formalCoxBlockwiseGuardEnsureRootDir(store.root, shard); err != nil {
			return "", err
		}
	}
	return filepath.Join(shard, "publication-"+artifactID+".json"), nil
}

func (store *formalCoxBlockwiseOpeningStore) privateKey(
	kind, slot string,
) ([32]byte, error) {
	var result [32]byte
	if store == nil || store.root == nil ||
		(kind != "handoff" && kind != "candidate") {
		return result, fmt.Errorf("formal-cox: invalid private opening key request")
	}
	artifact, err := hex.DecodeString(store.artifactID)
	if err != nil || len(artifact) != sha256.Size {
		clear(artifact)
		return result, fmt.Errorf("formal-cox: invalid private opening key binding")
	}
	reader := hkdf.New(sha256.New, store.key[:], artifact,
		[]byte(formalCoxBlockwiseOpeningDomain+"/private-aead/"+kind+"/"+slot))
	clear(artifact)
	if _, err := io.ReadFull(reader, result[:]); err != nil {
		clear(result[:])
		return result, err
	}
	return result, nil
}

func formalCoxBlockwiseOpeningPrivateAAD(
	record formalCoxBlockwiseOpeningEncryptedRecord,
) ([]byte, error) {
	record.Ciphertext = ""
	return json.Marshal(record)
}

func (store *formalCoxBlockwiseOpeningStore) encodePrivate(
	kind, slot string, value any,
) ([]byte, error) {
	plaintext, err := json.Marshal(value)
	if err != nil || len(plaintext) == 0 || len(plaintext) > formalCoxBlockwiseOpeningPrivateMax {
		clear(plaintext)
		return nil, fmt.Errorf("formal-cox: invalid private opening payload")
	}
	defer clear(plaintext)
	key, err := store.privateKey(kind, slot)
	if err != nil {
		return nil, err
	}
	defer clear(key[:])
	aead, err := exactGCNewAEAD(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		clear(nonce)
		return nil, err
	}
	record := formalCoxBlockwiseOpeningEncryptedRecord{
		Version: formalCoxBlockwiseOpeningVersion,
		Purpose: formalCoxBlockwiseOpeningPurpose,
		Kind:    kind, ArtifactID: store.artifactID, Slot: slot,
		Nonce: base64.StdEncoding.EncodeToString(nonce),
	}
	aad, err := formalCoxBlockwiseOpeningPrivateAAD(record)
	if err != nil {
		clear(nonce)
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	clear(nonce)
	clear(aad)
	record.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	clear(ciphertext)
	return json.Marshal(record)
}

func (store *formalCoxBlockwiseOpeningStore) decodePrivate(
	encoded []byte, kind, slot string, value any,
) error {
	var record formalCoxBlockwiseOpeningEncryptedRecord
	if err := formalCoxBlockwiseSourceDecodeCanonical(encoded,
		formalCoxBlockwiseOpeningPrivateMax, "private sticky opening record",
		&record); err != nil {
		return err
	}
	if record.Version != formalCoxBlockwiseOpeningVersion ||
		record.Purpose != formalCoxBlockwiseOpeningPurpose ||
		record.Kind != kind || record.ArtifactID != store.artifactID ||
		record.Slot != slot {
		return fmt.Errorf("formal-cox: private opening record binding mismatch")
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(record.Nonce)
	if err != nil || base64.StdEncoding.EncodeToString(nonce) != record.Nonce {
		clear(nonce)
		return fmt.Errorf("formal-cox: invalid private opening nonce")
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(record.Ciphertext)
	if err != nil || base64.StdEncoding.EncodeToString(ciphertext) != record.Ciphertext {
		clear(nonce)
		clear(ciphertext)
		return fmt.Errorf("formal-cox: invalid private opening ciphertext")
	}
	key, err := store.privateKey(kind, slot)
	if err != nil {
		clear(nonce)
		clear(ciphertext)
		return err
	}
	defer clear(key[:])
	aead, err := exactGCNewAEAD(key[:])
	if err != nil || len(nonce) != aead.NonceSize() ||
		len(ciphertext) < aead.Overhead() {
		clear(nonce)
		clear(ciphertext)
		return fmt.Errorf("formal-cox: invalid private opening AEAD")
	}
	aad, err := formalCoxBlockwiseOpeningPrivateAAD(record)
	if err != nil {
		clear(nonce)
		clear(ciphertext)
		return err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	clear(nonce)
	clear(ciphertext)
	clear(aad)
	if err != nil {
		clear(plaintext)
		return fmt.Errorf("formal-cox: private opening authentication failed")
	}
	defer clear(plaintext)
	return formalCoxBlockwiseSourceDecodeCanonical(plaintext,
		formalCoxBlockwiseOpeningPrivateMax, "private sticky opening payload", value)
}

func formalCoxBlockwiseOpeningHandoffMessage(
	header formalCoxBlockwiseOpeningHandoffHeader,
) ([]byte, error) {
	header.Signature = nil
	encoded, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalCoxBlockwiseOpeningDomain+"/local-handoff|"),
		encoded...), nil
}

func formalCoxBlockwiseOpeningLocalOutputSHA256(artifactID, planSHA256,
	peer, role string, shares []string, validity bool,
) (string, error) {
	return formalCoxBlockwiseOpeningHash("local-beta-validity", struct {
		ArtifactID    string   `json:"artifact_id"`
		PlanSHA256    string   `json:"plan_sha256"`
		Peer          string   `json:"peer"`
		Role          string   `json:"role"`
		Shares        []string `json:"shares"`
		ValidityShare bool     `json:"validity_share"`
	}{artifactID, planSHA256, peer, role,
		append([]string(nil), shares...), validity})
}

func (store *formalCoxBlockwiseOpeningStore) validateHandoffHeader(
	header formalCoxBlockwiseOpeningHandoffHeader,
) error {
	role, roleErr := store.roleForPeer(header.PeerName)
	peerID, peerErr := formalCoxBlockwiseSourcePeerID(store.pins[header.PeerName])
	last, lastErr := formalCoxBlockwiseWorkerStepAt(
		store.plan, store.plan.ScheduleSteps-1)
	completionDigest, completionErr :=
		formalCoxBlockwiseCompletionDigest(header.Completion)
	message, messageErr := formalCoxBlockwiseOpeningHandoffMessage(header)
	receiptMessage, receiptErr := formalCoxBlockwiseReceiptUnsigned(header.FinalReceipt)
	if roleErr != nil || peerErr != nil || lastErr != nil || completionErr != nil ||
		messageErr != nil || receiptErr != nil ||
		header.Version != formalCoxBlockwiseOpeningVersion ||
		header.Purpose != formalCoxBlockwiseOpeningPurpose ||
		header.ArtifactID != store.artifactID || header.PlanSHA256 != store.planSHA256 ||
		header.RunID != store.plan.RunID ||
		header.PinsetSHA256 != store.artifact.PinsetSHA256 ||
		header.FinalCursor != last || header.PeerID != peerID ||
		header.Role != role || header.CoefficientCount != store.plan.Policy.CovariateCount ||
		header.RingBits != store.plan.RingBits ||
		header.FractionBits != store.plan.Policy.FracBits ||
		header.ProductionReady || !formalCoxIsSHA256(header.LocalOutputSHA256) ||
		header.Completion.Version != formalCoxBlockwiseCompletionVersion ||
		header.Completion.PlanSHA256 != store.planSHA256 ||
		header.Completion.ScheduleSteps != store.plan.ScheduleSteps ||
		!header.Completion.FixedScheduleComplete ||
		header.Completion.OutputKind != "sealed_private_result_v1" ||
		header.Completion.ProductionReady ||
		header.Completion.CompletionSHA256 != completionDigest ||
		!formalCoxIsSHA256(header.Completion.TranscriptSHA256) ||
		!formalCoxIsSHA256(header.Completion.FinalCommitSHA256) ||
		header.FinalReceipt.Peer != header.PeerName ||
		header.FinalReceipt.PlanSHA256 != store.planSHA256 ||
		header.FinalReceipt.Step != last ||
		header.FinalReceipt.TranscriptSHA256 != header.Completion.TranscriptSHA256 ||
		len(header.FinalReceipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(store.pins[header.PeerName], receiptMessage,
			header.FinalReceipt.Signature) ||
		len(header.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(store.pins[header.PeerName], message, header.Signature) {
		return fmt.Errorf("formal-cox: invalid signed local opening handoff")
	}
	return nil
}

func (store *formalCoxBlockwiseOpeningStore) SubmitLocal(
	checkpoint *formalCoxBlockwiseCheckpointStore, privateKey ed25519.PrivateKey,
) (formalCoxBlockwiseOpeningHandoffHeader, bool, error) {
	var zero formalCoxBlockwiseOpeningHandoffHeader
	if store == nil || store.root == nil || checkpoint == nil ||
		len(privateKey) != ed25519.PrivateKeySize {
		return zero, false, fmt.Errorf("formal-cox: invalid local opening submission")
	}
	peer := checkpoint.peer
	role, err := store.roleForPeer(peer)
	checkpointPlanSHA, planErr := formalCoxBlockwisePlanSHA256(checkpoint.plan)
	if err != nil || planErr != nil || checkpointPlanSHA != store.planSHA256 ||
		!hmac.Equal(privateKey.Public().(ed25519.PublicKey), store.pins[peer]) {
		return zero, false, fmt.Errorf("formal-cox: local opening submission binding mismatch")
	}
	if existing, loadErr := store.loadPrivateHandoff(peer); loadErr == nil {
		return existing, true, nil
	} else if !os.IsNotExist(loadErr) {
		return zero, false, loadErr
	}
	completion, _, err := checkpoint.Completion()
	if err != nil {
		return zero, false, err
	}
	state, err := checkpoint.Load()
	if err != nil || state.LastReceipt == nil ||
		state.TranscriptSHA256 != completion.TranscriptSHA256 ||
		state.FinalCommitSHA256 != completion.FinalCommitSHA256 ||
		formalCoxBlockwisePrivateStateSHA256(state) != state.LastReceipt.StateSHA256 {
		return zero, false, fmt.Errorf("formal-cox: local final checkpoint is not bound")
	}
	sealed, err := checkpoint.FinalSealedOutput()
	if err != nil {
		return zero, false, err
	}
	defer exactGCZeroBigInts(sealed.CoefficientShares)
	shares := make([]string, len(sealed.CoefficientShares))
	for index, share := range sealed.CoefficientShares {
		shares[index] = share.Text(16)
	}
	defer func() {
		for index := range shares {
			shares[index] = ""
		}
	}()
	localSHA256, err := formalCoxBlockwiseOpeningLocalOutputSHA256(
		store.artifactID, store.planSHA256, peer, role, shares,
		sealed.ValidityShare)
	if err != nil {
		return zero, false, err
	}
	peerID, err := formalCoxBlockwiseSourcePeerID(store.pins[peer])
	if err != nil {
		return zero, false, err
	}
	header := formalCoxBlockwiseOpeningHandoffHeader{
		Version:    formalCoxBlockwiseOpeningVersion,
		Purpose:    formalCoxBlockwiseOpeningPurpose,
		ArtifactID: store.artifactID, PlanSHA256: store.planSHA256,
		RunID: store.plan.RunID, PinsetSHA256: store.artifact.PinsetSHA256,
		FinalCursor: state.LastReceipt.Step, Completion: completion,
		FinalReceipt: *state.LastReceipt,
		PeerName:     peer, PeerID: peerID, Role: role,
		CoefficientCount: store.plan.Policy.CovariateCount,
		RingBits:         store.plan.RingBits, FractionBits: store.plan.Policy.FracBits,
		LocalOutputSHA256: localSHA256, ProductionReady: false,
	}
	header.FinalReceipt.Signature = append(
		[]byte(nil), state.LastReceipt.Signature...)
	message, err := formalCoxBlockwiseOpeningHandoffMessage(header)
	if err != nil {
		return zero, false, err
	}
	header.Signature = ed25519.Sign(privateKey, message)
	if err := store.validateHandoffHeader(header); err != nil {
		return zero, false, err
	}
	payload := formalCoxBlockwiseOpeningPrivateHandoff{
		Header: header, CoefficientShares: shares,
		ValidityShare: sealed.ValidityShare,
	}
	encoded, err := store.encodePrivate("handoff", role, payload)
	if err != nil {
		return zero, false, err
	}
	defer clear(encoded)
	path, err := store.privateRelativePath(store.artifactID, "handoff", peer, true)
	if err != nil {
		return zero, false, err
	}
	store.mu.Lock()
	created, err := formalCoxBlockwiseGuardRootCreateRecord(store.root, path, encoded)
	if err == nil {
		encoded, err = formalCoxBlockwiseGuardRootReadRecord(
			store.root, path, formalCoxBlockwiseOpeningPrivateMax)
	}
	store.mu.Unlock()
	if err != nil {
		return zero, false, err
	}
	var existing formalCoxBlockwiseOpeningPrivateHandoff
	if err := store.decodePrivate(encoded, "handoff", role, &existing); err != nil {
		return zero, false, err
	}
	defer func() {
		for index := range existing.CoefficientShares {
			existing.CoefficientShares[index] = ""
		}
	}()
	if !formalCoxBlockwiseOpeningEqual(existing, payload) {
		return zero, false, fmt.Errorf("formal-cox: conflicting local opening handoff")
	}
	return existing.Header, !created, nil
}

func (store *formalCoxBlockwiseOpeningStore) loadPrivateHandoffPayload(
	peer string,
) (formalCoxBlockwiseOpeningPrivateHandoff, error) {
	var zero formalCoxBlockwiseOpeningPrivateHandoff
	role, err := store.roleForPeer(peer)
	if err != nil {
		return zero, err
	}
	path, err := store.privateRelativePath(store.artifactID, "handoff", peer, false)
	if err != nil {
		return zero, err
	}
	store.mu.Lock()
	encoded, err := formalCoxBlockwiseGuardRootReadRecord(
		store.root, path, formalCoxBlockwiseOpeningPrivateMax)
	store.mu.Unlock()
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	var payload formalCoxBlockwiseOpeningPrivateHandoff
	if err := store.decodePrivate(encoded, "handoff", role, &payload); err != nil {
		return zero, err
	}
	if err := store.validateHandoffHeader(payload.Header); err != nil ||
		len(payload.CoefficientShares) != store.plan.Policy.CovariateCount {
		return zero, fmt.Errorf("formal-cox: invalid private local opening handoff")
	}
	values, err := formalCoxBlockwiseDecodeValues(payload.CoefficientShares,
		store.plan.Policy.CovariateCount, store.plan.RingBits)
	if err != nil {
		return zero, err
	}
	exactGCZeroBigInts(values)
	want, err := formalCoxBlockwiseOpeningLocalOutputSHA256(
		store.artifactID, store.planSHA256, payload.Header.PeerName,
		payload.Header.Role, payload.CoefficientShares, payload.ValidityShare)
	if err != nil || want != payload.Header.LocalOutputSHA256 {
		return zero, fmt.Errorf("formal-cox: private local output digest mismatch")
	}
	return payload, nil
}

func (store *formalCoxBlockwiseOpeningStore) loadPrivateHandoff(
	peer string,
) (formalCoxBlockwiseOpeningHandoffHeader, error) {
	payload, err := store.loadPrivateHandoffPayload(peer)
	if err != nil {
		return formalCoxBlockwiseOpeningHandoffHeader{}, err
	}
	for index := range payload.CoefficientShares {
		payload.CoefficientShares[index] = ""
	}
	return payload.Header, nil
}

func (store *formalCoxBlockwiseOpeningStore) pairRoot(
	left, right formalCoxBlockwiseOpeningHandoffHeader,
) (string, error) {
	if err := store.validateHandoffHeader(left); err != nil {
		return "", err
	}
	if err := store.validateHandoffHeader(right); err != nil {
		return "", err
	}
	peers := store.plan.Policy.ComputePeers
	if left.PeerName != peers[0] || right.PeerName != peers[1] ||
		left.Role != "garbler" || right.Role != "evaluator" ||
		left.PlanSHA256 != right.PlanSHA256 || left.RunID != right.RunID ||
		left.FinalCursor != right.FinalCursor ||
		left.Completion.TranscriptSHA256 != right.Completion.TranscriptSHA256 ||
		left.Completion.FinalCommitSHA256 != right.Completion.FinalCommitSHA256 {
		return "", fmt.Errorf("formal-cox: local opening handoffs do not form a pair")
	}
	receipts := []formalCoxBlockwiseStepReceipt{left.FinalReceipt, right.FinalReceipt}
	if err := formalCoxBlockwiseValidateReceiptPair(
		store.plan, receipts, store.pins); err != nil {
		return "", err
	}
	commit, err := formalCoxBlockwiseFinalCommitSHA256(receipts)
	if err != nil || commit != left.Completion.FinalCommitSHA256 {
		return "", fmt.Errorf("formal-cox: local opening final barrier mismatch")
	}
	return formalCoxBlockwiseOpeningHash("signed-handoff-pair",
		[]formalCoxBlockwiseOpeningHandoffHeader{left, right})
}

func formalCoxBlockwiseOpeningCandidateSHA256(
	candidate formalCoxBlockwiseOpeningCandidate,
) (string, error) {
	return formalCoxBlockwiseOpeningHash("candidate", candidate)
}

func formalCoxBlockwiseOpeningIntentFor(
	candidate formalCoxBlockwiseOpeningCandidate,
) (formalCoxBlockwiseOpeningIntent, error) {
	digest, err := formalCoxBlockwiseOpeningCandidateSHA256(candidate)
	if err != nil {
		return formalCoxBlockwiseOpeningIntent{}, err
	}
	return formalCoxBlockwiseOpeningIntent{
		Version:    formalCoxBlockwiseOpeningVersion,
		Purpose:    formalCoxBlockwiseOpeningPurpose,
		ArtifactID: candidate.ArtifactID, CandidateSHA256: digest,
		FinalPairRootSHA256: candidate.FinalPairRootSHA256,
		OpeningMode:         candidate.OpeningMode,
		ExpPostprocessMode:  candidate.ExpPostprocessMode,
		ProductionReady:     false,
	}, nil
}

func formalCoxBlockwiseOpeningRational(value *big.Int, denominator *big.Int) string {
	return new(big.Rat).SetFrac(new(big.Int).Set(value),
		new(big.Int).Set(denominator)).RatString()
}

// buildCandidate is the sole controlled finalizer scope in which both local
// share vectors coexist. It returns only the reconstructed private candidate;
// Prepare encrypts that candidate before exposing an opaque signing intent.
func (store *formalCoxBlockwiseOpeningStore) buildCandidate() (
	formalCoxBlockwiseOpeningCandidate, error,
) {
	var zero formalCoxBlockwiseOpeningCandidate
	peers := store.plan.Policy.ComputePeers
	left, err := store.loadPrivateHandoffPayload(peers[0])
	if err != nil {
		return zero, err
	}
	defer func() {
		for index := range left.CoefficientShares {
			left.CoefficientShares[index] = ""
		}
	}()
	right, err := store.loadPrivateHandoffPayload(peers[1])
	if err != nil {
		return zero, err
	}
	defer func() {
		for index := range right.CoefficientShares {
			right.CoefficientShares[index] = ""
		}
	}()
	pairRoot, err := store.pairRoot(left.Header, right.Header)
	if err != nil {
		return zero, err
	}
	leftShares, err := formalCoxBlockwiseDecodeValues(left.CoefficientShares,
		store.plan.Policy.CovariateCount, store.plan.RingBits)
	if err != nil {
		return zero, err
	}
	defer exactGCZeroBigInts(leftShares)
	rightShares, err := formalCoxBlockwiseDecodeValues(right.CoefficientShares,
		store.plan.Policy.CovariateCount, store.plan.RingBits)
	if err != nil {
		return zero, err
	}
	defer exactGCZeroBigInts(rightShares)
	residues, valid, err := reconstructFormalCoxOutput(
		formalCoxSealedOutput{CoefficientShares: leftShares,
			ValidityShare: left.ValidityShare},
		formalCoxSealedOutput{CoefficientShares: rightShares,
			ValidityShare: right.ValidityShare}, store.plan.RingBits)
	if err != nil {
		return zero, err
	}
	defer exactGCZeroBigInts(residues)
	parsed, err := parseFormalCoxBlockwisePolicy(store.plan.Policy)
	if err != nil {
		return zero, err
	}
	signed := make([]*big.Int, len(residues))
	defer exactGCZeroBigInts(signed)
	normSquared := new(big.Int)
	for index, residue := range residues {
		signed[index] = exactGCReferenceSigned(residue, store.plan.RingBits)
		if !valid && signed[index].Sign() != 0 {
			return zero, fmt.Errorf("formal-cox: invalid execution exposed non-zero beta")
		}
		normSquared.Add(normSquared,
			new(big.Int).Mul(new(big.Int).Set(signed[index]), signed[index]))
	}
	boundSquared := new(big.Int).Mul(
		new(big.Int).Set(parsed.betaNorm), parsed.betaNorm)
	if valid && normSquared.Cmp(boundSquared) > 0 {
		return zero, fmt.Errorf("formal-cox: opened beta exceeds certified L2 bound")
	}
	digestScale := new(big.Int).Lsh(big.NewInt(1),
		uint(store.plan.Policy.ExpCertificateBits))
	coefficients := make([]formalCoxBlockwiseOpeningCoefficient, len(signed))
	for index, beta := range signed {
		interval, err := formalCoxExpDyadic(beta, parsed.scale,
			store.plan.Policy.ExpCertificateBits)
		if err != nil {
			return zero, err
		}
		midpointNumerator := new(big.Int).Add(interval.low, interval.high)
		midpointDenominator := new(big.Int).Lsh(
			new(big.Int).Set(digestScale), 1)
		coefficients[index] = formalCoxBlockwiseOpeningCoefficient{
			Index: index, BetaSteps: beta.String(),
			BetaRational: formalCoxBlockwiseOpeningRational(beta, parsed.scale),
			HazardRatioLowerRational: formalCoxBlockwiseOpeningRational(
				interval.low, digestScale),
			HazardRatioUpperRational: formalCoxBlockwiseOpeningRational(
				interval.high, digestScale),
			HazardRatioMidpointRational: formalCoxBlockwiseOpeningRational(
				midpointNumerator, midpointDenominator),
		}
	}
	candidate := formalCoxBlockwiseOpeningCandidate{
		Version:    formalCoxBlockwiseOpeningVersion,
		Purpose:    formalCoxBlockwiseOpeningPurpose,
		ArtifactID: store.artifactID, Artifact: store.artifact,
		PlanSHA256: store.planSHA256, FinalPairRootSHA256: pairRoot,
		FinalTranscriptSHA256: left.Header.Completion.TranscriptSHA256,
		FinalCommitSHA256:     left.Header.Completion.FinalCommitSHA256,
		FinalCursor:           left.Header.FinalCursor,
		CoefficientCount:      store.plan.Policy.CovariateCount,
		RingBits:              store.plan.RingBits, FractionBits: store.plan.Policy.FracBits,
		ExpCertificateBits: store.plan.Policy.ExpCertificateBits,
		OpeningMode:        formalCoxBlockwiseOpeningMode,
		ExpPostprocessMode: formalCoxBlockwiseExpOpeningMode,
		Valid:              valid, Coefficients: coefficients, ProductionReady: false,
	}
	if err := store.validateCandidate(candidate); err != nil {
		return zero, err
	}
	return candidate, nil
}

func formalCoxBlockwiseValidateOpeningCandidateCore(
	candidate formalCoxBlockwiseOpeningCandidate,
	pins map[string]ed25519.PublicKey,
) error {
	if formalCoxBlockwiseValidateStickyArtifact(candidate.Artifact, pins) != nil {
		return fmt.Errorf("formal-cox: opening candidate artifact is invalid")
	}
	artifactID, err := formalCoxBlockwiseStickyArtifactID(candidate.Artifact)
	if err != nil || candidate.Version != formalCoxBlockwiseOpeningVersion ||
		candidate.Purpose != formalCoxBlockwiseOpeningPurpose ||
		candidate.ArtifactID != artifactID || candidate.ProductionReady ||
		!formalCoxIsSHA256(candidate.PlanSHA256) ||
		!formalCoxIsSHA256(candidate.FinalPairRootSHA256) ||
		!formalCoxIsSHA256(candidate.FinalTranscriptSHA256) ||
		!formalCoxIsSHA256(candidate.FinalCommitSHA256) ||
		candidate.CoefficientCount != candidate.Artifact.CovariateCount ||
		candidate.CoefficientCount != len(candidate.Coefficients) ||
		candidate.RingBits < 128 || candidate.RingBits > exactGCMaxRingBits ||
		candidate.FractionBits < 8 || candidate.FractionBits > 60 ||
		candidate.FractionBits != candidate.Artifact.FractionBits ||
		candidate.ExpCertificateBits < 96 || candidate.ExpCertificateBits > 4096 ||
		candidate.FinalCursor.ScheduleIndex < 0 ||
		candidate.OpeningMode != formalCoxBlockwiseOpeningMode ||
		candidate.ExpPostprocessMode != formalCoxBlockwiseExpOpeningMode {
		return fmt.Errorf("formal-cox: invalid public opening candidate")
	}
	scale := new(big.Int).Lsh(big.NewInt(1), uint(candidate.FractionBits))
	dyadicScale := new(big.Int).Lsh(big.NewInt(1),
		uint(candidate.ExpCertificateBits))
	signedLimit := new(big.Int).Lsh(big.NewInt(1),
		uint(candidate.RingBits-1))
	signedLower := new(big.Int).Neg(new(big.Int).Set(signedLimit))
	for index, coefficient := range candidate.Coefficients {
		if len(coefficient.BetaSteps) < 1 ||
			len(coefficient.BetaSteps) > formalCoxPhase1MaxDecimalDigits {
			return fmt.Errorf("formal-cox: invalid public beta coefficient")
		}
		beta, ok := new(big.Int).SetString(coefficient.BetaSteps, 10)
		if !ok || beta.String() != coefficient.BetaSteps ||
			beta.Cmp(signedLower) < 0 || beta.Cmp(signedLimit) >= 0 ||
			coefficient.Index != index ||
			(!candidate.Valid && beta.Sign() != 0) ||
			coefficient.BetaRational !=
				formalCoxBlockwiseOpeningRational(beta, scale) {
			return fmt.Errorf("formal-cox: invalid public beta coefficient")
		}
		interval, intervalErr := formalCoxExpDyadic(
			beta, scale, candidate.ExpCertificateBits)
		if intervalErr != nil {
			return intervalErr
		}
		midpointNumerator := new(big.Int).Add(interval.low, interval.high)
		midpointDenominator := new(big.Int).Lsh(
			new(big.Int).Set(dyadicScale), 1)
		if coefficient.HazardRatioLowerRational !=
			formalCoxBlockwiseOpeningRational(interval.low, dyadicScale) ||
			coefficient.HazardRatioUpperRational !=
				formalCoxBlockwiseOpeningRational(interval.high, dyadicScale) ||
			coefficient.HazardRatioMidpointRational !=
				formalCoxBlockwiseOpeningRational(
					midpointNumerator, midpointDenominator) {
			return fmt.Errorf("formal-cox: invalid deterministic hazard-ratio postprocess")
		}
	}
	return nil
}

func (store *formalCoxBlockwiseOpeningStore) validateCandidate(
	candidate formalCoxBlockwiseOpeningCandidate,
) error {
	last, err := formalCoxBlockwiseWorkerStepAt(store.plan,
		store.plan.ScheduleSteps-1)
	if err != nil || formalCoxBlockwiseValidateOpeningCandidateCore(
		candidate, store.pins) != nil ||
		candidate.ArtifactID != store.artifactID ||
		!formalCoxBlockwiseOpeningEqual(candidate.Artifact, store.artifact) ||
		candidate.PlanSHA256 != store.planSHA256 ||
		candidate.FinalCursor != last ||
		candidate.CoefficientCount != store.plan.Policy.CovariateCount ||
		candidate.RingBits != store.plan.RingBits ||
		candidate.FractionBits != store.plan.Policy.FracBits ||
		candidate.ExpCertificateBits != store.plan.Policy.ExpCertificateBits {
		return fmt.Errorf("formal-cox: sticky opening candidate binding mismatch")
	}
	parsed, err := parseFormalCoxBlockwisePolicy(store.plan.Policy)
	if err != nil {
		return err
	}
	normSquared := new(big.Int)
	for _, coefficient := range candidate.Coefficients {
		value, _ := new(big.Int).SetString(coefficient.BetaSteps, 10)
		normSquared.Add(normSquared,
			new(big.Int).Mul(new(big.Int).Set(value), value))
	}
	boundSquared := new(big.Int).Mul(
		new(big.Int).Set(parsed.betaNorm), parsed.betaNorm)
	if candidate.Valid && normSquared.Cmp(boundSquared) > 0 {
		return fmt.Errorf("formal-cox: public beta exceeds certified L2 bound")
	}
	return nil
}

func (store *formalCoxBlockwiseOpeningStore) stageCandidate(
	candidate formalCoxBlockwiseOpeningCandidate,
) (formalCoxBlockwiseOpeningCandidate, bool, error) {
	var zero formalCoxBlockwiseOpeningCandidate
	if err := store.validateCandidate(candidate); err != nil {
		return zero, false, err
	}
	encoded, err := store.encodePrivate("candidate", "candidate", candidate)
	if err != nil {
		return zero, false, err
	}
	defer clear(encoded)
	path, err := store.privateRelativePath(store.artifactID, "candidate", "", true)
	if err != nil {
		return zero, false, err
	}
	store.mu.Lock()
	created, err := formalCoxBlockwiseGuardRootCreateRecord(store.root, path, encoded)
	if err == nil {
		encoded, err = formalCoxBlockwiseGuardRootReadRecord(
			store.root, path, formalCoxBlockwiseOpeningPrivateMax)
	}
	store.mu.Unlock()
	if err != nil {
		return zero, false, err
	}
	var existing formalCoxBlockwiseOpeningCandidate
	if err := store.decodePrivate(encoded, "candidate", "candidate", &existing); err != nil {
		return zero, false, err
	}
	if err := store.validateCandidate(existing); err != nil ||
		!formalCoxBlockwiseOpeningEqual(existing, candidate) {
		return zero, false, fmt.Errorf("formal-cox: conflicting durable opening candidate")
	}
	return existing, !created, nil
}

func (store *formalCoxBlockwiseOpeningStore) loadCandidate() (
	formalCoxBlockwiseOpeningCandidate, error,
) {
	var zero formalCoxBlockwiseOpeningCandidate
	path, err := store.privateRelativePath(store.artifactID, "candidate", "", false)
	if err != nil {
		return zero, err
	}
	store.mu.Lock()
	encoded, err := formalCoxBlockwiseGuardRootReadRecord(
		store.root, path, formalCoxBlockwiseOpeningPrivateMax)
	store.mu.Unlock()
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	var candidate formalCoxBlockwiseOpeningCandidate
	if err := store.decodePrivate(encoded, "candidate", "candidate", &candidate); err != nil {
		return zero, err
	}
	if err := store.validateCandidate(candidate); err != nil {
		return zero, err
	}
	return candidate, nil
}

func (store *formalCoxBlockwiseOpeningStore) Prepare(
	phaseHook func(string) error,
) (formalCoxBlockwiseOpeningIntent, formalCoxBlockwiseOpeningPublication,
	bool, error) {
	var zeroIntent formalCoxBlockwiseOpeningIntent
	var zeroPublication formalCoxBlockwiseOpeningPublication
	if store == nil || store.root == nil {
		return zeroIntent, zeroPublication, false,
			fmt.Errorf("formal-cox: invalid sticky opening store")
	}
	if publication, err := store.Replay(store.artifactID); err == nil {
		return zeroIntent, publication, true, nil
	} else if !os.IsNotExist(err) {
		return zeroIntent, zeroPublication, false, err
	}
	if candidate, err := store.loadCandidate(); err == nil {
		intent, err := formalCoxBlockwiseOpeningIntentFor(candidate)
		return intent, zeroPublication, false, err
	} else if !os.IsNotExist(err) {
		return zeroIntent, zeroPublication, false, err
	}
	if phaseHook != nil {
		if err := phaseHook("before_private_open"); err != nil {
			return zeroIntent, zeroPublication, false, err
		}
	}
	candidate, err := store.buildCandidate()
	if err != nil {
		return zeroIntent, zeroPublication, false, err
	}
	candidate, _, err = store.stageCandidate(candidate)
	if err != nil {
		return zeroIntent, zeroPublication, false, err
	}
	intent, err := formalCoxBlockwiseOpeningIntentFor(candidate)
	return intent, zeroPublication, false, err
}

func formalCoxBlockwiseOpeningReceiptSHA256(
	receipt jointDPBiomedicalGaussianSignature,
) (string, error) {
	return formalCoxBlockwiseOpeningHash("authority-receipt", receipt)
}

func formalCoxBlockwiseOpeningAuthorityMessage(
	intent formalCoxBlockwiseOpeningIntent, signer, role, predecessor string,
) ([]byte, error) {
	encoded, err := json.Marshal(struct {
		Intent                   formalCoxBlockwiseOpeningIntent `json:"intent"`
		Signer                   string                          `json:"signer"`
		Role                     string                          `json:"role"`
		PredecessorReceiptSHA256 string                          `json:"predecessor_receipt_sha256,omitempty"`
	}{intent, signer, role, predecessor})
	if err != nil {
		return nil, err
	}
	return append([]byte(formalCoxBlockwiseOpeningDomain+"/authority-sign-once|"),
		encoded...), nil
}

func formalCoxBlockwiseValidateOpeningReceiptAt(
	intent formalCoxBlockwiseOpeningIntent,
	receipts []jointDPBiomedicalGaussianSignature, position int,
	artifact formalCoxBlockwiseStickyArtifact,
	pins map[string]ed25519.PublicKey,
) error {
	if len(artifact.NoiseAuthorities) != 2 || position < 0 || position > 1 ||
		len(receipts) <= position {
		return fmt.Errorf("formal-cox: incomplete ordered opening receipts")
	}
	authority := artifact.NoiseAuthorities[position]
	receipt := receipts[position]
	predecessor := ""
	var err error
	if position == 1 {
		if err := formalCoxBlockwiseValidateOpeningReceiptAt(
			intent, receipts, 0, artifact, pins); err != nil {
			return err
		}
		predecessor, err = formalCoxBlockwiseOpeningReceiptSHA256(receipts[0])
		if err != nil {
			return err
		}
	}
	message, err := formalCoxBlockwiseOpeningAuthorityMessage(
		intent, authority.PeerName, authority.Role, predecessor)
	if err != nil || receipt.Signer != authority.PeerName ||
		len(receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pins[authority.PeerName], message, receipt.Signature) {
		return fmt.Errorf("formal-cox: invalid ordered opening receipt")
	}
	return nil
}

func (store *formalCoxBlockwiseOpeningStore) signerMAC(
	record formalCoxBlockwiseOpeningSignerRecord,
) (string, error) {
	record.RecordMAC = ""
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, store.key[:])
	_, _ = mac.Write([]byte(formalCoxBlockwiseOpeningDomain + "/signer-record|"))
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (store *formalCoxBlockwiseOpeningStore) encodeSigner(
	record formalCoxBlockwiseOpeningSignerRecord,
) ([]byte, error) {
	mac, err := store.signerMAC(record)
	if err != nil {
		return nil, err
	}
	record.RecordMAC = mac
	return json.Marshal(record)
}

func (store *formalCoxBlockwiseOpeningStore) decodeSigner(
	encoded []byte,
) (formalCoxBlockwiseOpeningSignerRecord, error) {
	var zero formalCoxBlockwiseOpeningSignerRecord
	var record formalCoxBlockwiseOpeningSignerRecord
	if err := formalCoxBlockwiseSourceDecodeCanonical(encoded,
		formalCoxBlockwiseOpeningSignerMax, "sticky opening signer record",
		&record); err != nil {
		return zero, err
	}
	want, err := store.signerMAC(record)
	role, roleErr := store.roleForPeer(record.Signer)
	if err != nil || roleErr != nil ||
		!hmac.Equal([]byte(want), []byte(record.RecordMAC)) ||
		record.Version != formalCoxBlockwiseOpeningVersion ||
		record.Purpose != formalCoxBlockwiseOpeningPurpose ||
		record.ArtifactID != store.artifactID ||
		!formalCoxIsSHA256(record.CandidateSHA256) ||
		record.Role != role || record.Receipt.Signer != record.Signer ||
		len(record.Receipt.Signature) != ed25519.SignatureSize {
		return zero, fmt.Errorf("formal-cox: invalid sticky opening signer record")
	}
	return record, nil
}

func (store *formalCoxBlockwiseOpeningStore) loadSigner(
	peer string,
) (formalCoxBlockwiseOpeningSignerRecord, error) {
	var zero formalCoxBlockwiseOpeningSignerRecord
	path, err := store.signerRelativePath(store.artifactID, peer, false)
	if err != nil {
		return zero, err
	}
	store.mu.Lock()
	encoded, err := formalCoxBlockwiseGuardRootReadRecord(
		store.root, path, formalCoxBlockwiseOpeningSignerMax)
	store.mu.Unlock()
	if err != nil {
		return zero, err
	}
	return store.decodeSigner(encoded)
}

func (store *formalCoxBlockwiseOpeningStore) SignOnce(
	intent formalCoxBlockwiseOpeningIntent, peer string,
	privateKey ed25519.PrivateKey,
	predecessors []jointDPBiomedicalGaussianSignature,
) (jointDPBiomedicalGaussianSignature, bool, error) {
	var zero jointDPBiomedicalGaussianSignature
	if store == nil || store.root == nil || len(privateKey) != ed25519.PrivateKeySize ||
		!hmac.Equal(privateKey.Public().(ed25519.PublicKey), store.pins[peer]) {
		return zero, false, fmt.Errorf("formal-cox: invalid sticky opening signer")
	}
	candidate, err := store.loadCandidate()
	if err != nil {
		return zero, false, err
	}
	wantIntent, err := formalCoxBlockwiseOpeningIntentFor(candidate)
	if err != nil || intent.ProductionReady ||
		!formalCoxBlockwiseOpeningEqual(intent, wantIntent) {
		return zero, false, fmt.Errorf("formal-cox: opening intent differs from staged candidate")
	}
	role, err := store.roleForPeer(peer)
	if err != nil {
		return zero, false, err
	}
	position := 0
	predecessor := ""
	if role == "garbler" {
		if len(predecessors) != 0 {
			return zero, false, fmt.Errorf("formal-cox: opening garbler has a predecessor")
		}
	} else {
		position = 1
		if len(predecessors) != 1 ||
			formalCoxBlockwiseValidateOpeningReceiptAt(intent,
				predecessors, 0, store.artifact, store.pins) != nil {
			return zero, false,
				fmt.Errorf("formal-cox: evaluator lacks exact garbler opening receipt")
		}
		predecessor, err = formalCoxBlockwiseOpeningReceiptSHA256(predecessors[0])
		if err != nil {
			return zero, false, err
		}
	}
	if store.artifact.NoiseAuthorities[position].PeerName != peer {
		return zero, false, fmt.Errorf("formal-cox: opening signer role mismatch")
	}
	message, err := formalCoxBlockwiseOpeningAuthorityMessage(
		intent, peer, role, predecessor)
	if err != nil {
		return zero, false, err
	}
	receipt := jointDPBiomedicalGaussianSignature{
		Signer: peer, Signature: ed25519.Sign(privateKey, message),
	}
	record := formalCoxBlockwiseOpeningSignerRecord{
		Version:    formalCoxBlockwiseOpeningVersion,
		Purpose:    formalCoxBlockwiseOpeningPurpose,
		ArtifactID: store.artifactID, CandidateSHA256: intent.CandidateSHA256,
		Signer: peer, Role: role, PredecessorReceiptSHA256: predecessor,
		Receipt: receipt,
	}
	encoded, err := store.encodeSigner(record)
	if err != nil {
		return zero, false, err
	}
	path, err := store.signerRelativePath(store.artifactID, peer, true)
	if err != nil {
		return zero, false, err
	}
	store.mu.Lock()
	created, err := formalCoxBlockwiseGuardRootCreateRecord(store.root, path, encoded)
	if err == nil {
		encoded, err = formalCoxBlockwiseGuardRootReadRecord(
			store.root, path, formalCoxBlockwiseOpeningSignerMax)
	}
	store.mu.Unlock()
	if err != nil {
		return zero, false, err
	}
	existing, err := store.decodeSigner(encoded)
	if err != nil || !formalCoxBlockwiseOpeningEqual(existing.Receipt, receipt) ||
		existing.CandidateSHA256 != record.CandidateSHA256 ||
		existing.PredecessorReceiptSHA256 != predecessor || existing.Role != role {
		return zero, false, fmt.Errorf("formal-cox: conflicting sticky opening signature")
	}
	return existing.Receipt, !created, nil
}

func formalCoxBlockwiseValidateOpeningCertificate(
	certificate formalCoxBlockwiseOpeningCertificate,
	pins map[string]ed25519.PublicKey,
) error {
	if certificate.Version != formalCoxBlockwiseOpeningVersion ||
		certificate.Purpose != formalCoxBlockwiseOpeningPurpose ||
		certificate.ProductionReady ||
		formalCoxBlockwiseValidateOpeningCandidateCore(
			certificate.Candidate, pins) != nil {
		return fmt.Errorf("formal-cox: invalid sticky opening certificate")
	}
	wantIntent, err := formalCoxBlockwiseOpeningIntentFor(certificate.Candidate)
	if err != nil || certificate.Intent.ProductionReady ||
		!formalCoxBlockwiseOpeningEqual(certificate.Intent, wantIntent) ||
		len(certificate.AuthorityReceipts) != 2 {
		return fmt.Errorf("formal-cox: opening certificate intent mismatch")
	}
	for position := 0; position < 2; position++ {
		if err := formalCoxBlockwiseValidateOpeningReceiptAt(
			certificate.Intent, certificate.AuthorityReceipts, position,
			certificate.Candidate.Artifact, pins); err != nil {
			return err
		}
	}
	return nil
}

func formalCoxBlockwiseOpeningCertificateSHA256(encoded []byte) string {
	digest := sha256.Sum256(append(
		[]byte(formalCoxBlockwiseOpeningDomain+"/public-certificate|"), encoded...))
	return hex.EncodeToString(digest[:])
}

func formalCoxBlockwiseDecodeOpeningPublication(
	publication formalCoxBlockwiseOpeningPublication,
	pins map[string]ed25519.PublicKey,
) (formalCoxBlockwiseOpeningCertificate, error) {
	var zero formalCoxBlockwiseOpeningCertificate
	if !formalCoxIsSHA256(publication.ArtifactID) ||
		!formalCoxIsSHA256(publication.CertificateSHA256) ||
		len(publication.Certificate) < 2 ||
		len(publication.Certificate) > formalCoxBlockwiseOpeningPublicMax ||
		formalCoxBlockwiseOpeningCertificateSHA256(publication.Certificate) !=
			publication.CertificateSHA256 {
		return zero, fmt.Errorf("formal-cox: invalid sticky opening publication")
	}
	var certificate formalCoxBlockwiseOpeningCertificate
	if err := formalCoxBlockwiseSourceDecodeCanonical(publication.Certificate,
		formalCoxBlockwiseOpeningPublicMax, "sticky opening certificate",
		&certificate); err != nil {
		return zero, err
	}
	if err := formalCoxBlockwiseValidateOpeningCertificate(
		certificate, pins); err != nil ||
		certificate.Candidate.ArtifactID != publication.ArtifactID {
		return zero, fmt.Errorf("formal-cox: sticky opening publication authentication failed")
	}
	return certificate, nil
}

func (store *formalCoxBlockwiseOpeningStore) publicMAC(
	record formalCoxBlockwiseOpeningPublicRecord,
) (string, error) {
	record.RecordMAC = ""
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, store.key[:])
	_, _ = mac.Write([]byte(formalCoxBlockwiseOpeningDomain + "/public-record|"))
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (store *formalCoxBlockwiseOpeningStore) encodePublicRecord(
	record formalCoxBlockwiseOpeningPublicRecord,
) ([]byte, error) {
	mac, err := store.publicMAC(record)
	if err != nil {
		return nil, err
	}
	record.RecordMAC = mac
	return json.Marshal(record)
}

func (store *formalCoxBlockwiseOpeningStore) decodePublicRecord(
	encoded []byte,
) (formalCoxBlockwiseOpeningPublication, error) {
	var zero formalCoxBlockwiseOpeningPublication
	var record formalCoxBlockwiseOpeningPublicRecord
	if err := formalCoxBlockwiseSourceDecodeCanonical(encoded,
		formalCoxBlockwiseOpeningPublicMax, "sticky opening public record",
		&record); err != nil {
		return zero, err
	}
	want, err := store.publicMAC(record)
	certificate := []byte(record.CertificateJSON)
	publication := formalCoxBlockwiseOpeningPublication{
		ArtifactID:        record.ArtifactID,
		CertificateSHA256: record.CertificateSHA256,
		Certificate:       append([]byte(nil), certificate...), Replayed: true,
	}
	if err != nil || !hmac.Equal([]byte(want), []byte(record.RecordMAC)) ||
		record.Version != formalCoxBlockwiseOpeningVersion ||
		record.Purpose != formalCoxBlockwiseOpeningPurpose ||
		record.ArtifactID != store.artifactID ||
		record.CertificateSHA256 !=
			formalCoxBlockwiseOpeningCertificateSHA256(certificate) {
		return zero, fmt.Errorf("formal-cox: public opening record authentication failed")
	}
	if _, err := formalCoxBlockwiseDecodeOpeningPublication(
		publication, store.pins); err != nil {
		return zero, err
	}
	return publication, nil
}

func (store *formalCoxBlockwiseOpeningStore) Replay(
	artifactID string,
) (formalCoxBlockwiseOpeningPublication, error) {
	var zero formalCoxBlockwiseOpeningPublication
	if store == nil || store.root == nil || artifactID != store.artifactID {
		return zero, fmt.Errorf("formal-cox: invalid sticky opening replay")
	}
	path, err := store.publicRelativePath(artifactID, false)
	if err != nil {
		return zero, err
	}
	store.mu.Lock()
	encoded, err := formalCoxBlockwiseGuardRootReadRecord(
		store.root, path, formalCoxBlockwiseOpeningPublicMax)
	store.mu.Unlock()
	if err != nil {
		return zero, err
	}
	return store.decodePublicRecord(encoded)
}

func formalCoxBlockwiseOpeningReceiptsEqual(
	left, right []jointDPBiomedicalGaussianSignature,
) bool {
	return formalCoxBlockwiseOpeningEqual(left, right)
}

func (store *formalCoxBlockwiseOpeningStore) Publish(
	intent formalCoxBlockwiseOpeningIntent,
	receipts []jointDPBiomedicalGaussianSignature, phaseHook func(string) error,
) (formalCoxBlockwiseOpeningPublication, error) {
	var zero formalCoxBlockwiseOpeningPublication
	if store == nil || store.root == nil {
		return zero, fmt.Errorf("formal-cox: invalid sticky opening publication store")
	}
	if existing, err := store.Replay(store.artifactID); err == nil {
		certificate, decodeErr := formalCoxBlockwiseDecodeOpeningPublication(
			existing, store.pins)
		if decodeErr != nil || !formalCoxBlockwiseOpeningEqual(
			certificate.Intent, intent) || !formalCoxBlockwiseOpeningReceiptsEqual(
			certificate.AuthorityReceipts, receipts) {
			return zero, fmt.Errorf("formal-cox: conflicting public opening replay")
		}
		return existing, nil
	} else if !os.IsNotExist(err) {
		return zero, err
	}
	candidate, err := store.loadCandidate()
	if err != nil {
		return zero, err
	}
	wantIntent, err := formalCoxBlockwiseOpeningIntentFor(candidate)
	if err != nil || intent.ProductionReady ||
		!formalCoxBlockwiseOpeningEqual(intent, wantIntent) || len(receipts) != 2 {
		return zero, fmt.Errorf("formal-cox: publication differs from staged opening")
	}
	for position, peer := range store.plan.Policy.ComputePeers {
		if err := formalCoxBlockwiseValidateOpeningReceiptAt(
			intent, receipts, position, store.artifact, store.pins); err != nil {
			return zero, err
		}
		record, err := store.loadSigner(peer)
		predecessor := ""
		if position == 1 {
			predecessor, _ = formalCoxBlockwiseOpeningReceiptSHA256(receipts[0])
		}
		if err != nil || record.CandidateSHA256 != intent.CandidateSHA256 ||
			record.PredecessorReceiptSHA256 != predecessor ||
			!formalCoxBlockwiseOpeningEqual(record.Receipt, receipts[position]) {
			return zero, fmt.Errorf("formal-cox: publication lacks durable ordered SignOnce")
		}
	}
	certificate := formalCoxBlockwiseOpeningCertificate{
		Version:   formalCoxBlockwiseOpeningVersion,
		Purpose:   formalCoxBlockwiseOpeningPurpose,
		Candidate: candidate, Intent: intent,
		AuthorityReceipts: append(
			[]jointDPBiomedicalGaussianSignature(nil), receipts...),
		ProductionReady: false,
	}
	if err := formalCoxBlockwiseValidateOpeningCertificate(
		certificate, store.pins); err != nil {
		return zero, err
	}
	certificateJSON, err := json.Marshal(certificate)
	if err != nil || len(certificateJSON) > formalCoxBlockwiseOpeningPublicMax {
		return zero, fmt.Errorf("formal-cox: invalid public opening certificate")
	}
	publication := formalCoxBlockwiseOpeningPublication{
		ArtifactID:        store.artifactID,
		CertificateSHA256: formalCoxBlockwiseOpeningCertificateSHA256(certificateJSON),
		Certificate:       append([]byte(nil), certificateJSON...), Replayed: false,
	}
	if phaseHook != nil {
		if err := phaseHook("before_publication_cas"); err != nil {
			return zero, err
		}
	}
	record := formalCoxBlockwiseOpeningPublicRecord{
		Version:           formalCoxBlockwiseOpeningVersion,
		Purpose:           formalCoxBlockwiseOpeningPurpose,
		ArtifactID:        store.artifactID,
		CertificateSHA256: publication.CertificateSHA256,
		CertificateJSON:   string(certificateJSON),
	}
	encoded, err := store.encodePublicRecord(record)
	if err != nil {
		return zero, err
	}
	path, err := store.publicRelativePath(store.artifactID, true)
	if err != nil {
		return zero, err
	}
	store.mu.Lock()
	created, err := formalCoxBlockwiseGuardRootCreateRecord(store.root, path, encoded)
	if err == nil {
		encoded, err = formalCoxBlockwiseGuardRootReadRecord(
			store.root, path, formalCoxBlockwiseOpeningPublicMax)
	}
	store.mu.Unlock()
	if err != nil {
		return zero, err
	}
	existing, err := store.decodePublicRecord(encoded)
	if err != nil || existing.CertificateSHA256 != publication.CertificateSHA256 ||
		!bytes.Equal(existing.Certificate, publication.Certificate) {
		return zero, fmt.Errorf("formal-cox: conflicting public Cox opening")
	}
	existing.Replayed = !created
	return existing, nil
}
