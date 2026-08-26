package main

// Shared, internal handoff from the two designated compute roles to one
// durable finalizer.  The protocol is deliberately closed over formal GLM and
// formal Cox.  Family files provide the typed payload codecs; this file owns
// only their common ticket, recipient-bound envelope, CAS, ordered intent
// authorization and post-publication ACK rules.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/hkdf"
)

const (
	formalFinalizerHandoffCapabilityVersion   = "dsvert-typed-finalizer-handoff-capability-v1"
	formalFinalizerHandoffTicketVersion       = "dsvert-typed-finalizer-handoff-ticket-v1"
	formalFinalizerHandoffEnvelopeVersion     = "dsvert-typed-finalizer-handoff-envelope-v1"
	formalFinalizerHandoffPlaintextVersion    = "dsvert-typed-finalizer-handoff-plaintext-v1"
	formalFinalizerHandoffIntentVersion       = "dsvert-typed-finalizer-handoff-intent-authorization-v1"
	formalFinalizerHandoffAckVersion          = "dsvert-typed-finalizer-handoff-publication-ack-v1"
	formalFinalizerHandoffTransportKeyVersion = "dsvert-typed-finalizer-handoff-transport-key-v1"
	formalFinalizerHandoffDomain              = "dsVert/typed-finalizer-handoff/v1"

	formalFinalizerHandoffFamilyGLM = "formal_glm"
	formalFinalizerHandoffFamilyCox = "formal_cox"

	formalFinalizerHandoffGLMPurpose = "formal_glm_phase21_sticky_release_v1"
	formalFinalizerHandoffCoxPurpose = "formal_cox_blockwise_sticky_opening_v1"

	formalFinalizerHandoffGLMOneDrawKind           = "formal_glm_one_draw_local_output_v1"
	formalFinalizerHandoffGLMFullKind              = "formal_glm_full_local_output_v1"
	formalFinalizerHandoffCoxOpeningKind           = "formal_cox_opening_local_output_v1"
	formalFinalizerHandoffGLMOneDrawPayloadVersion = "dsvert-formal-glm-finalizer-transit-one-draw-v1"
	formalFinalizerHandoffGLMFullPayloadVersion    = "dsvert-formal-glm-finalizer-transit-full-v1"
	formalFinalizerHandoffCoxPayloadVersion        = "dsvert-formal-cox-finalizer-transit-opening-v1"

	formalFinalizerHandoffMaxPayload       = 4 << 20
	formalFinalizerHandoffMaxRecord        = 8 << 20
	formalFinalizerHandoffRockRoot         = "/srv/dsvert-synopsis"
	formalFinalizerHandoffDefaultStateRoot = "/srv/dsvert-synopsis/formal-finalizer-handoff-v1"
	formalFinalizerHandoffStateRootEnv     = "DSVERT_FINALIZER_STATE_ROOT"
)

var formalFinalizerHandoffStateRoot = formalFinalizerHandoffConfiguredStateRootV1(
	os.Getenv(formalFinalizerHandoffStateRootEnv))

func formalFinalizerHandoffConfiguredStateRootV1(configured string) string {
	if configured == "" {
		return formalFinalizerHandoffDefaultStateRoot
	}
	if !filepath.IsAbs(configured) || filepath.Clean(configured) != configured {
		panic("typed-finalizer-handoff: invalid configured state root")
	}
	return configured
}

var errFormalFinalizerHandoffAuthorityLockBusy = errors.New(
	"typed-finalizer-handoff: authority lock busy")

type formalFinalizerHandoffFamilyCapability struct {
	Family       string   `json:"family"`
	Purpose      string   `json:"purpose"`
	PayloadKinds []string `json:"payload_kinds"`
}

type formalFinalizerHandoffCapability struct {
	Version           string                                   `json:"version"`
	InternalAvailable bool                                     `json:"internal_available"`
	ProductionReady   bool                                     `json:"production_ready"`
	ExposedThroughDSI bool                                     `json:"exposed_through_dsi"`
	DurableStateRoot  string                                   `json:"durable_state_root"`
	Families          []formalFinalizerHandoffFamilyCapability `json:"families"`
}

func formalFinalizerHandoffCapabilities() formalFinalizerHandoffCapability {
	return formalFinalizerHandoffCapability{
		Version:           formalFinalizerHandoffCapabilityVersion,
		InternalAvailable: true, ProductionReady: false,
		ExposedThroughDSI: true,
		DurableStateRoot:  formalFinalizerHandoffStateRoot,
		Families: []formalFinalizerHandoffFamilyCapability{
			{Family: formalFinalizerHandoffFamilyGLM,
				Purpose: formalFinalizerHandoffGLMPurpose,
				PayloadKinds: []string{
					formalFinalizerHandoffGLMOneDrawKind,
					formalFinalizerHandoffGLMFullKind,
				}},
			{Family: formalFinalizerHandoffFamilyCox,
				Purpose: formalFinalizerHandoffCoxPurpose,
				PayloadKinds: []string{
					formalFinalizerHandoffCoxOpeningKind,
				}},
		},
	}
}

func formalFinalizerHandoffLookup(family, purpose string) (
	formalFinalizerHandoffFamilyCapability, error,
) {
	for _, candidate := range formalFinalizerHandoffCapabilities().Families {
		if candidate.Family == family && candidate.Purpose == purpose {
			candidate.PayloadKinds = append([]string(nil), candidate.PayloadKinds...)
			return candidate, nil
		}
	}
	return formalFinalizerHandoffFamilyCapability{},
		fmt.Errorf("typed-finalizer-handoff: unsupported family or purpose")
}

func formalFinalizerHandoffKindAllowed(capability formalFinalizerHandoffFamilyCapability,
	kind string,
) bool {
	for _, candidate := range capability.PayloadKinds {
		if candidate == kind {
			return true
		}
	}
	return false
}

type formalFinalizerHandoffAuthority struct {
	PeerName string `json:"peer_name"`
	PeerID   string `json:"peer_id"`
	Role     string `json:"role"`
}

// ArtifactID is supplied by the family canonicalizer.  The transport ticket,
// final pair root and every execution identifier are intentionally inputs to
// this bridge only; this package never derives or rewrites ArtifactID.
type formalFinalizerHandoffBinding struct {
	Family              string                            `json:"family"`
	Purpose             string                            `json:"purpose"`
	ArtifactID          string                            `json:"artifact_id"`
	FinalPairRootSHA256 string                            `json:"final_pair_root_sha256"`
	PlanSHA256          string                            `json:"plan_sha256"`
	PinsetSHA256        string                            `json:"pinset_sha256"`
	Authorities         []formalFinalizerHandoffAuthority `json:"authorities"`
	Finalizer           formalFinalizerHandoffAuthority   `json:"finalizer"`
}

type formalFinalizerHandoffTicket struct {
	Version                     string `json:"version"`
	Family                      string `json:"family"`
	Purpose                     string `json:"purpose"`
	ArtifactID                  string `json:"artifact_id"`
	FinalPairRootSHA256         string `json:"final_pair_root_sha256"`
	PlanSHA256                  string `json:"plan_sha256"`
	PinsetSHA256                string `json:"pinset_sha256"`
	FinalizerPeerName           string `json:"finalizer_peer_name"`
	FinalizerPeerID             string `json:"finalizer_peer_id"`
	FinalizerRole               string `json:"finalizer_role"`
	RecipientTransportPublicKey []byte `json:"recipient_x25519_public_key"`
	TransportKeySHA256          string `json:"transport_key_sha256"`
	IssuerPeerName              string `json:"issuer_peer_name"`
	IssuerPeerID                string `json:"issuer_peer_id"`
	ProductionReady             bool   `json:"-"`
	Signature                   []byte `json:"signature"`
}

type formalFinalizerHandoffTransportKeyRecord struct {
	Version             string `json:"version"`
	Family              string `json:"family"`
	Purpose             string `json:"purpose"`
	ArtifactID          string `json:"artifact_id"`
	FinalPairRootSHA256 string `json:"final_pair_root_sha256"`
	PlanSHA256          string `json:"plan_sha256"`
	PinsetSHA256        string `json:"pinset_sha256"`
	FinalizerPeerName   string `json:"finalizer_peer_name"`
	FinalizerPeerID     string `json:"finalizer_peer_id"`
	TransportPublicKey  []byte `json:"transport_public_key"`
	TransportKeySHA256  string `json:"transport_key_sha256"`
	Nonce               []byte `json:"nonce"`
	Ciphertext          []byte `json:"ciphertext"`
	ProductionReady     bool   `json:"-"`
	Signature           []byte `json:"signature"`
}

type formalFinalizerHandoffPlaintext struct {
	Version             string          `json:"version"`
	Family              string          `json:"family"`
	Purpose             string          `json:"purpose"`
	ArtifactID          string          `json:"artifact_id"`
	FinalPairRootSHA256 string          `json:"final_pair_root_sha256"`
	PlanSHA256          string          `json:"plan_sha256"`
	PinsetSHA256        string          `json:"pinset_sha256"`
	TicketSHA256        string          `json:"ticket_sha256"`
	SenderPeerName      string          `json:"sender_peer_name"`
	SenderPeerID        string          `json:"sender_peer_id"`
	SenderRole          string          `json:"sender_role"`
	PayloadKind         string          `json:"payload_kind"`
	PayloadSHA256       string          `json:"payload_sha256"`
	Payload             json.RawMessage `json:"payload"`
}

type formalFinalizerHandoffEnvelope struct {
	Version                     string `json:"version"`
	Family                      string `json:"family"`
	Purpose                     string `json:"purpose"`
	ArtifactID                  string `json:"artifact_id"`
	FinalPairRootSHA256         string `json:"final_pair_root_sha256"`
	PlanSHA256                  string `json:"plan_sha256"`
	PinsetSHA256                string `json:"pinset_sha256"`
	TicketSHA256                string `json:"ticket_sha256"`
	FinalizerPeerName           string `json:"finalizer_peer_name"`
	FinalizerPeerID             string `json:"finalizer_peer_id"`
	RecipientTransportKeySHA256 string `json:"recipient_transport_key_sha256"`
	SenderPeerName              string `json:"sender_peer_name"`
	SenderPeerID                string `json:"sender_peer_id"`
	SenderRole                  string `json:"sender_role"`
	PayloadKind                 string `json:"payload_kind"`
	PayloadSHA256               string `json:"payload_sha256"`
	CiphertextSHA256            string `json:"ciphertext_sha256"`
	Ciphertext                  []byte `json:"ciphertext"`
	ProductionReady             bool   `json:"-"`
	Signature                   []byte `json:"signature"`
}

type formalFinalizerHandoffIntentAuthorization struct {
	Version                  string `json:"version"`
	Family                   string `json:"family"`
	Purpose                  string `json:"purpose"`
	ArtifactID               string `json:"artifact_id"`
	FinalPairRootSHA256      string `json:"final_pair_root_sha256"`
	PlanSHA256               string `json:"plan_sha256"`
	PinsetSHA256             string `json:"pinset_sha256"`
	TicketSHA256             string `json:"ticket_sha256"`
	SignerPeerName           string `json:"signer_peer_name"`
	SignerPeerID             string `json:"signer_peer_id"`
	SignerRole               string `json:"signer_role"`
	IntentSHA256             string `json:"intent_sha256"`
	LocalGuardSHA256         string `json:"local_guard_sha256"`
	PredecessorReceiptSHA256 string `json:"predecessor_receipt_sha256,omitempty"`
	ProductionReady          bool   `json:"-"`
	Signature                []byte `json:"signature"`
}

type formalFinalizerHandoffCommitProof struct {
	Version             string `json:"version"`
	Family              string `json:"family"`
	Purpose             string `json:"purpose"`
	ArtifactID          string `json:"artifact_id"`
	FinalPairRootSHA256 string `json:"final_pair_root_sha256"`
	PlanSHA256          string `json:"plan_sha256"`
	PinsetSHA256        string `json:"pinset_sha256"`
	TicketSHA256        string `json:"ticket_sha256"`
	CertificateSHA256   string `json:"certificate_sha256"`
	FinalizerPeerName   string `json:"finalizer_peer_name"`
	FinalizerPeerID     string `json:"finalizer_peer_id"`
	ProductionReady     bool   `json:"-"`
	Signature           []byte `json:"signature"`
}

// Only family-local publication stores implement this unexported interface.
// No CLI/JSON field can replace the actual ArtifactID-keyed replay check with
// an analyst-selected boolean.
type formalFinalizerHandoffPublicationGuard interface {
	formalFinalizerHandoffVerifyPublication(
		artifactID, certificateSHA256 string) error
}

type formalFinalizerHandoffTerminalAckError struct {
	Proof formalFinalizerHandoffCommitProof
}

func (err *formalFinalizerHandoffTerminalAckError) Error() string {
	return "typed-finalizer-handoff: canonical publication is already acknowledged"
}

func (store *formalGLMPhase21StickyReleaseStore) formalFinalizerHandoffVerifyPublication(
	artifactID, certificateSHA256 string,
) error {
	publication, err := store.Replay(artifactID)
	if err != nil || publication.CertificateSHA256 != certificateSHA256 {
		return fmt.Errorf("formal-glm: exact sticky publication is absent")
	}
	return nil
}

func (store *formalCoxBlockwiseOpeningStore) formalFinalizerHandoffVerifyPublication(
	artifactID, certificateSHA256 string,
) error {
	publication, err := store.Replay(artifactID)
	if err != nil || publication.CertificateSHA256 != certificateSHA256 {
		return fmt.Errorf("formal-cox: exact sticky publication is absent")
	}
	return nil
}

func formalFinalizerHandoffPeer(binding formalFinalizerHandoffBinding,
	role string,
) (formalFinalizerHandoffAuthority, error) {
	position := -1
	if role == "garbler" {
		position = 0
	} else if role == "evaluator" {
		position = 1
	}
	if position < 0 || len(binding.Authorities) != 2 ||
		binding.Authorities[position].Role != role {
		return formalFinalizerHandoffAuthority{},
			fmt.Errorf("typed-finalizer-handoff: invalid authority role")
	}
	return binding.Authorities[position], nil
}

func formalFinalizerHandoffPathSafePeerName(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		alphaNumeric := character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9'
		if !alphaNumeric && (index == 0 ||
			(character != '.' && character != '_' && character != '-')) {
			return false
		}
	}
	return true
}

func formalFinalizerHandoffValidateBinding(binding formalFinalizerHandoffBinding,
	pins map[string]ed25519.PublicKey,
) error {
	if _, err := formalFinalizerHandoffLookup(binding.Family, binding.Purpose); err != nil {
		return err
	}
	if !formalGLMIsSHA256(binding.ArtifactID) ||
		!formalGLMIsSHA256(binding.FinalPairRootSHA256) ||
		!formalGLMIsSHA256(binding.PlanSHA256) ||
		!formalGLMIsSHA256(binding.PinsetSHA256) || len(binding.Authorities) != 2 {
		return fmt.Errorf("typed-finalizer-handoff: invalid canonical binding")
	}
	pinset, err := formalGLMPhase16PinsetSHA256(pins)
	if err != nil || !hmac.Equal([]byte(pinset), []byte(binding.PinsetSHA256)) {
		return fmt.Errorf("typed-finalizer-handoff: pinset mismatch")
	}
	seen := make(map[string]bool, 2)
	for index, role := range []string{"garbler", "evaluator"} {
		authority := binding.Authorities[index]
		pin := pins[authority.PeerName]
		peerID, peerErr := formalGLMPhase16PeerID(pin)
		if peerErr != nil || authority.Role != role ||
			!formalFinalizerHandoffPathSafePeerName(authority.PeerName) ||
			authority.PeerID != peerID || seen[authority.PeerName] {
			return fmt.Errorf("typed-finalizer-handoff: invalid authority binding")
		}
		seen[authority.PeerName] = true
	}
	if binding.Finalizer != binding.Authorities[0] ||
		binding.Finalizer.Role != "garbler" {
		return fmt.Errorf("typed-finalizer-handoff: finalizer is not the fixed garbler")
	}
	return nil
}

func formalFinalizerHandoffTransportKeySHA256(public []byte) (string, error) {
	if len(public) != 32 {
		return "", fmt.Errorf("typed-finalizer-handoff: invalid X25519 public key")
	}
	curve := ecdh.X25519()
	peer, err := curve.NewPublicKey(public)
	probeSeed := sha256.Sum256([]byte(formalFinalizerHandoffDomain + "/x25519-probe"))
	probe, probeErr := curve.NewPrivateKey(probeSeed[:])
	if err != nil || probeErr != nil {
		return "", fmt.Errorf("typed-finalizer-handoff: invalid X25519 public key")
	}
	if _, err := probe.ECDH(peer); err != nil {
		return "", fmt.Errorf("typed-finalizer-handoff: invalid X25519 public key")
	}
	digest := sha256.Sum256(append(
		[]byte(formalFinalizerHandoffDomain+"/transport-key|"), public...))
	return hex.EncodeToString(digest[:]), nil
}

func formalFinalizerHandoffTicketMessage(ticket formalFinalizerHandoffTicket) (
	[]byte, error,
) {
	ticket.Signature = nil
	encoded, err := json.Marshal(ticket)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalFinalizerHandoffDomain+"/ticket|"), encoded...), nil
}

func formalFinalizerHandoffTicketSHA256(ticket formalFinalizerHandoffTicket) (
	string, error,
) {
	encoded, err := json.Marshal(ticket)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalFinalizerHandoffDomain+"/signed-ticket|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalFinalizerHandoffIssueTicket(binding formalFinalizerHandoffBinding,
	transportPublic []byte, signingKey ed25519.PrivateKey,
	pins map[string]ed25519.PublicKey,
) (formalFinalizerHandoffTicket, error) {
	var zero formalFinalizerHandoffTicket
	if formalFinalizerHandoffValidateBinding(binding, pins) != nil ||
		len(signingKey) != ed25519.PrivateKeySize {
		return zero, fmt.Errorf("typed-finalizer-handoff: invalid ticket policy")
	}
	finalizer := binding.Finalizer
	if !hmac.Equal(signingKey.Public().(ed25519.PublicKey),
		pins[finalizer.PeerName]) {
		return zero, fmt.Errorf("typed-finalizer-handoff: ticket issuer is not finalizer")
	}
	transportSHA, err := formalFinalizerHandoffTransportKeySHA256(transportPublic)
	if err != nil {
		return zero, err
	}
	ticket := formalFinalizerHandoffTicket{
		Version: formalFinalizerHandoffTicketVersion,
		Family:  binding.Family, Purpose: binding.Purpose,
		ArtifactID:          binding.ArtifactID,
		FinalPairRootSHA256: binding.FinalPairRootSHA256,
		PlanSHA256:          binding.PlanSHA256, PinsetSHA256: binding.PinsetSHA256,
		FinalizerPeerName: finalizer.PeerName, FinalizerPeerID: finalizer.PeerID,
		FinalizerRole:               "garbler",
		RecipientTransportPublicKey: append([]byte(nil), transportPublic...),
		TransportKeySHA256:          transportSHA,
		IssuerPeerName:              finalizer.PeerName, IssuerPeerID: finalizer.PeerID,
		ProductionReady: false,
	}
	message, err := formalFinalizerHandoffTicketMessage(ticket)
	if err != nil {
		return zero, err
	}
	ticket.Signature = ed25519.Sign(signingKey, message)
	if err := formalFinalizerHandoffValidateTicket(ticket, binding, pins); err != nil {
		return zero, err
	}
	return ticket, nil
}

func formalFinalizerHandoffValidateTicket(ticket formalFinalizerHandoffTicket,
	binding formalFinalizerHandoffBinding, pins map[string]ed25519.PublicKey,
) error {
	if formalFinalizerHandoffValidateBinding(binding, pins) != nil ||
		ticket.Version != formalFinalizerHandoffTicketVersion ||
		ticket.ProductionReady || ticket.Family != binding.Family ||
		ticket.Purpose != binding.Purpose || ticket.ArtifactID != binding.ArtifactID ||
		ticket.FinalPairRootSHA256 != binding.FinalPairRootSHA256 ||
		ticket.PlanSHA256 != binding.PlanSHA256 ||
		ticket.PinsetSHA256 != binding.PinsetSHA256 {
		return fmt.Errorf("typed-finalizer-handoff: ticket binding mismatch")
	}
	finalizer := binding.Finalizer
	transportSHA, keyErr := formalFinalizerHandoffTransportKeySHA256(
		ticket.RecipientTransportPublicKey)
	message, messageErr := formalFinalizerHandoffTicketMessage(ticket)
	if keyErr != nil || messageErr != nil ||
		ticket.FinalizerPeerName != finalizer.PeerName ||
		ticket.FinalizerPeerID != finalizer.PeerID || ticket.FinalizerRole != "garbler" ||
		ticket.IssuerPeerName != finalizer.PeerName ||
		ticket.IssuerPeerID != finalizer.PeerID ||
		ticket.TransportKeySHA256 != transportSHA ||
		len(ticket.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pins[finalizer.PeerName], message, ticket.Signature) {
		return fmt.Errorf("typed-finalizer-handoff: invalid finalizer ticket")
	}
	return nil
}

func formalFinalizerHandoffTransportKeyMessage(
	record formalFinalizerHandoffTransportKeyRecord,
) ([]byte, error) {
	record.Signature = nil
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalFinalizerHandoffDomain+"/durable-transport-key|"),
		encoded...), nil
}

func formalFinalizerHandoffAtRestKey(storageRoot [32]byte,
	binding formalFinalizerHandoffBinding,
) ([32]byte, error) {
	var key [32]byte
	if !formalGLMPhase19KeyValid(storageRoot) ||
		!formalGLMIsSHA256(binding.ArtifactID) ||
		!formalFinalizerHandoffPathSafePeerName(
			binding.Finalizer.PeerName) || binding.Finalizer.PeerID == "" {
		return key, fmt.Errorf("typed-finalizer-handoff: invalid owner storage root")
	}
	info, err := json.Marshal(struct {
		Family            string `json:"family"`
		Purpose           string `json:"purpose"`
		ArtifactID        string `json:"artifact_id"`
		FinalizerPeerName string `json:"finalizer_peer_name"`
		FinalizerPeerID   string `json:"finalizer_peer_id"`
	}{binding.Family, binding.Purpose, binding.ArtifactID,
		binding.Finalizer.PeerName, binding.Finalizer.PeerID})
	if err != nil {
		return key, err
	}
	defer clear(info)
	salt := sha256.Sum256([]byte(
		formalFinalizerHandoffDomain + "/owner-root-aead/salt"))
	reader := hkdf.New(sha256.New, storageRoot[:], salt[:], append(
		[]byte(formalFinalizerHandoffDomain+"/owner-root-aead/info|"), info...))
	if _, err := io.ReadFull(reader, key[:]); err != nil ||
		!formalGLMPhase19KeyValid(key) {
		clear(key[:])
		return key,
			fmt.Errorf("typed-finalizer-handoff: at-rest key derivation failed")
	}
	return key, nil
}

func formalFinalizerHandoffTransportKeyAAD(
	record formalFinalizerHandoffTransportKeyRecord,
) ([]byte, error) {
	record.Ciphertext = nil
	record.Signature = nil
	return json.Marshal(record)
}

func formalFinalizerHandoffValidateTransportKeyRecord(
	record formalFinalizerHandoffTransportKeyRecord,
	binding formalFinalizerHandoffBinding, pins map[string]ed25519.PublicKey,
) error {
	if formalFinalizerHandoffValidateBinding(binding, pins) != nil ||
		record.Version != formalFinalizerHandoffTransportKeyVersion ||
		record.ProductionReady || record.Family != binding.Family ||
		record.Purpose != binding.Purpose ||
		record.ArtifactID != binding.ArtifactID ||
		record.FinalPairRootSHA256 != binding.FinalPairRootSHA256 ||
		record.PlanSHA256 != binding.PlanSHA256 ||
		record.PinsetSHA256 != binding.PinsetSHA256 ||
		record.FinalizerPeerName != binding.Finalizer.PeerName ||
		record.FinalizerPeerID != binding.Finalizer.PeerID ||
		len(record.Nonce) != 12 || len(record.Ciphertext) != 48 {
		return fmt.Errorf("typed-finalizer-handoff: invalid durable transport key")
	}
	keySHA, keyErr := formalFinalizerHandoffTransportKeySHA256(
		record.TransportPublicKey)
	message, messageErr := formalFinalizerHandoffTransportKeyMessage(record)
	if keyErr != nil || messageErr != nil || record.TransportKeySHA256 != keySHA ||
		len(record.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pins[binding.Finalizer.PeerName], message,
			record.Signature) {
		return fmt.Errorf("typed-finalizer-handoff: unauthenticated durable transport key")
	}
	return nil
}

func (store *formalFinalizerHandoffStore) sealTransportKeyRecord(
	transportPublic, secret []byte, privateKey ed25519.PrivateKey,
) (formalFinalizerHandoffTransportKeyRecord, error) {
	var zero formalFinalizerHandoffTransportKeyRecord
	if store == nil || store.root == nil || len(secret) != 32 ||
		len(privateKey) != ed25519.PrivateKeySize {
		return zero, fmt.Errorf("typed-finalizer-handoff: invalid transport key seal")
	}
	private, err := ecdh.X25519().NewPrivateKey(secret)
	keySHA, keyErr := formalFinalizerHandoffTransportKeySHA256(transportPublic)
	if err != nil || keyErr != nil || !hmac.Equal(
		private.PublicKey().Bytes(), transportPublic) {
		return zero, fmt.Errorf("typed-finalizer-handoff: transport keypair mismatch")
	}
	aead, err := formalGLMPhase20HandoffAEAD(store.atRestKey)
	if err != nil {
		return zero, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		clear(nonce)
		return zero, err
	}
	record := formalFinalizerHandoffTransportKeyRecord{
		Version: formalFinalizerHandoffTransportKeyVersion,
		Family:  store.binding.Family, Purpose: store.binding.Purpose,
		ArtifactID:          store.binding.ArtifactID,
		FinalPairRootSHA256: store.binding.FinalPairRootSHA256,
		PlanSHA256:          store.binding.PlanSHA256,
		PinsetSHA256:        store.binding.PinsetSHA256,
		FinalizerPeerName:   store.binding.Finalizer.PeerName,
		FinalizerPeerID:     store.binding.Finalizer.PeerID,
		TransportPublicKey:  append([]byte(nil), transportPublic...),
		TransportKeySHA256:  keySHA,
		Nonce:               append([]byte(nil), nonce...),
		ProductionReady:     false,
	}
	aad, err := formalFinalizerHandoffTransportKeyAAD(record)
	if err != nil {
		clear(nonce)
		return zero, err
	}
	record.Ciphertext = aead.Seal(nil, nonce, secret, aad)
	clear(nonce)
	clear(aad)
	message, err := formalFinalizerHandoffTransportKeyMessage(record)
	if err != nil {
		clear(record.Ciphertext)
		return zero, err
	}
	record.Signature = ed25519.Sign(privateKey, message)
	clear(message)
	if err := formalFinalizerHandoffValidateTransportKeyRecord(
		record, store.binding, store.pins); err != nil {
		clear(record.Ciphertext)
		return zero, err
	}
	return record, nil
}

func (store *formalFinalizerHandoffStore) openTransportKeyRecord(
	record formalFinalizerHandoffTransportKeyRecord,
) ([]byte, error) {
	if store == nil || store.root == nil ||
		formalFinalizerHandoffValidateTransportKeyRecord(
			record, store.binding, store.pins) != nil {
		return nil, fmt.Errorf("typed-finalizer-handoff: invalid encrypted transport key")
	}
	aead, err := formalGLMPhase20HandoffAEAD(store.atRestKey)
	if err != nil || len(record.Nonce) != aead.NonceSize() ||
		len(record.Ciphertext) < aead.Overhead() {
		return nil, fmt.Errorf("typed-finalizer-handoff: invalid transport key AEAD")
	}
	aad, err := formalFinalizerHandoffTransportKeyAAD(record)
	if err != nil {
		return nil, err
	}
	secret, err := aead.Open(nil, record.Nonce, record.Ciphertext, aad)
	clear(aad)
	if err != nil || len(secret) != 32 {
		clear(secret)
		return nil, fmt.Errorf("typed-finalizer-handoff: transport key authentication failed")
	}
	private, err := ecdh.X25519().NewPrivateKey(secret)
	if err != nil || !hmac.Equal(
		private.PublicKey().Bytes(), record.TransportPublicKey) {
		clear(secret)
		return nil, fmt.Errorf("typed-finalizer-handoff: durable transport keypair mismatch")
	}
	return secret, nil
}

func formalFinalizerHandoffCanonicalObject(encoded []byte, maximum int) error {
	if len(encoded) < 2 || len(encoded) > maximum || encoded[0] != '{' {
		return fmt.Errorf("typed-finalizer-handoff: invalid typed JSON payload")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil || value == nil {
		return fmt.Errorf("typed-finalizer-handoff: invalid typed JSON payload")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("typed-finalizer-handoff: trailing typed JSON payload")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return fmt.Errorf("typed-finalizer-handoff: non-canonical typed JSON payload")
	}
	return nil
}

func formalFinalizerHandoffPayloadSHA256(binding formalFinalizerHandoffBinding,
	ticketSHA256, sender, role, kind string, payload []byte,
) (string, error) {
	value := struct {
		Family              string          `json:"family"`
		Purpose             string          `json:"purpose"`
		ArtifactID          string          `json:"artifact_id"`
		FinalPairRootSHA256 string          `json:"final_pair_root_sha256"`
		PlanSHA256          string          `json:"plan_sha256"`
		PinsetSHA256        string          `json:"pinset_sha256"`
		TicketSHA256        string          `json:"ticket_sha256"`
		SenderPeerName      string          `json:"sender_peer_name"`
		SenderRole          string          `json:"sender_role"`
		PayloadKind         string          `json:"payload_kind"`
		Payload             json.RawMessage `json:"payload"`
	}{binding.Family, binding.Purpose, binding.ArtifactID,
		binding.FinalPairRootSHA256, binding.PlanSHA256, binding.PinsetSHA256,
		ticketSHA256, sender, role, kind, append(json.RawMessage(nil), payload...)}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalFinalizerHandoffDomain+"/typed-payload|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalFinalizerHandoffValidatePayloadSchema(
	binding formalFinalizerHandoffBinding, ticketSHA256, sender, role, kind string,
	payload []byte,
) error {
	if formalFinalizerHandoffCanonicalObject(
		payload, formalFinalizerHandoffMaxPayload) != nil {
		return fmt.Errorf("typed-finalizer-handoff: payload is not canonical JSON")
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(payload, &value); err != nil {
		return fmt.Errorf("typed-finalizer-handoff: invalid typed payload schema")
	}
	nested, version := "", ""
	switch kind {
	case formalFinalizerHandoffGLMOneDrawKind:
		if binding.Family != formalFinalizerHandoffFamilyGLM {
			return fmt.Errorf("typed-finalizer-handoff: cross-family payload kind")
		}
		nested, version = "one_draw", formalFinalizerHandoffGLMOneDrawPayloadVersion
	case formalFinalizerHandoffGLMFullKind:
		if binding.Family != formalFinalizerHandoffFamilyGLM {
			return fmt.Errorf("typed-finalizer-handoff: cross-family payload kind")
		}
		nested, version = "full", formalFinalizerHandoffGLMFullPayloadVersion
	case formalFinalizerHandoffCoxOpeningKind:
		if binding.Family != formalFinalizerHandoffFamilyCox {
			return fmt.Errorf("typed-finalizer-handoff: cross-family payload kind")
		}
		nested, version = "handoff", formalFinalizerHandoffCoxPayloadVersion
	default:
		return fmt.Errorf("typed-finalizer-handoff: unregistered payload kind")
	}
	wantKeys := map[string]bool{
		"version": true, "purpose": true, "artifact_id": true,
		"plan_sha256": true, "final_pair_root_sha256": true,
		"ticket_sha256": true, "sender_peer_name": true,
		"sender_peer_id": true, "sender_role": true, nested: true,
	}
	if len(value) != len(wantKeys) {
		return fmt.Errorf("typed-finalizer-handoff: typed payload field set mismatch")
	}
	for key := range value {
		if !wantKeys[key] {
			return fmt.Errorf("typed-finalizer-handoff: unknown typed payload field")
		}
	}
	readString := func(name string) (string, error) {
		var result string
		if err := json.Unmarshal(value[name], &result); err != nil || result == "" {
			return "", fmt.Errorf("typed-finalizer-handoff: invalid %s", name)
		}
		return result, nil
	}
	gotVersion, versionErr := readString("version")
	gotPurpose, purposeErr := readString("purpose")
	gotArtifact, artifactErr := readString("artifact_id")
	gotPlan, planErr := readString("plan_sha256")
	gotPair, pairErr := readString("final_pair_root_sha256")
	gotTicket, ticketErr := readString("ticket_sha256")
	gotSender, senderErr := readString("sender_peer_name")
	gotSenderID, senderIDErr := readString("sender_peer_id")
	gotRole, roleErr := readString("sender_role")
	authority, authorityErr := formalFinalizerHandoffPeer(binding, role)
	if versionErr != nil || purposeErr != nil || artifactErr != nil ||
		planErr != nil || pairErr != nil || ticketErr != nil || senderErr != nil ||
		senderIDErr != nil || roleErr != nil || authorityErr != nil ||
		gotVersion != version || gotPurpose != binding.Purpose ||
		gotArtifact != binding.ArtifactID || gotPlan != binding.PlanSHA256 ||
		gotPair != binding.FinalPairRootSHA256 || gotTicket != ticketSHA256 ||
		gotSender != sender || gotSenderID != authority.PeerID || gotRole != role {
		return fmt.Errorf("typed-finalizer-handoff: typed payload binding mismatch")
	}
	var nestedObject map[string]json.RawMessage
	if err := json.Unmarshal(value[nested], &nestedObject); err != nil ||
		len(nestedObject) == 0 {
		return fmt.Errorf("typed-finalizer-handoff: payload body is not a typed object")
	}
	return nil
}

func formalFinalizerHandoffEnvelopeMessage(envelope formalFinalizerHandoffEnvelope) (
	[]byte, error,
) {
	envelope.Signature = nil
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalFinalizerHandoffDomain+"/envelope|"), encoded...), nil
}

func formalFinalizerHandoffCiphertextSHA256(ciphertext []byte) string {
	digest := sha256.Sum256(append(
		[]byte(formalFinalizerHandoffDomain+"/ciphertext|"), ciphertext...))
	return hex.EncodeToString(digest[:])
}

// sealCanonical is private protocol plumbing.  Family adapters expose only
// SealGLM/SealCox wrappers whose concrete structs are validated before they
// reach this byte-level boundary.
func formalFinalizerHandoffSealCanonical(binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket, sender, kind string, payload []byte,
	signingKey ed25519.PrivateKey, pins map[string]ed25519.PublicKey,
) (formalFinalizerHandoffEnvelope, error) {
	var zero formalFinalizerHandoffEnvelope
	capability, err := formalFinalizerHandoffLookup(binding.Family, binding.Purpose)
	if err != nil || !formalFinalizerHandoffKindAllowed(capability, kind) ||
		formalFinalizerHandoffValidateTicket(ticket, binding, pins) != nil ||
		len(signingKey) != ed25519.PrivateKeySize {
		return zero, fmt.Errorf("typed-finalizer-handoff: invalid typed seal request")
	}
	role := ""
	var authority formalFinalizerHandoffAuthority
	for _, candidate := range binding.Authorities {
		if candidate.PeerName == sender {
			role, authority = candidate.Role, candidate
		}
	}
	if role == "" || !hmac.Equal(signingKey.Public().(ed25519.PublicKey),
		pins[sender]) {
		return zero, fmt.Errorf("typed-finalizer-handoff: sender is not an authority")
	}
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil {
		return zero, err
	}
	if err := formalFinalizerHandoffValidatePayloadSchema(
		binding, ticketSHA, sender, role, kind, payload); err != nil {
		return zero, err
	}
	payloadSHA, err := formalFinalizerHandoffPayloadSHA256(
		binding, ticketSHA, sender, role, kind, payload)
	if err != nil {
		return zero, err
	}
	plaintext := formalFinalizerHandoffPlaintext{
		Version: formalFinalizerHandoffPlaintextVersion,
		Family:  binding.Family, Purpose: binding.Purpose,
		ArtifactID:          binding.ArtifactID,
		FinalPairRootSHA256: binding.FinalPairRootSHA256,
		PlanSHA256:          binding.PlanSHA256, PinsetSHA256: binding.PinsetSHA256,
		TicketSHA256: ticketSHA, SenderPeerName: sender,
		SenderPeerID: authority.PeerID, SenderRole: role,
		PayloadKind: kind, PayloadSHA256: payloadSHA,
		Payload: append(json.RawMessage(nil), payload...),
	}
	plaintextJSON, err := json.Marshal(plaintext)
	if err != nil || len(plaintextJSON) > formalFinalizerHandoffMaxPayload+4096 {
		clear(plaintextJSON)
		return zero, fmt.Errorf("typed-finalizer-handoff: typed plaintext too large")
	}
	defer clear(plaintextJSON)
	ciphertext, err := transportEncryptBytes(
		plaintextJSON, ticket.RecipientTransportPublicKey)
	if err != nil {
		return zero, err
	}
	defer clear(ciphertext)
	envelope := formalFinalizerHandoffEnvelope{
		Version: formalFinalizerHandoffEnvelopeVersion,
		Family:  binding.Family, Purpose: binding.Purpose,
		ArtifactID:          binding.ArtifactID,
		FinalPairRootSHA256: binding.FinalPairRootSHA256,
		PlanSHA256:          binding.PlanSHA256, PinsetSHA256: binding.PinsetSHA256,
		TicketSHA256:                ticketSHA,
		FinalizerPeerName:           ticket.FinalizerPeerName,
		FinalizerPeerID:             ticket.FinalizerPeerID,
		RecipientTransportKeySHA256: ticket.TransportKeySHA256,
		SenderPeerName:              sender, SenderPeerID: authority.PeerID, SenderRole: role,
		PayloadKind: kind, PayloadSHA256: payloadSHA,
		CiphertextSHA256: formalFinalizerHandoffCiphertextSHA256(ciphertext),
		Ciphertext:       append([]byte(nil), ciphertext...), ProductionReady: false,
	}
	message, err := formalFinalizerHandoffEnvelopeMessage(envelope)
	if err != nil {
		return zero, err
	}
	envelope.Signature = ed25519.Sign(signingKey, message)
	if err := formalFinalizerHandoffValidateEnvelope(
		binding, ticket, envelope, pins); err != nil {
		return zero, err
	}
	return envelope, nil
}

func formalFinalizerHandoffValidateEnvelope(binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket, envelope formalFinalizerHandoffEnvelope,
	pins map[string]ed25519.PublicKey,
) error {
	capability, lookupErr := formalFinalizerHandoffLookup(binding.Family, binding.Purpose)
	ticketSHA, ticketErr := formalFinalizerHandoffTicketSHA256(ticket)
	message, messageErr := formalFinalizerHandoffEnvelopeMessage(envelope)
	if lookupErr != nil || ticketErr != nil || messageErr != nil ||
		formalFinalizerHandoffValidateTicket(ticket, binding, pins) != nil ||
		envelope.Version != formalFinalizerHandoffEnvelopeVersion ||
		envelope.ProductionReady || envelope.Family != binding.Family ||
		envelope.Purpose != binding.Purpose ||
		envelope.ArtifactID != binding.ArtifactID ||
		envelope.FinalPairRootSHA256 != binding.FinalPairRootSHA256 ||
		envelope.PlanSHA256 != binding.PlanSHA256 ||
		envelope.PinsetSHA256 != binding.PinsetSHA256 ||
		envelope.TicketSHA256 != ticketSHA ||
		envelope.FinalizerPeerName != ticket.FinalizerPeerName ||
		envelope.FinalizerPeerID != ticket.FinalizerPeerID ||
		envelope.RecipientTransportKeySHA256 != ticket.TransportKeySHA256 ||
		!formalFinalizerHandoffKindAllowed(capability, envelope.PayloadKind) ||
		!formalGLMIsSHA256(envelope.PayloadSHA256) ||
		len(envelope.Ciphertext) < 60 ||
		len(envelope.Ciphertext) > formalFinalizerHandoffMaxPayload+8192 ||
		envelope.CiphertextSHA256 !=
			formalFinalizerHandoffCiphertextSHA256(envelope.Ciphertext) {
		return fmt.Errorf("typed-finalizer-handoff: envelope binding mismatch")
	}
	authority, err := formalFinalizerHandoffPeer(binding, envelope.SenderRole)
	if err != nil || envelope.SenderPeerName != authority.PeerName ||
		envelope.SenderPeerID != authority.PeerID ||
		len(envelope.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pins[authority.PeerName], message, envelope.Signature) {
		return fmt.Errorf("typed-finalizer-handoff: invalid signed envelope")
	}
	return nil
}

func formalFinalizerHandoffOpenCanonical(binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket, envelope formalFinalizerHandoffEnvelope,
	recipientSecret []byte, pins map[string]ed25519.PublicKey,
) ([]byte, error) {
	if err := formalFinalizerHandoffValidateEnvelope(
		binding, ticket, envelope, pins); err != nil {
		return nil, err
	}
	if len(recipientSecret) != 32 {
		return nil, fmt.Errorf("typed-finalizer-handoff: invalid recipient secret key")
	}
	curve := ecdh.X25519()
	secret, err := curve.NewPrivateKey(recipientSecret)
	if err != nil || !hmac.Equal(secret.PublicKey().Bytes(),
		ticket.RecipientTransportPublicKey) {
		return nil, fmt.Errorf("typed-finalizer-handoff: recipient key does not match ticket")
	}
	plaintextJSON, err := transportDecryptBytes(envelope.Ciphertext, recipientSecret)
	if err != nil {
		return nil, err
	}
	defer clear(plaintextJSON)
	var plaintext formalFinalizerHandoffPlaintext
	if err := formalFinalizerHandoffDecodeCanonical(
		plaintextJSON, formalFinalizerHandoffMaxPayload+4096, &plaintext); err != nil {
		return nil, err
	}
	ticketSHA, _ := formalFinalizerHandoffTicketSHA256(ticket)
	wantPayloadSHA, payloadErr := formalFinalizerHandoffPayloadSHA256(
		binding, ticketSHA, envelope.SenderPeerName, envelope.SenderRole,
		envelope.PayloadKind, plaintext.Payload)
	if payloadErr != nil || plaintext.Version != formalFinalizerHandoffPlaintextVersion ||
		plaintext.Family != envelope.Family || plaintext.Purpose != envelope.Purpose ||
		plaintext.ArtifactID != envelope.ArtifactID ||
		plaintext.FinalPairRootSHA256 != envelope.FinalPairRootSHA256 ||
		plaintext.PlanSHA256 != envelope.PlanSHA256 ||
		plaintext.PinsetSHA256 != envelope.PinsetSHA256 ||
		plaintext.TicketSHA256 != envelope.TicketSHA256 ||
		plaintext.SenderPeerName != envelope.SenderPeerName ||
		plaintext.SenderPeerID != envelope.SenderPeerID ||
		plaintext.SenderRole != envelope.SenderRole ||
		plaintext.PayloadKind != envelope.PayloadKind ||
		plaintext.PayloadSHA256 != envelope.PayloadSHA256 ||
		wantPayloadSHA != envelope.PayloadSHA256 ||
		formalFinalizerHandoffValidatePayloadSchema(binding, ticketSHA,
			envelope.SenderPeerName, envelope.SenderRole,
			envelope.PayloadKind, plaintext.Payload) != nil {
		return nil, fmt.Errorf("typed-finalizer-handoff: decrypted typed payload mismatch")
	}
	return append([]byte(nil), plaintext.Payload...), nil
}

func formalFinalizerHandoffDecodeCanonical(encoded []byte, maximum int,
	value any,
) error {
	if len(encoded) < 64 || len(encoded) > maximum {
		return fmt.Errorf("typed-finalizer-handoff: invalid canonical record size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("typed-finalizer-handoff: trailing canonical record")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return fmt.Errorf("typed-finalizer-handoff: non-canonical record")
	}
	return nil
}

type formalFinalizerHandoffStore struct {
	mu             sync.Mutex
	dir            string
	root           *os.Root
	atRestKey      [32]byte
	binding        formalFinalizerHandoffBinding
	localAuthority *formalFinalizerHandoffAuthority
	authorityLock  *os.File
	pins           map[string]ed25519.PublicKey
}

type formalFinalizerHandoffAuthorityGuard struct {
	dir        string
	root       *os.Root
	artifactID string
	local      formalFinalizerHandoffAuthority
	lock       *os.File
	production bool
}

func newFormalFinalizerHandoffAuthorityGuard(dir, artifactID string,
	local formalFinalizerHandoffAuthority, production bool,
) (*formalFinalizerHandoffAuthorityGuard, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir ||
		!formalGLMIsSHA256(artifactID) ||
		!jointDPGaussianOneDrawPinnedPeer.MatchString(local.PeerID) ||
		!formalFinalizerHandoffPathSafePeerName(local.PeerName) ||
		(local.Role != "garbler" && local.Role != "evaluator") {
		return nil, fmt.Errorf("typed-finalizer-handoff: invalid authority guard")
	}
	if production {
		if formalFinalizerHandoffValidateProductionPath(dir) != nil ||
			dir != filepath.Join(formalFinalizerHandoffStateRoot, local.PeerName) {
			return nil, fmt.Errorf(
				"typed-finalizer-handoff: non-canonical authority guard path")
		}
	}
	if err := formalFinalizerHandoffEnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || !filepath.IsAbs(resolved) {
		return nil, fmt.Errorf("typed-finalizer-handoff: unresolved authority guard")
	}
	resolved = filepath.Clean(resolved)
	if production && formalFinalizerHandoffValidateResolvedProductionPath(
		dir, resolved) != nil {
		return nil, fmt.Errorf("typed-finalizer-handoff: authority guard left Rock")
	}
	root, err := os.OpenRoot(resolved)
	if err != nil {
		return nil, err
	}
	lock, err := formalFinalizerHandoffAcquireAuthorityLock(root, artifactID)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	return &formalFinalizerHandoffAuthorityGuard{
		dir: resolved, root: root, artifactID: artifactID,
		local: local, lock: lock, production: production,
	}, nil
}

func (guard *formalFinalizerHandoffAuthorityGuard) Close() {
	if guard == nil {
		return
	}
	if guard.lock != nil {
		_ = formalFinalizerHandoffUnlockAuthority(guard.lock)
		_ = guard.lock.Close()
		guard.lock = nil
	}
	if guard.root != nil {
		_ = guard.root.Close()
		guard.root = nil
	}
}

func openFormalFinalizerHandoffAuthorityStoreWithGuard(
	guard *formalFinalizerHandoffAuthorityGuard,
	binding formalFinalizerHandoffBinding,
	storageRoot [32]byte,
	pins map[string]ed25519.PublicKey,
) (*formalFinalizerHandoffStore, error) {
	if guard == nil || guard.root == nil || guard.lock == nil ||
		guard.artifactID != binding.ArtifactID ||
		!formalFinalizerHandoffBindingHasAuthority(binding, guard.local) {
		return nil, fmt.Errorf("typed-finalizer-handoff: guard binding mismatch")
	}
	store, err := openFormalFinalizerHandoffStore(
		guard.dir, binding, storageRoot, pins, guard.production, nil)
	if err != nil {
		return nil, err
	}
	local := guard.local
	store.localAuthority = &local
	store.authorityLock = guard.lock
	guard.lock = nil
	_ = guard.root.Close()
	guard.root = nil
	return store, nil
}

func formalFinalizerHandoffAcquireAuthorityLock(root *os.Root,
	artifactID string,
) (*os.File, error) {
	if root == nil || !formalGLMIsSHA256(artifactID) {
		return nil, fmt.Errorf("typed-finalizer-handoff: invalid authority lock")
	}
	name := "authority-lock-" + artifactID + ".bin"
	for attempt := 0; attempt < 4; attempt++ {
		pathInfo, statErr := root.Lstat(name)
		flags := os.O_RDWR
		if os.IsNotExist(statErr) {
			flags |= os.O_CREATE | os.O_EXCL
		} else if statErr != nil || !pathInfo.Mode().IsRegular() ||
			pathInfo.Mode()&os.ModeSymlink != 0 ||
			pathInfo.Mode().Perm()&0o077 != 0 ||
			!exactGCPrivateOwnedRegular(pathInfo) {
			return nil, fmt.Errorf("typed-finalizer-handoff: unsafe authority lock")
		}
		file, err := root.OpenFile(name, flags, 0o600)
		if err != nil {
			if os.IsExist(err) || os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf(
				"typed-finalizer-handoff: authority lock open failed")
		}
		fail := func() (*os.File, error) {
			_ = file.Close()
			return nil, fmt.Errorf("typed-finalizer-handoff: unsafe authority lock")
		}
		current, pathErr := root.Lstat(name)
		opened, fileErr := file.Stat()
		if pathErr != nil || fileErr != nil || !os.SameFile(current, opened) ||
			!current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 ||
			current.Mode().Perm()&0o077 != 0 ||
			!exactGCPrivateOwnedRegular(current) {
			return fail()
		}
		if err := file.Chmod(0o600); err != nil {
			return fail()
		}
		if err := formalFinalizerHandoffTryAuthorityLock(file); err != nil {
			_ = file.Close()
			if formalFinalizerHandoffAuthorityLockBusyV1(err) {
				return nil, fmt.Errorf("%w: %v",
					errFormalFinalizerHandoffAuthorityLockBusy, err)
			}
			return nil, fmt.Errorf("typed-finalizer-handoff: unsafe authority lock")
		}
		return file, nil
	}
	return nil, fmt.Errorf("typed-finalizer-handoff: authority lock changed")
}

func formalFinalizerHandoffAuthorityEqual(left,
	right formalFinalizerHandoffAuthority,
) bool {
	return left.PeerName == right.PeerName && left.PeerID == right.PeerID &&
		left.Role == right.Role
}

func formalFinalizerHandoffBindingHasAuthority(
	binding formalFinalizerHandoffBinding,
	authority formalFinalizerHandoffAuthority,
) bool {
	for _, candidate := range binding.Authorities {
		if formalFinalizerHandoffAuthorityEqual(candidate, authority) {
			return true
		}
	}
	return false
}

func formalFinalizerHandoffValidateProductionPath(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return fmt.Errorf("typed-finalizer-handoff: invalid production state path")
	}
	relative, err := filepath.Rel(formalFinalizerHandoffStateRoot, dir)
	if err != nil || relative == "." || relative == "" || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("typed-finalizer-handoff: state is outside Rock synopsis root")
	}
	return nil
}

func formalFinalizerHandoffValidateResolvedProductionPath(requested,
	resolved string,
) error {
	if requested != resolved {
		return fmt.Errorf("typed-finalizer-handoff: redirected production state path")
	}
	return formalFinalizerHandoffValidateProductionPath(resolved)
}

func newFormalFinalizerHandoffStore(dir string,
	binding formalFinalizerHandoffBinding, storageRoot [32]byte,
	pins map[string]ed25519.PublicKey,
) (*formalFinalizerHandoffStore, error) {
	if err := formalFinalizerHandoffValidateProductionPath(dir); err != nil {
		return nil, err
	}
	if dir != filepath.Join(formalFinalizerHandoffStateRoot,
		binding.Finalizer.PeerName) {
		return nil, fmt.Errorf("typed-finalizer-handoff: non-canonical finalizer state path")
	}
	return openFormalFinalizerHandoffStore(
		dir, binding, storageRoot, pins, true, nil)
}

func newFormalFinalizerHandoffStoreForTest(dir string,
	binding formalFinalizerHandoffBinding, storageRoot [32]byte,
	pins map[string]ed25519.PublicKey,
) (*formalFinalizerHandoffStore, error) {
	return openFormalFinalizerHandoffStore(
		dir, binding, storageRoot, pins, false, nil)
}

func newFormalFinalizerHandoffAuthorityStore(dir string,
	binding formalFinalizerHandoffBinding,
	local formalFinalizerHandoffAuthority,
	storageRoot [32]byte,
	pins map[string]ed25519.PublicKey,
) (*formalFinalizerHandoffStore, error) {
	guard, err := newFormalFinalizerHandoffAuthorityGuard(
		dir, binding.ArtifactID, local, true)
	if err != nil {
		return nil, err
	}
	defer guard.Close()
	return openFormalFinalizerHandoffAuthorityStoreWithGuard(
		guard, binding, storageRoot, pins)
}

func newFormalFinalizerHandoffAuthorityStoreForTest(dir string,
	binding formalFinalizerHandoffBinding,
	local formalFinalizerHandoffAuthority,
	storageRoot [32]byte,
	pins map[string]ed25519.PublicKey,
) (*formalFinalizerHandoffStore, error) {
	if !formalFinalizerHandoffBindingHasAuthority(binding, local) {
		return nil, fmt.Errorf("typed-finalizer-handoff: invalid local authority")
	}
	guard, err := newFormalFinalizerHandoffAuthorityGuard(
		dir, binding.ArtifactID, local, false)
	if err != nil {
		return nil, err
	}
	defer guard.Close()
	return openFormalFinalizerHandoffAuthorityStoreWithGuard(
		guard, binding, storageRoot, pins)
}

func formalFinalizerHandoffEnsurePrivateDir(dir string) error {
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(dir)
	}
	if err != nil || info == nil || !info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
		!formalFinalizerHandoffPrivateOwnedDirectory(info) {
		return fmt.Errorf("typed-finalizer-handoff: unsafe owner directory")
	}
	return nil
}

func formalFinalizerHandoffValidateRootOwnedDir(root *os.Root, name string) error {
	if err := formalGLMPhase21ValidateRootPrivateDir(root, name, false); err != nil {
		return err
	}
	current := ""
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		if err != nil || !formalFinalizerHandoffPrivateOwnedDirectory(info) {
			return fmt.Errorf("typed-finalizer-handoff: durable directory owner mismatch")
		}
	}
	return nil
}

func openFormalFinalizerHandoffStore(dir string,
	binding formalFinalizerHandoffBinding, storageRoot [32]byte,
	pins map[string]ed25519.PublicKey, production bool,
	localAuthority *formalFinalizerHandoffAuthority,
) (*formalFinalizerHandoffStore, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir ||
		formalFinalizerHandoffValidateBinding(binding, pins) != nil ||
		!formalGLMPhase19KeyValid(storageRoot) ||
		localAuthority != nil &&
			!formalFinalizerHandoffBindingHasAuthority(binding, *localAuthority) {
		return nil, fmt.Errorf("typed-finalizer-handoff: invalid store policy")
	}
	if info, err := os.Lstat(dir); err == nil &&
		(info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
		return nil, fmt.Errorf("typed-finalizer-handoff: unsafe store root")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := formalFinalizerHandoffEnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || !filepath.IsAbs(resolved) {
		return nil, fmt.Errorf("typed-finalizer-handoff: unresolved store root")
	}
	resolved = filepath.Clean(resolved)
	if production && formalFinalizerHandoffValidateResolvedProductionPath(
		dir, resolved) != nil {
		return nil, fmt.Errorf("typed-finalizer-handoff: resolved state left Rock")
	}
	root, err := os.OpenRoot(resolved)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{
		"transport-keys-v1", "tickets-v1", "outbox-v1", "ingress-v1",
		"intent-signatures-v1", "acks-v1",
	} {
		if err := formalGLMPhase21EnsureRootPrivateDir(root, name); err != nil {
			_ = root.Close()
			return nil, err
		}
		if err := formalFinalizerHandoffValidateRootOwnedDir(root, name); err != nil {
			_ = root.Close()
			return nil, err
		}
	}
	copyPins := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		copyPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	copyBinding := binding
	copyBinding.Authorities = append(
		[]formalFinalizerHandoffAuthority(nil), binding.Authorities...)
	var copyLocal *formalFinalizerHandoffAuthority
	if localAuthority != nil {
		value := *localAuthority
		copyLocal = &value
	}
	atRestKey, err := formalFinalizerHandoffAtRestKey(storageRoot, binding)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	var authorityLock *os.File
	if copyLocal != nil {
		authorityLock, err = formalFinalizerHandoffAcquireAuthorityLock(
			root, binding.ArtifactID)
		if err != nil {
			_ = root.Close()
			clear(atRestKey[:])
			return nil, err
		}
	}
	return &formalFinalizerHandoffStore{
		dir: resolved, root: root, atRestKey: atRestKey,
		binding: copyBinding, localAuthority: copyLocal,
		authorityLock: authorityLock, pins: copyPins,
	}, nil
}

func (store *formalFinalizerHandoffStore) requireLocalRole(role string) error {
	if store != nil && store.localAuthority != nil &&
		store.localAuthority.Role != role {
		return fmt.Errorf("typed-finalizer-handoff: operation targets another authority")
	}
	return nil
}

func (store *formalFinalizerHandoffStore) requireLocalFinalizer() error {
	if store != nil && store.localAuthority != nil &&
		!formalFinalizerHandoffAuthorityEqual(
			*store.localAuthority, store.binding.Finalizer) {
		return fmt.Errorf("typed-finalizer-handoff: operation requires local finalizer")
	}
	return nil
}

func (store *formalFinalizerHandoffStore) Close() {
	if store != nil && store.root != nil {
		if store.authorityLock != nil {
			_ = formalFinalizerHandoffUnlockAuthority(store.authorityLock)
			_ = store.authorityLock.Close()
			store.authorityLock = nil
		}
		_ = store.root.Close()
		store.root = nil
		clear(store.atRestKey[:])
	}
}

func (store *formalFinalizerHandoffStore) relativePath(kind, role,
	pairRoot string, create bool,
) (string, error) {
	if store == nil || store.root == nil ||
		!formalGLMIsSHA256(store.binding.ArtifactID) {
		return "", fmt.Errorf("typed-finalizer-handoff: closed store")
	}
	artifact := store.binding.ArtifactID
	shard := filepath.Join(kind, artifact[:2], artifact[2:4])
	if create {
		if err := formalGLMPhase21EnsureRootPrivateDir(store.root, shard); err != nil {
			return "", err
		}
		if err := formalFinalizerHandoffValidateRootOwnedDir(
			store.root, shard); err != nil {
			return "", err
		}
	} else if err := formalGLMPhase21ValidateRootPrivateDir(
		store.root, shard, false); err != nil {
		return "", err
	}
	name := ""
	switch kind {
	case "transport-keys-v1":
		name = "transport-key-" + artifact + ".json"
	case "tickets-v1":
		name = "ticket-" + artifact + ".json"
	case "outbox-v1":
		if role != "garbler" && role != "evaluator" {
			return "", fmt.Errorf("typed-finalizer-handoff: invalid outbox role")
		}
		name = "outbox-" + role + "-" + artifact + ".json"
	case "ingress-v1":
		if (role != "garbler" && role != "evaluator") ||
			!formalGLMIsSHA256(pairRoot) {
			return "", fmt.Errorf("typed-finalizer-handoff: invalid ingress slot")
		}
		name = "ingress-" + role + "-" + artifact + "-" + pairRoot + ".json"
	case "intent-signatures-v1":
		if role != "garbler" && role != "evaluator" {
			return "", fmt.Errorf("typed-finalizer-handoff: invalid intent role")
		}
		name = "intent-" + role + "-" + artifact + ".json"
	case "acks-v1":
		name = "ack-" + artifact + ".json"
	default:
		return "", fmt.Errorf("typed-finalizer-handoff: invalid durable record kind")
	}
	return filepath.Join(shard, name), nil
}

func (store *formalFinalizerHandoffStore) createAndRead(relative string,
	encoded []byte,
) ([]byte, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	created, err := formalGLMPhase21RootCreateRecord(store.root, relative, encoded)
	if err != nil {
		return nil, false, err
	}
	existing, err := formalGLMPhase21RootReadRecord(
		store.root, relative, formalFinalizerHandoffMaxRecord)
	return existing, !created, err
}

func (store *formalFinalizerHandoffStore) read(relative string) ([]byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return formalGLMPhase21RootReadRecord(
		store.root, relative, formalFinalizerHandoffMaxRecord)
}

func (store *formalFinalizerHandoffStore) CommitTicket(
	ticket formalFinalizerHandoffTicket,
) (formalFinalizerHandoffTicket, bool, error) {
	var zero formalFinalizerHandoffTicket
	if store == nil || formalFinalizerHandoffValidateTicket(
		ticket, store.binding, store.pins) != nil {
		return zero, false, fmt.Errorf("typed-finalizer-handoff: rejected ticket CAS")
	}
	encoded, err := json.Marshal(ticket)
	if err != nil {
		return zero, false, err
	}
	relative, err := store.relativePath("tickets-v1", "", "", true)
	if err != nil {
		return zero, false, err
	}
	existingJSON, replayed, err := store.createAndRead(relative, encoded)
	if err != nil {
		return zero, false, err
	}
	var existing formalFinalizerHandoffTicket
	if formalFinalizerHandoffDecodeCanonical(existingJSON,
		formalFinalizerHandoffMaxRecord, &existing) != nil ||
		formalFinalizerHandoffValidateTicket(existing, store.binding, store.pins) != nil ||
		!bytes.Equal(existingJSON, encoded) {
		return zero, false,
			fmt.Errorf("typed-finalizer-handoff: conflicting ArtifactID ticket")
	}
	return existing, replayed, nil
}

func (store *formalFinalizerHandoffStore) loadTicket() (
	formalFinalizerHandoffTicket, error,
) {
	var zero formalFinalizerHandoffTicket
	relative, err := store.relativePath("tickets-v1", "", "", false)
	if err != nil {
		return zero, err
	}
	encoded, err := store.read(relative)
	if err != nil {
		return zero, err
	}
	var ticket formalFinalizerHandoffTicket
	if formalFinalizerHandoffDecodeCanonical(encoded,
		formalFinalizerHandoffMaxRecord, &ticket) != nil ||
		formalFinalizerHandoffValidateTicket(ticket, store.binding, store.pins) != nil {
		return zero, fmt.Errorf("typed-finalizer-handoff: invalid durable ticket")
	}
	return ticket, nil
}

func (store *formalFinalizerHandoffStore) commitTransportKey(
	record formalFinalizerHandoffTransportKeyRecord,
) (formalFinalizerHandoffTransportKeyRecord, bool, error) {
	var zero formalFinalizerHandoffTransportKeyRecord
	if formalFinalizerHandoffValidateTransportKeyRecord(
		record, store.binding, store.pins) != nil {
		return zero, false, fmt.Errorf("typed-finalizer-handoff: rejected transport key CAS")
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return zero, false, err
	}
	relative, err := store.relativePath("transport-keys-v1", "", "", true)
	if err != nil {
		return zero, false, err
	}
	existingJSON, replayed, err := store.createAndRead(relative, encoded)
	if err != nil {
		return zero, false, err
	}
	var existing formalFinalizerHandoffTransportKeyRecord
	if formalFinalizerHandoffDecodeCanonical(existingJSON,
		formalFinalizerHandoffMaxRecord, &existing) != nil ||
		formalFinalizerHandoffValidateTransportKeyRecord(
			existing, store.binding, store.pins) != nil {
		return zero, false,
			fmt.Errorf("typed-finalizer-handoff: invalid durable transport key")
	}
	return existing, replayed, nil
}

func (store *formalFinalizerHandoffStore) loadTransportKey() (
	formalFinalizerHandoffTransportKeyRecord, []byte, error,
) {
	var zero formalFinalizerHandoffTransportKeyRecord
	relative, err := store.relativePath("transport-keys-v1", "", "", false)
	if err != nil {
		return zero, nil, err
	}
	encoded, err := store.read(relative)
	if err != nil {
		return zero, nil, err
	}
	var record formalFinalizerHandoffTransportKeyRecord
	if formalFinalizerHandoffDecodeCanonical(encoded,
		formalFinalizerHandoffMaxRecord, &record) != nil ||
		formalFinalizerHandoffValidateTransportKeyRecord(
			record, store.binding, store.pins) != nil {
		return zero, nil,
			fmt.Errorf("typed-finalizer-handoff: invalid durable transport key")
	}
	secret, err := store.openTransportKeyRecord(record)
	if err != nil {
		return zero, nil, err
	}
	return record, secret, nil
}

// IssueTicketOnce durably fixes the finalizer X25519 key before publishing its
// ticket.  A crash between the two CAS operations resumes from the same key;
// a concurrent generator accepts the first valid key record and cannot rotate
// the ArtifactID ticket afterwards.
func (store *formalFinalizerHandoffStore) IssueTicketOnce(
	privateKey ed25519.PrivateKey,
) (formalFinalizerHandoffTicket, []byte, bool, error) {
	var zero formalFinalizerHandoffTicket
	if store == nil || store.requireLocalFinalizer() != nil ||
		len(privateKey) != ed25519.PrivateKeySize ||
		!hmac.Equal(privateKey.Public().(ed25519.PublicKey),
			store.pins[store.binding.Finalizer.PeerName]) {
		return zero, nil, false,
			fmt.Errorf("typed-finalizer-handoff: invalid durable ticket issuer")
	}
	if existingTicket, ticketErr := store.loadTicket(); ticketErr == nil {
		existingKey, existingSecret, keyErr := store.loadTransportKey()
		if keyErr == nil {
			defer clear(existingSecret)
			if existingTicket.TransportKeySHA256 !=
				existingKey.TransportKeySHA256 ||
				!hmac.Equal(existingTicket.RecipientTransportPublicKey,
					existingKey.TransportPublicKey) {
				return zero, nil, false,
					fmt.Errorf("typed-finalizer-handoff: fixed ticket key mismatch")
			}
			return existingTicket,
				append([]byte(nil), existingSecret...), true, nil
		}
		if !os.IsNotExist(keyErr) {
			return zero, nil, false, keyErr
		}
		if ack, found, ackErr := store.PreflightAck(); ackErr != nil {
			return zero, nil, false, ackErr
		} else if found {
			return existingTicket, nil, true,
				&formalFinalizerHandoffTerminalAckError{Proof: ack}
		}
		return zero, nil, false,
			fmt.Errorf("typed-finalizer-handoff: fixed ticket lost durable key before ACK")
	} else if !os.IsNotExist(ticketErr) {
		return zero, nil, false, ticketErr
	}
	transport, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return zero, nil, false, err
	}
	secret := append([]byte(nil), transport.Bytes()...)
	defer clear(secret)
	record, err := store.sealTransportKeyRecord(
		transport.PublicKey().Bytes(), secret, privateKey)
	if err != nil {
		return zero, nil, false, err
	}
	storedKey, keyReplayed, err := store.commitTransportKey(record)
	clear(record.Ciphertext)
	if err != nil {
		return zero, nil, false, err
	}
	storedSecret, err := store.openTransportKeyRecord(storedKey)
	if err != nil {
		return zero, nil, false, err
	}
	defer clear(storedSecret)
	ticket, err := formalFinalizerHandoffIssueTicket(
		store.binding, storedKey.TransportPublicKey, privateKey, store.pins)
	if err != nil {
		return zero, nil, false, err
	}
	storedTicket, _, err := store.CommitTicket(ticket)
	if err != nil || storedTicket.TransportKeySHA256 != storedKey.TransportKeySHA256 {
		if err == nil {
			err = fmt.Errorf("typed-finalizer-handoff: durable ticket key mismatch")
		}
		return zero, nil, false, err
	}
	resultSecret := append([]byte(nil), storedSecret...)
	return storedTicket, resultSecret, keyReplayed, nil
}

func formalFinalizerHandoffEnvelopeSemanticEqual(left,
	right formalFinalizerHandoffEnvelope,
) bool {
	left.Ciphertext, right.Ciphertext = nil, nil
	left.CiphertextSHA256, right.CiphertextSHA256 = "", ""
	left.Signature, right.Signature = nil, nil
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func (store *formalFinalizerHandoffStore) commitEnvelope(kind string,
	envelope formalFinalizerHandoffEnvelope,
) (formalFinalizerHandoffEnvelope, bool, error) {
	var zero formalFinalizerHandoffEnvelope
	if kind == "outbox-v1" {
		if err := store.requireLocalRole(envelope.SenderRole); err != nil {
			return zero, false, err
		}
	} else if kind == "ingress-v1" {
		if err := store.requireLocalFinalizer(); err != nil {
			return zero, false, err
		}
	} else {
		return zero, false, fmt.Errorf("typed-finalizer-handoff: invalid envelope store")
	}
	if ack, found, err := store.PreflightAck(); err != nil {
		return zero, false, err
	} else if found {
		return zero, true, &formalFinalizerHandoffTerminalAckError{Proof: ack}
	}
	ticket, err := store.loadTicket()
	if err != nil || formalFinalizerHandoffValidateEnvelope(
		store.binding, ticket, envelope, store.pins) != nil {
		return zero, false, fmt.Errorf("typed-finalizer-handoff: rejected envelope CAS")
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return zero, false, err
	}
	pair := ""
	if kind == "ingress-v1" {
		pair = envelope.FinalPairRootSHA256
	}
	relative, err := store.relativePath(kind, envelope.SenderRole, pair, true)
	if err != nil {
		return zero, false, err
	}
	existingJSON, replayed, err := store.createAndRead(relative, encoded)
	if err != nil {
		return zero, false, err
	}
	var existing formalFinalizerHandoffEnvelope
	if formalFinalizerHandoffDecodeCanonical(existingJSON,
		formalFinalizerHandoffMaxRecord, &existing) != nil ||
		formalFinalizerHandoffValidateEnvelope(
			store.binding, ticket, existing, store.pins) != nil ||
		!formalFinalizerHandoffEnvelopeSemanticEqual(existing, envelope) {
		return zero, false,
			fmt.Errorf("typed-finalizer-handoff: conflicting durable envelope")
	}
	if ack, found, ackErr := store.PreflightAck(); ackErr != nil {
		return zero, false, ackErr
	} else if found {
		if _, cleanupErr := store.CleanupTransportAfterAck(ack); cleanupErr != nil {
			return zero, false, cleanupErr
		}
		return zero, true, &formalFinalizerHandoffTerminalAckError{Proof: ack}
	}
	return existing, replayed, nil
}

func (store *formalFinalizerHandoffStore) CommitOutbox(
	envelope formalFinalizerHandoffEnvelope,
) (formalFinalizerHandoffEnvelope, bool, error) {
	return store.commitEnvelope("outbox-v1", envelope)
}

func (store *formalFinalizerHandoffStore) CommitIngress(
	envelope formalFinalizerHandoffEnvelope,
) (formalFinalizerHandoffEnvelope, bool, error) {
	return store.commitEnvelope("ingress-v1", envelope)
}

func (store *formalFinalizerHandoffStore) loadEnvelope(kind, role string) (
	formalFinalizerHandoffEnvelope, error,
) {
	var zero formalFinalizerHandoffEnvelope
	if kind == "outbox-v1" {
		if err := store.requireLocalRole(role); err != nil {
			return zero, err
		}
	} else if kind == "ingress-v1" {
		if err := store.requireLocalFinalizer(); err != nil {
			return zero, err
		}
	} else {
		return zero, fmt.Errorf("typed-finalizer-handoff: invalid envelope load")
	}
	pair := ""
	if kind == "ingress-v1" {
		pair = store.binding.FinalPairRootSHA256
	}
	relative, err := store.relativePath(kind, role, pair, false)
	if err != nil {
		return zero, err
	}
	encoded, err := store.read(relative)
	if err != nil {
		return zero, err
	}
	var envelope formalFinalizerHandoffEnvelope
	ticket, ticketErr := store.loadTicket()
	if ticketErr != nil || formalFinalizerHandoffDecodeCanonical(encoded,
		formalFinalizerHandoffMaxRecord, &envelope) != nil ||
		formalFinalizerHandoffValidateEnvelope(
			store.binding, ticket, envelope, store.pins) != nil {
		return zero, fmt.Errorf("typed-finalizer-handoff: invalid durable envelope")
	}
	return envelope, nil
}

func (store *formalFinalizerHandoffStore) OpenIngressCanonical(role string,
	ticket formalFinalizerHandoffTicket, recipientSecret []byte,
) ([]byte, error) {
	if err := store.requireLocalFinalizer(); err != nil {
		return nil, err
	}
	storedTicket, err := store.loadTicket()
	if err != nil {
		return nil, err
	}
	want, _ := json.Marshal(storedTicket)
	got, _ := json.Marshal(ticket)
	if !bytes.Equal(want, got) {
		return nil, fmt.Errorf("typed-finalizer-handoff: ingress ticket changed")
	}
	envelope, err := store.loadEnvelope("ingress-v1", role)
	if err != nil {
		return nil, err
	}
	return formalFinalizerHandoffOpenCanonical(
		store.binding, ticket, envelope, recipientSecret, store.pins)
}

func (store *formalFinalizerHandoffStore) OpenIngressDurableCanonical(
	role string, ticket formalFinalizerHandoffTicket,
) ([]byte, error) {
	if err := store.requireLocalFinalizer(); err != nil {
		return nil, err
	}
	record, secret, err := store.loadTransportKey()
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	if record.TransportKeySHA256 != ticket.TransportKeySHA256 ||
		!hmac.Equal(record.TransportPublicKey,
			ticket.RecipientTransportPublicKey) {
		return nil, fmt.Errorf("typed-finalizer-handoff: ticket lost durable key binding")
	}
	return store.OpenIngressCanonical(role, ticket, secret)
}

func formalFinalizerHandoffIntentMessage(
	authorization formalFinalizerHandoffIntentAuthorization,
) ([]byte, error) {
	authorization.Signature = nil
	encoded, err := json.Marshal(authorization)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalFinalizerHandoffDomain+"/intent-authorization|"),
		encoded...), nil
}

func formalFinalizerHandoffIntentSHA256(
	authorization formalFinalizerHandoffIntentAuthorization,
) (string, error) {
	encoded, err := json.Marshal(authorization)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalFinalizerHandoffDomain+"/signed-intent-authorization|"),
		encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalFinalizerHandoffValidateIntentAuthorization(
	authorization formalFinalizerHandoffIntentAuthorization,
	binding formalFinalizerHandoffBinding, ticketSHA string,
	pins map[string]ed25519.PublicKey,
) error {
	authority, authorityErr := formalFinalizerHandoffPeer(
		binding, authorization.SignerRole)
	message, messageErr := formalFinalizerHandoffIntentMessage(authorization)
	if authorityErr != nil || messageErr != nil ||
		authorization.Version != formalFinalizerHandoffIntentVersion ||
		authorization.ProductionReady || authorization.Family != binding.Family ||
		authorization.Purpose != binding.Purpose ||
		authorization.ArtifactID != binding.ArtifactID ||
		authorization.FinalPairRootSHA256 != binding.FinalPairRootSHA256 ||
		authorization.PlanSHA256 != binding.PlanSHA256 ||
		authorization.PinsetSHA256 != binding.PinsetSHA256 ||
		authorization.TicketSHA256 != ticketSHA ||
		authorization.SignerPeerName != authority.PeerName ||
		authorization.SignerPeerID != authority.PeerID ||
		!formalGLMIsSHA256(authorization.IntentSHA256) ||
		!formalGLMIsSHA256(authorization.LocalGuardSHA256) ||
		(authorization.SignerRole == "garbler" &&
			authorization.PredecessorReceiptSHA256 != "") ||
		(authorization.SignerRole == "evaluator" &&
			!formalGLMIsSHA256(authorization.PredecessorReceiptSHA256)) ||
		len(authorization.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pins[authority.PeerName], message, authorization.Signature) {
		return fmt.Errorf("typed-finalizer-handoff: invalid intent authorization")
	}
	return nil
}

func (store *formalFinalizerHandoffStore) SignIntentOnce(
	ticket formalFinalizerHandoffTicket, role, intentSHA, localGuardSHA string,
	predecessors []formalFinalizerHandoffIntentAuthorization,
	privateKey ed25519.PrivateKey,
) (formalFinalizerHandoffIntentAuthorization, bool, error) {
	var zero formalFinalizerHandoffIntentAuthorization
	if err := store.requireLocalRole(role); err != nil {
		return zero, false, err
	}
	storedTicket, err := store.loadTicket()
	storedJSON, _ := json.Marshal(storedTicket)
	ticketJSON, _ := json.Marshal(ticket)
	authority, authorityErr := formalFinalizerHandoffPeer(store.binding, role)
	outbox, outboxErr := store.loadEnvelope("outbox-v1", role)
	if err != nil || authorityErr != nil || outboxErr != nil ||
		!bytes.Equal(storedJSON, ticketJSON) ||
		!formalGLMIsSHA256(intentSHA) || localGuardSHA != outbox.PayloadSHA256 ||
		len(privateKey) != ed25519.PrivateKeySize ||
		!hmac.Equal(privateKey.Public().(ed25519.PublicKey),
			store.pins[authority.PeerName]) {
		return zero, false,
			fmt.Errorf("typed-finalizer-handoff: intent lacks exact local guard")
	}
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil {
		return zero, false, err
	}
	predecessorSHA := ""
	if role == "garbler" {
		if len(predecessors) != 0 {
			return zero, false,
				fmt.Errorf("typed-finalizer-handoff: garbler intent has predecessor")
		}
	} else {
		if len(predecessors) != 1 ||
			formalFinalizerHandoffValidateIntentAuthorization(
				predecessors[0], store.binding, ticketSHA, store.pins) != nil ||
			predecessors[0].SignerRole != "garbler" ||
			predecessors[0].IntentSHA256 != intentSHA {
			return zero, false,
				fmt.Errorf("typed-finalizer-handoff: evaluator lacks exact predecessor")
		}
		predecessorSHA, err = formalFinalizerHandoffIntentSHA256(predecessors[0])
		if err != nil {
			return zero, false, err
		}
	}
	authorization := formalFinalizerHandoffIntentAuthorization{
		Version: formalFinalizerHandoffIntentVersion,
		Family:  store.binding.Family, Purpose: store.binding.Purpose,
		ArtifactID:          store.binding.ArtifactID,
		FinalPairRootSHA256: store.binding.FinalPairRootSHA256,
		PlanSHA256:          store.binding.PlanSHA256,
		PinsetSHA256:        store.binding.PinsetSHA256, TicketSHA256: ticketSHA,
		SignerPeerName: authority.PeerName, SignerPeerID: authority.PeerID,
		SignerRole: role, IntentSHA256: intentSHA,
		LocalGuardSHA256:         localGuardSHA,
		PredecessorReceiptSHA256: predecessorSHA, ProductionReady: false,
	}
	message, err := formalFinalizerHandoffIntentMessage(authorization)
	if err != nil {
		return zero, false, err
	}
	authorization.Signature = ed25519.Sign(privateKey, message)
	encoded, err := json.Marshal(authorization)
	if err != nil {
		return zero, false, err
	}
	relative, err := store.relativePath("intent-signatures-v1", role, "", true)
	if err != nil {
		return zero, false, err
	}
	existingJSON, replayed, err := store.createAndRead(relative, encoded)
	if err != nil {
		return zero, false, err
	}
	var existing formalFinalizerHandoffIntentAuthorization
	if formalFinalizerHandoffDecodeCanonical(existingJSON,
		formalFinalizerHandoffMaxRecord, &existing) != nil ||
		formalFinalizerHandoffValidateIntentAuthorization(
			existing, store.binding, ticketSHA, store.pins) != nil ||
		!bytes.Equal(existingJSON, encoded) {
		return zero, false,
			fmt.Errorf("typed-finalizer-handoff: conflicting ArtifactID SignOnce")
	}
	return existing, replayed, nil
}

func formalFinalizerHandoffCommitProofMessage(
	proof formalFinalizerHandoffCommitProof,
) ([]byte, error) {
	proof.Signature = nil
	encoded, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalFinalizerHandoffDomain+"/publication-ack|"),
		encoded...), nil
}

func formalFinalizerHandoffBuildCommitProof(binding formalFinalizerHandoffBinding,
	ticketSHA, certificateSHA string, privateKey ed25519.PrivateKey,
	pins map[string]ed25519.PublicKey,
) (formalFinalizerHandoffCommitProof, error) {
	var zero formalFinalizerHandoffCommitProof
	if formalFinalizerHandoffValidateBinding(binding, pins) != nil ||
		!formalGLMIsSHA256(ticketSHA) || !formalGLMIsSHA256(certificateSHA) ||
		len(privateKey) != ed25519.PrivateKeySize ||
		!hmac.Equal(privateKey.Public().(ed25519.PublicKey),
			pins[binding.Finalizer.PeerName]) {
		return zero, fmt.Errorf("typed-finalizer-handoff: invalid commit proof policy")
	}
	finalizer := binding.Finalizer
	proof := formalFinalizerHandoffCommitProof{
		Version: formalFinalizerHandoffAckVersion,
		Family:  binding.Family, Purpose: binding.Purpose,
		ArtifactID:          binding.ArtifactID,
		FinalPairRootSHA256: binding.FinalPairRootSHA256,
		PlanSHA256:          binding.PlanSHA256, PinsetSHA256: binding.PinsetSHA256,
		TicketSHA256: ticketSHA, CertificateSHA256: certificateSHA,
		FinalizerPeerName: finalizer.PeerName,
		FinalizerPeerID:   finalizer.PeerID, ProductionReady: false,
	}
	message, err := formalFinalizerHandoffCommitProofMessage(proof)
	if err != nil {
		return zero, err
	}
	proof.Signature = ed25519.Sign(privateKey, message)
	return proof, nil
}

func formalFinalizerHandoffValidateCommitProof(
	proof formalFinalizerHandoffCommitProof,
	binding formalFinalizerHandoffBinding, ticketSHA string,
	pins map[string]ed25519.PublicKey,
) error {
	finalizer := binding.Finalizer
	message, messageErr := formalFinalizerHandoffCommitProofMessage(proof)
	if messageErr != nil || proof.Version != formalFinalizerHandoffAckVersion ||
		proof.ProductionReady || proof.Family != binding.Family ||
		proof.Purpose != binding.Purpose || proof.ArtifactID != binding.ArtifactID ||
		proof.FinalPairRootSHA256 != binding.FinalPairRootSHA256 ||
		proof.PlanSHA256 != binding.PlanSHA256 ||
		proof.PinsetSHA256 != binding.PinsetSHA256 ||
		proof.TicketSHA256 != ticketSHA ||
		!formalGLMIsSHA256(proof.CertificateSHA256) ||
		proof.FinalizerPeerName != finalizer.PeerName ||
		proof.FinalizerPeerID != finalizer.PeerID ||
		len(proof.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pins[finalizer.PeerName], message, proof.Signature) {
		return fmt.Errorf("typed-finalizer-handoff: invalid commit proof")
	}
	return nil
}

func (store *formalFinalizerHandoffStore) AckAfterCommit(
	proof formalFinalizerHandoffCommitProof,
	publicationGuard formalFinalizerHandoffPublicationGuard,
) (formalFinalizerHandoffCommitProof, bool, error) {
	var zero formalFinalizerHandoffCommitProof
	if publicationGuard == nil {
		return zero, false,
			fmt.Errorf("typed-finalizer-handoff: missing publication guard")
	}
	ticket, err := store.loadTicket()
	if err != nil {
		return zero, false, err
	}
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil || formalFinalizerHandoffValidateCommitProof(
		proof, store.binding, ticketSHA, store.pins) != nil {
		return zero, false, fmt.Errorf("typed-finalizer-handoff: rejected ACK")
	}
	// The family store must prove that its ArtifactID-keyed public CAS already
	// contains these exact certificate bytes before cleanup can observe ACK.
	if err := publicationGuard.formalFinalizerHandoffVerifyPublication(
		proof.ArtifactID, proof.CertificateSHA256); err != nil {
		return zero, false,
			fmt.Errorf("typed-finalizer-handoff: publication is not durable: %w", err)
	}
	encoded, err := json.Marshal(proof)
	if err != nil {
		return zero, false, err
	}
	relative, err := store.relativePath("acks-v1", "", "", true)
	if err != nil {
		return zero, false, err
	}
	existingJSON, replayed, err := store.createAndRead(relative, encoded)
	if err != nil {
		return zero, false, err
	}
	var existing formalFinalizerHandoffCommitProof
	if formalFinalizerHandoffDecodeCanonical(existingJSON,
		formalFinalizerHandoffMaxRecord, &existing) != nil ||
		formalFinalizerHandoffValidateCommitProof(
			existing, store.binding, ticketSHA, store.pins) != nil ||
		!bytes.Equal(existingJSON, encoded) {
		return zero, false,
			fmt.Errorf("typed-finalizer-handoff: conflicting ArtifactID ACK")
	}
	return existing, replayed, nil
}

func (store *formalFinalizerHandoffStore) loadAck() (
	formalFinalizerHandoffCommitProof, error,
) {
	var zero formalFinalizerHandoffCommitProof
	relative, err := store.relativePath("acks-v1", "", "", false)
	if err != nil {
		return zero, err
	}
	encoded, err := store.read(relative)
	if err != nil {
		return zero, err
	}
	var proof formalFinalizerHandoffCommitProof
	ticket, ticketErr := store.loadTicket()
	ticketSHA, hashErr := formalFinalizerHandoffTicketSHA256(ticket)
	if ticketErr != nil || hashErr != nil ||
		formalFinalizerHandoffDecodeCanonical(encoded,
			formalFinalizerHandoffMaxRecord, &proof) != nil ||
		formalFinalizerHandoffValidateCommitProof(
			proof, store.binding, ticketSHA, store.pins) != nil {
		return zero, fmt.Errorf("typed-finalizer-handoff: invalid durable ACK")
	}
	return proof, nil
}

func (store *formalFinalizerHandoffStore) PreflightAck() (
	formalFinalizerHandoffCommitProof, bool, error,
) {
	proof, err := store.loadAck()
	if err == nil {
		return proof, true, nil
	}
	if os.IsNotExist(err) {
		return formalFinalizerHandoffCommitProof{}, false, nil
	}
	return formalFinalizerHandoffCommitProof{}, false, err
}

// CleanupTransportAfterAck reclaims only the encrypted transport plane.  The
// ArtifactID ticket, ordered SignOnce records, family publication and ACK stay
// durable forever, so a later replay never depends on a TTL or another draw.
func (store *formalFinalizerHandoffStore) CleanupTransportAfterAck(
	proof formalFinalizerHandoffCommitProof,
) (int, error) {
	ack, err := store.loadAck()
	if err != nil {
		return 0, fmt.Errorf("typed-finalizer-handoff: cleanup requires durable ACK")
	}
	want, _ := json.Marshal(ack)
	got, _ := json.Marshal(proof)
	if !bytes.Equal(want, got) {
		return 0, fmt.Errorf("typed-finalizer-handoff: cleanup ACK differs")
	}
	type target struct {
		kind string
		role string
		pair string
	}
	targets := make([]target, 0, 5)
	if store.localAuthority == nil {
		targets = append(targets, target{kind: "transport-keys-v1"})
		for _, role := range []string{"garbler", "evaluator"} {
			targets = append(targets,
				target{kind: "outbox-v1", role: role},
				target{kind: "ingress-v1", role: role,
					pair: store.binding.FinalPairRootSHA256})
		}
	} else {
		targets = append(targets,
			target{kind: "outbox-v1", role: store.localAuthority.Role})
		if formalFinalizerHandoffAuthorityEqual(
			*store.localAuthority, store.binding.Finalizer) {
			targets = append(targets, target{kind: "transport-keys-v1"})
			for _, role := range []string{"garbler", "evaluator"} {
				targets = append(targets, target{
					kind: "ingress-v1", role: role,
					pair: store.binding.FinalPairRootSHA256})
			}
		}
	}
	removed := 0
	for _, candidate := range targets {
		relative, pathErr := store.relativePath(
			candidate.kind, candidate.role, candidate.pair, false)
		if pathErr != nil {
			if os.IsNotExist(pathErr) {
				continue
			}
			return removed, pathErr
		}
		if _, statErr := store.root.Lstat(relative); os.IsNotExist(statErr) {
			continue
		} else if statErr != nil {
			return removed, statErr
		}
		switch candidate.kind {
		case "transport-keys-v1":
			_, secret, loadErr := store.loadTransportKey()
			if loadErr != nil {
				return removed, loadErr
			}
			clear(secret)
		default:
			if _, loadErr := store.loadEnvelope(
				candidate.kind, candidate.role); loadErr != nil {
				return removed, loadErr
			}
		}
		store.mu.Lock()
		removeErr := store.root.Remove(relative)
		if removeErr == nil {
			removeErr = formalGLMPhase21RootSyncDir(store.root, relative)
		}
		store.mu.Unlock()
		if removeErr != nil && !os.IsNotExist(removeErr) {
			return removed, removeErr
		}
		if removeErr == nil {
			removed++
		}
	}
	return removed, nil
}

func handleFormalFinalizerHandoffCapabilities() {
	output(formalFinalizerHandoffCapabilities())
}
