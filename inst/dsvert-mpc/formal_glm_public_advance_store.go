package main

// Rock-local replay fence for one public formal-GLM Advance receipt.  It
// persists only the incoming frame digest and the signed public response;
// peer frame bytes and all protected lifecycle material remain outside it.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
)

const (
	formalGLMPublicAdvanceStoreVersion = "dsvert-formal-glm-public-advance-store-v1"
	formalGLMPublicAdvanceStorePurpose = "formal_glm_public_advance_replay_fence_v1"
	formalGLMPublicAdvanceStoreDomain  = "dsVert/formal-glm/public-advance-store/v1"
	formalGLMPublicAdvanceStoreDir     = "advance-replay-v1"
	formalGLMPublicAdvanceStoreMax     = 32 << 20
)

type formalGLMPublicAdvanceRequestV1 struct {
	Version          string `json:"version"`
	Purpose          string `json:"purpose"`
	ReceiptSHA256    string `json:"receipt_sha256"`
	PeerFrameSHA256  string `json:"peer_frame_sha256,omitempty"`
	SignerPeerName   string `json:"signer_peer_name"`
	SignerIdentityPK string `json:"signer_identity_pk"`
	ProductionReady  bool   `json:"production_ready"`
	Signature        string `json:"signature"`
}

type formalGLMPublicAdvanceResponseRecordV1 struct {
	Version          string                           `json:"version"`
	Purpose          string                           `json:"purpose"`
	ReceiptSHA256    string                           `json:"receipt_sha256"`
	PeerFrameSHA256  string                           `json:"peer_frame_sha256,omitempty"`
	Response         formalGLMPublicAdvanceResponseV1 `json:"response"`
	SignerPeerName   string                           `json:"signer_peer_name"`
	SignerIdentityPK string                           `json:"signer_identity_pk"`
	ProductionReady  bool                             `json:"production_ready"`
	Signature        string                           `json:"signature"`
}

type formalGLMPublicAdvanceStoreV1 struct {
	mu           sync.Mutex
	dir          string
	root         *os.Root
	pins         map[string]ed25519.PublicKey
	pinsetSHA256 string
	signerPeer   string
	signingKey   ed25519.PrivateKey
}

func newFormalGLMPublicAdvanceStoreV1(
	dir string, pins map[string]ed25519.PublicKey,
	signerPeer string, signingKey ed25519.PrivateKey,
) (*formalGLMPublicAdvanceStoreV1, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir ||
		!formalGLMRegistryLabelV1(signerPeer, 128) ||
		len(signingKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("formal-glm public advance store: invalid configuration")
	}
	if err := formalGLMPhase18EnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || !filepath.IsAbs(resolved) {
		return nil, fmt.Errorf("formal-glm public advance store: redirected Rock root")
	}
	dir = filepath.Clean(resolved)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	if err := formalGLMPhase21EnsureRootPrivateDir(
		root, formalGLMPublicAdvanceStoreDir); err != nil {
		_ = root.Close()
		return nil, err
	}
	clonedPins := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		clonedPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	pinsetSHA256, err := formalGLMPhase16PinsetSHA256(clonedPins)
	if err != nil || len(clonedPins[signerPeer]) != ed25519.PublicKeySize ||
		!bytes.Equal(signingKey.Public().(ed25519.PublicKey), clonedPins[signerPeer]) {
		_ = root.Close()
		return nil, fmt.Errorf("formal-glm public advance store: invalid signer")
	}
	return &formalGLMPublicAdvanceStoreV1{
		dir: dir, root: root, pins: clonedPins, pinsetSHA256: pinsetSHA256,
		signerPeer: signerPeer,
		signingKey: append(ed25519.PrivateKey(nil), signingKey...),
	}, nil
}

func (store *formalGLMPublicAdvanceStoreV1) Close() {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root != nil {
		_ = store.root.Close()
		store.root = nil
	}
	clear(store.signingKey)
	store.signingKey = nil
	for peer, pin := range store.pins {
		clear(pin)
		delete(store.pins, peer)
	}
	store.pinsetSHA256, store.signerPeer = "", ""
}

func (store *formalGLMPublicAdvanceStoreV1) validForEndpointV1(
	pins map[string]ed25519.PublicKey, signerPeer string,
) bool {
	if store == nil {
		return false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	pinsetSHA256, err := formalGLMPhase16PinsetSHA256(pins)
	return err == nil && store.root != nil &&
		store.pinsetSHA256 == pinsetSHA256 && store.signerPeer == signerPeer &&
		len(store.signingKey) == ed25519.PrivateKeySize &&
		bytes.Equal(store.signingKey.Public().(ed25519.PublicKey), pins[signerPeer])
}

func formalGLMPublicAdvanceRequestMessageV1(
	record formalGLMPublicAdvanceRequestV1,
) ([]byte, error) {
	record.Signature = ""
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMPublicAdvanceStoreDomain+"/request|"), encoded...), nil
}

func formalGLMPublicAdvanceResponseRecordMessageV1(
	record formalGLMPublicAdvanceResponseRecordV1,
) ([]byte, error) {
	record.Signature = ""
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMPublicAdvanceStoreDomain+"/response|"), encoded...), nil
}

func formalGLMPublicAdvanceValidPeerSHA256V1(value string) bool {
	return value == "" || formalGLMIsSHA256(value)
}

func formalGLMValidatePublicAdvancePrecedingV1(
	preceding formalGLMPublicReceiptFrameV1,
	receiptSHA256, signerPeer string,
	pins map[string]ed25519.PublicKey,
) error {
	encoded, err := json.Marshal(preceding)
	if err != nil || formalGLMPublicReceiptSHA256V1(encoded) != receiptSHA256 ||
		preceding.SignerPeerName != signerPeer {
		return fmt.Errorf("formal-glm public advance store: invalid preceding receipt")
	}
	if _, err := formalGLMValidatePublicEndpointReceiptV1(encoded, pins); err != nil {
		return fmt.Errorf("formal-glm public advance store: invalid preceding receipt")
	}
	switch preceding.State {
	case formalGLMPublicStateProvisionPrepare,
		formalGLMPublicStateProvisionApprove,
		formalGLMPublicResolveUnique,
		formalGLMPublicStateRelay:
		return nil
	default:
		return fmt.Errorf("formal-glm public advance store: invalid preceding state")
	}
}

func formalGLMValidatePublicAdvanceRequestV1(
	record formalGLMPublicAdvanceRequestV1,
	pins map[string]ed25519.PublicKey,
) error {
	signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(record.Signature)
	message, messageErr := formalGLMPublicAdvanceRequestMessageV1(record)
	pin := pins[record.SignerPeerName]
	if record.Version != formalGLMPublicAdvanceStoreVersion ||
		record.Purpose != formalGLMPublicAdvanceStorePurpose ||
		!formalGLMIsSHA256(record.ReceiptSHA256) ||
		!formalGLMPublicAdvanceValidPeerSHA256V1(record.PeerFrameSHA256) ||
		record.ProductionReady ||
		!formalGLMRegistryLabelV1(record.SignerPeerName, 128) ||
		record.SignerIdentityPK != formalGLMIdentityPKV1(pin) ||
		len(pin) != ed25519.PublicKeySize || signatureErr != nil ||
		len(signature) != ed25519.SignatureSize || messageErr != nil ||
		!ed25519.Verify(pin, message, signature) {
		return fmt.Errorf("formal-glm public advance store: invalid request")
	}
	return nil
}

func formalGLMValidatePublicAdvanceResponseV1(
	preceding formalGLMPublicReceiptFrameV1,
	receiptSHA256, peerFrameSHA256 string,
	response formalGLMPublicAdvanceResponseV1,
	pins map[string]ed25519.PublicKey,
) error {
	next, err := formalGLMValidatePublicEndpointReceiptV1(
		[]byte(response.ReceiptFrameJSON), pins)
	if err != nil || response.Version != formalGLMPublicAdvanceResponseVersion ||
		response.Replayed || next.SelectorSHA256 != preceding.SelectorSHA256 ||
		next.Step != preceding.Step+1 ||
		next.PreviousReceiptSHA256 != receiptSHA256 ||
		next.PeerFrameSHA256 != peerFrameSHA256 {
		return fmt.Errorf("formal-glm public advance store: invalid response")
	}
	switch response.State {
	case formalGLMPublicStateProvision:
		if (preceding.State != formalGLMPublicStateProvisionPrepare &&
			preceding.State != formalGLMPublicStateProvisionApprove) ||
			(next.State != formalGLMPublicStateProvisionApprove &&
				next.State != formalGLMPublicResolveUnique) ||
			response.Relay != nil || response.PeerFrameJSON != "" ||
			response.PeerFrameRecipient != "" || response.PublicV2JSON != "" ||
			response.CertificateSHA256 != "" {
			return fmt.Errorf("formal-glm public advance store: invalid provision response")
		}
	case formalGLMPublicStateRelay:
		if (preceding.State != formalGLMPublicResolveUnique &&
			preceding.State != formalGLMPublicStateRelay) ||
			next.State != formalGLMPublicStateRelay || response.Relay == nil ||
			response.PeerFrameRecipient != response.Relay.RecipientPeerName ||
			response.PublicV2JSON != "" || response.CertificateSHA256 != "" ||
			!formalGLMRegistryLabelV1(response.Relay.SenderPeerName, 128) ||
			!formalGLMRegistryLabelV1(response.Relay.RecipientPeerName, 128) ||
			response.Relay.SenderPeerName == response.Relay.RecipientPeerName ||
			(response.Relay.Channel != formalGLMPublicRelayControl &&
				response.Relay.Channel != formalGLMPublicRelayOpening) {
			return fmt.Errorf("formal-glm public advance store: invalid relay response")
		}
		if _, err := formalGLMPublicValidateOpaquePeerFrameV1(
			[]byte(response.PeerFrameJSON)); err != nil || response.PeerFrameJSON == "" {
			return fmt.Errorf("formal-glm public advance store: invalid relay frame")
		}
	case formalGLMPublicStateComplete:
		var publication formalGLMPhase21PublicCertificateV2
		if (preceding.State != formalGLMPublicResolveUnique &&
			preceding.State != formalGLMPublicStateRelay) ||
			next.State != formalGLMPublicStateComplete || response.Relay != nil ||
			response.PeerFrameJSON != "" || response.PeerFrameRecipient != "" ||
			response.PublicV2JSON == "" ||
			!formalGLMIsSHA256(response.CertificateSHA256) ||
			formalGLMPublicStrictCanonicalJSONV1(
				[]byte(response.PublicV2JSON), formalGLMPublicMaxPeerFrameJSON,
				&publication) != nil ||
			formalGLMPhase21ValidatePublicCertificateV2(publication, pins) != nil ||
			publication.ArtifactID != next.Resolution.ArtifactID {
			return fmt.Errorf("formal-glm public advance store: invalid completed response")
		}
		digest, digestErr := formalGLMPhase21RockPublicCertificateDigest(publication)
		if digestErr != nil || digest != response.CertificateSHA256 {
			return fmt.Errorf("formal-glm public advance store: invalid completed digest")
		}
	case formalGLMPublicStateFailed:
		if response.Relay != nil || response.PeerFrameJSON != "" ||
			response.PeerFrameRecipient != "" || response.PublicV2JSON != "" ||
			response.CertificateSHA256 != "" || next.State != formalGLMPublicStateFailed {
			return fmt.Errorf("formal-glm public advance store: invalid failed response")
		}
	default:
		return fmt.Errorf("formal-glm public advance store: unsupported response")
	}
	return nil
}

func formalGLMValidatePublicAdvanceResponseRecordV1(
	record formalGLMPublicAdvanceResponseRecordV1,
	preceding formalGLMPublicReceiptFrameV1,
	pins map[string]ed25519.PublicKey,
) error {
	signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(record.Signature)
	message, messageErr := formalGLMPublicAdvanceResponseRecordMessageV1(record)
	pin := pins[record.SignerPeerName]
	if record.Version != formalGLMPublicAdvanceStoreVersion ||
		record.Purpose != formalGLMPublicAdvanceStorePurpose ||
		!formalGLMIsSHA256(record.ReceiptSHA256) ||
		!formalGLMPublicAdvanceValidPeerSHA256V1(record.PeerFrameSHA256) ||
		record.ProductionReady ||
		!formalGLMRegistryLabelV1(record.SignerPeerName, 128) ||
		record.SignerIdentityPK != formalGLMIdentityPKV1(pin) ||
		len(pin) != ed25519.PublicKeySize || signatureErr != nil ||
		len(signature) != ed25519.SignatureSize || messageErr != nil ||
		!ed25519.Verify(pin, message, signature) ||
		formalGLMValidatePublicAdvanceResponseV1(
			preceding, record.ReceiptSHA256, record.PeerFrameSHA256,
			record.Response, pins) != nil {
		return fmt.Errorf("formal-glm public advance store: invalid response record")
	}
	return nil
}

func (store *formalGLMPublicAdvanceStoreV1) recordDirRelativePathV1(
	receiptSHA256 string, create bool,
) (string, error) {
	if store == nil || store.root == nil || !formalGLMIsSHA256(receiptSHA256) {
		return "", fmt.Errorf("formal-glm public advance store: invalid receipt")
	}
	dir := filepath.Join(formalGLMPublicAdvanceStoreDir,
		receiptSHA256[:2], receiptSHA256[2:4], "advance-"+receiptSHA256)
	if create {
		if err := formalGLMPhase21EnsureRootPrivateDir(store.root, dir); err != nil {
			return "", err
		}
	} else if err := formalGLMPhase21ValidateRootPrivateDir(store.root, dir, false); err != nil {
		return "", err
	}
	return dir, nil
}

func (store *formalGLMPublicAdvanceStoreV1) requestRelativePathV1(
	receiptSHA256 string, create bool,
) (string, error) {
	dir, err := store.recordDirRelativePathV1(receiptSHA256, create)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "request.json"), nil
}

func (store *formalGLMPublicAdvanceStoreV1) responseRelativePathV1(
	receiptSHA256 string, create bool,
) (string, error) {
	dir, err := store.recordDirRelativePathV1(receiptSHA256, create)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "response.json"), nil
}

func (store *formalGLMPublicAdvanceStoreV1) signRequestV1(
	receiptSHA256, peerFrameSHA256 string,
) (formalGLMPublicAdvanceRequestV1, []byte, error) {
	request := formalGLMPublicAdvanceRequestV1{
		Version:       formalGLMPublicAdvanceStoreVersion,
		Purpose:       formalGLMPublicAdvanceStorePurpose,
		ReceiptSHA256: receiptSHA256, PeerFrameSHA256: peerFrameSHA256,
		SignerPeerName:   store.signerPeer,
		SignerIdentityPK: formalGLMIdentityPKV1(store.pins[store.signerPeer]),
		ProductionReady:  false,
	}
	message, err := formalGLMPublicAdvanceRequestMessageV1(request)
	if err != nil {
		return formalGLMPublicAdvanceRequestV1{}, nil, err
	}
	request.Signature = formalGLMSignatureBase64URLV1(
		ed25519.Sign(store.signingKey, message))
	encoded, err := json.Marshal(request)
	if err != nil || formalGLMValidatePublicAdvanceRequestV1(request, store.pins) != nil {
		return formalGLMPublicAdvanceRequestV1{}, nil,
			fmt.Errorf("formal-glm public advance store: could not sign request")
	}
	return request, encoded, nil
}

func (store *formalGLMPublicAdvanceStoreV1) readRequestLockedV1(
	receiptSHA256 string,
) (formalGLMPublicAdvanceRequestV1, bool, error) {
	var zero formalGLMPublicAdvanceRequestV1
	path, err := store.requestRelativePathV1(receiptSHA256, false)
	if err != nil {
		if os.IsNotExist(err) {
			return zero, false, nil
		}
		return zero, false, err
	}
	encoded, err := formalGLMPhase21RootReadRecord(
		store.root, path, formalGLMPublicAdvanceStoreMax)
	if os.IsNotExist(err) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, err
	}
	defer clear(encoded)
	var request formalGLMPublicAdvanceRequestV1
	if formalGLMPhase21RockStrictDecode(encoded, &request) != nil ||
		request.ReceiptSHA256 != receiptSHA256 ||
		request.SignerPeerName != store.signerPeer ||
		formalGLMValidatePublicAdvanceRequestV1(request, store.pins) != nil {
		return zero, false, fmt.Errorf("formal-glm public advance store: invalid durable request")
	}
	return request, true, nil
}

func (store *formalGLMPublicAdvanceStoreV1) readResponseLockedV1(
	preceding formalGLMPublicReceiptFrameV1,
	receiptSHA256 string,
) (formalGLMPublicAdvanceResponseV1, bool, error) {
	var zero formalGLMPublicAdvanceResponseV1
	path, err := store.responseRelativePathV1(receiptSHA256, false)
	if err != nil {
		if os.IsNotExist(err) {
			return zero, false, nil
		}
		return zero, false, err
	}
	encoded, err := formalGLMPhase21RootReadRecord(
		store.root, path, formalGLMPublicAdvanceStoreMax)
	if os.IsNotExist(err) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, err
	}
	defer clear(encoded)
	var record formalGLMPublicAdvanceResponseRecordV1
	if formalGLMPhase21RockStrictDecode(encoded, &record) != nil ||
		record.ReceiptSHA256 != receiptSHA256 ||
		record.SignerPeerName != store.signerPeer ||
		formalGLMValidatePublicAdvanceResponseRecordV1(
			record, preceding, store.pins) != nil {
		return zero, false, fmt.Errorf("formal-glm public advance store: invalid durable response")
	}
	return record.Response, true, nil
}

func (store *formalGLMPublicAdvanceStoreV1) BeginV1(
	preceding formalGLMPublicReceiptFrameV1,
	receiptSHA256, peerFrameSHA256 string,
) (formalGLMPublicAdvanceResponseV1, bool, error) {
	var zero formalGLMPublicAdvanceResponseV1
	if store == nil || !formalGLMIsSHA256(receiptSHA256) ||
		!formalGLMPublicAdvanceValidPeerSHA256V1(peerFrameSHA256) {
		return zero, false, fmt.Errorf("formal-glm public advance store: invalid begin")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil || len(store.signingKey) != ed25519.PrivateKeySize {
		return zero, false, fmt.Errorf("formal-glm public advance store: closed")
	}
	if formalGLMValidatePublicAdvancePrecedingV1(
		preceding, receiptSHA256, store.signerPeer, store.pins) != nil {
		return zero, false, fmt.Errorf("formal-glm public advance store: invalid begin")
	}
	request, encoded, err := store.signRequestV1(receiptSHA256, peerFrameSHA256)
	if err != nil {
		return zero, false, err
	}
	defer clear(encoded)
	path, err := store.requestRelativePathV1(receiptSHA256, true)
	if err != nil {
		return zero, false, err
	}
	created, err := formalGLMPhase21RootCreateRecord(store.root, path, encoded)
	if err != nil {
		return zero, false, err
	}
	if !created {
		existing, found, readErr := store.readRequestLockedV1(receiptSHA256)
		if readErr != nil || !found ||
			existing.PeerFrameSHA256 != request.PeerFrameSHA256 {
			return zero, false, fmt.Errorf("formal-glm public advance store: receipt already consumed")
		}
	}
	return store.readResponseLockedV1(preceding, receiptSHA256)
}

func (store *formalGLMPublicAdvanceStoreV1) CommitV1(
	preceding formalGLMPublicReceiptFrameV1,
	receiptSHA256, peerFrameSHA256 string,
	response formalGLMPublicAdvanceResponseV1,
) (formalGLMPublicAdvanceResponseV1, bool, error) {
	var zero formalGLMPublicAdvanceResponseV1
	if store == nil {
		return zero, false, fmt.Errorf("formal-glm public advance store: invalid commit")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil || len(store.signingKey) != ed25519.PrivateKeySize {
		return zero, false, fmt.Errorf("formal-glm public advance store: closed")
	}
	if formalGLMValidatePublicAdvancePrecedingV1(
		preceding, receiptSHA256, store.signerPeer, store.pins) != nil {
		return zero, false, fmt.Errorf("formal-glm public advance store: invalid commit")
	}
	if formalGLMValidatePublicAdvanceResponseV1(
		preceding, receiptSHA256, peerFrameSHA256, response, store.pins) != nil {
		return zero, false, fmt.Errorf("formal-glm public advance store: invalid commit")
	}
	request, found, err := store.readRequestLockedV1(receiptSHA256)
	if err != nil || !found || request.PeerFrameSHA256 != peerFrameSHA256 {
		return zero, false, fmt.Errorf("formal-glm public advance store: missing durable request")
	}
	response.Replayed = false
	record := formalGLMPublicAdvanceResponseRecordV1{
		Version:       formalGLMPublicAdvanceStoreVersion,
		Purpose:       formalGLMPublicAdvanceStorePurpose,
		ReceiptSHA256: receiptSHA256, PeerFrameSHA256: peerFrameSHA256,
		Response: response, SignerPeerName: store.signerPeer,
		SignerIdentityPK: formalGLMIdentityPKV1(store.pins[store.signerPeer]),
		ProductionReady:  false,
	}
	message, err := formalGLMPublicAdvanceResponseRecordMessageV1(record)
	if err != nil {
		return zero, false, err
	}
	record.Signature = formalGLMSignatureBase64URLV1(
		ed25519.Sign(store.signingKey, message))
	encoded, err := json.Marshal(record)
	if err != nil || formalGLMValidatePublicAdvanceResponseRecordV1(
		record, preceding, store.pins) != nil {
		return zero, false, fmt.Errorf("formal-glm public advance store: could not sign response")
	}
	defer clear(encoded)
	path, err := store.responseRelativePathV1(receiptSHA256, true)
	if err != nil {
		return zero, false, err
	}
	created, err := formalGLMPhase21RootCreateRecord(store.root, path, encoded)
	if err != nil {
		return zero, false, err
	}
	if created {
		return response, false, nil
	}
	stored, found, err := store.readResponseLockedV1(preceding, receiptSHA256)
	if err != nil || !found || !reflect.DeepEqual(stored, response) {
		return zero, false, fmt.Errorf("formal-glm public advance store: response conflict")
	}
	stored.Replayed = true
	return stored, true, nil
}
