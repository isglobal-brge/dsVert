package main

// Rock-local continuation for the final formal-Cox control relay.  The
// short-lived caller can carry only a recipient's signed X25519 public key and
// opaque ciphertext.  The corresponding private key and all record selection
// stay in the authority's existing control store.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	formalCoxControlRecipientTransportVersion = "dsvert-formal-cox-control-recipient-transport-v1"
	formalCoxControlRecipientTransportDir     = "recipient-transport-v1"
	formalCoxControlRelayReceiptVersion       = "dsvert-formal-cox-control-relay-receipt-v1"
)

// formalCoxBlockwiseLiveControlRecipientV1 is the only key material which
// can leave Rock: the ephemeral X25519 public key and its identity signature.
// Its JSON never contains a private key, a path, a candidate, or a source
// record.
type formalCoxBlockwiseLiveControlRecipientV1 struct {
	TransportPublic    string `json:"transport_public"`
	TransportSignature string `json:"transport_signature"`
	ProductionReady    bool   `json:"production_ready"`
}

// formalCoxBlockwiseLiveControlRelaySourceV1 contains an authenticated opaque
// envelope.  Record kind, direction and durable source location are omitted.
type formalCoxBlockwiseLiveControlRelaySourceV1 struct {
	Available         bool   `json:"available"`
	EnvelopeBase64URL string `json:"envelope_base64url"`
	EnvelopeSHA256    string `json:"envelope_sha256"`
	ProductionReady   bool   `json:"production_ready"`
}

// formalCoxBlockwiseLiveControlRelayReceiptV1 is signed by the importing
// authority.  The sender accepts an acknowledgement only after checking that
// it covers its currently leased opaque envelope and the pinned peer identity.
type formalCoxBlockwiseLiveControlRelayReceiptV1 struct {
	Version           string `json:"version"`
	ArtifactID        string `json:"artifact_id"`
	ExecutionSHA256   string `json:"execution_sha256"`
	RecordType        string `json:"record_type"`
	SenderRole        string `json:"sender_role"`
	RecordSHA256      string `json:"record_sha256"`
	EnvelopeSHA256    string `json:"envelope_sha256"`
	RecipientPeerName string `json:"recipient_peer_name"`
	RecipientPeerID   string `json:"recipient_peer_id"`
	RecipientRole     string `json:"recipient_role"`
	Signature         string `json:"signature"`
	ProductionReady   bool   `json:"production_ready"`
}

type formalCoxControlRecipientTransportRecord struct {
	Version            string `json:"version"`
	ArtifactID         string `json:"artifact_id"`
	ExecutionSHA256    string `json:"execution_sha256"`
	PeerName           string `json:"peer_name"`
	PeerID             string `json:"peer_id"`
	Role               string `json:"role"`
	TransportPrivate   string `json:"transport_private"`
	TransportPublic    string `json:"transport_public"`
	TransportSignature string `json:"transport_signature"`
}

func (store *formalCoxBlockwiseControlStore) recipientTransportPathV1() (string, error) {
	if store == nil || store.guard == nil ||
		!formalCoxIsSHA256(store.context.ArtifactID) ||
		!formalCoxIsSHA256(store.context.ExecutionSHA256) ||
		store.local.PeerName == "" || store.local.PeerID == "" ||
		(store.local.Role != "garbler" && store.local.Role != "evaluator") {
		return "", fmt.Errorf("formal-cox control: invalid recipient transport context")
	}
	dir := filepath.Join(formalCoxControlStoreDir, formalCoxControlRecipientTransportDir)
	if err := formalGLMPhase21EnsureRootPrivateDir(store.guard.root, dir); err != nil {
		return "", err
	}
	return filepath.Join(dir, store.context.ArtifactID+"-"+
		store.context.ExecutionSHA256+"-"+store.local.Role+".json"), nil
}

func formalCoxControlRecipientTransportDecodeV1(encoded []byte,
	store *formalCoxBlockwiseControlStore, signing ed25519.PrivateKey,
) ([]byte, []byte, []byte, error) {
	if store == nil || len(signing) != ed25519.PrivateKeySize {
		return nil, nil, nil, fmt.Errorf("formal-cox control: invalid recipient transport")
	}
	var record formalCoxControlRecipientTransportRecord
	if formalCoxControlDecodeCanonical(encoded, &record) != nil ||
		record.Version != formalCoxControlRecipientTransportVersion ||
		record.ArtifactID != store.context.ArtifactID ||
		record.ExecutionSHA256 != store.context.ExecutionSHA256 ||
		record.PeerName != store.local.PeerName || record.PeerID != store.local.PeerID ||
		record.Role != store.local.Role ||
		!ed25519.PublicKey(signing.Public().(ed25519.PublicKey)).Equal(store.pins[store.local.PeerName]) {
		return nil, nil, nil, fmt.Errorf("formal-cox control: invalid recipient transport")
	}
	private, err := base64.StdEncoding.Strict().DecodeString(record.TransportPrivate)
	if err != nil || len(private) != 32 ||
		base64.StdEncoding.EncodeToString(private) != record.TransportPrivate {
		clear(private)
		return nil, nil, nil, fmt.Errorf("formal-cox control: invalid recipient transport")
	}
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		clear(private)
		return nil, nil, nil, fmt.Errorf("formal-cox control: invalid recipient transport")
	}
	public, err := base64.StdEncoding.Strict().DecodeString(record.TransportPublic)
	if err != nil || len(public) != 32 ||
		base64.StdEncoding.EncodeToString(public) != record.TransportPublic ||
		!bytes.Equal(public, key.PublicKey().Bytes()) {
		clear(private)
		clear(public)
		return nil, nil, nil, fmt.Errorf("formal-cox control: invalid recipient transport")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(record.TransportSignature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.StdEncoding.EncodeToString(signature) != record.TransportSignature ||
		!ed25519.Verify(store.pins[store.local.PeerName], public, signature) {
		clear(private)
		clear(public)
		clear(signature)
		return nil, nil, nil, fmt.Errorf("formal-cox control: invalid recipient transport")
	}
	return private, public, signature, nil
}

func (store *formalCoxBlockwiseControlStore) recipientTransportV1(
	signing ed25519.PrivateKey,
) ([]byte, []byte, []byte, error) {
	path, err := store.recipientTransportPathV1()
	if err != nil {
		return nil, nil, nil, err
	}
	encoded, readErr := formalGLMPhase21RootReadRecord(
		store.guard.root, path, 64<<10)
	if readErr == nil {
		defer clear(encoded)
		return formalCoxControlRecipientTransportDecodeV1(encoded, store, signing)
	}
	if !os.IsNotExist(readErr) {
		return nil, nil, nil, readErr
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	private := key.Bytes()
	public := key.PublicKey().Bytes()
	signature := ed25519.Sign(signing, public)
	record := formalCoxControlRecipientTransportRecord{
		Version:         formalCoxControlRecipientTransportVersion,
		ArtifactID:      store.context.ArtifactID,
		ExecutionSHA256: store.context.ExecutionSHA256,
		PeerName:        store.local.PeerName, PeerID: store.local.PeerID,
		Role:               store.local.Role,
		TransportPrivate:   base64.StdEncoding.EncodeToString(private),
		TransportPublic:    base64.StdEncoding.EncodeToString(public),
		TransportSignature: base64.StdEncoding.EncodeToString(signature),
	}
	encoded, err = json.Marshal(record)
	if err != nil {
		clear(private)
		clear(public)
		clear(signature)
		return nil, nil, nil, err
	}
	created, err := store.createRecord(path, encoded, 64<<10)
	clear(encoded)
	if err != nil {
		clear(private)
		clear(public)
		clear(signature)
		return nil, nil, nil, err
	}
	if created {
		return private, public, signature, nil
	}
	clear(private)
	clear(public)
	clear(signature)
	encoded, err = formalGLMPhase21RootReadRecord(store.guard.root, path, 64<<10)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(encoded)
	return formalCoxControlRecipientTransportDecodeV1(encoded, store, signing)
}

func (controller *formalCoxBlockwiseExchangeController) withFinalizerControlStoreV1(
	headers [2]formalCoxBlockwiseOpeningHandoffHeader, stateRoot string, production bool,
	continueV1 func(*formalCoxBlockwiseControlStore, ed25519.PrivateKey,
		formalFinalizerHandoffBinding) error,
) error {
	if continueV1 == nil {
		return fmt.Errorf("formal-cox live control: unavailable relay continuation")
	}
	return controller.finalizerBridgeAtRootV1(headers,
		func(bridge *formalCoxBlockwiseSourceBridge,
			opening *formalCoxBlockwiseOpeningStore) error {
			context, local, signing, err := formalCoxBlockwiseLiveControlContext(bridge)
			if err != nil {
				return err
			}
			defer clear(signing)
			defer formalCoxBlockwiseClearPinsV1(context.pins)
			store, err := newFormalCoxBlockwiseControlStore(
				filepath.Join(stateRoot, local.PeerName), context, local, production)
			if err != nil {
				return err
			}
			defer store.Close()
			binding, err := formalCoxBlockwiseOpeningFinalizerBinding(opening, headers)
			if err != nil || formalFinalizerHandoffValidateBinding(binding, context.pins) != nil {
				return fmt.Errorf("formal-cox live control: invalid relay binding")
			}
			return continueV1(store, signing, binding)
		})
}

func (controller *formalCoxBlockwiseExchangeController) FinalizerControlRecipientAtRootV1(
	headers [2]formalCoxBlockwiseOpeningHandoffHeader, stateRoot string, production bool,
) (formalCoxBlockwiseLiveControlRecipientV1, error) {
	var result formalCoxBlockwiseLiveControlRecipientV1
	err := controller.withFinalizerControlStoreV1(headers, stateRoot, production,
		func(store *formalCoxBlockwiseControlStore, signing ed25519.PrivateKey,
			_ formalFinalizerHandoffBinding) error {
			_, public, signature, err := store.recipientTransportV1(signing)
			if err != nil {
				return err
			}
			defer clear(public)
			defer clear(signature)
			result = formalCoxBlockwiseLiveControlRecipientV1{
				TransportPublic:    base64.StdEncoding.EncodeToString(public),
				TransportSignature: base64.StdEncoding.EncodeToString(signature),
				ProductionReady:    false,
			}
			return nil
		})
	return result, err
}

func (controller *formalCoxBlockwiseExchangeController) FinalizerControlSourceAtRootV1(
	headers [2]formalCoxBlockwiseOpeningHandoffHeader,
	recipientPublic, recipientSignature []byte, stateRoot string, production bool,
) (formalCoxBlockwiseLiveControlRelaySourceV1, error) {
	result := formalCoxBlockwiseLiveControlRelaySourceV1{ProductionReady: false}
	err := controller.withFinalizerControlStoreV1(headers, stateRoot, production,
		func(store *formalCoxBlockwiseControlStore, _ ed25519.PrivateKey,
			_ formalFinalizerHandoffBinding) error {
			descriptor, err := store.DescribeNextSource(
				recipientPublic, recipientSignature, time.Now())
			if err == errFormalCoxControlNoSource {
				return nil
			}
			if err != nil {
				return err
			}
			relative, err := formalGLMPhase21RockRelative(store.guard.dir, descriptor.SourcePath)
			if err != nil {
				return fmt.Errorf("formal-cox live control: invalid opaque relay location")
			}
			envelope, err := formalGLMPhase21RootReadRecord(
				store.guard.root, relative, formalCoxControlMaxEnvelopeJSON)
			if err != nil || formalCoxControlRawSHA256(envelope) != descriptor.EnvelopeSHA256 {
				clear(envelope)
				return fmt.Errorf("formal-cox live control: invalid opaque relay envelope")
			}
			defer clear(envelope)
			result = formalCoxBlockwiseLiveControlRelaySourceV1{
				Available: true, EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
				EnvelopeSHA256: descriptor.EnvelopeSHA256, ProductionReady: false,
			}
			return nil
		})
	return result, err
}

func (controller *formalCoxBlockwiseExchangeController) FinalizerControlImportAtRootV1(
	headers [2]formalCoxBlockwiseOpeningHandoffHeader, encoded []byte,
	stateRoot string, production bool,
) (formalCoxBlockwiseLiveControlRelayReceiptV1, error) {
	var result formalCoxBlockwiseLiveControlRelayReceiptV1
	err := controller.withFinalizerControlStoreV1(headers, stateRoot, production,
		func(store *formalCoxBlockwiseControlStore, signing ed25519.PrivateKey,
			_ formalFinalizerHandoffBinding) error {
			secret, _, _, err := store.recipientTransportV1(signing)
			if err != nil {
				return err
			}
			defer clear(secret)
			ingress, err := store.ImportCanonical(encoded, secret, time.Now())
			if err != nil {
				return err
			}
			result = formalCoxBlockwiseLiveControlRelayReceiptV1{
				Version:    formalCoxControlRelayReceiptVersion,
				ArtifactID: store.context.ArtifactID, ExecutionSHA256: store.context.ExecutionSHA256,
				RecordType: ingress.RecordType, SenderRole: ingress.SenderRole,
				RecordSHA256:      ingress.RecordSHA256,
				EnvelopeSHA256:    formalCoxControlRawSHA256(encoded),
				RecipientPeerName: store.local.PeerName, RecipientPeerID: store.local.PeerID,
				RecipientRole: store.local.Role, ProductionReady: false,
			}
			message, err := formalCoxControlRelayReceiptMessageV1(result)
			if err != nil {
				return err
			}
			defer clear(message)
			result.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(signing, message))
			return nil
		})
	return result, err
}

func (controller *formalCoxBlockwiseExchangeController) FinalizerControlDeliveredAtRootV1(
	headers [2]formalCoxBlockwiseOpeningHandoffHeader,
	receipt formalCoxBlockwiseLiveControlRelayReceiptV1,
	stateRoot string, production bool,
) (formalCoxBlockwiseControlDeliveryReceipt, error) {
	var result formalCoxBlockwiseControlDeliveryReceipt
	err := controller.withFinalizerControlStoreV1(headers, stateRoot, production,
		func(store *formalCoxBlockwiseControlStore, _ ed25519.PrivateKey,
			binding formalFinalizerHandoffBinding) error {
			receiptSHA, err := formalCoxControlValidateRelayReceiptV1(store, binding, receipt)
			if err != nil {
				return err
			}
			defer clear(receiptSHA)
			result, err = store.MarkNextDelivered(
				receipt.EnvelopeSHA256,
				formalCoxControlRawSHA256(receiptSHA), time.Now())
			return err
		})
	return result, err
}

func formalCoxControlRelayReceiptMessageV1(
	receipt formalCoxBlockwiseLiveControlRelayReceiptV1,
) ([]byte, error) {
	receipt.Signature = ""
	if receipt.Version != formalCoxControlRelayReceiptVersion ||
		receipt.ProductionReady || !formalCoxIsSHA256(receipt.ArtifactID) ||
		!formalCoxIsSHA256(receipt.ExecutionSHA256) || !formalCoxIsSHA256(receipt.RecordSHA256) ||
		!formalCoxIsSHA256(receipt.EnvelopeSHA256) || receipt.RecordType == "" ||
		(receipt.SenderRole != "garbler" && receipt.SenderRole != "evaluator") ||
		(receipt.RecipientRole != "garbler" && receipt.RecipientRole != "evaluator") ||
		receipt.RecipientPeerName == "" || receipt.RecipientPeerID == "" {
		return nil, fmt.Errorf("formal-cox live control: invalid relay receipt")
	}
	return json.Marshal(receipt)
}

func formalCoxControlValidateRelayReceiptV1(
	store *formalCoxBlockwiseControlStore, binding formalFinalizerHandoffBinding,
	receipt formalCoxBlockwiseLiveControlRelayReceiptV1,
) ([]byte, error) {
	if store == nil || store.guard == nil || receipt.ArtifactID != store.context.ArtifactID ||
		receipt.ExecutionSHA256 != store.context.ExecutionSHA256 ||
		receipt.SenderRole != store.local.Role || receipt.Signature == "" {
		return nil, fmt.Errorf("formal-cox live control: invalid relay receipt")
	}
	recipientRole, err := formalCoxControlDirection(receipt.RecordType, store.local.Role)
	if err != nil || receipt.RecipientRole != recipientRole {
		return nil, fmt.Errorf("formal-cox live control: invalid relay receipt")
	}
	recipient, err := formalFinalizerHandoffPeer(binding, recipientRole)
	if err != nil || receipt.RecipientPeerName != recipient.PeerName ||
		receipt.RecipientPeerID != recipient.PeerID {
		return nil, fmt.Errorf("formal-cox live control: invalid relay receipt")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(receipt.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.StdEncoding.EncodeToString(signature) != receipt.Signature {
		clear(signature)
		return nil, fmt.Errorf("formal-cox live control: invalid relay receipt")
	}
	defer clear(signature)
	message, err := formalCoxControlRelayReceiptMessageV1(receipt)
	if err != nil || !ed25519.Verify(store.pins[recipient.PeerName], message, signature) {
		clear(message)
		return nil, fmt.Errorf("formal-cox live control: invalid relay receipt")
	}
	delivery, delivered, err := store.readDelivery(receipt.RecordType)
	if err != nil {
		clear(message)
		return nil, err
	}
	if delivered {
		if delivery.RecordSHA256 != receipt.RecordSHA256 ||
			delivery.EnvelopeSHA256 != receipt.EnvelopeSHA256 ||
			delivery.ReceiptSHA256 != formalCoxControlRawSHA256(message) {
			clear(message)
			return nil, fmt.Errorf("formal-cox live control: conflicting relay receipt replay")
		}
		return message, nil
	}
	source, err := store.nextSourceRecord()
	if err != nil {
		clear(message)
		return nil, err
	}
	defer clear(source.record)
	if source.recordType != receipt.RecordType ||
		formalCoxControlSHA(formalCoxControlRecordDomain, source.record) != receipt.RecordSHA256 {
		clear(message)
		return nil, fmt.Errorf("formal-cox live control: stale relay receipt")
	}
	return message, nil
}
