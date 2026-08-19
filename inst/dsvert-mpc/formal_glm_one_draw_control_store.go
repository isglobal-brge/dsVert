package main

// Rock-owned durable source and ingress state for the closed formal GLM
// lifecycle control relay. The caller supplies no record kind or path: both
// are derived from the local authority role and exact lifecycle records.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	formalGLMControlStoreVersion      = "dsvert-formal-glm-one-draw-control-store-v1"
	formalGLMControlLeaseVersion      = "dsvert-formal-glm-one-draw-control-lease-v1"
	formalGLMControlDeliveryVersion   = "dsvert-formal-glm-one-draw-control-delivery-v1"
	formalGLMControlDescriptorVersion = "dsvert-formal-glm-one-draw-control-source-v1"
	formalGLMControlContextVersion    = "dsvert-formal-glm-one-draw-control-context-v1"
	formalGLMControlIngressVersion    = "dsvert-formal-glm-one-draw-control-ingress-v1"
	formalGLMControlStoreDir          = "formal-glm-control-relay-v1"

	formalGLMControlMaxEnvelopeJSON = ((formalGLMControlMaxEnvelope+2)/3)*4 + 32<<10
)

var (
	formalGLMControlOutboxTTL      = 24 * time.Hour
	errFormalGLMControlNoSource    = errors.New("formal-glm control: no source record ready")
	errFormalGLMControlOutboxLease = errors.New("formal-glm control: another recipient lease is active")
)

type formalGLMOneDrawControlBridgeContext struct {
	Version        string                     `json:"version"`
	Protocol       string                     `json:"protocol"`
	AAD            formalGLMOneDrawControlAAD `json:"aad"`
	RecordSHA256   string                     `json:"record_sha256"`
	EnvelopeSHA256 string                     `json:"envelope_sha256"`
	EnvelopeBytes  int64                      `json:"envelope_bytes"`
}

type formalGLMOneDrawControlSourceDescriptor struct {
	Version        string                               `json:"version"`
	SourcePath     string                               `json:"source_path"`
	EnvelopeBytes  int64                                `json:"envelope_bytes"`
	PayloadChars   int64                                `json:"payload_chars"`
	EnvelopeSHA256 string                               `json:"envelope_sha256"`
	Context        formalGLMOneDrawControlBridgeContext `json:"context"`
}

type formalGLMOneDrawControlLease struct {
	Version                     string `json:"version"`
	Protocol                    string `json:"protocol"`
	ArtifactID                  string `json:"artifact_id"`
	RecordType                  string `json:"record_type"`
	SenderRole                  string `json:"sender_role"`
	RecipientRole               string `json:"recipient_role"`
	RecordSHA256                string `json:"record_sha256"`
	EnvelopeSHA256              string `json:"envelope_sha256"`
	EnvelopeBytes               int64  `json:"envelope_bytes"`
	RecipientTransportKeySHA256 string `json:"recipient_transport_key_sha256"`
	CreatedUnix                 int64  `json:"created_unix"`
	ExpiresUnix                 int64  `json:"expires_unix"`
}

type formalGLMOneDrawControlDelivery struct {
	Version        string `json:"version"`
	Protocol       string `json:"protocol"`
	ArtifactID     string `json:"artifact_id"`
	RecordType     string `json:"record_type"`
	SenderRole     string `json:"sender_role"`
	RecipientRole  string `json:"recipient_role"`
	RecordSHA256   string `json:"record_sha256"`
	EnvelopeSHA256 string `json:"envelope_sha256"`
	ReceiptSHA256  string `json:"receipt_sha256"`
	DeliveredUnix  int64  `json:"delivered_unix"`
}

type formalGLMOneDrawControlDeliveryReceipt struct {
	Version        string `json:"version"`
	State          string `json:"state"`
	ArtifactID     string `json:"artifact_id"`
	RecordType     string `json:"record_type"`
	EnvelopeSHA256 string `json:"envelope_sha256"`
	Replayed       bool   `json:"replayed"`
}

type formalGLMOneDrawControlIngressReceipt struct {
	Version      string `json:"version"`
	State        string `json:"state"`
	ArtifactID   string `json:"artifact_id"`
	RecordType   string `json:"record_type"`
	SenderRole   string `json:"sender_role"`
	RecordSHA256 string `json:"record_sha256"`
	Replayed     bool   `json:"replayed"`
}

type formalGLMOneDrawControlStore struct {
	guard   *formalFinalizerHandoffAuthorityGuard
	binding formalFinalizerHandoffBinding
	local   formalFinalizerHandoffAuthority
	pins    map[string]ed25519.PublicKey
}

func formalGLMControlRawSHA256(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func formalGLMControlMarshalEnvelope(
	envelope formalGLMOneDrawControlEnvelope,
) ([]byte, error) {
	if envelope.ProductionReady ||
		envelope.Version != formalGLMControlEnvelopeVersion ||
		envelope.Protocol != formalGLMOneDrawControlProtocol ||
		len(envelope.Ciphertext) < 60 ||
		len(envelope.Ciphertext) > formalGLMControlMaxEnvelope {
		return nil, fmt.Errorf("formal-glm control: invalid canonical envelope")
	}
	encoded, err := json.Marshal(envelope)
	if err != nil || len(encoded) < 64 || len(encoded) > formalGLMControlMaxEnvelopeJSON {
		clear(encoded)
		return nil, fmt.Errorf("formal-glm control: invalid canonical envelope")
	}
	return encoded, nil
}

func formalGLMControlDecodeEnvelope(encoded []byte) (
	formalGLMOneDrawControlEnvelope, error,
) {
	var envelope formalGLMOneDrawControlEnvelope
	if len(encoded) < 64 || len(encoded) > formalGLMControlMaxEnvelopeJSON ||
		encoded[0] != '{' {
		return envelope, fmt.Errorf("formal-glm control: invalid envelope size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		clear(envelope.Ciphertext)
		return formalGLMOneDrawControlEnvelope{},
			fmt.Errorf("formal-glm control: invalid typed envelope")
	}
	var trailing any
	canonical, err := json.Marshal(envelope)
	if decoder.Decode(&trailing) != io.EOF || err != nil ||
		!bytes.Equal(canonical, encoded) {
		clear(canonical)
		clear(envelope.Ciphertext)
		return formalGLMOneDrawControlEnvelope{},
			fmt.Errorf("formal-glm control: non-canonical typed envelope")
	}
	clear(canonical)
	return envelope, nil
}

func newFormalGLMOneDrawControlStore(root string,
	binding formalFinalizerHandoffBinding,
	local formalFinalizerHandoffAuthority,
	pins map[string]ed25519.PublicKey, production bool,
) (*formalGLMOneDrawControlStore, error) {
	if binding.Family != formalFinalizerHandoffFamilyGLM ||
		binding.Purpose != formalFinalizerHandoffGLMPurpose ||
		formalFinalizerHandoffValidateBinding(binding, pins) != nil ||
		!formalFinalizerHandoffBindingHasAuthority(binding, local) {
		return nil, fmt.Errorf("formal-glm control: invalid Rock store binding")
	}
	guard, err := newFormalFinalizerHandoffAuthorityGuard(
		root, binding.ArtifactID, local, production)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{
		filepath.Join(formalGLMControlStoreDir, "outbox-v1"),
		filepath.Join(formalGLMControlStoreDir, "lease-v1"),
		filepath.Join(formalGLMControlStoreDir, "delivery-v1"),
	} {
		if err := formalGLMPhase21EnsureRootPrivateDir(
			guard.root, name); err != nil {
			guard.Close()
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
	return &formalGLMOneDrawControlStore{
		guard: guard, binding: copyBinding, local: local, pins: copyPins,
	}, nil
}

func (store *formalGLMOneDrawControlStore) Close() {
	if store != nil && store.guard != nil {
		store.guard.Close()
		store.guard = nil
	}
}

func formalGLMControlOutboundSequence(role string) []string {
	if role == "garbler" {
		return []string{
			formalGLMControlRecordStage, formalGLMControlRecordTicket,
			formalGLMControlRecordCandidate,
			formalGLMControlRecordBaseCertificate,
			formalGLMControlRecordAuthorization, formalGLMControlRecordAck,
		}
	}
	if role == "evaluator" {
		return []string{
			formalGLMControlRecordStage, formalGLMControlRecordSealReceipt,
			formalGLMControlRecordLocalRelease,
			formalGLMControlRecordAuthorization,
		}
	}
	return nil
}

func formalGLMControlInboundSequence(role string) []string {
	if role == "garbler" {
		return []string{
			formalGLMControlRecordStage, formalGLMControlRecordSealReceipt,
			formalGLMControlRecordLocalRelease,
			formalGLMControlRecordAuthorization,
		}
	}
	if role == "evaluator" {
		return []string{
			formalGLMControlRecordStage, formalGLMControlRecordTicket,
			formalGLMControlRecordCandidate,
			formalGLMControlRecordBaseCertificate,
			formalGLMControlRecordAuthorization, formalGLMControlRecordAck,
		}
	}
	return nil
}

func (store *formalGLMOneDrawControlStore) lifecyclePath(
	recordType, senderRole string,
) (string, error) {
	root, artifactID := store.guard.dir, store.binding.ArtifactID
	switch recordType {
	case formalGLMControlRecordStage:
		return formalGLMPhase21RockStageRecordPath(root, artifactID, senderRole)
	case formalGLMControlRecordTicket:
		return formalGLMPhase21RockTicketRecordPath(root, artifactID)
	case formalGLMControlRecordSealReceipt:
		return formalGLMPhase21RockSealRecordPath(root, artifactID, senderRole)
	case formalGLMControlRecordCandidate:
		return formalGLMPhase21RockCandidateRecordPath(root, artifactID)
	case formalGLMControlRecordLocalRelease:
		return formalGLMPhase21RockLocalReleaseRecordPath(
			root, artifactID, senderRole)
	case formalGLMControlRecordBaseCertificate:
		return formalGLMPhase21RockBaseCertificateRecordPath(root, artifactID)
	case formalGLMControlRecordAuthorization:
		return formalGLMPhase21RockAuthorizationRecordPath(
			root, artifactID, senderRole)
	case formalGLMControlRecordAck:
		return formalGLMPhase21RockAckRecordPath(root, artifactID)
	default:
		return "", fmt.Errorf("formal-glm control: invalid lifecycle record type")
	}
}

func (store *formalGLMOneDrawControlStore) readLifecycleRaw(
	recordType, senderRole string,
) ([]byte, error) {
	path, err := store.lifecyclePath(recordType, senderRole)
	if err != nil {
		return nil, err
	}
	relative, err := formalGLMPhase21RockRelative(store.guard.dir, path)
	if err != nil {
		return nil, err
	}
	return formalGLMPhase21RootReadRecord(
		store.guard.root, relative, formalGLMControlMaxRecord)
}

func (store *formalGLMOneDrawControlStore) loadTicket() (
	formalFinalizerHandoffTicket, error,
) {
	var zero formalFinalizerHandoffTicket
	encoded, err := store.readLifecycleRaw(
		formalGLMControlRecordTicket, "garbler")
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	var record formalGLMPhase21RockTicketRecord
	if formalGLMControlDecodeCanonical(encoded, &record) != nil ||
		formalFinalizerHandoffValidateTicket(
			record.Ticket, store.binding, store.pins) != nil {
		return zero, fmt.Errorf("formal-glm control: invalid durable ticket record")
	}
	return record.Ticket, nil
}

func formalGLMControlTicketFromRecord(encoded []byte) (
	formalFinalizerHandoffTicket, error,
) {
	var zero formalFinalizerHandoffTicket
	var record formalGLMPhase21RockTicketRecord
	if formalGLMControlDecodeCanonical(encoded, &record) != nil {
		return zero, fmt.Errorf("formal-glm control: invalid ticket source")
	}
	return record.Ticket, nil
}

func (store *formalGLMOneDrawControlStore) validateLifecycleRaw(
	recordType, senderRole string, encoded []byte,
) (formalFinalizerHandoffTicket, error) {
	var ticket formalFinalizerHandoffTicket
	var err error
	if recordType == formalGLMControlRecordTicket {
		ticket, err = formalGLMControlTicketFromRecord(encoded)
	} else if recordType != formalGLMControlRecordStage {
		ticket, err = store.loadTicket()
	}
	if err != nil {
		return formalFinalizerHandoffTicket{}, err
	}
	if _, err := formalGLMControlValidateRecord(
		recordType, senderRole, encoded, store.binding, ticket,
		store.pins); err != nil {
		return formalFinalizerHandoffTicket{}, err
	}
	return ticket, nil
}

func (store *formalGLMOneDrawControlStore) relayShard(
	kind string, create bool,
) (string, error) {
	if store == nil || store.guard == nil || store.guard.root == nil ||
		(kind != "outbox-v1" && kind != "lease-v1" &&
			kind != "delivery-v1") {
		return "", fmt.Errorf("formal-glm control: closed Rock store")
	}
	artifact := store.binding.ArtifactID
	relative := filepath.Join(formalGLMControlStoreDir, kind,
		artifact[:2], artifact[2:4])
	if create {
		if err := formalGLMPhase21EnsureRootPrivateDir(
			store.guard.root, relative); err != nil {
			return "", err
		}
	} else if err := formalGLMPhase21ValidateRootPrivateDir(
		store.guard.root, relative, false); err != nil {
		return "", err
	}
	return relative, nil
}

func (store *formalGLMOneDrawControlStore) outboxStem(
	recordType, recipientKeySHA string,
) (string, error) {
	if _, err := formalGLMControlDirection(recordType, store.local.Role); err != nil || !formalGLMIsSHA256(recipientKeySHA) {
		return "", fmt.Errorf("formal-glm control: invalid outbox slot")
	}
	return recordType + "-" + store.binding.ArtifactID + "-" +
		recipientKeySHA, nil
}

func (store *formalGLMOneDrawControlStore) outboxPaths(
	recordType, recipientKeySHA string, create bool,
) (string, string, error) {
	stem, err := store.outboxStem(recordType, recipientKeySHA)
	if err != nil {
		return "", "", err
	}
	outboxDir, err := store.relayShard("outbox-v1", create)
	if err != nil {
		return "", "", err
	}
	leaseDir, err := store.relayShard("lease-v1", create)
	if err != nil {
		return "", "", err
	}
	return filepath.Join(outboxDir, stem+".json"),
		filepath.Join(leaseDir, stem+".json"), nil
}

func (store *formalGLMOneDrawControlStore) deliveryPath(
	recordType string, create bool,
) (string, error) {
	if _, err := formalGLMControlDirection(recordType, store.local.Role); err != nil {
		return "", fmt.Errorf("formal-glm control: invalid delivery slot")
	}
	dir, err := store.relayShard("delivery-v1", create)
	if err != nil {
		return "", err
	}
	name := recordType + "-" + store.local.Role + "-" +
		store.binding.ArtifactID + ".json"
	return filepath.Join(dir, name), nil
}

func (store *formalGLMOneDrawControlStore) createRecord(
	relative string, encoded []byte, maximum int,
) (bool, error) {
	if len(encoded) < 64 || len(encoded) > maximum {
		return false, fmt.Errorf("formal-glm control: invalid durable record")
	}
	if err := formalGLMPhase21RockEnsureParent(
		store.guard.root, relative); err != nil {
		return false, err
	}
	created, err := formalGLMPhase21RootCreateRecord(
		store.guard.root, relative, encoded)
	if err != nil {
		return false, err
	}
	existing, err := formalGLMPhase21RootReadRecord(
		store.guard.root, relative, int64(maximum))
	if err != nil || !bytes.Equal(existing, encoded) {
		clear(existing)
		return false, fmt.Errorf("formal-glm control: conflicting durable record")
	}
	clear(existing)
	return created, nil
}

func (store *formalGLMOneDrawControlStore) removeRecord(
	relative string, maximum int64,
) error {
	info, err := store.guard.root.Lstat(relative)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
		!exactGCPrivateOwnedRegular(info) || info.Size() < 64 ||
		info.Size() > maximum {
		return fmt.Errorf("formal-glm control: unsafe durable cleanup")
	}
	if err := store.guard.root.Remove(relative); err != nil {
		return fmt.Errorf("formal-glm control: durable cleanup failed")
	}
	return formalGLMPhase21RootSyncDir(store.guard.root, relative)
}

func (store *formalGLMOneDrawControlStore) readDelivery(
	recordType string,
) (formalGLMOneDrawControlDelivery, bool, error) {
	var zero formalGLMOneDrawControlDelivery
	relative, err := store.deliveryPath(recordType, true)
	if err != nil {
		return zero, false, err
	}
	encoded, err := formalGLMPhase21RootReadRecord(
		store.guard.root, relative, 64<<10)
	if os.IsNotExist(err) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, err
	}
	defer clear(encoded)
	var delivery formalGLMOneDrawControlDelivery
	recipientRole, directionErr := formalGLMControlDirection(
		recordType, store.local.Role)
	if formalFinalizerHandoffDecodeCanonical(
		encoded, 64<<10, &delivery) != nil || directionErr != nil ||
		delivery.Version != formalGLMControlDeliveryVersion ||
		delivery.Protocol != formalGLMOneDrawControlProtocol ||
		delivery.ArtifactID != store.binding.ArtifactID ||
		delivery.RecordType != recordType ||
		delivery.SenderRole != store.local.Role ||
		delivery.RecipientRole != recipientRole ||
		!formalGLMIsSHA256(delivery.RecordSHA256) ||
		!formalGLMIsSHA256(delivery.EnvelopeSHA256) ||
		!formalGLMIsSHA256(delivery.ReceiptSHA256) ||
		delivery.DeliveredUnix < 1 {
		return zero, false, fmt.Errorf("formal-glm control: invalid delivery marker")
	}
	return delivery, true, nil
}

func formalGLMControlKnownRecordType(value string) bool {
	switch value {
	case formalGLMControlRecordStage, formalGLMControlRecordTicket,
		formalGLMControlRecordSealReceipt, formalGLMControlRecordCandidate,
		formalGLMControlRecordLocalRelease,
		formalGLMControlRecordBaseCertificate,
		formalGLMControlRecordAuthorization, formalGLMControlRecordAck:
		return true
	}
	return false
}

type formalGLMControlOutboxEntry struct {
	lease        formalGLMOneDrawControlLease
	leasePath    string
	envelopePath string
	envelope     []byte
}

func (store *formalGLMOneDrawControlStore) decodeLeaseName(name string) (
	string, string, error,
) {
	artifact := store.binding.ArtifactID
	if filepath.Base(name) != name || filepath.Ext(name) != ".json" {
		return "", "", fmt.Errorf("formal-glm control: invalid lease inventory")
	}
	stem := name[:len(name)-len(".json")]
	for _, recordType := range []string{
		formalGLMControlRecordStage, formalGLMControlRecordTicket,
		formalGLMControlRecordSealReceipt, formalGLMControlRecordCandidate,
		formalGLMControlRecordLocalRelease,
		formalGLMControlRecordBaseCertificate,
		formalGLMControlRecordAuthorization, formalGLMControlRecordAck,
	} {
		prefix := recordType + "-" + artifact + "-"
		if len(stem) == len(prefix)+64 && stem[:len(prefix)] == prefix {
			keySHA := stem[len(prefix):]
			if formalGLMIsSHA256(keySHA) {
				return recordType, keySHA, nil
			}
		}
	}
	return "", "", fmt.Errorf("formal-glm control: invalid lease inventory")
}

func (store *formalGLMOneDrawControlStore) validateLease(
	lease formalGLMOneDrawControlLease, recordType, keySHA string,
) error {
	recipientRole, err := formalGLMControlDirection(recordType, store.local.Role)
	if err != nil || lease.Version != formalGLMControlLeaseVersion ||
		lease.Protocol != formalGLMOneDrawControlProtocol ||
		lease.ArtifactID != store.binding.ArtifactID ||
		lease.RecordType != recordType || lease.SenderRole != store.local.Role ||
		lease.RecipientRole != recipientRole ||
		lease.RecipientTransportKeySHA256 != keySHA ||
		!formalGLMIsSHA256(lease.RecordSHA256) ||
		!formalGLMIsSHA256(lease.EnvelopeSHA256) ||
		lease.EnvelopeBytes < 64 ||
		lease.EnvelopeBytes > formalGLMControlMaxEnvelopeJSON ||
		lease.CreatedUnix < 1 || lease.ExpiresUnix-lease.CreatedUnix !=
		int64(formalGLMControlOutboxTTL/time.Second) {
		return fmt.Errorf("formal-glm control: invalid outbox lease")
	}
	return nil
}

func (store *formalGLMOneDrawControlStore) readDirectory(
	relative string,
) ([]os.DirEntry, error) {
	dir, err := store.guard.root.Open(relative)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("formal-glm control: invalid relay inventory")
		}
	}
	return entries, nil
}

func (store *formalGLMOneDrawControlStore) outboxInventory(
	now time.Time, sweepExpired bool,
) ([]formalGLMControlOutboxEntry, error) {
	if now.Unix() < 1 {
		return nil, fmt.Errorf("formal-glm control: invalid relay clock")
	}
	leaseDir, err := store.relayShard("lease-v1", true)
	if err != nil {
		return nil, err
	}
	outboxDir, err := store.relayShard("outbox-v1", true)
	if err != nil {
		return nil, err
	}
	leaseEntries, err := store.readDirectory(leaseDir)
	if err != nil {
		return nil, err
	}
	active := make([]formalGLMControlOutboxEntry, 0, len(leaseEntries))
	paired := make(map[string]bool, len(leaseEntries))
	for _, inventory := range leaseEntries {
		recordType, keySHA, err := store.decodeLeaseName(inventory.Name())
		if err != nil {
			return nil, err
		}
		leasePath := filepath.Join(leaseDir, inventory.Name())
		envelopePath := filepath.Join(outboxDir, inventory.Name())
		leaseJSON, err := formalGLMPhase21RootReadRecord(
			store.guard.root, leasePath, 64<<10)
		if err != nil {
			return nil, err
		}
		var lease formalGLMOneDrawControlLease
		decodeErr := formalFinalizerHandoffDecodeCanonical(
			leaseJSON, 64<<10, &lease)
		clear(leaseJSON)
		if decodeErr != nil || store.validateLease(
			lease, recordType, keySHA) != nil {
			return nil, fmt.Errorf("formal-glm control: invalid durable lease")
		}
		delivery, delivered, err := store.readDelivery(recordType)
		if err != nil {
			return nil, err
		}
		if delivered && delivery.RecordSHA256 != lease.RecordSHA256 {
			return nil, fmt.Errorf("formal-glm control: delivery changed source record")
		}
		if delivered || sweepExpired && now.Unix() > lease.ExpiresUnix {
			if err := store.removeRecord(
				envelopePath, formalGLMControlMaxEnvelopeJSON); err != nil {
				return nil, err
			}
			if err := store.removeRecord(leasePath, 64<<10); err != nil {
				return nil, err
			}
			continue
		}
		envelopeJSON, err := formalGLMPhase21RootReadRecord(
			store.guard.root, envelopePath, formalGLMControlMaxEnvelopeJSON)
		if err != nil || int64(len(envelopeJSON)) != lease.EnvelopeBytes ||
			formalGLMControlRawSHA256(envelopeJSON) != lease.EnvelopeSHA256 {
			clear(envelopeJSON)
			return nil, fmt.Errorf("formal-glm control: invalid durable outbox")
		}
		envelope, decodeErr := formalGLMControlDecodeEnvelope(envelopeJSON)
		if decodeErr != nil || envelope.AAD.RecordType != recordType ||
			envelope.AAD.SenderRole != store.local.Role ||
			envelope.RecordSHA256 != lease.RecordSHA256 ||
			envelope.RecipientTransportKeySHA256 != keySHA ||
			formalGLMControlValidateAAD(store.binding, envelope.AAD) != nil {
			clear(envelope.Ciphertext)
			clear(envelopeJSON)
			return nil, fmt.Errorf("formal-glm control: outbox binding changed")
		}
		clear(envelope.Ciphertext)
		paired[inventory.Name()] = true
		active = append(active, formalGLMControlOutboxEntry{
			lease: lease, leasePath: leasePath,
			envelopePath: envelopePath, envelope: envelopeJSON,
		})
	}
	outboxEntries, err := store.readDirectory(outboxDir)
	if err != nil {
		return nil, err
	}
	for _, inventory := range outboxEntries {
		if _, _, err := store.decodeLeaseName(inventory.Name()); err != nil {
			return nil, err
		}
		if paired[inventory.Name()] {
			continue
		}
		if err := store.removeRecord(
			filepath.Join(outboxDir, inventory.Name()),
			formalGLMControlMaxEnvelopeJSON); err != nil {
			return nil, err
		}
	}
	return active, nil
}

func formalGLMControlClearOutboxEntries(
	entries []formalGLMControlOutboxEntry,
) {
	for index := range entries {
		clear(entries[index].envelope)
	}
}

func (store *formalGLMOneDrawControlStore) RetainedBytes(
	now time.Time,
) (int64, error) {
	entries, err := store.outboxInventory(now, true)
	if err != nil {
		return 0, err
	}
	defer formalGLMControlClearOutboxEntries(entries)
	var total int64
	for _, entry := range entries {
		info, err := store.guard.root.Lstat(entry.leasePath)
		if err != nil || !info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
			!exactGCPrivateOwnedRegular(info) || info.Size() < 64 ||
			info.Size() > 64<<10 {
			return 0, fmt.Errorf("formal-glm control: unsafe retained lease")
		}
		if total > int64(formalGLMControlMaxEnvelopeJSON)*8-
			int64(len(entry.envelope))-info.Size() {
			return 0, fmt.Errorf("formal-glm control: retained accounting overflow")
		}
		total += int64(len(entry.envelope)) + info.Size()
	}
	return total, nil
}

func (store *formalGLMOneDrawControlStore) lifecycleRecordPresent(
	recordType, senderRole string,
) (bool, error) {
	encoded, err := store.readLifecycleRaw(recordType, senderRole)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer clear(encoded)
	if _, err := store.validateLifecycleRaw(
		recordType, senderRole, encoded); err != nil {
		return false, err
	}
	return true, nil
}

func (store *formalGLMOneDrawControlStore) sourcePrerequisiteReady(
	recordType string,
) (bool, error) {
	switch recordType {
	case formalGLMControlRecordStage:
		return true, nil
	case formalGLMControlRecordTicket:
		return store.lifecycleRecordPresent(
			formalGLMControlRecordStage, "evaluator")
	case formalGLMControlRecordSealReceipt:
		return store.lifecycleRecordPresent(
			formalGLMControlRecordTicket, "garbler")
	case formalGLMControlRecordCandidate:
		return store.lifecycleRecordPresent(
			formalGLMControlRecordSealReceipt, "evaluator")
	case formalGLMControlRecordLocalRelease:
		return store.lifecycleRecordPresent(
			formalGLMControlRecordCandidate, "garbler")
	case formalGLMControlRecordBaseCertificate:
		return store.lifecycleRecordPresent(
			formalGLMControlRecordLocalRelease, "evaluator")
	case formalGLMControlRecordAuthorization:
		if store.local.Role == "garbler" {
			return store.lifecycleRecordPresent(
				formalGLMControlRecordBaseCertificate, "garbler")
		}
		return store.lifecycleRecordPresent(
			formalGLMControlRecordAuthorization, "garbler")
	case formalGLMControlRecordAck:
		return store.lifecycleRecordPresent(
			formalGLMControlRecordAuthorization, "evaluator")
	default:
		return false, fmt.Errorf("formal-glm control: invalid source state")
	}
}

func (store *formalGLMOneDrawControlStore) terminal() (bool, error) {
	if store.local.Role == "garbler" {
		_, found, err := store.readDelivery(formalGLMControlRecordAck)
		return found, err
	}
	return store.lifecycleRecordPresent(formalGLMControlRecordAck, "garbler")
}

type formalGLMControlSourceRecord struct {
	recordType string
	record     []byte
	ticket     formalFinalizerHandoffTicket
}

func (store *formalGLMOneDrawControlStore) nextSourceRecord() (
	formalGLMControlSourceRecord, error,
) {
	var zero formalGLMControlSourceRecord
	terminal, err := store.terminal()
	if err != nil {
		return zero, err
	}
	if terminal {
		return zero, errFormalGLMControlNoSource
	}
	sequence := formalGLMControlOutboundSequence(store.local.Role)
	if len(sequence) == 0 {
		return zero, fmt.Errorf("formal-glm control: invalid local role")
	}
	for index, recordType := range sequence {
		_, delivered, err := store.readDelivery(recordType)
		if err != nil {
			return zero, err
		}
		if delivered {
			continue
		}
		for _, later := range sequence[index+1:] {
			if _, found, err := store.readDelivery(later); err != nil {
				return zero, err
			} else if found {
				return zero, fmt.Errorf(
					"formal-glm control: reordered durable delivery")
			}
		}
		ready, err := store.sourcePrerequisiteReady(recordType)
		if err != nil {
			return zero, err
		}
		if !ready {
			return zero, errFormalGLMControlNoSource
		}
		encoded, err := store.readLifecycleRaw(recordType, store.local.Role)
		if os.IsNotExist(err) {
			return zero, errFormalGLMControlNoSource
		}
		if err != nil {
			return zero, err
		}
		ticket, err := store.validateLifecycleRaw(
			recordType, store.local.Role, encoded)
		if err != nil {
			clear(encoded)
			return zero, err
		}
		return formalGLMControlSourceRecord{
			recordType: recordType, record: encoded, ticket: ticket,
		}, nil
	}
	return zero, errFormalGLMControlNoSource
}

func formalGLMControlBase64URLChars(size int64) (int64, error) {
	if size < 64 || size > formalGLMControlMaxEnvelopeJSON {
		return 0, fmt.Errorf("formal-glm control: invalid source size")
	}
	result := (size / 3) * 4
	switch size % 3 {
	case 1:
		result += 2
	case 2:
		result += 3
	}
	return result, nil
}

func (store *formalGLMOneDrawControlStore) sourceDescriptor(
	entry formalGLMControlOutboxEntry,
) (formalGLMOneDrawControlSourceDescriptor, error) {
	var zero formalGLMOneDrawControlSourceDescriptor
	if len(entry.envelope) < 64 ||
		int64(len(entry.envelope)) != entry.lease.EnvelopeBytes ||
		formalGLMControlRawSHA256(entry.envelope) != entry.lease.EnvelopeSHA256 {
		return zero, fmt.Errorf("formal-glm control: invalid source outbox")
	}
	envelope, err := formalGLMControlDecodeEnvelope(entry.envelope)
	if err != nil {
		return zero, err
	}
	defer clear(envelope.Ciphertext)
	payloadChars, err := formalGLMControlBase64URLChars(
		entry.lease.EnvelopeBytes)
	if err != nil {
		return zero, err
	}
	sourcePath := filepath.Join(store.guard.dir, entry.envelopePath)
	if !filepath.IsAbs(sourcePath) || filepath.Clean(sourcePath) != sourcePath {
		return zero, fmt.Errorf("formal-glm control: invalid source path")
	}
	context := formalGLMOneDrawControlBridgeContext{
		Version:  formalGLMControlContextVersion,
		Protocol: formalGLMOneDrawControlProtocol, AAD: envelope.AAD,
		RecordSHA256:   envelope.RecordSHA256,
		EnvelopeSHA256: entry.lease.EnvelopeSHA256,
		EnvelopeBytes:  entry.lease.EnvelopeBytes,
	}
	return formalGLMOneDrawControlSourceDescriptor{
		Version: formalGLMControlDescriptorVersion, SourcePath: sourcePath,
		EnvelopeBytes:  entry.lease.EnvelopeBytes,
		PayloadChars:   payloadChars,
		EnvelopeSHA256: entry.lease.EnvelopeSHA256, Context: context,
	}, nil
}

func (store *formalGLMOneDrawControlStore) DescribeNextSource(
	recipientTransportPublic, recipientTransportSignature []byte,
	now time.Time,
) (formalGLMOneDrawControlSourceDescriptor, error) {
	var zero formalGLMOneDrawControlSourceDescriptor
	source, err := store.nextSourceRecord()
	if err != nil {
		return zero, err
	}
	defer clear(source.record)
	entries, err := store.outboxInventory(now, true)
	if err != nil {
		return zero, err
	}
	defer formalGLMControlClearOutboxEntries(entries)
	recipientRole, _ := formalGLMControlDirection(
		source.recordType, store.local.Role)
	if _, err := formalGLMControlValidateRecipientTransport(
		store.binding, recipientRole, recipientTransportPublic,
		recipientTransportSignature, store.pins); err != nil {
		return zero, err
	}
	keySHA := formalGLMControlSHA(
		formalGLMControlAADDomain+"recipient-key|", recipientTransportPublic)
	recordSHA := formalGLMControlSHA(
		formalGLMControlRecordDomain, source.record)
	for _, entry := range entries {
		if entry.lease.RecordType != source.recordType ||
			entry.lease.RecordSHA256 != recordSHA {
			return zero, fmt.Errorf("formal-glm control: stale active outbox")
		}
		if entry.lease.RecipientTransportKeySHA256 != keySHA {
			return zero, errFormalGLMControlOutboxLease
		}
		return store.sourceDescriptor(entry)
	}
	envelope, err := formalGLMOneDrawControlSeal(
		store.binding, source.recordType, store.local.Role, source.record,
		source.ticket, recipientTransportPublic, recipientTransportSignature,
		store.pins)
	if err != nil {
		return zero, err
	}
	defer clear(envelope.Ciphertext)
	envelopeJSON, err := formalGLMControlMarshalEnvelope(envelope)
	if err != nil {
		return zero, err
	}
	defer clear(envelopeJSON)
	envelopeSHA := formalGLMControlRawSHA256(envelopeJSON)
	lease := formalGLMOneDrawControlLease{
		Version:    formalGLMControlLeaseVersion,
		Protocol:   formalGLMOneDrawControlProtocol,
		ArtifactID: store.binding.ArtifactID,
		RecordType: source.recordType, SenderRole: store.local.Role,
		RecipientRole: recipientRole, RecordSHA256: envelope.RecordSHA256,
		EnvelopeSHA256: envelopeSHA, EnvelopeBytes: int64(len(envelopeJSON)),
		RecipientTransportKeySHA256: keySHA, CreatedUnix: now.Unix(),
		ExpiresUnix: now.Add(formalGLMControlOutboxTTL).Unix(),
	}
	leaseJSON, err := json.Marshal(lease)
	if err != nil {
		return zero, err
	}
	defer clear(leaseJSON)
	envelopePath, leasePath, err := store.outboxPaths(
		source.recordType, keySHA, true)
	if err != nil {
		return zero, err
	}
	if _, err := store.createRecord(
		envelopePath, envelopeJSON, formalGLMControlMaxEnvelopeJSON); err != nil {
		return zero, err
	}
	if _, err := store.createRecord(leasePath, leaseJSON, 64<<10); err != nil {
		return zero, err
	}
	committed, err := store.outboxInventory(now, false)
	if err != nil {
		return zero, err
	}
	defer formalGLMControlClearOutboxEntries(committed)
	if len(committed) != 1 ||
		committed[0].lease.EnvelopeSHA256 != envelopeSHA {
		return zero, fmt.Errorf("formal-glm control: outbox CAS was not durable")
	}
	return store.sourceDescriptor(committed[0])
}

func formalGLMControlDeliveryReceipt(
	delivery formalGLMOneDrawControlDelivery, replayed bool,
) formalGLMOneDrawControlDeliveryReceipt {
	return formalGLMOneDrawControlDeliveryReceipt{
		Version: formalGLMControlDeliveryVersion, State: "delivered",
		ArtifactID: delivery.ArtifactID, RecordType: delivery.RecordType,
		EnvelopeSHA256: delivery.EnvelopeSHA256, Replayed: replayed,
	}
}

func (store *formalGLMOneDrawControlStore) MarkNextDelivered(
	envelopeSHA256, receiptSHA256 string, now time.Time,
) (formalGLMOneDrawControlDeliveryReceipt, error) {
	var zero formalGLMOneDrawControlDeliveryReceipt
	if !formalGLMIsSHA256(envelopeSHA256) ||
		!formalGLMIsSHA256(receiptSHA256) || now.Unix() < 1 {
		return zero, fmt.Errorf("formal-glm control: invalid delivery receipt")
	}
	for _, recordType := range formalGLMControlOutboundSequence(
		store.local.Role) {
		delivery, found, err := store.readDelivery(recordType)
		if err != nil {
			return zero, err
		}
		if !found || delivery.EnvelopeSHA256 != envelopeSHA256 {
			continue
		}
		if delivery.ReceiptSHA256 != receiptSHA256 {
			return zero, fmt.Errorf("formal-glm control: conflicting delivery replay")
		}
		entries, cleanupErr := store.outboxInventory(now, false)
		formalGLMControlClearOutboxEntries(entries)
		if cleanupErr != nil {
			return zero, cleanupErr
		}
		return formalGLMControlDeliveryReceipt(delivery, true), nil
	}
	source, err := store.nextSourceRecord()
	if err != nil {
		return zero, err
	}
	defer clear(source.record)
	recordSHA := formalGLMControlSHA(
		formalGLMControlRecordDomain, source.record)
	entries, err := store.outboxInventory(now, false)
	if err != nil {
		return zero, err
	}
	defer formalGLMControlClearOutboxEntries(entries)
	var selected *formalGLMControlOutboxEntry
	for index := range entries {
		entry := &entries[index]
		if entry.lease.EnvelopeSHA256 == envelopeSHA256 {
			if selected != nil {
				return zero, fmt.Errorf("formal-glm control: ambiguous outbox delivery")
			}
			selected = entry
		}
	}
	if selected == nil || selected.lease.RecordType != source.recordType ||
		selected.lease.RecordSHA256 != recordSHA {
		return zero, fmt.Errorf("formal-glm control: receipt has no current outbox")
	}
	delivery := formalGLMOneDrawControlDelivery{
		Version:    formalGLMControlDeliveryVersion,
		Protocol:   formalGLMOneDrawControlProtocol,
		ArtifactID: store.binding.ArtifactID,
		RecordType: source.recordType, SenderRole: store.local.Role,
		RecipientRole: selected.lease.RecipientRole,
		RecordSHA256:  recordSHA, EnvelopeSHA256: envelopeSHA256,
		ReceiptSHA256: receiptSHA256, DeliveredUnix: now.Unix(),
	}
	encoded, err := json.Marshal(delivery)
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	path, err := store.deliveryPath(source.recordType, true)
	if err != nil {
		return zero, err
	}
	created, err := store.createRecord(path, encoded, 64<<10)
	if err != nil || !created {
		if err == nil {
			err = fmt.Errorf("formal-glm control: conflicting delivery CAS")
		}
		return zero, err
	}
	if err := store.removeRecord(
		selected.envelopePath, formalGLMControlMaxEnvelopeJSON); err != nil {
		return zero, err
	}
	if err := store.removeRecord(selected.leasePath, 64<<10); err != nil {
		return zero, err
	}
	return formalGLMControlDeliveryReceipt(delivery, false), nil
}

func (store *formalGLMOneDrawControlStore) importDeliveryPrerequisite(
	recordType string,
) error {
	prior := ""
	if store.local.Role == "evaluator" {
		switch recordType {
		case formalGLMControlRecordTicket:
			prior = formalGLMControlRecordStage
		case formalGLMControlRecordCandidate:
			prior = formalGLMControlRecordSealReceipt
		case formalGLMControlRecordBaseCertificate:
			prior = formalGLMControlRecordLocalRelease
		case formalGLMControlRecordAuthorization:
			prior = formalGLMControlRecordLocalRelease
		case formalGLMControlRecordAck:
			prior = formalGLMControlRecordAuthorization
		}
	} else {
		switch recordType {
		case formalGLMControlRecordSealReceipt:
			prior = formalGLMControlRecordTicket
		case formalGLMControlRecordLocalRelease:
			prior = formalGLMControlRecordCandidate
		case formalGLMControlRecordAuthorization:
			prior = formalGLMControlRecordAuthorization
		}
	}
	if prior == "" {
		return nil
	}
	_, found, err := store.readDelivery(prior)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("formal-glm control: cross-direction record reordered")
	}
	return nil
}

func (store *formalGLMOneDrawControlStore) ImportCanonical(
	encoded []byte, recipientTransportSecret []byte, now time.Time,
) (formalGLMOneDrawControlIngressReceipt, error) {
	var zero formalGLMOneDrawControlIngressReceipt
	if now.Unix() < 1 {
		return zero, fmt.Errorf("formal-glm control: invalid ingress clock")
	}
	envelope, err := formalGLMControlDecodeEnvelope(encoded)
	if err != nil {
		return zero, err
	}
	defer clear(envelope.Ciphertext)
	if envelope.AAD.RecipientRole != store.local.Role ||
		envelope.AAD.RecipientPeerName != store.local.PeerName ||
		envelope.AAD.RecipientPeerID != store.local.PeerID {
		return zero, fmt.Errorf("formal-glm control: ingress targets another Rock")
	}
	sequence := formalGLMControlInboundSequence(store.local.Role)
	target := -1
	for index, recordType := range sequence {
		if recordType == envelope.AAD.RecordType {
			target = index
			break
		}
	}
	if target < 0 {
		return zero, fmt.Errorf("formal-glm control: invalid inbound direction")
	}
	var ticket formalFinalizerHandoffTicket
	if envelope.AAD.RecordType != formalGLMControlRecordStage &&
		envelope.AAD.RecordType != formalGLMControlRecordTicket {
		ticket, err = store.loadTicket()
		if err != nil {
			return zero, fmt.Errorf("formal-glm control: post-ticket ingress lacks ticket")
		}
	}
	plaintext, err := formalGLMOneDrawControlOpen(
		store.binding, envelope, ticket, recipientTransportSecret, store.pins)
	if err != nil {
		return zero, err
	}
	defer clear(plaintext)
	for index := 0; index < target; index++ {
		senderRole := "garbler"
		if store.local.Role == "garbler" {
			senderRole = "evaluator"
		}
		present, err := store.lifecycleRecordPresent(
			sequence[index], senderRole)
		if err != nil {
			return zero, err
		}
		if !present {
			return zero, fmt.Errorf("formal-glm control: inbound record reordered")
		}
	}
	path, err := store.lifecyclePath(
		envelope.AAD.RecordType, envelope.AAD.SenderRole)
	if err != nil {
		return zero, err
	}
	relative, err := formalGLMPhase21RockRelative(store.guard.dir, path)
	if err != nil {
		return zero, err
	}
	existing, readErr := formalGLMPhase21RootReadRecord(
		store.guard.root, relative, formalGLMControlMaxRecord)
	if readErr == nil {
		defer clear(existing)
		if !bytes.Equal(existing, plaintext) {
			return zero, fmt.Errorf("formal-glm control: conflicting ingress replay")
		}
		return formalGLMOneDrawControlIngressReceipt{
			Version: formalGLMControlIngressVersion,
			State:   "ingress_committed", ArtifactID: store.binding.ArtifactID,
			RecordType:   envelope.AAD.RecordType,
			SenderRole:   envelope.AAD.SenderRole,
			RecordSHA256: envelope.RecordSHA256, Replayed: true,
		}, nil
	}
	if !os.IsNotExist(readErr) {
		return zero, readErr
	}
	if err := store.importDeliveryPrerequisite(
		envelope.AAD.RecordType); err != nil {
		return zero, err
	}
	for index := target + 1; index < len(sequence); index++ {
		senderRole := envelope.AAD.SenderRole
		present, err := store.lifecycleRecordPresent(
			sequence[index], senderRole)
		if err != nil {
			return zero, err
		}
		if present {
			return zero, fmt.Errorf("formal-glm control: later ingress already exists")
		}
	}
	created, err := store.createRecord(
		relative, plaintext, formalGLMControlMaxRecord)
	if err != nil || !created {
		if err == nil {
			err = fmt.Errorf("formal-glm control: ingress CAS did not create")
		}
		return zero, err
	}
	return formalGLMOneDrawControlIngressReceipt{
		Version: formalGLMControlIngressVersion,
		State:   "ingress_committed", ArtifactID: store.binding.ArtifactID,
		RecordType:   envelope.AAD.RecordType,
		SenderRole:   envelope.AAD.SenderRole,
		RecordSHA256: envelope.RecordSHA256, Replayed: false,
	}, nil
}
