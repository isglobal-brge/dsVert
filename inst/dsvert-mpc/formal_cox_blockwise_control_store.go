package main

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
	"reflect"
	"time"
)

const (
	formalCoxControlStoreVersion      = "dsvert-formal-cox-blockwise-control-store-v1"
	formalCoxControlLeaseVersion      = "dsvert-formal-cox-blockwise-control-lease-v1"
	formalCoxControlDeliveryVersion   = "dsvert-formal-cox-blockwise-control-delivery-v1"
	formalCoxControlDescriptorVersion = "dsvert-formal-cox-blockwise-control-source-v1"
	formalCoxControlBridgeVersion     = "dsvert-formal-cox-blockwise-control-bridge-v1"
	formalCoxControlIngressVersion    = "dsvert-formal-cox-blockwise-control-ingress-v1"
	formalCoxControlStoreDir          = "formal-cox-blockwise-control-relay-v1"

	formalCoxControlMaxEnvelopeJSON = ((formalCoxControlMaxEnvelope+2)/3)*4 + 32<<10
)

var (
	formalCoxControlOutboxTTL      = 24 * time.Hour
	errFormalCoxControlNoSource    = errors.New("formal-cox control: no source record ready")
	errFormalCoxControlOutboxLease = errors.New("formal-cox control: another recipient lease is active")
)

type formalCoxBlockwiseControlBridgeContext struct {
	Version        string                       `json:"version"`
	Protocol       string                       `json:"protocol"`
	AAD            formalCoxBlockwiseControlAAD `json:"aad"`
	RecordSHA256   string                       `json:"record_sha256"`
	EnvelopeSHA256 string                       `json:"envelope_sha256"`
	EnvelopeBytes  int64                        `json:"envelope_bytes"`
}

type formalCoxBlockwiseControlSourceDescriptor struct {
	Version        string                                 `json:"version"`
	SourcePath     string                                 `json:"source_path"`
	EnvelopeBytes  int64                                  `json:"envelope_bytes"`
	PayloadChars   int64                                  `json:"payload_chars"`
	EnvelopeSHA256 string                                 `json:"envelope_sha256"`
	Context        formalCoxBlockwiseControlBridgeContext `json:"context"`
}

type formalCoxBlockwiseControlDeliveryReceipt struct {
	Version        string `json:"version"`
	State          string `json:"state"`
	ArtifactID     string `json:"artifact_id"`
	RecordType     string `json:"record_type"`
	EnvelopeSHA256 string `json:"envelope_sha256"`
	Replayed       bool   `json:"replayed"`
}

type formalCoxBlockwiseControlIngressReceipt struct {
	Version      string `json:"version"`
	State        string `json:"state"`
	ArtifactID   string `json:"artifact_id"`
	RecordType   string `json:"record_type"`
	SenderRole   string `json:"sender_role"`
	RecordSHA256 string `json:"record_sha256"`
	Replayed     bool   `json:"replayed"`
}

type formalCoxBlockwiseControlLease struct {
	Version                     string `json:"version"`
	Protocol                    string `json:"protocol"`
	ArtifactID                  string `json:"artifact_id"`
	ExecutionSHA256             string `json:"execution_sha256"`
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

type formalCoxBlockwiseControlDelivery struct {
	Version         string `json:"version"`
	Protocol        string `json:"protocol"`
	ArtifactID      string `json:"artifact_id"`
	ExecutionSHA256 string `json:"execution_sha256"`
	RecordType      string `json:"record_type"`
	SenderRole      string `json:"sender_role"`
	RecipientRole   string `json:"recipient_role"`
	RecordSHA256    string `json:"record_sha256"`
	EnvelopeSHA256  string `json:"envelope_sha256"`
	ReceiptSHA256   string `json:"receipt_sha256"`
	DeliveredUnix   int64  `json:"delivered_unix"`
}

type formalCoxControlOutboxEntry struct {
	lease        formalCoxBlockwiseControlLease
	leasePath    string
	envelopePath string
	envelope     []byte
}

type formalCoxControlSourceRecord struct {
	recordType string
	record     []byte
	binding    formalFinalizerHandoffBinding
	ticket     formalFinalizerHandoffTicket
	related    formalCoxBlockwiseControlRelated
}

type formalCoxBlockwiseControlStore struct {
	guard   *formalFinalizerHandoffAuthorityGuard
	context formalCoxBlockwiseControlContext
	local   formalFinalizerHandoffAuthority
	pins    map[string]ed25519.PublicKey
}

func formalCoxControlLifecyclePath(root string,
	context formalCoxBlockwiseControlContext, recordType, senderRole string,
) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		!formalCoxIsSHA256(context.ArtifactID) ||
		!formalCoxIsSHA256(context.ExecutionSHA256) {
		return "", fmt.Errorf("formal-cox control: invalid lifecycle root")
	}
	if _, err := formalCoxControlDirection(recordType, senderRole); err != nil {
		return "", err
	}
	name := ""
	switch recordType {
	case formalCoxControlRecordPreflight, formalCoxControlRecordHeader,
		formalCoxControlRecordAuthorization:
		name = recordType + "-" + senderRole + ".json"
	case formalCoxControlRecordTicket, formalCoxControlRecordCandidate,
		formalCoxControlRecordPublication, formalCoxControlRecordAck:
		name = recordType + ".json"
	case formalCoxControlRecordEnvelope, formalCoxControlRecordCommit:
		name = recordType + "-evaluator.json"
	default:
		return "", fmt.Errorf("formal-cox control: invalid lifecycle record type")
	}
	base := filepath.Join(root, formalCoxControlStoreDir, "lifecycle-v1",
		context.ArtifactID[:2], context.ArtifactID[2:4],
		context.ExecutionSHA256[:2], context.ExecutionSHA256[2:4],
		context.ArtifactID+"-"+context.ExecutionSHA256)
	return filepath.Join(base, name), nil
}

func newFormalCoxBlockwiseControlStore(root string,
	context formalCoxBlockwiseControlContext,
	local formalFinalizerHandoffAuthority, production bool,
) (*formalCoxBlockwiseControlStore, error) {
	rebuilt, err := formalCoxControlContextFor(context.plan, context.pins)
	if err != nil || !formalCoxControlContextPublicEqual(rebuilt, context) ||
		!formalCoxControlContextHasAuthority(context, local) {
		return nil, fmt.Errorf("formal-cox control: invalid Rock store context")
	}
	guard, err := newFormalFinalizerHandoffAuthorityGuard(
		root, context.ArtifactID, local, production)
	if err != nil {
		return nil, err
	}
	for _, kind := range []string{"outbox-v1", "lease-v1", "delivery-v1"} {
		relative := filepath.Join(formalCoxControlStoreDir, kind)
		if err := formalGLMPhase21EnsureRootPrivateDir(
			guard.root, relative); err != nil {
			guard.Close()
			return nil, err
		}
	}
	copyPins := make(map[string]ed25519.PublicKey, len(context.pins))
	for peer, pin := range context.pins {
		copyPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	context.pins = copyPins
	return &formalCoxBlockwiseControlStore{
		guard: guard, context: context, local: local, pins: copyPins,
	}, nil
}

func formalCoxControlContextPublicEqual(left,
	right formalCoxBlockwiseControlContext,
) bool {
	left.plan, right.plan = formalCoxBlockwisePlan{}, formalCoxBlockwisePlan{}
	left.artifact, right.artifact = formalCoxBlockwiseStickyArtifact{},
		formalCoxBlockwiseStickyArtifact{}
	left.pins, right.pins = nil, nil
	return reflect.DeepEqual(left, right)
}

func formalCoxControlContextHasAuthority(
	context formalCoxBlockwiseControlContext,
	authority formalFinalizerHandoffAuthority,
) bool {
	for _, candidate := range context.Authorities {
		if formalFinalizerHandoffAuthorityEqual(candidate, authority) {
			return true
		}
	}
	return false
}

func (store *formalCoxBlockwiseControlStore) Close() {
	if store != nil && store.guard != nil {
		store.guard.Close()
		store.guard = nil
	}
}

func (store *formalCoxBlockwiseControlStore) lifecyclePath(
	recordType, senderRole string,
) (string, error) {
	if store == nil || store.guard == nil {
		return "", fmt.Errorf("formal-cox control: closed Rock store")
	}
	return formalCoxControlLifecyclePath(
		store.guard.dir, store.context, recordType, senderRole)
}

func (store *formalCoxBlockwiseControlStore) readLifecycleRaw(
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
		store.guard.root, relative, formalCoxControlMaxRecord)
}

func (store *formalCoxBlockwiseControlStore) loadHeaders() (
	[2]formalCoxBlockwiseOpeningHandoffHeader, error,
) {
	var headers [2]formalCoxBlockwiseOpeningHandoffHeader
	for index, role := range []string{"garbler", "evaluator"} {
		encoded, err := store.readLifecycleRaw(
			formalCoxControlRecordHeader, role)
		if err != nil {
			return headers, err
		}
		var record formalCoxBlockwiseRockHeaderRecord
		decodeErr := formalCoxControlDecodeCanonical(encoded, &record)
		_, validateErr := formalCoxControlValidateRecord(
			store.context, formalFinalizerHandoffBinding{},
			formalCoxControlRecordHeader, role, encoded,
			formalFinalizerHandoffTicket{}, formalCoxBlockwiseControlRelated{})
		clear(encoded)
		if decodeErr != nil || validateErr != nil {
			return headers, fmt.Errorf("formal-cox control: invalid durable headers")
		}
		headers[index] = record.Header
	}
	return headers, nil
}

func (store *formalCoxBlockwiseControlStore) loadBinding() (
	formalFinalizerHandoffBinding, error,
) {
	var zero formalFinalizerHandoffBinding
	headers, err := store.loadHeaders()
	if err != nil {
		return zero, err
	}
	validator := &formalCoxBlockwiseOpeningStore{
		plan: store.context.plan, planSHA256: store.context.PlanSHA256,
		pins: store.pins, artifact: store.context.artifact,
		artifactID: store.context.ArtifactID,
	}
	pairRoot, err := validator.pairRoot(headers[0], headers[1])
	if err != nil {
		return zero, err
	}
	binding := formalFinalizerHandoffBinding{
		Family: store.context.Family, Purpose: store.context.Purpose,
		ArtifactID:          store.context.ArtifactID,
		FinalPairRootSHA256: pairRoot,
		PlanSHA256:          store.context.PlanSHA256,
		PinsetSHA256:        store.context.PinsetSHA256,
		Authorities: append([]formalFinalizerHandoffAuthority(nil),
			store.context.Authorities...),
		Finalizer: store.context.Finalizer,
	}
	if err := formalCoxControlValidateBinding(store.context, binding); err != nil {
		return zero, err
	}
	return binding, nil
}

func (store *formalCoxBlockwiseControlStore) loadTicket(
	binding formalFinalizerHandoffBinding,
) (formalFinalizerHandoffTicket, error) {
	var zero formalFinalizerHandoffTicket
	encoded, err := store.readLifecycleRaw(formalCoxControlRecordTicket, "garbler")
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	var record formalCoxBlockwiseRockTicketRecord
	if formalCoxControlDecodeCanonical(encoded, &record) != nil {
		return zero, fmt.Errorf("formal-cox control: invalid durable ticket")
	}
	if _, err := formalCoxControlValidateRecord(
		store.context, binding, formalCoxControlRecordTicket, "garbler",
		encoded, record.Ticket, formalCoxBlockwiseControlRelated{}); err != nil {
		return zero, err
	}
	return record.Ticket, nil
}

func (store *formalCoxBlockwiseControlStore) decodeCandidate(
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
) (*formalCoxBlockwiseRockCandidateRecord, error) {
	encoded, err := store.readLifecycleRaw(
		formalCoxControlRecordCandidate, "garbler")
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	var record formalCoxBlockwiseRockCandidateRecord
	if formalCoxControlDecodeCanonical(encoded, &record) != nil {
		return nil, fmt.Errorf("formal-cox control: invalid durable candidate")
	}
	if _, err := formalCoxControlValidateRecord(
		store.context, binding, formalCoxControlRecordCandidate, "garbler",
		encoded, ticket, formalCoxBlockwiseControlRelated{}); err != nil {
		return nil, err
	}
	return &record, nil
}

func (store *formalCoxBlockwiseControlStore) decodeGarblerAuthorization(
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	candidate *formalCoxBlockwiseRockCandidateRecord,
) (*formalCoxBlockwiseRockAuthorizationRecord, error) {
	encoded, err := store.readLifecycleRaw(
		formalCoxControlRecordAuthorization, "garbler")
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	var record formalCoxBlockwiseRockAuthorizationRecord
	if formalCoxControlDecodeCanonical(encoded, &record) != nil {
		return nil, fmt.Errorf("formal-cox control: invalid durable authorization")
	}
	if _, err := formalCoxControlValidateRecord(
		store.context, binding, formalCoxControlRecordAuthorization, "garbler",
		encoded, ticket, formalCoxBlockwiseControlRelated{
			Candidate: candidate,
		}); err != nil {
		return nil, err
	}
	return &record, nil
}

func (store *formalCoxBlockwiseControlStore) decodePublication(
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	candidate *formalCoxBlockwiseRockCandidateRecord,
) (*formalCoxBlockwiseRockPublicationRecord, error) {
	encoded, err := store.readLifecycleRaw(
		formalCoxControlRecordPublication, "garbler")
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	var record formalCoxBlockwiseRockPublicationRecord
	if formalCoxControlDecodeCanonical(encoded, &record) != nil {
		return nil, fmt.Errorf("formal-cox control: invalid durable publication")
	}
	if _, err := formalCoxControlValidateRecord(
		store.context, binding, formalCoxControlRecordPublication, "garbler",
		encoded, ticket, formalCoxBlockwiseControlRelated{
			Candidate: candidate,
		}); err != nil {
		return nil, err
	}
	return &record, nil
}

func (store *formalCoxBlockwiseControlStore) relatedFor(
	recordType, senderRole string,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
) (formalCoxBlockwiseControlRelated, error) {
	var related formalCoxBlockwiseControlRelated
	if recordType == formalCoxControlRecordAuthorization ||
		recordType == formalCoxControlRecordPublication ||
		recordType == formalCoxControlRecordCommit ||
		recordType == formalCoxControlRecordAck {
		candidate, err := store.decodeCandidate(binding, ticket)
		if err != nil {
			return related, err
		}
		related.Candidate = candidate
	}
	if recordType == formalCoxControlRecordAuthorization &&
		senderRole == "evaluator" {
		garbler, err := store.decodeGarblerAuthorization(
			binding, ticket, related.Candidate)
		if err != nil {
			return related, err
		}
		related.GarblerAuthorization = garbler
	}
	if recordType == formalCoxControlRecordCommit ||
		recordType == formalCoxControlRecordAck {
		publication, err := store.decodePublication(
			binding, ticket, related.Candidate)
		if err != nil {
			return related, err
		}
		related.Publication = publication
	}
	return related, nil
}

func (store *formalCoxBlockwiseControlStore) validationState(
	recordType, senderRole string, encoded []byte,
) (formalFinalizerHandoffBinding, formalFinalizerHandoffTicket,
	formalCoxBlockwiseControlRelated, error,
) {
	var binding formalFinalizerHandoffBinding
	var ticket formalFinalizerHandoffTicket
	var related formalCoxBlockwiseControlRelated
	if recordType == formalCoxControlRecordPreflight ||
		recordType == formalCoxControlRecordHeader {
		return binding, ticket, related, nil
	}
	var err error
	binding, err = store.loadBinding()
	if err != nil {
		return binding, ticket, related, err
	}
	if recordType == formalCoxControlRecordTicket {
		var record formalCoxBlockwiseRockTicketRecord
		if formalCoxControlDecodeCanonical(encoded, &record) != nil {
			return binding, ticket, related,
				fmt.Errorf("formal-cox control: invalid ticket source")
		}
		ticket = record.Ticket
	} else {
		ticket, err = store.loadTicket(binding)
		if err != nil {
			return binding, ticket, related, err
		}
	}
	related, err = store.relatedFor(recordType, senderRole, binding, ticket)
	return binding, ticket, related, err
}

func (store *formalCoxBlockwiseControlStore) validateLifecycleRaw(
	recordType, senderRole string, encoded []byte,
) (formalFinalizerHandoffBinding, formalFinalizerHandoffTicket,
	formalCoxBlockwiseControlRelated, error,
) {
	binding, ticket, related, err := store.validationState(
		recordType, senderRole, encoded)
	if err != nil {
		return binding, ticket, related, err
	}
	if _, err := formalCoxControlValidateRecord(
		store.context, binding, recordType, senderRole,
		encoded, ticket, related); err != nil {
		return binding, ticket, related, err
	}
	return binding, ticket, related, nil
}

func formalCoxControlMarshalEnvelope(
	envelope formalCoxBlockwiseControlEnvelope,
) ([]byte, error) {
	if envelope.ProductionReady ||
		envelope.Version != formalCoxControlEnvelopeVersion ||
		envelope.Protocol != formalCoxBlockwiseControlProtocol ||
		len(envelope.Ciphertext) < 60 ||
		len(envelope.Ciphertext) > formalCoxControlMaxEnvelope {
		return nil, fmt.Errorf("formal-cox control: invalid canonical envelope")
	}
	encoded, err := json.Marshal(envelope)
	if err != nil || len(encoded) < 64 || len(encoded) > formalCoxControlMaxEnvelopeJSON {
		clear(encoded)
		return nil, fmt.Errorf("formal-cox control: invalid canonical envelope")
	}
	return encoded, nil
}

func formalCoxControlDecodeEnvelope(encoded []byte) (
	formalCoxBlockwiseControlEnvelope, error,
) {
	var envelope formalCoxBlockwiseControlEnvelope
	if len(encoded) < 64 || len(encoded) > formalCoxControlMaxEnvelopeJSON ||
		encoded[0] != '{' {
		return envelope, fmt.Errorf("formal-cox control: invalid envelope size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		clear(envelope.Ciphertext)
		return formalCoxBlockwiseControlEnvelope{},
			fmt.Errorf("formal-cox control: invalid typed envelope")
	}
	var trailing any
	canonical, err := json.Marshal(envelope)
	if decoder.Decode(&trailing) != io.EOF || err != nil ||
		!bytes.Equal(canonical, encoded) {
		clear(canonical)
		clear(envelope.Ciphertext)
		return formalCoxBlockwiseControlEnvelope{},
			fmt.Errorf("formal-cox control: non-canonical typed envelope")
	}
	clear(canonical)
	return envelope, nil
}

func formalCoxControlRawSHA256(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func formalCoxControlOutboundSequence(role string) []string {
	if role == "garbler" {
		return []string{
			formalCoxControlRecordPreflight, formalCoxControlRecordHeader,
			formalCoxControlRecordTicket, formalCoxControlRecordCandidate,
			formalCoxControlRecordAuthorization,
			formalCoxControlRecordPublication, formalCoxControlRecordAck,
		}
	}
	if role == "evaluator" {
		return []string{
			formalCoxControlRecordPreflight, formalCoxControlRecordHeader,
			formalCoxControlRecordEnvelope,
			formalCoxControlRecordAuthorization, formalCoxControlRecordCommit,
		}
	}
	return nil
}

func formalCoxControlInboundSequence(role string) []string {
	if role == "garbler" {
		return []string{
			formalCoxControlRecordPreflight, formalCoxControlRecordHeader,
			formalCoxControlRecordEnvelope,
			formalCoxControlRecordAuthorization, formalCoxControlRecordCommit,
		}
	}
	if role == "evaluator" {
		return []string{
			formalCoxControlRecordPreflight, formalCoxControlRecordHeader,
			formalCoxControlRecordTicket, formalCoxControlRecordCandidate,
			formalCoxControlRecordAuthorization,
			formalCoxControlRecordPublication, formalCoxControlRecordAck,
		}
	}
	return nil
}

func (store *formalCoxBlockwiseControlStore) relayShard(
	kind string, create bool,
) (string, error) {
	if store == nil || store.guard == nil || store.guard.root == nil ||
		(kind != "outbox-v1" && kind != "lease-v1" &&
			kind != "delivery-v1") {
		return "", fmt.Errorf("formal-cox control: closed Rock store")
	}
	artifact, execution := store.context.ArtifactID,
		store.context.ExecutionSHA256
	relative := filepath.Join(formalCoxControlStoreDir, kind,
		artifact[:2], artifact[2:4], execution[:2], execution[2:4])
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

func (store *formalCoxBlockwiseControlStore) outboxStem(
	recordType, recipientKeySHA string,
) (string, error) {
	if _, err := formalCoxControlDirection(
		recordType, store.local.Role); err != nil ||
		!formalCoxIsSHA256(recipientKeySHA) {
		return "", fmt.Errorf("formal-cox control: invalid outbox slot")
	}
	return recordType + "-" + store.context.ArtifactID + "-" +
		store.context.ExecutionSHA256 + "-" + recipientKeySHA, nil
}

func (store *formalCoxBlockwiseControlStore) outboxPaths(
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

func (store *formalCoxBlockwiseControlStore) deliveryPath(
	recordType string, create bool,
) (string, error) {
	if _, err := formalCoxControlDirection(
		recordType, store.local.Role); err != nil {
		return "", fmt.Errorf("formal-cox control: invalid delivery slot")
	}
	dir, err := store.relayShard("delivery-v1", create)
	if err != nil {
		return "", err
	}
	name := recordType + "-" + store.local.Role + "-" +
		store.context.ArtifactID + "-" + store.context.ExecutionSHA256 + ".json"
	return filepath.Join(dir, name), nil
}

func (store *formalCoxBlockwiseControlStore) createRecord(
	relative string, encoded []byte, maximum int,
) (bool, error) {
	if len(encoded) < 64 || len(encoded) > maximum {
		return false, fmt.Errorf("formal-cox control: invalid durable record")
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
		return false, fmt.Errorf("formal-cox control: conflicting durable record")
	}
	clear(existing)
	return created, nil
}

func (store *formalCoxBlockwiseControlStore) removeRecord(
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
		return fmt.Errorf("formal-cox control: unsafe durable cleanup")
	}
	if err := store.guard.root.Remove(relative); err != nil {
		return fmt.Errorf("formal-cox control: durable cleanup failed")
	}
	return formalGLMPhase21RootSyncDir(store.guard.root, relative)
}

func (store *formalCoxBlockwiseControlStore) readDirectory(
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
			return nil, fmt.Errorf("formal-cox control: invalid relay inventory")
		}
	}
	return entries, nil
}

func (store *formalCoxBlockwiseControlStore) readDelivery(
	recordType string,
) (formalCoxBlockwiseControlDelivery, bool, error) {
	var zero formalCoxBlockwiseControlDelivery
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
	var delivery formalCoxBlockwiseControlDelivery
	recipientRole, directionErr := formalCoxControlDirection(
		recordType, store.local.Role)
	if formalFinalizerHandoffDecodeCanonical(
		encoded, 64<<10, &delivery) != nil || directionErr != nil ||
		delivery.Version != formalCoxControlDeliveryVersion ||
		delivery.Protocol != formalCoxBlockwiseControlProtocol ||
		delivery.ArtifactID != store.context.ArtifactID ||
		delivery.ExecutionSHA256 != store.context.ExecutionSHA256 ||
		delivery.RecordType != recordType ||
		delivery.SenderRole != store.local.Role ||
		delivery.RecipientRole != recipientRole ||
		!formalCoxIsSHA256(delivery.RecordSHA256) ||
		!formalCoxIsSHA256(delivery.EnvelopeSHA256) ||
		!formalCoxIsSHA256(delivery.ReceiptSHA256) || delivery.DeliveredUnix < 1 {
		return zero, false, fmt.Errorf("formal-cox control: invalid delivery marker")
	}
	return delivery, true, nil
}

func formalCoxControlKnownRecordType(value string) bool {
	switch value {
	case formalCoxControlRecordPreflight, formalCoxControlRecordHeader,
		formalCoxControlRecordTicket, formalCoxControlRecordEnvelope,
		formalCoxControlRecordCandidate,
		formalCoxControlRecordAuthorization,
		formalCoxControlRecordPublication, formalCoxControlRecordCommit,
		formalCoxControlRecordAck:
		return true
	}
	return false
}

func (store *formalCoxBlockwiseControlStore) decodeLeaseName(name string) (
	string, string, error,
) {
	if filepath.Base(name) != name || filepath.Ext(name) != ".json" {
		return "", "", fmt.Errorf("formal-cox control: invalid lease inventory")
	}
	stem := name[:len(name)-len(".json")]
	for _, recordType := range []string{
		formalCoxControlRecordPreflight, formalCoxControlRecordHeader,
		formalCoxControlRecordTicket, formalCoxControlRecordEnvelope,
		formalCoxControlRecordCandidate,
		formalCoxControlRecordAuthorization,
		formalCoxControlRecordPublication, formalCoxControlRecordCommit,
		formalCoxControlRecordAck,
	} {
		prefix := recordType + "-" + store.context.ArtifactID + "-" +
			store.context.ExecutionSHA256 + "-"
		if len(stem) == len(prefix)+64 && stem[:len(prefix)] == prefix {
			keySHA := stem[len(prefix):]
			if formalCoxIsSHA256(keySHA) {
				return recordType, keySHA, nil
			}
		}
	}
	return "", "", fmt.Errorf("formal-cox control: invalid lease inventory")
}

func (store *formalCoxBlockwiseControlStore) validateLease(
	lease formalCoxBlockwiseControlLease, recordType, keySHA string,
) error {
	recipientRole, err := formalCoxControlDirection(recordType, store.local.Role)
	if err != nil || lease.Version != formalCoxControlLeaseVersion ||
		lease.Protocol != formalCoxBlockwiseControlProtocol ||
		lease.ArtifactID != store.context.ArtifactID ||
		lease.ExecutionSHA256 != store.context.ExecutionSHA256 ||
		lease.RecordType != recordType || lease.SenderRole != store.local.Role ||
		lease.RecipientRole != recipientRole ||
		lease.RecipientTransportKeySHA256 != keySHA ||
		!formalCoxIsSHA256(lease.RecordSHA256) ||
		!formalCoxIsSHA256(lease.EnvelopeSHA256) || lease.EnvelopeBytes < 64 ||
		lease.EnvelopeBytes > formalCoxControlMaxEnvelopeJSON ||
		lease.CreatedUnix < 1 || lease.ExpiresUnix-lease.CreatedUnix !=
		int64(formalCoxControlOutboxTTL/time.Second) {
		return fmt.Errorf("formal-cox control: invalid outbox lease")
	}
	return nil
}

func (store *formalCoxBlockwiseControlStore) outboxInventory(
	now time.Time, sweepExpired bool,
) ([]formalCoxControlOutboxEntry, error) {
	if now.Unix() < 1 {
		return nil, fmt.Errorf("formal-cox control: invalid relay clock")
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
	active := make([]formalCoxControlOutboxEntry, 0, len(leaseEntries))
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
		var lease formalCoxBlockwiseControlLease
		decodeErr := formalFinalizerHandoffDecodeCanonical(
			leaseJSON, 64<<10, &lease)
		clear(leaseJSON)
		if decodeErr != nil || store.validateLease(
			lease, recordType, keySHA) != nil {
			return nil, fmt.Errorf("formal-cox control: invalid durable lease")
		}
		delivery, delivered, err := store.readDelivery(recordType)
		if err != nil {
			return nil, err
		}
		if delivered && delivery.RecordSHA256 != lease.RecordSHA256 {
			return nil, fmt.Errorf("formal-cox control: delivery changed source record")
		}
		if delivered || sweepExpired && now.Unix() > lease.ExpiresUnix {
			if err := store.removeRecord(
				envelopePath, formalCoxControlMaxEnvelopeJSON); err != nil {
				return nil, err
			}
			if err := store.removeRecord(leasePath, 64<<10); err != nil {
				return nil, err
			}
			continue
		}
		envelopeJSON, err := formalGLMPhase21RootReadRecord(
			store.guard.root, envelopePath, formalCoxControlMaxEnvelopeJSON)
		if err != nil || int64(len(envelopeJSON)) != lease.EnvelopeBytes ||
			formalCoxControlRawSHA256(envelopeJSON) != lease.EnvelopeSHA256 {
			clear(envelopeJSON)
			return nil, fmt.Errorf("formal-cox control: invalid durable outbox")
		}
		envelope, decodeErr := formalCoxControlDecodeEnvelope(envelopeJSON)
		if decodeErr != nil || envelope.AAD.RecordType != recordType ||
			envelope.AAD.SenderRole != store.local.Role ||
			envelope.AAD.RecordSHA256 != lease.RecordSHA256 ||
			envelope.RecipientTransportKeySHA256 != keySHA ||
			formalCoxControlValidateAAD(store.context, envelope.AAD) != nil {
			clear(envelope.Ciphertext)
			clear(envelopeJSON)
			return nil, fmt.Errorf("formal-cox control: outbox binding changed")
		}
		clear(envelope.Ciphertext)
		paired[inventory.Name()] = true
		active = append(active, formalCoxControlOutboxEntry{
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
			formalCoxControlMaxEnvelopeJSON); err != nil {
			return nil, err
		}
	}
	return active, nil
}

func formalCoxControlClearOutboxEntries(entries []formalCoxControlOutboxEntry) {
	for index := range entries {
		clear(entries[index].envelope)
	}
}

func (store *formalCoxBlockwiseControlStore) lifecycleRecordPresent(
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
	if _, _, _, err := store.validateLifecycleRaw(
		recordType, senderRole, encoded); err != nil {
		return false, err
	}
	return true, nil
}

func (store *formalCoxBlockwiseControlStore) sourcePrerequisiteReady(
	recordType string,
) (bool, error) {
	switch store.local.Role {
	case "garbler":
		switch recordType {
		case formalCoxControlRecordPreflight:
			return true, nil
		case formalCoxControlRecordHeader:
			return store.lifecycleRecordPresent(
				formalCoxControlRecordPreflight, "evaluator")
		case formalCoxControlRecordTicket:
			return store.lifecycleRecordPresent(
				formalCoxControlRecordHeader, "evaluator")
		case formalCoxControlRecordCandidate:
			return store.lifecycleRecordPresent(
				formalCoxControlRecordEnvelope, "evaluator")
		case formalCoxControlRecordAuthorization:
			return store.lifecycleRecordPresent(
				formalCoxControlRecordCandidate, "garbler")
		case formalCoxControlRecordPublication:
			return store.lifecycleRecordPresent(
				formalCoxControlRecordAuthorization, "evaluator")
		case formalCoxControlRecordAck:
			return store.lifecycleRecordPresent(
				formalCoxControlRecordCommit, "evaluator")
		}
	case "evaluator":
		switch recordType {
		case formalCoxControlRecordPreflight:
			return true, nil
		case formalCoxControlRecordHeader:
			return store.lifecycleRecordPresent(
				formalCoxControlRecordPreflight, "garbler")
		case formalCoxControlRecordEnvelope:
			return store.lifecycleRecordPresent(
				formalCoxControlRecordTicket, "garbler")
		case formalCoxControlRecordAuthorization:
			return store.lifecycleRecordPresent(
				formalCoxControlRecordAuthorization, "garbler")
		case formalCoxControlRecordCommit:
			return store.lifecycleRecordPresent(
				formalCoxControlRecordPublication, "garbler")
		}
	}
	return false, fmt.Errorf("formal-cox control: invalid source state")
}

func (store *formalCoxBlockwiseControlStore) terminal() (bool, error) {
	if store.local.Role == "garbler" {
		_, found, err := store.readDelivery(formalCoxControlRecordAck)
		return found, err
	}
	return store.lifecycleRecordPresent(formalCoxControlRecordAck, "garbler")
}

func (store *formalCoxBlockwiseControlStore) nextSourceRecord() (
	formalCoxControlSourceRecord, error,
) {
	var zero formalCoxControlSourceRecord
	terminal, err := store.terminal()
	if err != nil {
		return zero, err
	}
	if terminal {
		return zero, errFormalCoxControlNoSource
	}
	sequence := formalCoxControlOutboundSequence(store.local.Role)
	if len(sequence) == 0 {
		return zero, fmt.Errorf("formal-cox control: invalid local role")
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
				return zero,
					fmt.Errorf("formal-cox control: reordered durable delivery")
			}
		}
		ready, err := store.sourcePrerequisiteReady(recordType)
		if err != nil {
			return zero, err
		}
		if !ready {
			return zero, errFormalCoxControlNoSource
		}
		encoded, err := store.readLifecycleRaw(recordType, store.local.Role)
		if os.IsNotExist(err) {
			return zero, errFormalCoxControlNoSource
		}
		if err != nil {
			return zero, err
		}
		binding, ticket, related, err := store.validateLifecycleRaw(
			recordType, store.local.Role, encoded)
		if err != nil {
			clear(encoded)
			return zero, err
		}
		return formalCoxControlSourceRecord{
			recordType: recordType, record: encoded,
			binding: binding, ticket: ticket, related: related,
		}, nil
	}
	return zero, errFormalCoxControlNoSource
}

func formalCoxControlBase64URLChars(size int64) (int64, error) {
	if size < 64 || size > formalCoxControlMaxEnvelopeJSON {
		return 0, fmt.Errorf("formal-cox control: invalid source size")
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

func (store *formalCoxBlockwiseControlStore) sourceDescriptor(
	entry formalCoxControlOutboxEntry,
) (formalCoxBlockwiseControlSourceDescriptor, error) {
	var zero formalCoxBlockwiseControlSourceDescriptor
	if len(entry.envelope) < 64 ||
		int64(len(entry.envelope)) != entry.lease.EnvelopeBytes ||
		formalCoxControlRawSHA256(entry.envelope) != entry.lease.EnvelopeSHA256 {
		return zero, fmt.Errorf("formal-cox control: invalid source outbox")
	}
	envelope, err := formalCoxControlDecodeEnvelope(entry.envelope)
	if err != nil {
		return zero, err
	}
	defer clear(envelope.Ciphertext)
	payloadChars, err := formalCoxControlBase64URLChars(entry.lease.EnvelopeBytes)
	if err != nil {
		return zero, err
	}
	sourcePath := filepath.Join(store.guard.dir, entry.envelopePath)
	if !filepath.IsAbs(sourcePath) || filepath.Clean(sourcePath) != sourcePath {
		return zero, fmt.Errorf("formal-cox control: invalid source path")
	}
	context := formalCoxBlockwiseControlBridgeContext{
		Version:  formalCoxControlBridgeVersion,
		Protocol: formalCoxBlockwiseControlProtocol, AAD: envelope.AAD,
		RecordSHA256:   envelope.AAD.RecordSHA256,
		EnvelopeSHA256: entry.lease.EnvelopeSHA256,
		EnvelopeBytes:  entry.lease.EnvelopeBytes,
	}
	return formalCoxBlockwiseControlSourceDescriptor{
		Version: formalCoxControlDescriptorVersion, SourcePath: sourcePath,
		EnvelopeBytes: entry.lease.EnvelopeBytes, PayloadChars: payloadChars,
		EnvelopeSHA256: entry.lease.EnvelopeSHA256, Context: context,
	}, nil
}

func (store *formalCoxBlockwiseControlStore) DescribeNextSource(
	recipientTransportPublic, recipientTransportSignature []byte, now time.Time,
) (formalCoxBlockwiseControlSourceDescriptor, error) {
	var zero formalCoxBlockwiseControlSourceDescriptor
	source, err := store.nextSourceRecord()
	if err != nil {
		return zero, err
	}
	defer clear(source.record)
	entries, err := store.outboxInventory(now, true)
	if err != nil {
		return zero, err
	}
	defer formalCoxControlClearOutboxEntries(entries)
	recipientRole, _ := formalCoxControlDirection(
		source.recordType, store.local.Role)
	if _, err := formalCoxControlValidateRecipientTransport(
		store.context, recipientRole, recipientTransportPublic,
		recipientTransportSignature); err != nil {
		return zero, err
	}
	keySHA := formalCoxControlSHA(
		formalCoxControlAADDomain+"recipient-key|", recipientTransportPublic)
	recordSHA := formalCoxControlSHA(
		formalCoxControlRecordDomain, source.record)
	for _, entry := range entries {
		if entry.lease.RecordType != source.recordType ||
			entry.lease.RecordSHA256 != recordSHA {
			return zero, fmt.Errorf("formal-cox control: stale active outbox")
		}
		if entry.lease.RecipientTransportKeySHA256 != keySHA {
			return zero, errFormalCoxControlOutboxLease
		}
		return store.sourceDescriptor(entry)
	}
	envelope, err := formalCoxBlockwiseControlSeal(
		store.context, source.binding, source.recordType, store.local.Role,
		source.record, source.ticket, recipientTransportPublic,
		recipientTransportSignature, source.related)
	if err != nil {
		return zero, err
	}
	defer clear(envelope.Ciphertext)
	envelopeJSON, err := formalCoxControlMarshalEnvelope(envelope)
	if err != nil {
		return zero, err
	}
	defer clear(envelopeJSON)
	envelopeSHA := formalCoxControlRawSHA256(envelopeJSON)
	lease := formalCoxBlockwiseControlLease{
		Version:         formalCoxControlLeaseVersion,
		Protocol:        formalCoxBlockwiseControlProtocol,
		ArtifactID:      store.context.ArtifactID,
		ExecutionSHA256: store.context.ExecutionSHA256,
		RecordType:      source.recordType, SenderRole: store.local.Role,
		RecipientRole:  recipientRole,
		RecordSHA256:   envelope.AAD.RecordSHA256,
		EnvelopeSHA256: envelopeSHA, EnvelopeBytes: int64(len(envelopeJSON)),
		RecipientTransportKeySHA256: keySHA, CreatedUnix: now.Unix(),
		ExpiresUnix: now.Add(formalCoxControlOutboxTTL).Unix(),
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
		envelopePath, envelopeJSON, formalCoxControlMaxEnvelopeJSON); err != nil {
		return zero, err
	}
	if _, err := store.createRecord(leasePath, leaseJSON, 64<<10); err != nil {
		return zero, err
	}
	committed, err := store.outboxInventory(now, false)
	if err != nil {
		return zero, err
	}
	defer formalCoxControlClearOutboxEntries(committed)
	if len(committed) != 1 ||
		committed[0].lease.EnvelopeSHA256 != envelopeSHA {
		return zero, fmt.Errorf("formal-cox control: outbox CAS was not durable")
	}
	return store.sourceDescriptor(committed[0])
}

func (store *formalCoxBlockwiseControlStore) importDeliveryPrerequisite(
	recordType string,
) error {
	prior := ""
	if store.local.Role == "evaluator" {
		switch recordType {
		case formalCoxControlRecordHeader:
			prior = formalCoxControlRecordPreflight
		case formalCoxControlRecordTicket:
			prior = formalCoxControlRecordHeader
		case formalCoxControlRecordCandidate,
			formalCoxControlRecordAuthorization:
			prior = formalCoxControlRecordEnvelope
		case formalCoxControlRecordPublication:
			prior = formalCoxControlRecordAuthorization
		case formalCoxControlRecordAck:
			prior = formalCoxControlRecordCommit
		}
	} else {
		switch recordType {
		case formalCoxControlRecordHeader:
			prior = formalCoxControlRecordPreflight
		case formalCoxControlRecordEnvelope:
			prior = formalCoxControlRecordTicket
		case formalCoxControlRecordAuthorization:
			prior = formalCoxControlRecordAuthorization
		case formalCoxControlRecordCommit:
			prior = formalCoxControlRecordPublication
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
		return fmt.Errorf("formal-cox control: cross-direction record reordered")
	}
	return nil
}

func formalCoxControlDeliveryReceipt(
	delivery formalCoxBlockwiseControlDelivery, replayed bool,
) formalCoxBlockwiseControlDeliveryReceipt {
	return formalCoxBlockwiseControlDeliveryReceipt{
		Version: formalCoxControlDeliveryVersion, State: "delivered",
		ArtifactID: delivery.ArtifactID, RecordType: delivery.RecordType,
		EnvelopeSHA256: delivery.EnvelopeSHA256, Replayed: replayed,
	}
}

func (store *formalCoxBlockwiseControlStore) ImportCanonical(
	encoded []byte, recipientTransportSecret []byte, now time.Time,
) (formalCoxBlockwiseControlIngressReceipt, error) {
	var zero formalCoxBlockwiseControlIngressReceipt
	if now.Unix() < 1 {
		return zero, fmt.Errorf("formal-cox control: invalid ingress clock")
	}
	envelope, err := formalCoxControlDecodeEnvelope(encoded)
	if err != nil {
		return zero, err
	}
	defer clear(envelope.Ciphertext)
	if envelope.AAD.RecipientRole != store.local.Role ||
		envelope.AAD.RecipientPeerName != store.local.PeerName ||
		envelope.AAD.RecipientPeerID != store.local.PeerID {
		return zero, fmt.Errorf("formal-cox control: ingress targets another Rock")
	}
	sequence := formalCoxControlInboundSequence(store.local.Role)
	target := -1
	for index, recordType := range sequence {
		if recordType == envelope.AAD.RecordType {
			target = index
			break
		}
	}
	if target < 0 {
		return zero, fmt.Errorf("formal-cox control: invalid inbound direction")
	}
	var binding formalFinalizerHandoffBinding
	var ticket formalFinalizerHandoffTicket
	var related formalCoxBlockwiseControlRelated
	preTicket := envelope.AAD.RecordType == formalCoxControlRecordPreflight ||
		envelope.AAD.RecordType == formalCoxControlRecordHeader
	if !preTicket {
		binding, err = store.loadBinding()
		if err != nil {
			return zero, fmt.Errorf("formal-cox control: post-ticket ingress lacks pair")
		}
		if envelope.AAD.RecordType != formalCoxControlRecordTicket {
			ticket, err = store.loadTicket(binding)
			if err != nil {
				return zero, fmt.Errorf("formal-cox control: post-ticket ingress lacks ticket")
			}
		}
		related, err = store.relatedFor(
			envelope.AAD.RecordType, envelope.AAD.SenderRole, binding, ticket)
		if err != nil && envelope.AAD.RecordType != formalCoxControlRecordTicket {
			return zero, err
		}
	}
	plaintext, err := formalCoxBlockwiseControlOpen(
		store.context, binding, envelope, ticket,
		recipientTransportSecret, related)
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
			return zero, fmt.Errorf("formal-cox control: inbound record reordered")
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
		store.guard.root, relative, formalCoxControlMaxRecord)
	if readErr == nil {
		defer clear(existing)
		if !bytes.Equal(existing, plaintext) {
			return zero, fmt.Errorf("formal-cox control: conflicting ingress replay")
		}
		return formalCoxBlockwiseControlIngressReceipt{
			Version: formalCoxControlIngressVersion,
			State:   "ingress_committed", ArtifactID: store.context.ArtifactID,
			RecordType:   envelope.AAD.RecordType,
			SenderRole:   envelope.AAD.SenderRole,
			RecordSHA256: envelope.AAD.RecordSHA256, Replayed: true,
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
		present, err := store.lifecycleRecordPresent(
			sequence[index], envelope.AAD.SenderRole)
		if err != nil {
			return zero, err
		}
		if present {
			return zero, fmt.Errorf("formal-cox control: later ingress already exists")
		}
	}
	created, err := store.createRecord(relative, plaintext, formalCoxControlMaxRecord)
	if err != nil || !created {
		if err == nil {
			err = fmt.Errorf("formal-cox control: ingress CAS did not create")
		}
		return zero, err
	}
	return formalCoxBlockwiseControlIngressReceipt{
		Version: formalCoxControlIngressVersion,
		State:   "ingress_committed", ArtifactID: store.context.ArtifactID,
		RecordType:   envelope.AAD.RecordType,
		SenderRole:   envelope.AAD.SenderRole,
		RecordSHA256: envelope.AAD.RecordSHA256, Replayed: false,
	}, nil
}

func (store *formalCoxBlockwiseControlStore) MarkNextDelivered(
	envelopeSHA256, receiptSHA256 string, now time.Time,
) (formalCoxBlockwiseControlDeliveryReceipt, error) {
	var zero formalCoxBlockwiseControlDeliveryReceipt
	if !formalCoxIsSHA256(envelopeSHA256) ||
		!formalCoxIsSHA256(receiptSHA256) || now.Unix() < 1 {
		return zero, fmt.Errorf("formal-cox control: invalid delivery receipt")
	}
	for _, recordType := range formalCoxControlOutboundSequence(store.local.Role) {
		delivery, found, err := store.readDelivery(recordType)
		if err != nil {
			return zero, err
		}
		if !found || delivery.EnvelopeSHA256 != envelopeSHA256 {
			continue
		}
		if delivery.ReceiptSHA256 != receiptSHA256 {
			return zero, fmt.Errorf("formal-cox control: conflicting delivery replay")
		}
		entries, cleanupErr := store.outboxInventory(now, false)
		formalCoxControlClearOutboxEntries(entries)
		if cleanupErr != nil {
			return zero, cleanupErr
		}
		return formalCoxControlDeliveryReceipt(delivery, true), nil
	}
	source, err := store.nextSourceRecord()
	if err != nil {
		return zero, err
	}
	defer clear(source.record)
	recordSHA := formalCoxControlSHA(
		formalCoxControlRecordDomain, source.record)
	entries, err := store.outboxInventory(now, false)
	if err != nil {
		return zero, err
	}
	defer formalCoxControlClearOutboxEntries(entries)
	var selected *formalCoxControlOutboxEntry
	for index := range entries {
		entry := &entries[index]
		if entry.lease.EnvelopeSHA256 == envelopeSHA256 {
			if selected != nil {
				return zero, fmt.Errorf("formal-cox control: ambiguous outbox delivery")
			}
			selected = entry
		}
	}
	if selected == nil || selected.lease.RecordType != source.recordType ||
		selected.lease.RecordSHA256 != recordSHA {
		return zero, fmt.Errorf("formal-cox control: receipt has no current outbox")
	}
	delivery := formalCoxBlockwiseControlDelivery{
		Version:         formalCoxControlDeliveryVersion,
		Protocol:        formalCoxBlockwiseControlProtocol,
		ArtifactID:      store.context.ArtifactID,
		ExecutionSHA256: store.context.ExecutionSHA256,
		RecordType:      source.recordType, SenderRole: store.local.Role,
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
			err = fmt.Errorf("formal-cox control: conflicting delivery CAS")
		}
		return zero, err
	}
	if err := store.removeRecord(
		selected.envelopePath, formalCoxControlMaxEnvelopeJSON); err != nil {
		return zero, err
	}
	if err := store.removeRecord(selected.leasePath, 64<<10); err != nil {
		return zero, err
	}
	return formalCoxControlDeliveryReceipt(delivery, false), nil
}

func (store *formalCoxBlockwiseControlStore) RetainedBytes(
	now time.Time,
) (int64, error) {
	entries, err := store.outboxInventory(now, true)
	if err != nil {
		return 0, err
	}
	defer formalCoxControlClearOutboxEntries(entries)
	var total int64
	for _, entry := range entries {
		info, err := store.guard.root.Lstat(entry.leasePath)
		if err != nil || !info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
			!exactGCPrivateOwnedRegular(info) || info.Size() < 64 ||
			info.Size() > 64<<10 {
			return 0, fmt.Errorf("formal-cox control: unsafe retained lease")
		}
		if total > int64(formalCoxControlMaxEnvelopeJSON)*9-
			int64(len(entry.envelope))-info.Size() {
			return 0, fmt.Errorf("formal-cox control: retained accounting overflow")
		}
		total += int64(len(entry.envelope)) + info.Size()
	}
	return total, nil
}
