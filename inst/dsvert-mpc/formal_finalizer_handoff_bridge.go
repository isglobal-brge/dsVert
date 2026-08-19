package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
)

const (
	formalFinalizerHandoffBridgeDescriptorVersion = "dsvert-formal-finalizer-handoff-source-descriptor-v1"
	formalFinalizerHandoffBridgeContextVersion    = "dsvert-formal-finalizer-handoff-typed-context-v1"
	formalFinalizerHandoffBridgeIngressVersion    = "dsvert-formal-finalizer-handoff-ingress-v1"
	formalFinalizerHandoffMaxOuterPayloadChars    = (formalFinalizerHandoffMaxRecord/3)*4 + 3
)

type formalFinalizerHandoffBridgeContext struct {
	Version             string `json:"version"`
	Family              string `json:"family"`
	Purpose             string `json:"purpose"`
	ArtifactID          string `json:"artifact_id"`
	FinalPairRootSHA256 string `json:"final_pair_root_sha256"`
	PlanSHA256          string `json:"plan_sha256"`
	PinsetSHA256        string `json:"pinset_sha256"`
	TicketSHA256        string `json:"ticket_sha256"`
	SenderPeerName      string `json:"sender_peer_name"`
	SenderRole          string `json:"sender_role"`
	FinalizerPeerName   string `json:"finalizer_peer_name"`
	PayloadKind         string `json:"payload_kind"`
	EnvelopeSHA256      string `json:"envelope_sha256"`
	EnvelopeBytes       int64  `json:"envelope_bytes"`
}

// formalFinalizerHandoffOutboxDescriptor is an internal Rock-local bridge
// contract. SourcePath is never part of a DSI response; the purpose-specific R
// producer uses it only to read the already validated durable outbox.
type formalFinalizerHandoffOutboxDescriptor struct {
	Version        string                              `json:"version"`
	SourcePath     string                              `json:"source_path"`
	EnvelopeBytes  int64                               `json:"envelope_bytes"`
	PayloadChars   int64                               `json:"payload_chars"`
	EnvelopeSHA256 string                              `json:"envelope_sha256"`
	Context        formalFinalizerHandoffBridgeContext `json:"context"`
}

type formalFinalizerHandoffIngressReceipt struct {
	Version        string `json:"version"`
	State          string `json:"state"`
	ArtifactID     string `json:"artifact_id"`
	SenderRole     string `json:"sender_role"`
	EnvelopeSHA256 string `json:"envelope_sha256"`
	Replayed       bool   `json:"replayed"`
}

func formalFinalizerHandoffBase64URLChars(size int64) (int64, error) {
	if size < 1 || size > formalFinalizerHandoffMaxRecord {
		return 0, fmt.Errorf("typed-finalizer-handoff: invalid bridge record size")
	}
	result := (size / 3) * 4
	switch size % 3 {
	case 1:
		result += 2
	case 2:
		result += 3
	}
	if result < 1 || result > formalFinalizerHandoffMaxOuterPayloadChars {
		return 0, fmt.Errorf("typed-finalizer-handoff: invalid bridge payload size")
	}
	return result, nil
}

// DescribeOutboxCanonical validates the durable outbox through the same store
// path used by the formal lifecycle, then returns only bounded metadata and its
// internal source path. No ciphertext is copied into the descriptor.
func (store *formalFinalizerHandoffStore) DescribeOutboxCanonical(
	role string,
) (formalFinalizerHandoffOutboxDescriptor, error) {
	var zero formalFinalizerHandoffOutboxDescriptor
	if store == nil || store.root == nil || store.localAuthority == nil ||
		role != "evaluator" || store.localAuthority.Role != role {
		return zero, fmt.Errorf("typed-finalizer-handoff: invalid outbox descriptor owner")
	}
	if _, found, err := store.PreflightAck(); err != nil {
		return zero, err
	} else if found {
		return zero, fmt.Errorf(
			"typed-finalizer-handoff: publication already acknowledged")
	}
	envelope, err := store.loadEnvelope("outbox-v1", role)
	if err != nil {
		return zero, err
	}
	defer clear(envelope.Ciphertext)
	encoded, err := json.Marshal(envelope)
	if err != nil || len(encoded) < 64 || len(encoded) > formalFinalizerHandoffMaxRecord {
		clear(encoded)
		return zero, fmt.Errorf("typed-finalizer-handoff: invalid canonical outbox")
	}
	defer clear(encoded)
	payloadChars, err := formalFinalizerHandoffBase64URLChars(int64(len(encoded)))
	if err != nil {
		return zero, err
	}
	digest := sha256.Sum256(encoded)
	envelopeSHA := hex.EncodeToString(digest[:])
	relative, err := store.relativePath("outbox-v1", role, "", false)
	if err != nil {
		return zero, err
	}
	sourcePath := filepath.Join(store.dir, relative)
	if !filepath.IsAbs(sourcePath) || filepath.Clean(sourcePath) != sourcePath {
		return zero, fmt.Errorf("typed-finalizer-handoff: invalid outbox source path")
	}
	context := formalFinalizerHandoffBridgeContext{
		Version: formalFinalizerHandoffBridgeContextVersion,
		Family:  envelope.Family, Purpose: envelope.Purpose,
		ArtifactID:          envelope.ArtifactID,
		FinalPairRootSHA256: envelope.FinalPairRootSHA256,
		PlanSHA256:          envelope.PlanSHA256,
		PinsetSHA256:        envelope.PinsetSHA256,
		TicketSHA256:        envelope.TicketSHA256,
		SenderPeerName:      envelope.SenderPeerName,
		SenderRole:          envelope.SenderRole,
		FinalizerPeerName:   envelope.FinalizerPeerName,
		PayloadKind:         envelope.PayloadKind,
		EnvelopeSHA256:      envelopeSHA,
		EnvelopeBytes:       int64(len(encoded)),
	}
	return formalFinalizerHandoffOutboxDescriptor{
		Version:    formalFinalizerHandoffBridgeDescriptorVersion,
		SourcePath: sourcePath, EnvelopeBytes: int64(len(encoded)),
		PayloadChars: payloadChars, EnvelopeSHA256: envelopeSHA,
		Context: context,
	}, nil
}

// ImportIngressCanonical is the only byte-bearing shared helper. Its caller is
// a private lifecycle consumer; the method strictly validates the canonical
// signed envelope and persists it through CommitIngress's finalizer-only CAS.
func (store *formalFinalizerHandoffStore) ImportIngressCanonical(
	expectedRole string, encoded []byte,
) (formalFinalizerHandoffIngressReceipt, error) {
	var zero formalFinalizerHandoffIngressReceipt
	if store == nil || store.root == nil || store.localAuthority == nil ||
		!formalFinalizerHandoffAuthorityEqual(
			*store.localAuthority, store.binding.Finalizer) {
		return zero, fmt.Errorf("typed-finalizer-handoff: ingress import requires finalizer")
	}
	if expectedRole != "evaluator" {
		return zero, fmt.Errorf("typed-finalizer-handoff: invalid ingress sender role")
	}
	var envelope formalFinalizerHandoffEnvelope
	if formalFinalizerHandoffDecodeCanonical(
		encoded, formalFinalizerHandoffMaxRecord, &envelope) != nil ||
		envelope.SenderRole != expectedRole {
		clear(envelope.Ciphertext)
		return zero, fmt.Errorf("typed-finalizer-handoff: invalid canonical ingress")
	}
	defer clear(envelope.Ciphertext)
	stored, replayed, err := store.CommitIngress(envelope)
	if err != nil {
		return zero, err
	}
	defer clear(stored.Ciphertext)
	canonical, err := json.Marshal(stored)
	if err != nil || len(canonical) < 64 ||
		len(canonical) > formalFinalizerHandoffMaxRecord {
		clear(canonical)
		return zero, fmt.Errorf("typed-finalizer-handoff: invalid committed ingress")
	}
	digest := sha256.Sum256(canonical)
	clear(canonical)
	return formalFinalizerHandoffIngressReceipt{
		Version: formalFinalizerHandoffBridgeIngressVersion,
		State:   "ingress_committed", ArtifactID: stored.ArtifactID,
		SenderRole:     stored.SenderRole,
		EnvelopeSHA256: hex.EncodeToString(digest[:]), Replayed: replayed,
	}, nil
}
