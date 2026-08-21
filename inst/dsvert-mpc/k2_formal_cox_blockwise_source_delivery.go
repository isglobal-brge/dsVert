package main

// A source delivery carries one recipient-encrypted Cox source envelope from
// the producer's private outbox to that exact recipient.  It is an internal
// transport DTO: no source row, Rock path, producer key, or recipient secret
// is ever included.

import (
	"bytes"
	"encoding/json"
	"fmt"
)

const (
	formalCoxBlockwiseSourceDeliveryVersion = "dsvert-formal-cox-blockwise-source-delivery-v1"
	formalCoxBlockwiseSourceDeliveryPurpose = "formal-cox-recipient-encrypted-source-delivery-v1"
)

type formalCoxBlockwiseSourceDelivery struct {
	Version           string                                    `json:"version"`
	Purpose           string                                    `json:"purpose"`
	Receipt           formalCoxBlockwiseSourceProductionReceipt `json:"receipt"`
	ReceiptSHA256     string                                    `json:"receipt_sha256"`
	RecipientPeerName string                                    `json:"recipient_peer_name"`
	Envelope          json.RawMessage                           `json:"envelope"`
	Binding           json.RawMessage                           `json:"binding"`
}

func formalCoxBlockwiseSourceDeliveryRecipientIndex(
	session *formalCoxBlockwiseSourceSession, recipient string,
) (int, error) {
	if session == nil || session.context == nil {
		return 0, fmt.Errorf("formal-cox: invalid source delivery session")
	}
	for index, peer := range session.context.plan.Policy.ComputePeers {
		if peer == recipient {
			return index, nil
		}
	}
	return 0, fmt.Errorf("formal-cox: source delivery recipient is not a compute peer")
}

func (delivery formalCoxBlockwiseSourceDelivery) validate(
	session *formalCoxBlockwiseSourceSession,
) error {
	index, err := formalCoxBlockwiseSourceDeliveryRecipientIndex(
		session, delivery.RecipientPeerName)
	if err != nil || delivery.Version != formalCoxBlockwiseSourceDeliveryVersion ||
		delivery.Purpose != formalCoxBlockwiseSourceDeliveryPurpose ||
		!formalCoxIsSHA256(delivery.ReceiptSHA256) ||
		len(delivery.Envelope) < 2 || len(delivery.Binding) < 2 {
		return fmt.Errorf("formal-cox: invalid source delivery")
	}
	receiptSHA, err := formalCoxBlockwiseSourceProductionReceiptSHA256(
		delivery.Receipt)
	if err != nil || receiptSHA != delivery.ReceiptSHA256 ||
		formalCoxBlockwiseValidateSourceProductionReceipt(
			session, delivery.Receipt,
			session.context.pins[delivery.Receipt.Binding.SourcePeerName]) != nil {
		return fmt.Errorf("formal-cox: source delivery receipt is invalid")
	}
	wantBinding, err := json.Marshal(delivery.Receipt.PairManifest)
	if err != nil || !bytes.Equal(wantBinding, delivery.Binding) {
		return fmt.Errorf("formal-cox: source delivery binding is not canonical")
	}
	envelope, digest, err := formalCoxBlockwiseSourceValidatePublicEnvelope(
		session, delivery.RecipientPeerName, delivery.Envelope)
	if err != nil || envelope.Header.SourcePeerName !=
		delivery.Receipt.Binding.SourcePeerName ||
		envelope.Header.BlockIndex != delivery.Receipt.Binding.BlockIndex ||
		envelope.Header.StepKind != formalCoxBlockwiseStepBlock ||
		delivery.Receipt.PairManifest.Recipients[index].EnvelopeSHA256 != digest {
		return fmt.Errorf("formal-cox: source delivery envelope is invalid")
	}
	if _, err := formalCoxBlockwiseSourceValidatePairManifest(
		session, delivery.Receipt.PairManifest, envelope.Header, digest); err != nil {
		return fmt.Errorf("formal-cox: source delivery pair binding is invalid")
	}
	return nil
}

// Delivery returns a verified, recipient-specific ciphertext only after the
// block's intent, two outbox bindings, signed receipt and durable cursor have
// all committed.  This makes delivery restart-safe without materialising the
// original source again.
func (producer *formalCoxBlockwiseSourceProducer) Delivery(
	block int, recipient string,
) (formalCoxBlockwiseSourceDelivery, error) {
	producer.mu.Lock()
	defer producer.mu.Unlock()
	var zero formalCoxBlockwiseSourceDelivery
	if producer.closed || producer.owner == nil || block < 0 {
		return zero, fmt.Errorf("formal-cox: source producer is closed or delivery block is invalid")
	}
	index, err := formalCoxBlockwiseSourceDeliveryRecipientIndex(
		producer.session, recipient)
	if err != nil {
		return zero, err
	}
	state, err := producer.readState()
	if err != nil || block >= state.NextBlock {
		return zero, fmt.Errorf("formal-cox: source delivery block is not committed")
	}
	receipt, receiptSHA, err := producer.validateCommittedBlock(
		block, receiptPreviousForBlock(producer, block))
	if err != nil {
		return zero, err
	}
	envelope, err := formalCoxBlockwiseReadPrivateFile(
		producer.outboxPath(block, index), 2, producer.session.context.maximum)
	if err != nil {
		return zero, err
	}
	binding, err := json.Marshal(receipt.PairManifest)
	if err != nil {
		return zero, err
	}
	delivery := formalCoxBlockwiseSourceDelivery{
		Version:           formalCoxBlockwiseSourceDeliveryVersion,
		Purpose:           formalCoxBlockwiseSourceDeliveryPurpose,
		Receipt:           receipt,
		ReceiptSHA256:     receiptSHA,
		RecipientPeerName: recipient,
		Envelope:          append(json.RawMessage(nil), envelope...),
		Binding:           append(json.RawMessage(nil), binding...),
	}
	if err := delivery.validate(producer.session); err != nil {
		return zero, err
	}
	return delivery, nil
}

// Accept imports a delivery only into its designated recipient's store.  The
// store revalidates and decrypts the ciphertext while persisting its canonical
// source slot, so a caller cannot turn this DTO into a trusted plaintext path.
func (delivery formalCoxBlockwiseSourceDelivery) Accept(
	store *formalCoxBlockwiseSourceStore,
) (bool, error) {
	if store == nil {
		return false, fmt.Errorf("formal-cox: source delivery store is absent")
	}
	store.mu.Lock()
	closed := store.closed || store.owner == nil
	session := store.session
	recipient := store.recipient
	store.mu.Unlock()
	if closed || recipient != delivery.RecipientPeerName {
		return false, fmt.Errorf("formal-cox: source delivery recipient mismatch")
	}
	if err := delivery.validate(session); err != nil {
		return false, err
	}
	return store.Accept(delivery.Envelope, delivery.Binding)
}
